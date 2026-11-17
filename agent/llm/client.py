"""
agent/llm/client.py
Gerencia a comunicação com a API do Groq (Llama 3) usando Pydantic para Structured Outputs.
"""
import os
import json
import re
import time
from pathlib import Path
from openai import OpenAI
from pydantic import BaseModel

# The default is the model the pipeline was built and measured with. It is overridable because a
# provider can withdraw a model: on 2026-11-04 the Groq account answered 404 for it.
MODELO_LLM = os.getenv("AUDIT_LLM_MODEL", "llama-3.3-70b-versatile")


def _load_env_file() -> None:
    """Load simple KEY=VALUE lines without warning on notes/malformed lines."""
    env_path = Path(__file__).resolve().parents[2] / ".env"
    if not env_path.exists():
        return

    for line in env_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        key = key.strip()
        if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", key):
            continue
        os.environ.setdefault(key, value.strip().strip('"').strip("'"))

_RETRY_AFTER_RE = re.compile(r"try again in ([\d.]+)s")


def _rate_limit_wait(error: str) -> float | None:
    """Segundos a esperar quando o Groq recusa por tokens-por-minuto, ou None se nao foi isso.

    O tier on_demand e de 8000 TPM e um prompt de diagnostico ja usa metade disso, entao
    duas chamadas seguidas estouram o limite -- foi assim que o GovTokenEscrow parou no
    estagio de reparo com 4 achados ja confirmados pelo Prover. A propria mensagem do erro
    diz quanto esperar; esperar e repetir e a resposta certa, e nao desistir da rodada.
    """
    if "rate_limit_exceeded" not in error and "429" not in error:
        return None
    match = _RETRY_AFTER_RE.search(error)
    if match:
        return min(float(match.group(1)) + 1.0, 60.0)
    return 20.0


def get_client() -> OpenAI:
    _load_env_file()
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        raise EnvironmentError("GROQ_API_KEY não encontrada no arquivo .env!")
    return OpenAI(
        api_key=api_key,
        base_url="https://api.groq.com/openai/v1",
    )

def _normalizar_chaves(obj):
    """Remove acentos das chaves do JSON — o modelo às vezes retorna padrão_cvl em vez de padrao_cvl."""
    acentos = str.maketrans("ãáàâäçéêëíîïóôõöúûüñ", "aaaaceeeiiiooooouuun")
    if isinstance(obj, dict):
        return {k.translate(acentos): _normalizar_chaves(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [_normalizar_chaves(i) for i in obj]
    return obj

def chamar_ia_json(
    system_prompt: str,
    user_prompt: str,
    schema_esperado: BaseModel,
    max_tokens: int | None = None,
    _room_to_answer: bool = True,
    _rate_retries: int = 2,
) -> dict:
    client = get_client()
    system_com_schema = (
        f"{system_prompt}\n\n"
        f"You must return only valid JSON. Do not use markdown.\n"
        f"The JSON must exactly match this schema:\n{schema_esperado.model_json_schema()}"
    )
    try:
        kwargs = {
            "model": MODELO_LLM,
            "messages": [
                {"role": "system", "content": system_com_schema},
                {"role": "user", "content": user_prompt}
            ],
            "response_format": {"type": "json_object"},
            "temperature": 0.0,
        }
        if max_tokens:
            kwargs["max_tokens"] = max_tokens
        if not _room_to_answer and "gpt-oss" in MODELO_LLM:
            # Na segunda tentativa, pede menos raciocinio: o que falta e orcamento, e esse
            # parametro e dos modelos gpt-oss, por isso vai so quando o modelo e um deles.
            kwargs["extra_body"] = {"reasoning_effort": "low"}
        response = client.chat.completions.create(**kwargs)
        conteudo_bruto = response.choices[0].message.content
        dados_json = _normalizar_chaves(json.loads(conteudo_bruto))
        dados_validados = schema_esperado.model_validate(dados_json)
        return dados_validados.model_dump()
    except Exception as e:
        # Groq retorna 400 com failed_generation quando JSON tem chars especiais
        # O JSON gerado geralmente está correto — tentamos extraí-lo diretamente
        err_str = str(e)
        if 'failed_generation' in err_str:
            try:
                import re as _re
                match = _re.search(r"'failed_generation':\s*'(.*?)'(?:\s*\}|\s*,)", err_str, _re.DOTALL)
                if match:
                    raw = match.group(1).replace("\\'", "'").replace('\\"', '"')
                    dados_json = _normalizar_chaves(json.loads(raw))
                    dados_validados = schema_esperado.model_validate(dados_json)
                    print("   ↩️  JSON recuperado do failed_generation")
                    return dados_validados.model_dump()
            except Exception:
                pass
        espera = _rate_limit_wait(err_str)
        if espera is not None and _rate_retries > 0:
            print(f"   ⏳ 429 do Groq (TPM): esperando {espera:.0f}s e repetindo")
            time.sleep(espera)
            return chamar_ia_json(
                system_prompt, user_prompt, schema_esperado, max_tokens,
                _room_to_answer, _rate_retries - 1,
            )
        if _room_to_answer and "json_validate_failed" in err_str:
            # Modelo de raciocinio: os tokens de raciocinio contam no `max_tokens`, entao um
            # orcamento apertado termina com o modelo tendo pensado e nao dito nada -- e o
            # Groq reporta `json_validate_failed` com `failed_generation` vazio, que nao da
            # nada para recuperar. O que falta e espaco, nao outro prompt.
            folga = max(4 * (max_tokens or 1400), 4000)
            print(f"   ↩️  Repetindo com max_tokens={folga} e menos raciocinio")
            return chamar_ia_json(
                system_prompt, user_prompt, schema_esperado, folga,
                _room_to_answer=False, _rate_retries=_rate_retries,
            )
        print(f"[ERRO DE API/PARSE] Falha ao consultar o Groq: {e}")
        raise

def chamar_ia_texto(
    system_prompt: str,
    user_prompt: str,
    max_tokens: int | None = None,
    _rate_retries: int = 2,
) -> str:
    client = get_client()
    try:
        kwargs = {
            "model": MODELO_LLM,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            "temperature": 0.0,
        }
        if max_tokens:
            kwargs["max_tokens"] = max_tokens
        response = client.chat.completions.create(**kwargs)
        return response.choices[0].message.content
    except Exception as e:
        espera = _rate_limit_wait(str(e))
        if espera is not None and _rate_retries > 0:
            print(f"   ⏳ 429 do Groq (TPM): esperando {espera:.0f}s e repetindo")
            time.sleep(espera)
            return chamar_ia_texto(system_prompt, user_prompt, max_tokens, _rate_retries - 1)
        print(f"❌ [ERRO DE API/TEXTO] Falha ao consultar o modelo: {e}")
        return ""

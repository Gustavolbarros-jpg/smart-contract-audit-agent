"""
agent/llm/client.py
Gerencia a comunicação com a API do Groq (Llama 3) usando Pydantic para Structured Outputs.
"""
import os
import json
from openai import OpenAI
from pydantic import BaseModel
from dotenv import load_dotenv

load_dotenv()

MODELO_LLM = "llama-3.3-70b-versatile"

def get_client() -> OpenAI:
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

def chamar_ia_json(system_prompt: str, user_prompt: str, schema_esperado: BaseModel) -> dict:
    client = get_client()
    system_com_schema = (
        f"{system_prompt}\n\n"
        f"VOCÊ DEVE RETORNAR APENAS UM JSON VÁLIDO. NÃO USE MARKDOWN.\n"
        f"O JSON deve seguir EXATAMENTE este schema:\n{schema_esperado.model_json_schema()}"
    )
    try:
        response = client.chat.completions.create(
            model=MODELO_LLM,
            messages=[
                {"role": "system", "content": system_com_schema},
                {"role": "user", "content": user_prompt}
            ],
            response_format={"type": "json_object"},
            temperature=0.0
        )
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
        print(f"[ERRO DE API/PARSE] Falha ao consultar o Groq: {e}")
        raise

def chamar_ia_texto(system_prompt: str, user_prompt: str) -> str:
    client = get_client()
    try:
        response = client.chat.completions.create(
            model=MODELO_LLM,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            temperature=0.0
        )
        return response.choices[0].message.content
    except Exception as e:
        print(f"❌ [ERRO DE API/TEXTO] Falha ao consultar o modelo: {e}")
        return ""
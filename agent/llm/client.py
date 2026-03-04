"""
agent/llm/client.py
Gerencia a comunicação com a API do Groq (Llama 3) usando Pydantic para Structured Outputs.
"""
import os
import json
from openai import OpenAI
from pydantic import BaseModel
from dotenv import load_dotenv  # <-- Adicione esta linha

load_dotenv()  #

# Vamos usar o Llama 3 de 70 Bilhões de parâmetros (Excelente para código/Solidity)
MODELO_LLM = "llama-3.3-70b-versatile"

def get_client() -> OpenAI:
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        raise EnvironmentError("GROQ_API_KEY não encontrada no arquivo .env!")
    
    # O Groq é 100% compatível com a biblioteca da OpenAI
    return OpenAI(
        api_key=api_key,
        base_url="https://api.groq.com/openai/v1",
    )

def chamar_ia_json(system_prompt: str, user_prompt: str, schema_esperado: BaseModel) -> dict:
    """
    Chama a IA e obriga-a a retornar um JSON válido baseado no Pydantic Schema.
    """
    client = get_client()
    
    # Injetamos o schema no prompt de sistema para guiar a IA
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
            response_format={"type": "json_object"}, # Força o modo JSON
            temperature=0.1 # Temperatura baixa para código preciso
        )
        
        conteudo_bruto = response.choices[0].message.content
        
        # Lemos o JSON e validamos contra o contrato do Pydantic
        dados_json = json.loads(conteudo_bruto)
        dados_validados = schema_esperado.model_validate(dados_json)
        return dados_validados.model_dump()
        
    except Exception as e:
        print(f"[ERRO DE API/PARSE] Falha ao consultar o Groq: {e}")
        raise
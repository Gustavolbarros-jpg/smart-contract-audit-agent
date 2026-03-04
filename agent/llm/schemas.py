"""
agent/llm/schemas.py
Define a estrutura rígida de dados que esperamos da IA (Grok).
Isso substitui o parseamento frágil de strings.
"""
from pydantic import BaseModel, Field
from typing import List, Literal, Optional

# --- Modelos para a Etapa 1 (Slither) ---

class ElementoVulneravel(BaseModel):
    name: str = Field(description="Nome da variável, função ou expressão")
    type: str = Field(description="O tipo do elemento (ex: variable, function, node)")
    line: Optional[str] = Field(default="", description="Número da linha (se existir)")

class Vulnerabilidade(BaseModel):
    id: str = Field(description="ID sequencial: VULN_001, VULN_002...")
    type: str = Field(description="O tipo da vulnerabilidade reportado pelo Slither")
    description: str
    function: str
    line: Optional[str] = Field(default="", description="Linha da vulnerabilidade (se existir)")
    impact: str = Field(description="Ex: high, medium, low, informational")
    confidence: str = Field(description="Ex: high, medium, low")
    elements: List[ElementoVulneravel]
    propriedade_formal: str = Field(description="Deixe vazio se não for verificável via Certora")
    padrao_cvl: str = Field(description="Deixe vazio se não for verificável via Certora")

class RelatorioSlitherNormalizado(BaseModel):
    vulnerabilidades: List[Vulnerabilidade]


# --- (MANTENHA O RESTO DO FICHEIRO EXATAMENTE COMO ESTAVA) ---
# class VulnerabilidadeAnalisada(BaseModel):
# ...

# --- Modelos para a Etapa 4 (Análise do Certora) ---

class VulnerabilidadeAnalisada(BaseModel):
    id: str
    type: str
    function: str
    rule: str = Field(description="A regra CVL que foi verificada")
    status: Literal["confirmed", "confirmed_static", "not_confirmed", "inconclusive"]
    evidencia: Optional[str] = Field(default=None, description="Explicação do porquê foi confirmada ou não")

class AnaliseCertora(BaseModel):
    analises: List[VulnerabilidadeAnalisada]




# --- Modelos para as Etapas de Geração de Código (2, 3 e 5) ---

class CodigoGerado(BaseModel):
    codigo: str = Field(description="O código-fonte completo gerado (pode ser CVL ou Solidity, dependendo da etapa)")

class ValidacaoSpec(BaseModel):
    valido: bool = Field(description="True se o .spec estiver perfeito, False se tiver erros de sintaxe")
    erros: List[str] = Field(description="Lista de erros encontrados (se houver)")
    codigo_corrigido: str = Field(description="O código .spec completo, corrigido caso haja erros, ou original se for válido")
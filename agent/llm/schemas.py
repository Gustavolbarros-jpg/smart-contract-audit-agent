"""
agent/llm/schemas.py
Defines the strict structured outputs expected from the LLM.
This replaces fragile string parsing.
"""
from pydantic import BaseModel, Field
from typing import List, Literal, Optional

# --- Stage 1 models (Slither) ---

class ElementoVulneravel(BaseModel):
    name: str = Field(description="Variable, function, node, or expression name")
    type: str = Field(description="Element type, such as variable, function, or node")
    line: Optional[str] = Field(default="", description="Source line, when available")

class Vulnerabilidade(BaseModel):
    id: str = Field(description="Exact sequential ID: VULN_001, VULN_002...")
    type: str = Field(description="Slither detector type")
    description: str
    function: str
    line: Optional[str] = Field(default="", description="Finding line or line range, when available")
    impact: str = Field(description="Example: high, medium, low, informational")
    confidence: str = Field(description="Example: high, medium, low")
    elements: List[ElementoVulneravel]
    propriedade_formal: str = Field(description="Formal property; leave empty if not suitable for Certora")
    padrao_cvl: str = Field(default="", description="CVL pattern name; leave empty if not suitable for Certora")

class RelatorioSlitherNormalizado(BaseModel):
    vulnerabilidades: List[Vulnerabilidade]


# --- Formal planning model (LLM as agent) ---

class RegraFormalPlanejada(BaseModel):
    id: str = Field(description="Exact vulnerability ID; never renumber")
    rule_names: List[str] = Field(description="Valid, unique CVL rule names")
    formal_property: str = Field(description="Formal property to verify")
    cvl_strategy: str = Field(description="Concrete CVL strategy to test the property")
    required_methods: List[str] = Field(default_factory=list, description="Required CVL methods{} signatures or function names")
    assumptions: List[str] = Field(default_factory=list, description="Assumptions needed by the proof")
    reason: str = Field(description="Reason for selecting this vulnerability")


class FindingFormalIgnorado(BaseModel):
    id: str = Field(description="Exact skipped vulnerability ID")
    reason: str = Field(description="Reason for not formalizing this finding now")


class PlanoFormal(BaseModel):
    selected_rules: List[RegraFormalPlanejada]
    skipped_findings: List[FindingFormalIgnorado] = Field(default_factory=list)
    global_assumptions: List[str] = Field(default_factory=list)


# --- Stage 4 models (Certora analysis) ---

class VulnerabilidadeAnalisada(BaseModel):
    id: str
    type: str
    function: str
    rule: str = Field(description="The checked CVL rule")
    status: Literal["confirmed", "confirmed_static", "not_confirmed", "inconclusive"]
    evidencia: Optional[str] = Field(default=None, description="Evidence explaining the result")

class AnaliseCertora(BaseModel):
    analises: List[VulnerabilidadeAnalisada]


# --- Code-generation models ---

class CodigoGerado(BaseModel):
    codigo: str = Field(description="Complete generated source code, either CVL or Solidity depending on the step")

class ValidacaoSpec(BaseModel):
    valido: bool = Field(description="True if the spec is valid; false if syntax/type issues remain")
    erros: List[str] = Field(description="List of detected errors")
    codigo_corrigido: str = Field(description="Complete corrected spec, or original if already valid")


# --- Failure diagnosis model ---

class FalhaDiagnosticada(BaseModel):
    id: str = Field(description="Vulnerability ID: VULN_XXX")
    rule_que_falhou: str = Field(description="Failed CVL rule name")
    motivo: str = Field(description="Root cause in Solidity code")
    linha: Optional[int] = Field(default=None, description="Exact contract line to patch, when available")
    codigo_atual: Optional[str] = Field(default=None, description="Current buggy snippet")
    correcao_necessaria: str = Field(description="Exact required change")

class DiagnosticoFalhas(BaseModel):
    falhas: List[FalhaDiagnosticada]

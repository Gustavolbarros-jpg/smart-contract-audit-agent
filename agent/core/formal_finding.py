"""Transforma a violação de uma propriedade formal num achado que o pipeline sabe reparar.

O pipeline só repara o que o stack estático reporta, e isso foi medido: **9 dos 46**
mutantes do DeFiVault produzem achado novo no Slither. Para AOR, BOR, UOR, EED e PKR o
relatório vem vazio, então o estágio de reparo nunca é alcançado — por mais capaz que a LLM
seja. O oráculo formal local, com a mesma spec congelada, mata **18 dos 46** e diz qual
propriedade quebrou e com que valores.

Este módulo é o adaptador entre os dois: uma regra violada vira um achado, com a função
responsável e o contraexemplo como evidência, para que diagnóstico e reparo rodem sobre
evidência que o stack estático não consegue produzir. É a peça da fase 2 descrita em
``docs/experimento-generalizacao-pre-registro.md`` §9.3.

Não reivindica nada sobre reparo: só converte evidência. Quem repara é o estágio seguinte.
"""

from __future__ import annotations

import re

from core.certora_counterexample import extract_counterexamples

FORMAL_VIOLATION = "formal-property-violation"
VACUITY_SUFFIX = "-rule_not_vacuous"

_VIOLATED_RE = re.compile(r"^Violated:[ \t]*(\S+)[ \t]*$", re.MULTILINE)
_ASSERT_MESSAGE_RE = re.compile(r"^Failed on (\S+):\s*\n\s*Assert message:\s*(.+)$", re.MULTILINE)
_RULE_BLOCK_RE = re.compile(r"\brule\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:\([^)]*\))?\s*\{", re.MULTILINE)
_CALL_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*(?:@withrevert|@norevert)?\s*\(")
_METHODS_ENVFREE_RE = re.compile(
    r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^)]*\)[^;]*\benvfree\b", re.MULTILINE
)

# Nomes que aparecem como chamada no corpo de uma regra sem serem função do contrato.
_CVL_KEYWORDS = frozenset(
    {
        "require", "assert", "requireInvariant", "satisfy", "to_mathint", "to_uint256",
        "assert_uint256", "require_uint256", "havoc", "forall", "exists", "f", "e",
        "lastReverted", "lastHasThrown", "sinvoke", "invoke", "max_uint256", "nativeBalances",
    }
)


def _rule_bodies(spec_source: str) -> dict[str, str]:
    """Corpo de cada ``rule`` da spec, por nome."""
    bodies: dict[str, str] = {}
    for match in _RULE_BLOCK_RE.finditer(spec_source or ""):
        start = match.end() - 1
        depth = 0
        for index in range(start, len(spec_source)):
            if spec_source[index] == "{":
                depth += 1
            elif spec_source[index] == "}":
                depth -= 1
                if depth == 0:
                    bodies[match.group(1)] = spec_source[start + 1: index]
                    break
    return bodies


def function_under_rule(rule_name: str, spec_source: str) -> str:
    """A função do contrato que a regra exercita.

    Uma regra chama getters ``envfree`` para ler estado e **uma** função sob teste; os
    getters estão declarados no bloco ``methods`` e saem da conta, do mesmo jeito que as
    palavras de CVL. O que sobra primeiro é a função responsável pelo que falhou.
    """
    body = _rule_bodies(spec_source).get(rule_name, "")
    if not body:
        return ""
    getters = set(_METHODS_ENVFREE_RE.findall(spec_source or ""))
    for name in _CALL_RE.findall(body):
        if name in _CVL_KEYWORDS or name in getters:
            continue
        return name
    return ""


def violated_rules(log: str) -> list[str]:
    """Regras violadas no log, sem os sanity checks de vacuidade."""
    seen: list[str] = []
    for name in _VIOLATED_RE.findall(log or ""):
        if name.endswith(VACUITY_SUFFIX) or name in seen:
            continue
        seen.append(name)
    return seen


def assert_messages(log: str) -> dict[str, str]:
    """Mensagem de assert por regra, como o Prover a imprime no resumo de falhas."""
    return {rule: message.strip() for rule, message in _ASSERT_MESSAGE_RE.findall(log or "")}


def findings_from_violations(
    log: str,
    spec_source: str,
    start_index: int = 1,
    id_prefix: str = "VULN_F",
) -> list[dict]:
    """Um achado por regra violada, no formato que o resto do pipeline consome."""
    messages = assert_messages(log)
    counterexamples = extract_counterexamples(log or "")
    findings: list[dict] = []
    for offset, rule in enumerate(violated_rules(log)):
        function = function_under_rule(rule, spec_source)
        message = messages.get(rule, "")
        findings.append(
            {
                "id": f"{id_prefix}{start_index + offset:03d}",
                "type": FORMAL_VIOLATION,
                "function": f"{function}()" if function else "",
                "rule": rule,
                "severity": "High",
                "description": (
                    f"A propriedade {rule} foi violada pelo Prover"
                    + (f" em {function}" if function else "")
                    + (f": {message}" if message else ".")
                ),
                "counterexample": counterexamples.get(rule, {}),
                "origin": "certora_local_oracle",
            }
        )
    return findings

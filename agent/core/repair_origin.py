"""Qual trilha reparou cada achado: o patch determinístico ou a LLM.

Até aqui isso só dava para *inferir* dos artefatos da rodada, e foi essa inferência que
deixou a afirmação de generalização sem como falhar: quando a inferência foi feita com
cuidado, os 13 reparos medidos eram **todos** determinísticos. Daqui para frente a origem é
um campo que o caminho de código escreve, não uma leitura das sobras.

Origem é a trilha que *tentou* o reparo, não o veredito: o sucesso vem da comparação
Certora/Slither depois. Cruzar as duas coisas é o que permite dizer "a LLM consertou N
achados que o patch determinístico não cobria" — ou que não consertou nenhum.
"""

from __future__ import annotations

DETERMINISTIC = "deterministic"
LLM = "llm"
NONE = "none"

_OUTCOMES = ("resolvidas", "persistentes", "inconclusivas")


def repair_origins(
    confirmed_ids,
    deterministic_ids,
    llm_ids=None,
) -> dict[str, str]:
    """Mapa id -> origem, para todos os IDs confirmados da rodada.

    ``llm_ids`` é o conjunto que sobrou para a LLM depois do patch mecânico. Um ID
    confirmado que não está em nenhum dos dois não teve reparo tentado: ``none``.
    """
    deterministic = set(deterministic_ids or ())
    llm = set(llm_ids or ())
    origins: dict[str, str] = {}
    for vuln_id in sorted(set(confirmed_ids or ())):
        if vuln_id in deterministic:
            # O patch mecânico roda primeiro, de propósito: uma falha de LLM não deve
            # bloquear o que já era mecânico. Por isso ele vence o empate.
            origins[vuln_id] = DETERMINISTIC
        elif vuln_id in llm:
            origins[vuln_id] = LLM
        else:
            origins[vuln_id] = NONE
    return origins


def count_by_origin(comparison: dict, origins: dict[str, str]) -> dict[str, dict[str, int]]:
    """Resolvidas/persistentes/inconclusivas separadas por origem do reparo."""
    counts: dict[str, dict[str, int]] = {}
    for outcome in _OUTCOMES:
        for item in comparison.get(outcome, []) or []:
            origin = origins.get(item.get("id"), NONE)
            bucket = counts.setdefault(origin, {name: 0 for name in _OUTCOMES})
            bucket[outcome] += 1
    return counts


def stamp_origins(comparison: dict, origins: dict[str, str]) -> dict:
    """Escreve a origem em cada item da comparação e acrescenta o agregado por origem."""
    for outcome in _OUTCOMES:
        for item in comparison.get(outcome, []) or []:
            item["origem"] = origins.get(item.get("id"), NONE)
    comparison["por_origem"] = count_by_origin(comparison, origins)
    return comparison

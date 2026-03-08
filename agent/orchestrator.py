"""
agent/orchestrator.py
Orquestrador com Loop de Auto-Correção + Diagnóstico + Validação automática de spec.

FLUXO:
  Etapa 1  → Slither normaliza vulnerabilidades
  Etapa 3  → Gera spec CVL + autocorreção automática (@withrevert, block.timestamp)
  Certora  → Verifica contrato ORIGINAL
  Etapa 4  → Identifica confirmed/confirmed_static
  Etapa 5  → Diagnostica + corrige → salva em agent_outputs/ (NÃO em smart-audt ainda)
  Etapa 6  → Loop: Certora no FIXED → compara → se OK move para smart-audt/contracts/
"""
import os
import json
import re
from pathlib import Path
import shutil

from tools.slither_cli import run_slither
from tools.certora_cli import run_certora
from tools.spec_validator import corrigir_spec, validar_spec, deduplicar_spec, remover_rules_vazias
from llm.client import chamar_ia_json, chamar_ia_texto
from llm.schemas import (
    RelatorioSlitherNormalizado,
    CodigoGerado,
    AnaliseCertora,
    DiagnosticoFalhas,
)
from prompts import system_prompts as sp

MAX_TENTATIVAS_CORRECAO = 3


def salvar_arquivo(caminho: str, conteudo: str):
    with open(caminho, "w", encoding="utf-8") as f:
        f.write(conteudo)
    print(f"💾 Salvo: {caminho}")


def limpar_strings_solidity(codigo: str) -> str:
    """Remove caracteres não-ASCII de strings literais no Solidity."""
    substituicoes = {
        'endereço': 'address', 'dono': 'owner', 'proprietário': 'owner',
        'contrato': 'contract', 'saldo': 'balance', 'falhou': 'failed',
        'destino': 'destination', 'zero': 'zero', 'insuficiente': 'insufficient',
        'sucesso': 'success', 'não': 'not', 'é': 'is', 'para': 'to',
    }
    def limpar_string(m):
        s = m.group(1)
        for pt, en in substituicoes.items():
            s = s.replace(pt, en)
        s = s.encode('ascii', 'ignore').decode('ascii')
        return f'"{s}"'
    return re.sub(r'"([^"]*)"', limpar_string, codigo)


def limpar_codigo_solidity(texto_bruto: str) -> str:
    match = re.search(r'```solidity\n(.*?)\n```', texto_bruto, re.DOTALL)
    if match:
        return match.group(1).strip()
    linhas = texto_bruto.split('\n')
    return '\n'.join([l for l in linhas if '```' not in l and "Aqui está" not in l]).strip()


def preparar_spec(spec_raw: str, caminho: str) -> str:
    """Remove vazias, deduplica, autocorrige, valida e salva o spec."""
    spec_corrigido, vazias = remover_rules_vazias(spec_raw)
    if vazias:
        print(f"   🗑️  Rules vazias removidas ({len(vazias)}):")
        for v in vazias:
            print(f"      → {v}")

    spec_corrigido, dups = deduplicar_spec(spec_corrigido)
    if dups:
        print(f"   🧹 Duplicatas removidas ({len(dups)}):")
        for d in dups:
            print(f"      → {d}")

    spec_corrigido, correcoes = corrigir_spec(spec_corrigido)
    if correcoes:
        print(f"   🔧 Auto-correções no spec ({len(correcoes)}):")
        for c in correcoes:
            print(f"      → {c}")

    valido, erros = validar_spec(spec_corrigido)
    if not valido:
        print(f"   ⚠️  Avisos restantes ({len(erros)}):")
        for e in erros:
            print(f"      → {e}")

    salvar_arquivo(caminho, spec_corrigido)
    return spec_corrigido


def comparar_resultados(vulns_confirmadas_original: list, analise_pos: dict) -> dict:
    def normalizar_rule(nome):
        return nome.split('-rule_not_vacuous')[0].split('-sanity')[0].strip()

    ids_orig = {v["id"] for v in vulns_confirmadas_original}
    analises_pos = {v["id"]: v for v in analise_pos.get("analises", [])}

    for v in analises_pos.values():
        if "rule" in v:
            v["rule"] = normalizar_rule(v["rule"])

    resolvidas, persistentes, inconclusivas = [], [], []

    for vuln_original in vulns_confirmadas_original:
        vuln_id = vuln_original["id"]
        res = analises_pos.get(vuln_id)

        if not res:
            inconclusivas.append({"id": vuln_id, "motivo": "Não encontrada no resultado"})
            continue

        status = res.get("status", "")
        rule_name = res.get("rule", vuln_original.get("rule", "unknown_rule"))
        vuln_type = vuln_original.get("type", "unknown_type")

        if status == "not_confirmed":
            resolvidas.append({"id": vuln_id, "type": vuln_type, "rule": rule_name})
        elif status == "confirmed":
            persistentes.append({"id": vuln_id, "type": vuln_type, "rule": rule_name, "evidencia": res.get("evidencia", "")})
        else:
            inconclusivas.append({"id": vuln_id, "status": status, "motivo": res.get("evidencia", "inconclusive/erro")})

    return {
        "total_original": len(ids_orig),
        "resolvidas": resolvidas,
        "persistentes": persistentes,
        "inconclusivas": inconclusivas,
        "taxa_resolucao": f"{len(resolvidas)}/{len(ids_orig)}"
    }


def imprimir_comparacao(comparacao: dict):
    print("\n" + "─" * 60)
    print("📊 COMPARAÇÃO: ORIGINAL vs PÓS-CORREÇÃO")
    print("─" * 60)
    print(f"   Taxa de resolução: {comparacao['taxa_resolucao']}")
    for v in comparacao["resolvidas"]:
        print(f"   ✅ {v['id']} — {v['type']} (rule: {v['rule']})")
    for v in comparacao["persistentes"]:
        print(f"   ❌ {v['id']} — {v['type']} (rule: {v['rule']})")
        if v.get("evidencia"):
            print(f"      → {v['evidencia']}")
    for v in comparacao["inconclusivas"]:
        print(f"   ⚠️  {v['id']} — {v.get('motivo', '')}")
    print("─" * 60)


def executar_pipeline(contract_path: str):
    print("\n" + "=" * 60)
    print("🚀 INICIANDO AUDIT AGENT PIPELINE (SELF-HEALING MODE)")
    print("=" * 60)

    if not os.path.exists(contract_path):
        print(f"❌ Erro: Contrato não encontrado em {contract_path}")
        return

    with open(contract_path, "r", encoding="utf-8") as f:
        contract_source = f.read()

    nome_contrato = Path(contract_path).stem
    pasta_output  = Path("agent_outputs")
    pasta_output.mkdir(exist_ok=True)

    # ── ETAPA 1: Slither ─────────────────────────────────────────
    print("\n▶️  ETAPA 1: Executando Slither e Normalizando...")
    slither_raw = run_slither(contract_path)
    vulns_normalizadas = chamar_ia_json(
        sp.PROMPT_ETAPA1_NORMALIZAR,
        f"DADOS:\n{json.dumps(slither_raw)}\nCONTRATO:\n{contract_source}",
        RelatorioSlitherNormalizado
    )
    salvar_arquivo(str(pasta_output / "etapa1_vulns.json"),
                   json.dumps(vulns_normalizadas, indent=2, ensure_ascii=False))

    # ── ETAPA 3: Gerar + autocorrigir Spec ───────────────────────
    print("\n▶️  ETAPA 3: Gerando e validando Spec CVL...")
    spec_gerado = chamar_ia_json(
        sp.PROMPT_ETAPA3_GERAR_SPEC,
        f"VULNS:\n{json.dumps(vulns_normalizadas)}\nCONTRATO:\n{contract_source}",
        CodigoGerado
    )
    caminho_spec = pasta_output / f"{nome_contrato}.spec"
    preparar_spec(spec_gerado["codigo"], str(caminho_spec))

    # ── CERTORA no ORIGINAL ──────────────────────────────────────
    print("\n▶️  CERTORA PROVER: Verificando contrato ORIGINAL...")
    certora_log = run_certora(contract_path, str(caminho_spec), str(pasta_output))
    salvar_arquivo(str(pasta_output / "certora_original_log.txt"), certora_log)

    analise = chamar_ia_json(
        sp.PROMPT_ETAPA4_ANALISAR,
        f"LOG:\n{certora_log}\nVULNS:\n{json.dumps(vulns_normalizadas)}",
        AnaliseCertora
    )
    salvar_arquivo(str(pasta_output / "etapa4_analise.json"),
                   json.dumps(analise, indent=2, ensure_ascii=False))

    vulns_confirmadas = [
        v for v in analise["analises"]
        if v["status"] in ("confirmed", "confirmed_static")
    ]

    if not vulns_confirmadas:
        print("\n✅ Nenhuma vulnerabilidade confirmada! O contrato já está seguro.")
        return

    print(f"\n🔴 {len(vulns_confirmadas)} confirmada(s): {[v['id'] for v in vulns_confirmadas]}")

    # ── ETAPA 5: Diagnóstico + Primeira Correção ─────────────────
    print("\n▶️  ETAPA 5: Diagnosticando e corrigindo...")
    diagnostico = chamar_ia_json(
        sp.PROMPT_DIAGNOSTICO,
        f"LOG:\n{certora_log}\nVULNS_CONFIRMADAS:\n{json.dumps(vulns_confirmadas)}\nCONTRATO:\n{contract_source}",
        DiagnosticoFalhas
    )
    salvar_arquivo(str(pasta_output / "diagnostico_t0.json"),
                   json.dumps(diagnostico, indent=2, ensure_ascii=False))

    print(f"   🔍 {len(diagnostico.get('falhas', []))} causa(s) identificada(s):")
    for f in diagnostico.get("falhas", []):
        print(f"   → {f['id']}: {f['motivo']} (linha {f.get('linha', '?')})")

    fix_bruto = chamar_ia_texto(
        sp.PROMPT_ETAPA5_CORRIGIR,
        f"CONTRATO:\n{contract_source}\n\n"
        f"DIAGNÓSTICO:\n{json.dumps(diagnostico, indent=2, ensure_ascii=False)}\n\n"
        f"VULNS CONFIRMADAS:\n{json.dumps(vulns_confirmadas, indent=2, ensure_ascii=False)}\n\n"
        f"LOG CERTORA:\n{certora_log}"
    )
    codigo_fix = limpar_strings_solidity(limpar_codigo_solidity(fix_bruto))

    caminho_fix_temp = pasta_output / f"{nome_contrato}_FIXED.sol"
    salvar_arquivo(str(caminho_fix_temp), codigo_fix)

    # ── ETAPA 6: Loop de Validação Formal ────────────────────────
    tentativa = 1
    while tentativa <= MAX_TENTATIVAS_CORRECAO:
        print(f"\n▶️  ETAPA 6 [Tentativa {tentativa}/{MAX_TENTATIVAS_CORRECAO}]: Validando com Certora...")

        certora_fix_log = run_certora(str(caminho_fix_temp), str(caminho_spec), str(pasta_output), contract_name_override=nome_contrato)
        salvar_arquivo(str(pasta_output / f"certora_fix_log_t{tentativa}.txt"), certora_fix_log)

        analise_fix = chamar_ia_json(
            sp.PROMPT_ETAPA6_ANALISAR_FIX,
            f"LOG:\n{certora_fix_log}\nVULNS:\n{json.dumps(vulns_confirmadas)}",
            AnaliseCertora
        )
        salvar_arquivo(str(pasta_output / f"etapa6_analise_t{tentativa}.json"),
                       json.dumps(analise_fix, indent=2, ensure_ascii=False))

        comparacao = comparar_resultados(vulns_confirmadas, analise_fix)
        salvar_arquivo(str(pasta_output / f"comparacao_t{tentativa}.json"),
                       json.dumps(comparacao, indent=2, ensure_ascii=False))
        imprimir_comparacao(comparacao)

        falhas_persistentes  = comparacao["persistentes"]
        falhas_inconclusivas = comparacao["inconclusivas"]

        if not falhas_persistentes and not falhas_inconclusivas:
            destino_final = Path(contract_path).parent / f"{nome_contrato}_FIXED.sol"
            shutil.copy(str(caminho_fix_temp), str(destino_final))
            print(f"\n🛡️  SUCESSO na tentativa {tentativa}! Certora aprovou 0 falhas.")
            print(f"✅ Contrato validado copiado para: {destino_final}")
            break

        if tentativa == MAX_TENTATIVAS_CORRECAO:
            print(f"\n❌ Limite de {MAX_TENTATIVAS_CORRECAO} tentativas atingido.")
            if falhas_persistentes:
                print(f"   Persistentes: {[v['id'] for v in falhas_persistentes]}")
            if falhas_inconclusivas:
                print(f"   Inconclusivas (erro/compilação): {[v['id'] for v in falhas_inconclusivas]}")
            print(f"   Última versão em: {caminho_fix_temp}")
            break

        todas_falhas = falhas_persistentes + falhas_inconclusivas
        print(f"\n   ⚠️  {len(todas_falhas)} falha(s) — diagnosticando...")

        with open(caminho_fix_temp, "r", encoding="utf-8") as fc:
            codigo_fix_atual = fc.read()

        ids_falhas = [v["id"] for v in todas_falhas]
        vulns_falhas_full = [v for v in vulns_confirmadas if v["id"] in ids_falhas]

        diagnostico_fix = chamar_ia_json(
            sp.PROMPT_DIAGNOSTICO,
            f"LOG:\n{certora_fix_log}\n"
            f"VULNS_CONFIRMADAS:\n{json.dumps(vulns_falhas_full)}\n"
            f"CONTRATO:\n{codigo_fix_atual}",
            DiagnosticoFalhas
        )
        salvar_arquivo(str(pasta_output / f"diagnostico_t{tentativa}.json"),
                       json.dumps(diagnostico_fix, indent=2, ensure_ascii=False))

        for fd in diagnostico_fix.get("falhas", []):
            print(f"   → {fd['id']}: {fd['motivo']} (linha {fd.get('linha', '?')})")

        re_fix_bruto = chamar_ia_texto(
            sp.PROMPT_ETAPA5_CORRIGIR,
            f"[TENTATIVA {tentativa}]\n\n"
            f"DIAGNÓSTICO:\n{json.dumps(diagnostico_fix, indent=2, ensure_ascii=False)}\n\n"
            f"CONTRATO ATUAL:\n{codigo_fix_atual}\n\n"
            f"LOG CERTORA:\n{certora_fix_log}\n\n"
            f"Corrija APENAS o que o diagnóstico indica."
        )
        codigo_fix = limpar_strings_solidity(limpar_codigo_solidity(re_fix_bruto))
        salvar_arquivo(str(caminho_fix_temp), codigo_fix)

        tentativa += 1

    print("\n" + "=" * 60)
    print("✨ PIPELINE CONCLUÍDO ✨")
    print("=" * 60)


if __name__ == "__main__":
    executar_pipeline("../smart-audt/contracts/DeFiVault.sol")
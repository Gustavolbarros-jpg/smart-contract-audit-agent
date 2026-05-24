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

from core.certora_parser import analyze_certora_log
from core.certora_error_catalog import analyze_certora_errors, has_certora_blocking_error
from core.contract_context import build_contract_brief, build_methods_block, choose_auth_probe_function
from core.diagnosis_context import compact_certora_log, filter_plan_by_ids, sanitize_diagnosis_ids
from core.formal_candidate import build_formal_candidates
from core.formal_plan import build_planner_input, build_spec_plan_input, sanitize_formal_plan
from core.patch_guard import (
    analyze_patch,
    compact_patch_guard_report,
    repair_obvious_patch_guard_issues,
)
from core.run_store import copy_contract, create_run_dir, save_json, save_text, write_metadata
from core.slither_normalizer import normalize_slither_json
from core.spec_patterns import build_spec_pattern_context
from core.static_analysis import (
    analyze_static_after_fix,
    append_static_entries_to_plan,
    static_confirmed_analyses,
    static_confirmed_findings,
)
from core.toolchain import check_solidity_toolchain
from tools.slither_cli import run_slither_raw
from tools.certora_cli import run_certora
from tools.spec_validator import (
    corrigir_spec,
    validar_spec,
    deduplicar_spec,
    aplicar_auth_probe_rules,
    aplicar_target_binding_rules,
    envolver_blocos_vuln_sem_rule,
    quebrar_instrucoes_multiplas,
    inserir_requires_zero_address,
    normalizar_methods_com_corpo,
    remover_rules_vazias,
    remover_wrapper_rules,
    remover_prefixo_revert_duplicado,
    substituir_methods_block,
)
from llm.client import MODELO_LLM, chamar_ia_json, chamar_ia_texto
from llm.schemas import (
    RelatorioSlitherNormalizado,
    PlanoFormal,
    CodigoGerado,
    DiagnosticoFalhas,
)
from prompts import system_prompts as sp

MAX_TENTATIVAS_CORRECAO = 3
MAX_TENTATIVAS_PATCH_GUARD = 2


def salvar_arquivo(caminho: str, conteudo: str):
    with open(caminho, "w", encoding="utf-8") as f:
        f.write(conteudo)
    print(f"💾 Salvo: {caminho}")


def registrar_bloqueio(pasta_output: Path, run_dir: Path, stage: str, reason: str, detail: str = ""):
    status = {
        "stage": stage,
        "status": "blocked",
        "reason": reason,
        "detail": detail,
    }
    save_json(run_dir / f"{stage}_status.json", status)
    salvar_arquivo(str(pasta_output / f"{stage}_status.json"),
                   json.dumps(status, indent=2, ensure_ascii=False))
    print(f"\n❌ Pipeline bloqueado em {stage}: {reason}")
    if detail:
        print(f"   Detalhe: {detail[:500]}")


def executar_patch_guard(
    pasta_output: Path,
    run_dir: Path,
    tentativa_label: str,
    contract_source: str,
    codigo_fix: str,
    vulns_confirmadas_full: list,
    diagnostico: dict,
) -> dict:
    resultado = analyze_patch(
        contract_source,
        codigo_fix,
        vulns_confirmadas_full,
        diagnostico,
    )
    nome_artefato = f"patch_guard_{tentativa_label}.json"
    save_json(run_dir / nome_artefato, resultado)
    salvar_arquivo(str(pasta_output / nome_artefato),
                   json.dumps(resultado, indent=2, ensure_ascii=False))

    resumo = resultado["summary"]
    print(
        f"   🧯 Patch guard: {resultado['status']} "
        f"({resumo['errors']} erro(s), {resumo['warnings']} aviso(s))"
    )
    for issue in resultado["issues"][:5]:
        line = issue.get("line") or "?"
        print(f"      → [{issue['severity']}] {issue['type']} linha {line}: {issue['detail']}")

    return resultado


def revisar_patch_rejeitado_por_guard(
    pasta_output: Path,
    run_dir: Path,
    caminho_fix_temp: Path,
    tentativa_label: str,
    contract_source: str,
    codigo_fix: str,
    vulns_confirmadas_full: list,
    diagnostico: dict,
) -> tuple[bool, str, dict]:
    codigo_atual = codigo_fix
    ultimo_guard = {}

    for retry in range(MAX_TENTATIVAS_PATCH_GUARD + 1):
        label = tentativa_label if retry == 0 else f"{tentativa_label}_guard_retry{retry}"
        salvar_arquivo(str(caminho_fix_temp), codigo_atual)
        save_text(run_dir / f"fixed_{label}.sol", codigo_atual)

        ultimo_guard = executar_patch_guard(
            pasta_output,
            run_dir,
            label,
            contract_source,
            codigo_atual,
            vulns_confirmadas_full,
            diagnostico,
        )
        if not ultimo_guard["should_block"]:
            if retry:
                save_text(run_dir / f"fixed_{tentativa_label}_accepted.sol", codigo_atual)
            return True, codigo_atual, ultimo_guard

        if retry == MAX_TENTATIVAS_PATCH_GUARD:
            registrar_bloqueio(
                pasta_output,
                run_dir,
                f"patch_guard_{label}",
                "Patch da LLM alterou elementos fora do escopo minimo permitido",
                json.dumps(ultimo_guard["issues"][:20], ensure_ascii=False),
            )
            return False, codigo_atual, ultimo_guard

        codigo_auto, correcoes_auto = repair_obvious_patch_guard_issues(
            contract_source,
            codigo_atual,
            ultimo_guard,
        )
        if correcoes_auto and codigo_auto != codigo_atual:
            auto_label = f"{label}_autorepair"
            print(f"   🔧 Patch guard aplicou {len(correcoes_auto)} restauração(ões) determinística(s).")
            save_json(run_dir / f"patch_guard_autorepair_{label}.json", {"correcoes": correcoes_auto})
            codigo_atual = codigo_auto
            salvar_arquivo(str(caminho_fix_temp), codigo_atual)
            save_text(run_dir / f"fixed_{auto_label}.sol", codigo_atual)
            ultimo_guard = executar_patch_guard(
                pasta_output,
                run_dir,
                auto_label,
                contract_source,
                codigo_atual,
                vulns_confirmadas_full,
                diagnostico,
            )
            if not ultimo_guard["should_block"]:
                save_text(run_dir / f"fixed_{tentativa_label}_accepted.sol", codigo_atual)
                return True, codigo_atual, ultimo_guard

        print(f"   🔁 Patch guard bloqueou {label}; pedindo revisão mínima à LLM...")
        prompt_input = (
            f"ORIGINAL_CONTRACT:\n{contract_source}\n\n"
            f"REJECTED_PATCH:\n{codigo_atual}\n\n"
            f"DIAGNOSIS:\n{json.dumps(diagnostico, indent=2, ensure_ascii=False)}\n\n"
            f"CONFIRMED_VULNERABILITIES:\n"
            f"{json.dumps(vulns_confirmadas_full, indent=2, ensure_ascii=False)}\n\n"
            f"PATCH_GUARD_REPORT:\n"
            f"{json.dumps(compact_patch_guard_report(ultimo_guard), indent=2, ensure_ascii=False)}"
        )
        save_text(run_dir / f"patch_guard_repair_prompt_{label}.txt", prompt_input)

        try:
            revisao_bruta = chamar_ia_texto(sp.PROMPT_PATCH_GUARD_REPAIR, prompt_input)
        except Exception as exc:
            registrar_bloqueio(
                pasta_output,
                run_dir,
                f"patch_guard_repair_{label}",
                "Falha ao consultar a LLM para revisar patch bloqueado pelo guard",
                str(exc),
            )
            return False, codigo_atual, ultimo_guard

        codigo_revisado = limpar_strings_solidity(limpar_codigo_solidity(revisao_bruta))
        if not codigo_revisado.strip():
            registrar_bloqueio(
                pasta_output,
                run_dir,
                f"patch_guard_repair_{label}_empty",
                "A LLM não retornou código Solidity ao revisar patch bloqueado",
            )
            return False, codigo_atual, ultimo_guard

        codigo_atual = codigo_revisado

    return False, codigo_atual, ultimo_guard


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


def preparar_spec(
    spec_raw: str,
    caminho: str,
    methods_block: str = "",
    rule_name_by_id: dict[str, str] | None = None,
    auth_probe: dict | None = None,
    rule_context_by_id: dict[str, dict] | None = None,
) -> str:
    """Remove vazias, deduplica, autocorrige, valida e salva o spec."""
    rule_name_by_id = rule_name_by_id or {}
    rule_context_by_id = rule_context_by_id or {}
    spec_corrigido, methods = substituir_methods_block(spec_raw, methods_block)
    if methods:
        print(f"   🧱 Methods determinístico aplicado ({len(methods)}):")
        for m in methods:
            print(f"      → {m}")

    spec_corrigido, vazias = remover_rules_vazias(spec_corrigido)
    if vazias:
        print(f"   🗑️  Rules vazias removidas ({len(vazias)}):")
        for v in vazias:
            print(f"      → {v}")

    spec_corrigido, wrappers = remover_wrapper_rules(spec_corrigido)
    if wrappers:
        print(f"   🧹 Wrappers inválidos removidos ({len(wrappers)}):")
        for w in wrappers:
            print(f"      → {w}")

    spec_corrigido, corpos = normalizar_methods_com_corpo(spec_corrigido)
    if corpos:
        print(f"   🧹 Corpos inválidos em methods{{}} removidos ({len(corpos)}):")
        for c in corpos:
            print(f"      → {c}")

    spec_corrigido, loose_rules = envolver_blocos_vuln_sem_rule(spec_corrigido, rule_name_by_id)
    if loose_rules:
        print(f"   🧱 Rules ausentes reconstruídas ({len(loose_rules)}):")
        for r in loose_rules:
            print(f"      → {r}")

    spec_corrigido, multi_stmt = quebrar_instrucoes_multiplas(spec_corrigido)
    if multi_stmt:
        print(f"   🧹 Instruções múltiplas separadas ({len(multi_stmt)}):")
        for m in multi_stmt:
            print(f"      → {m}")

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

    spec_corrigido, zero_requires = inserir_requires_zero_address(spec_corrigido)
    if zero_requires:
        print(f"   🔧 Requires zero inseridos ({len(zero_requires)}):")
        for z in zero_requires:
            print(f"      → {z}")

    spec_corrigido, revert_prefixes = remover_prefixo_revert_duplicado(spec_corrigido)
    if revert_prefixes:
        print(f"   🧹 Prefixos revert duplicados removidos ({len(revert_prefixes)}):")
        for rp in revert_prefixes:
            print(f"      → {rp}")

    spec_corrigido, auth_correcoes = aplicar_auth_probe_rules(spec_corrigido, auth_probe)
    if auth_correcoes:
        print(f"   🔐 Rules de auth ajustadas ({len(auth_correcoes)}):")
        for a in auth_correcoes:
            print(f"      → {a}")

    spec_corrigido, target_correcoes = aplicar_target_binding_rules(
        spec_corrigido,
        rule_context_by_id,
        methods_block,
    )
    if target_correcoes:
        print(f"   🎯 Chamadas alvo ajustadas ({len(target_correcoes)}):")
        for t in target_correcoes:
            print(f"      → {t}")

    valido, erros = validar_spec(spec_corrigido)
    if not valido:
        print(f"   ⚠️  Avisos restantes ({len(erros)}):")
        for e in erros:
            print(f"      → {e}")

    salvar_arquivo(caminho, spec_corrigido)
    return spec_corrigido


def certora_tem_erro(log: str) -> bool:
    return has_certora_blocking_error(log)


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


def executar_pipeline(contract_path: str, copy_final: bool = True):
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
    repo_root = Path(__file__).resolve().parents[1]
    run_dir = create_run_dir(contract_path, root=str(repo_root / "runs"))
    copy_contract(contract_path, run_dir)
    write_metadata(run_dir, contract_path, MODELO_LLM)
    print(f"📁 Run artifacts: {run_dir}")

    toolchain_status = check_solidity_toolchain(contract_source)
    save_json(run_dir / "toolchain_status.json", toolchain_status)
    if not toolchain_status["ok"]:
        registrar_bloqueio(
            pasta_output,
            run_dir,
            "toolchain_preflight",
            "Versao do solc incompativel com o pragma do contrato",
            json.dumps(toolchain_status, ensure_ascii=False),
        )
        return

    # ── ETAPA 1: Slither ─────────────────────────────────────────
    print("\n▶️  ETAPA 1: Executando Slither e normalizando deterministicamente...")
    slither_raw = run_slither_raw(contract_path)
    save_json(run_dir / "slither_raw.json", slither_raw)

    relatorio_normalizado = normalize_slither_json(slither_raw, contract_path)
    save_json(run_dir / "slither_normalized.json", relatorio_normalizado)

    candidatos_formais = build_formal_candidates(relatorio_normalizado)
    save_json(run_dir / "formal_candidates.json", candidatos_formais)
    achados_static = static_confirmed_findings(relatorio_normalizado)
    save_json(run_dir / "static_confirmed_findings.json", {"vulnerabilidades": achados_static})

    vulns_normalizadas = RelatorioSlitherNormalizado.model_validate({
        "vulnerabilidades": relatorio_normalizado["vulnerabilidades"]
    }).model_dump()

    salvar_arquivo(str(pasta_output / "etapa1_vulns.json"),
                   json.dumps(vulns_normalizadas, indent=2, ensure_ascii=False))
    save_json(run_dir / "etapa1_vulns.json", vulns_normalizadas)
    print(
        f"   → {relatorio_normalizado['stats']['total']} achado(s), "
        f"{len(candidatos_formais)} candidato(s) formal(is), "
        f"{len(achados_static)} static-confirmed"
    )

    if not candidatos_formais and not achados_static:
        print("\n✅ Slither não gerou candidatos formalizáveis ou static-confirmed.")
        print(f"   Evidências preservadas em: {run_dir}")
        return

    # ── ETAPA 2: Planejamento formal com LLM ─────────────────────
    print("\n▶️  ETAPA 2: Planejando formalização com LLM...")
    entrada_planejador = build_planner_input(candidatos_formais)
    save_json(run_dir / "formal_planner_input.json", entrada_planejador)

    if candidatos_formais:
        try:
            plano_bruto = chamar_ia_json(
                sp.PROMPT_ETAPA2_PLANEJAR_FORMALIZACAO,
                f"CANDIDATOS_FORMAIS:\n{json.dumps(entrada_planejador, ensure_ascii=False)}",
                PlanoFormal,
            )
        except Exception as exc:
            registrar_bloqueio(
                pasta_output,
                run_dir,
                "llm_formal_planner",
                "Falha ao consultar a LLM para planejar formalização",
                str(exc),
            )
            return
    else:
        plano_bruto = {"selected_rules": [], "skipped_findings": [], "global_assumptions": []}

    save_json(run_dir / "formal_plan_raw.json", plano_bruto)

    plano_formal = sanitize_formal_plan(plano_bruto, candidatos_formais)
    salvar_arquivo(str(pasta_output / "formal_plan.json"),
                   json.dumps(plano_formal, indent=2, ensure_ascii=False))
    save_json(run_dir / "formal_plan.json", plano_formal)

    selected_ids = {item["id"] for item in plano_formal["selected_rules"]}
    vulns_planejadas = [
        vuln for vuln in vulns_normalizadas["vulnerabilidades"]
        if vuln["id"] in selected_ids
    ]
    vulns_para_diagnostico = vulns_planejadas + achados_static
    save_json(run_dir / "selected_vulnerabilities.json", {"vulnerabilidades": vulns_para_diagnostico})

    print(
        f"   → {len(plano_formal['selected_rules'])} selecionada(s), "
        f"{len(plano_formal['skipped_findings'])} ignorada(s)"
    )

    if not plano_formal["selected_rules"] and not achados_static:
        print("\n⚠️  A LLM não selecionou nenhuma vulnerabilidade para Certora.")
        print(f"   Plano salvo em: {run_dir / 'formal_plan.json'}")
        return

    caminho_spec = pasta_output / f"{nome_contrato}.spec"
    spec_corrigido = ""
    certora_log = ""
    analises_certora = []

    if plano_formal["selected_rules"]:
        # ── ETAPA 3: Gerar + autocorrigir Spec ───────────────────────
        print("\n▶️  ETAPA 3: Gerando e validando Spec CVL...")
        plano_spec = build_spec_plan_input(plano_formal)
        contrato_resumido = build_contract_brief(contract_source, vulns_planejadas)
        spec_patterns = build_spec_pattern_context(plano_formal["selected_rules"])
        methods_block = build_methods_block(contract_source)
        auth_probe = choose_auth_probe_function(contract_source)
        save_json(run_dir / "spec_plan_input.json", plano_spec)
        save_text(run_dir / "contract_brief.txt", contrato_resumido)
        save_text(run_dir / "spec_patterns.md", spec_patterns)
        save_text(run_dir / "methods.cvl", methods_block)
        save_json(run_dir / "auth_probe.json", auth_probe or {})

        try:
            spec_gerado = chamar_ia_json(
                sp.PROMPT_ETAPA3_GERAR_SPEC,
                f"PLANO_FORMAL:\n{json.dumps(plano_spec, ensure_ascii=False)}\n"
                f"SPEC_PATTERNS:\n{spec_patterns}\n"
                f"CONTRATO_RESUMIDO:\n{contrato_resumido}",
                CodigoGerado
            )
        except Exception as exc:
            registrar_bloqueio(
                pasta_output,
                run_dir,
                "llm_spec_generation",
                "Falha ao consultar a LLM para gerar spec CVL",
                str(exc),
            )
            return

        rule_name_by_id = {
            item["id"]: item["rule_names"][0]
            for item in plano_formal["selected_rules"]
            if item.get("rule_names")
        }
        rule_context_by_id = {
            item["id"]: item
            for item in plano_formal["selected_rules"]
        }
        spec_corrigido = preparar_spec(
            spec_gerado["codigo"],
            str(caminho_spec),
            methods_block,
            rule_name_by_id,
            auth_probe,
            rule_context_by_id,
        )
        save_text(run_dir / "generated.spec", spec_corrigido)

        # ── CERTORA no ORIGINAL ──────────────────────────────────────
        print("\n▶️  CERTORA PROVER: Verificando contrato ORIGINAL...")
        certora_log = run_certora(contract_path, str(caminho_spec), str(pasta_output))
        salvar_arquivo(str(pasta_output / "certora_original_log.txt"), certora_log)
        save_text(run_dir / "certora_original.log", certora_log)

        if certora_tem_erro(certora_log):
            error_analysis = analyze_certora_errors(certora_log)
            status = {
                "stage": "certora_original",
                "status": "blocked",
                "reason": "Certora/spec/solc error detected before LLM analysis",
                "certora_error_analysis": error_analysis,
            }
            save_json(run_dir / "certora_error_analysis.json", error_analysis)
            save_json(run_dir / "certora_status.json", status)
            salvar_arquivo(str(pasta_output / "certora_status.json"),
                           json.dumps(status, indent=2, ensure_ascii=False))
            print("\n❌ Certora retornou erro de compilação/spec. Pipeline bloqueado antes da análise LLM.")
            print(f"   Veja: {run_dir / 'certora_original.log'}")
            return

        analises_certora = analyze_certora_log(
            certora_log,
            vulns_planejadas,
            spec_corrigido,
        )["analises"]

    analise = {"analises": analises_certora + static_confirmed_analyses(achados_static)}
    salvar_arquivo(str(pasta_output / "etapa4_analise.json"),
                   json.dumps(analise, indent=2, ensure_ascii=False))
    save_json(run_dir / "analysis.json", analise)

    vulns_confirmadas = [
        v for v in analise["analises"]
        if v["status"] in ("confirmed", "confirmed_static")
    ]
    vulns_inconclusivas = [
        v for v in analise["analises"]
        if v["status"] == "inconclusive"
    ]

    if not vulns_confirmadas:
        if vulns_inconclusivas:
            registrar_bloqueio(
                pasta_output,
                run_dir,
                "certora_inconclusive",
                "Certora não confirmou vulnerabilidades, mas houve rules inconclusivas",
                json.dumps(vulns_inconclusivas, ensure_ascii=False),
            )
            return
        print("\n✅ Nenhuma vulnerabilidade confirmada! O contrato já está seguro.")
        return

    if vulns_inconclusivas:
        save_json(run_dir / "analysis_inconclusive.json", {"analises": vulns_inconclusivas})
        print(f"\n⚠️  {len(vulns_inconclusivas)} vulnerabilidade(s) ficaram inconclusivas; veja analysis_inconclusive.json")

    print(f"\n🔴 {len(vulns_confirmadas)} confirmada(s): {[v['id'] for v in vulns_confirmadas]}")

    # ── ETAPA 5: Diagnóstico + Primeira Correção ─────────────────
    print("\n▶️  ETAPA 5: Diagnosticando e corrigindo...")
    ids_confirmadas = {v["id"] for v in vulns_confirmadas}
    rules_confirmadas = [v.get("rule", "") for v in vulns_confirmadas]
    vulns_confirmadas_full = [
        vuln for vuln in vulns_para_diagnostico
        if vuln["id"] in ids_confirmadas
    ]
    diagnosis_plan = filter_plan_by_ids(
        append_static_entries_to_plan(plano_formal, achados_static),
        ids_confirmadas,
    )
    diagnosis_log = compact_certora_log(certora_log, rules_confirmadas)
    if achados_static:
        diagnosis_log += "\n\nSTATIC_SLITHER_FINDINGS:\n" + json.dumps(
            static_confirmed_analyses(achados_static),
            ensure_ascii=False,
        )
    diagnosis_contract = build_contract_brief(contract_source, vulns_confirmadas_full)
    save_text(run_dir / "diagnosis_t0_log_context.txt", diagnosis_log)
    save_text(run_dir / "diagnosis_t0_contract_context.txt", diagnosis_contract)

    try:
        diagnostico = chamar_ia_json(
            sp.PROMPT_DIAGNOSTICO,
            f"LOG_RELEVANTE:\n{diagnosis_log}\n"
            f"PLANO_FORMAL:\n{json.dumps(diagnosis_plan, ensure_ascii=False)}\n"
            f"VULNS_CONFIRMADAS:\n{json.dumps(vulns_confirmadas, ensure_ascii=False)}\n"
            f"CONTRATO_RESUMIDO:\n{diagnosis_contract}",
            DiagnosticoFalhas
        )
    except Exception as exc:
        registrar_bloqueio(
            pasta_output,
            run_dir,
            "llm_initial_diagnosis",
            "Falha ao consultar a LLM para diagnosticar vulnerabilidades confirmadas",
            str(exc),
        )
        return

    diagnostico = sanitize_diagnosis_ids(diagnostico, ids_confirmadas)
    if not diagnostico.get("falhas"):
        registrar_bloqueio(
            pasta_output,
            run_dir,
            "llm_initial_diagnosis_empty",
            "A LLM não retornou diagnóstico para os IDs confirmados",
        )
        return

    salvar_arquivo(str(pasta_output / "diagnostico_t0.json"),
                   json.dumps(diagnostico, indent=2, ensure_ascii=False))
    save_json(run_dir / "diagnosis_t0.json", diagnostico)
    diagnostico_patch_guard = {"falhas": list(diagnostico.get("falhas", []))}

    print(f"   🔍 {len(diagnostico.get('falhas', []))} causa(s) identificada(s):")
    for f in diagnostico.get("falhas", []):
        print(f"   → {f['id']}: {f['motivo']} (linha {f.get('linha', '?')})")

    fix_bruto = chamar_ia_texto(
        sp.PROMPT_ETAPA5_CORRIGIR,
        f"CONTRATO:\n{contract_source}\n\n"
        f"DIAGNÓSTICO:\n{json.dumps(diagnostico, indent=2, ensure_ascii=False)}\n\n"
        f"VULNS CONFIRMADAS:\n{json.dumps(vulns_confirmadas, indent=2, ensure_ascii=False)}\n\n"
        f"LOG CERTORA RELEVANTE:\n{diagnosis_log}"
    )
    if not fix_bruto.strip():
        registrar_bloqueio(
            pasta_output,
            run_dir,
            "llm_initial_fix",
            "A LLM não retornou código Solidity para a primeira correção",
        )
        return

    codigo_fix = limpar_strings_solidity(limpar_codigo_solidity(fix_bruto))

    caminho_fix_temp = pasta_output / f"{nome_contrato}_FIXED.sol"
    patch_guard_ok, codigo_fix, _ = revisar_patch_rejeitado_por_guard(
        pasta_output,
        run_dir,
        caminho_fix_temp,
        "t0",
        contract_source,
        codigo_fix,
        vulns_confirmadas_full,
        diagnostico_patch_guard,
    )
    if not patch_guard_ok:
        return

    # ── ETAPA 6: Loop de Validação Formal ────────────────────────
    tentativa = 1
    while tentativa <= MAX_TENTATIVAS_CORRECAO:
        print(f"\n▶️  ETAPA 6 [Tentativa {tentativa}/{MAX_TENTATIVAS_CORRECAO}]: Validando com Certora...")

        analises_fix_certora = []
        certora_fix_log = ""
        if plano_formal["selected_rules"]:
            certora_fix_log = run_certora(str(caminho_fix_temp), str(caminho_spec), str(pasta_output), contract_name_override=nome_contrato)
            salvar_arquivo(str(pasta_output / f"certora_fix_log_t{tentativa}.txt"), certora_fix_log)
            save_text(run_dir / f"certora_fixed_t{tentativa}.log", certora_fix_log)

            if certora_tem_erro(certora_fix_log):
                error_analysis = analyze_certora_errors(certora_fix_log)
                status = {
                    "stage": f"certora_fixed_t{tentativa}",
                    "status": "blocked",
                    "reason": "Certora/spec/solc error detected before LLM fix analysis",
                    "certora_error_analysis": error_analysis,
                }
                save_json(run_dir / f"certora_error_analysis_t{tentativa}.json", error_analysis)
                save_json(run_dir / f"certora_status_t{tentativa}.json", status)
                salvar_arquivo(str(pasta_output / f"certora_status_t{tentativa}.json"),
                               json.dumps(status, indent=2, ensure_ascii=False))
                print("\n❌ Certora retornou erro na validação do FIXED. Pipeline bloqueado antes da análise LLM.")
                print(f"   Veja: {run_dir / f'certora_fixed_t{tentativa}.log'}")
                break

            vulns_confirmadas_formais = [
                vuln for vuln in vulns_confirmadas
                if not str(vuln.get("rule", "")).startswith("slither:")
            ]
            analises_fix_certora = analyze_certora_log(certora_fix_log, vulns_confirmadas_formais, spec_corrigido)["analises"]

        fixed_slither_raw = run_slither_raw(str(caminho_fix_temp))
        fixed_relatorio_normalizado = normalize_slither_json(fixed_slither_raw, str(caminho_fix_temp))
        save_json(run_dir / f"slither_fixed_t{tentativa}.json", fixed_relatorio_normalizado)
        analise_fix = {
            "analises": analises_fix_certora + analyze_static_after_fix(achados_static, fixed_relatorio_normalizado)
        }
        salvar_arquivo(str(pasta_output / f"etapa6_analise_t{tentativa}.json"),
                       json.dumps(analise_fix, indent=2, ensure_ascii=False))
        save_json(run_dir / f"analysis_fixed_t{tentativa}.json", analise_fix)

        comparacao = comparar_resultados(vulns_confirmadas, analise_fix)
        salvar_arquivo(str(pasta_output / f"comparacao_t{tentativa}.json"),
                       json.dumps(comparacao, indent=2, ensure_ascii=False))
        save_json(run_dir / f"comparison_t{tentativa}.json", comparacao)
        imprimir_comparacao(comparacao)

        falhas_persistentes  = comparacao["persistentes"]
        falhas_inconclusivas = comparacao["inconclusivas"]

        if not falhas_persistentes and not falhas_inconclusivas:
            destino_final = Path(contract_path).parent / f"{nome_contrato}_FIXED.sol"
            if copy_final:
                shutil.copy(str(caminho_fix_temp), str(destino_final))
            print(f"\n🛡️  SUCESSO na tentativa {tentativa}! Certora aprovou 0 falhas.")
            if copy_final:
                print(f"✅ Contrato validado copiado para: {destino_final}")
            else:
                print(f"✅ Contrato validado mantido em: {caminho_fix_temp}")
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
        ids_falhas_set = set(ids_falhas)
        rules_falhas = [v.get("rule", "") for v in todas_falhas]
        vulns_falhas_full = [v for v in vulns_confirmadas if v["id"] in ids_falhas_set]
        vulns_falhas_contexto = [
            vuln for vuln in vulns_planejadas
            if vuln["id"] in ids_falhas_set
        ]
        diagnosis_fix_plan = filter_plan_by_ids(plano_formal, ids_falhas_set)
        diagnosis_fix_log = compact_certora_log(certora_fix_log, rules_falhas)
        diagnosis_fix_contract = build_contract_brief(codigo_fix_atual, vulns_falhas_contexto)
        save_text(run_dir / f"diagnosis_t{tentativa}_log_context.txt", diagnosis_fix_log)
        save_text(run_dir / f"diagnosis_t{tentativa}_contract_context.txt", diagnosis_fix_contract)

        try:
            diagnostico_fix = chamar_ia_json(
                sp.PROMPT_DIAGNOSTICO,
                f"LOG_RELEVANTE:\n{diagnosis_fix_log}\n"
                f"PLANO_FORMAL:\n{json.dumps(diagnosis_fix_plan, ensure_ascii=False)}\n"
                f"VULNS_CONFIRMADAS:\n{json.dumps(vulns_falhas_full)}\n"
                f"CONTRATO_RESUMIDO:\n{diagnosis_fix_contract}",
                DiagnosticoFalhas
            )
        except Exception as exc:
            registrar_bloqueio(
                pasta_output,
                run_dir,
                f"llm_diagnosis_t{tentativa}",
                "Falha ao consultar a LLM para diagnosticar falhas persistentes",
                str(exc),
            )
            break

        diagnostico_fix = sanitize_diagnosis_ids(diagnostico_fix, ids_falhas_set)
        if not diagnostico_fix.get("falhas"):
            registrar_bloqueio(
                pasta_output,
                run_dir,
                f"llm_diagnosis_t{tentativa}_empty",
                "A LLM não retornou diagnóstico para os IDs persistentes",
            )
            break

        salvar_arquivo(str(pasta_output / f"diagnostico_t{tentativa}.json"),
                       json.dumps(diagnostico_fix, indent=2, ensure_ascii=False))
        save_json(run_dir / f"diagnosis_t{tentativa}.json", diagnostico_fix)
        diagnostico_patch_guard["falhas"].extend(diagnostico_fix.get("falhas", []))

        for fd in diagnostico_fix.get("falhas", []):
            print(f"   → {fd['id']}: {fd['motivo']} (linha {fd.get('linha', '?')})")

        re_fix_bruto = chamar_ia_texto(
            sp.PROMPT_ETAPA5_CORRIGIR,
            f"[TENTATIVA {tentativa}]\n\n"
            f"DIAGNÓSTICO:\n{json.dumps(diagnostico_fix, indent=2, ensure_ascii=False)}\n\n"
            f"CONTRATO ATUAL:\n{codigo_fix_atual}\n\n"
            f"LOG CERTORA RELEVANTE:\n{diagnosis_fix_log}\n\n"
            f"Corrija APENAS o que o diagnóstico indica."
        )
        codigo_fix = limpar_strings_solidity(limpar_codigo_solidity(re_fix_bruto))
        if not codigo_fix.strip():
            registrar_bloqueio(
                pasta_output,
                run_dir,
                f"llm_refix_t{tentativa}",
                "A LLM não retornou código Solidity para a nova correção",
            )
            break

        patch_guard_ok, codigo_fix, _ = revisar_patch_rejeitado_por_guard(
            pasta_output,
            run_dir,
            caminho_fix_temp,
            f"t{tentativa}",
            contract_source,
            codigo_fix,
            vulns_confirmadas_full,
            diagnostico_patch_guard,
        )
        if not patch_guard_ok:
            break

        tentativa += 1

    print("\n" + "=" * 60)
    print("✨ PIPELINE CONCLUÍDO ✨")
    print("=" * 60)


if __name__ == "__main__":
    executar_pipeline("../smart-audt/contracts/DeFiVault.sol")

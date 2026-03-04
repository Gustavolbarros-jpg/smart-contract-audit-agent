#!/usr/bin/env python3
"""
audit_pandas.py
Módulo de análise e cruzamento de dados do pipeline de auditoria.
Integra com slither_minify.py e logs do Certora.

Uso:
    python3 audit_pandas.py \
        --vulns slither.min.json \
        --logs-dir /home/gflb/TesteCertora \
        --output relatorio_final.csv
"""

import os
import re
import json
import argparse
import pandas as pd
from pathlib import Path


# ─── Etapa A: Carregar e analisar vulnerabilidades ─────────────────────────────

TIPOS_COM_CVL = [
    "reentrancy-eth", "reentrancy-no-eth", "tx-origin",
    "arbitrary-send-eth", "suicidal", "missing-zero-check",
    "integer-overflow", "integer-underflow", "timestamp", "block-number"
]

TIPOS_REENTRANCIA = ["reentrancy-eth", "reentrancy-no-eth", "reentrancy-benign"]


def carregar_vulns(json_path: str) -> pd.DataFrame:
    """
    Lê o slither.min.json e transforma em DataFrame.
    Adapta ao schema real do arquivo (sem padrão_cvl, com function_signature).
    """
    with open(json_path, "r") as f:
        data = json.load(f)

    df = pd.DataFrame(data)

    # ── Normalizar nomes de colunas ──────────────────────────
    # Schema real usa function_signature em vez de function
    if "function_signature" in df.columns and "function" not in df.columns:
        df = df.rename(columns={"function_signature": "function"})

    # Adicionar id sequencial se não existir
    if "id" not in df.columns:
        df.insert(0, "id", [f"VULN_{i+1:03d}" for i in range(len(df))])

    # ── Tratamento de dados ──────────────────────────────────

    # 1. Remover colunas completamente vazias
    df = df.dropna(axis=1, how="all")

    # 2. Preencher campos de texto vazios
    for col in ["function", "line"]:
        if col in df.columns:
            df[col] = df[col].replace("", pd.NA).fillna("N/A")

    # 3. Normalizar impact e confidence para lowercase
    for col in ["impact", "confidence"]:
        if col in df.columns:
            df[col] = df[col].str.lower().str.strip()

    # 4. Flag: tem chamada externa?
    if "external_calls" in df.columns:
        df["tem_call_externa"] = df["external_calls"].apply(
            lambda x: len(x) > 0 if isinstance(x, list) else False
        )
    else:
        df["tem_call_externa"] = False

    # 5. Flag: tipo tem especificacao CVL?
    df["tem_cvl"] = df["type"].isin(TIPOS_COM_CVL)

    # 6. Flag: e reentrancia?
    df["eh_reentrancia"] = df["type"].isin(TIPOS_REENTRANCIA)

    # 7. Feature engineering — impact score numerico
    impact_map = {"high": 3, "medium": 2, "low": 1, "informational": 0}
    df["impact_score"] = df["impact"].map(impact_map).fillna(0).astype(int)

    # 8. Feature engineering — confidence score numerico
    conf_map = {"high": 3, "medium": 2, "low": 1}
    df["confidence_score"] = df["confidence"].map(conf_map).fillna(0).astype(int)

    # 9. Score de prioridade = impact x confidence
    df["priority_score"] = df["impact_score"] * df["confidence_score"]

    return df


def analise_exploratoria(df: pd.DataFrame):
    print("\n" + "=" * 55)
    print("  ANALISE EXPLORATORIA — Vulnerabilidades")
    print("=" * 55)

    print(f"\nTotal de vulnerabilidades : {len(df)}")
    print(f"Com especificacao CVL     : {df['tem_cvl'].sum()}")
    print(f"Sem especificacao CVL     : {(~df['tem_cvl']).sum()}")
    print(f"Com call externa          : {df['tem_call_externa'].sum()}")
    print(f"Reentrancia               : {df['eh_reentrancia'].sum()}")

    print("\n-- Distribuicao por Impact --")
    print(df["impact"].value_counts().to_string())

    print("\n-- Distribuicao por Tipo --")
    print(df["type"].value_counts().to_string())

    if "category" in df.columns:
        print("\n-- Distribuicao por Categoria --")
        print(df["category"].value_counts().to_string())

    print("\n-- Top 5 por Priority Score (com CVL) --")
    top = df[df["tem_cvl"]].nlargest(5, "priority_score")[
        ["id", "type", "function", "impact", "confidence", "priority_score"]
    ]
    print(top.to_string(index=False))


# ─── Etapa B: Parsear logs do Certora ──────────────────────────────────────────

def parsear_log(log_path: str) -> list:
    with open(log_path, "r", errors="ignore") as f:
        content = f.read()

    resultados = []

    # Extrair nome do contrato
    contrato = "unknown"
    m = re.search(r"The scene contains \d+ contracts?:\s+(\w+)", content)
    if m:
        contrato = m.group(1)

    # Extrair spec usada
    spec = "unknown"
    m = re.search(r"Checking CVL\s+(\S+)\s+for contract", content)
    if m:
        spec = Path(m.group(1)).name

    # Verified → not_violated
    for match in re.finditer(r"Verified:\s+(\w+)", content):
        resultados.append({
            "contrato": contrato,
            "spec":     spec,
            "rule":     match.group(1),
            "status":   "not_violated",
            "log_file": Path(log_path).name
        })

    # FAILED / Violated → violated
    for match in re.finditer(r"(?:FAILED|Violated):\s+(\w+)", content):
        resultados.append({
            "contrato": contrato,
            "spec":     spec,
            "rule":     match.group(1),
            "status":   "violated",
            "log_file": Path(log_path).name
        })

    # TIMEOUT → inconclusive
    for match in re.finditer(r"TIMEOUT.*?rule\s+(\w+)", content):
        resultados.append({
            "contrato": contrato,
            "spec":     spec,
            "rule":     match.group(1),
            "status":   "inconclusive_timeout",
            "log_file": Path(log_path).name
        })

    return resultados


def carregar_todos_logs(logs_dir: str) -> pd.DataFrame:
    todos = []
    logs_dir = Path(logs_dir)

    # Logs diretos na pasta
    for log_file in logs_dir.glob("*_logs.txt"):
        todos.extend(parsear_log(str(log_file)))

    # Logs dentro de subpastas emv-*
    for subdir in logs_dir.glob("emv-*"):
        for log_file in subdir.glob("*.txt"):
            todos.extend(parsear_log(str(log_file)))

    if not todos:
        print("[WARN] Nenhum log do Certora encontrado.")
        return pd.DataFrame()

    df = pd.DataFrame(todos)
    df = df.drop_duplicates(subset=["contrato", "rule", "status", "log_file"])
    df["status"] = df["status"].str.lower().str.strip()

    return df


def analise_certora(df_logs: pd.DataFrame):
    if df_logs.empty:
        return

    print("\n" + "=" * 55)
    print("  ANALISE — Resultados Certora")
    print("=" * 55)

    print(f"\nTotal de verificacoes : {len(df_logs)}")
    print(f"Contratos analisados  : {df_logs['contrato'].nunique()}")

    print("\n-- Resultados por Status --")
    print(df_logs["status"].value_counts().to_string())

    print("\n-- Resultados por Contrato --")
    pivot = df_logs.groupby(["contrato", "status"]).size().unstack(fill_value=0)
    print(pivot.to_string())


# ─── Etapa C: Cruzar dados ─────────────────────────────────────────────────────

def cruzar_dados(df_vulns: pd.DataFrame, df_logs: pd.DataFrame) -> pd.DataFrame:
    if df_logs.empty:
        df_vulns = df_vulns.copy()
        df_vulns["certora_status"] = "sem_log"
        df_vulns["confirmed_static"] = False
        return df_vulns

    def buscar_status(row):
        tipo = str(row.get("type", "")).replace("-", "").lower()
        fn   = str(row.get("function", "")).lower()[:6]

        match = df_logs[
            df_logs["rule"].str.lower().str.contains(fn, na=False) |
            df_logs["rule"].str.lower().str.contains(tipo[:8], na=False)
        ]

        if match.empty:
            return "sem_correspondencia"

        statuses = match["status"].unique()
        if "violated" in statuses:
            return "confirmed"
        elif "not_violated" in statuses:
            return "not_confirmed"
        else:
            return "inconclusive"

    df_vulns = df_vulns.copy()
    df_vulns["certora_status"] = df_vulns.apply(buscar_status, axis=1)

    # Escalonamento estatico de reentrancia
    df_vulns["confirmed_static"] = (
        (df_vulns["certora_status"] == "not_confirmed") &
        (df_vulns["eh_reentrancia"]) &
        (df_vulns["tem_call_externa"])
    )

    return df_vulns


def relatorio_final(df: pd.DataFrame):
    print("\n" + "=" * 55)
    print("  RELATORIO FINAL — Decisao de Correcao")
    print("=" * 55)

    confirmed    = df[df["certora_status"] == "confirmed"]
    conf_static  = df[df["confirmed_static"]]
    not_conf     = df[(df["certora_status"] == "not_confirmed") & (~df["confirmed_static"])]
    sem_corr     = df[df["certora_status"] == "sem_correspondencia"]

    cols = ["id", "type", "function", "impact", "priority_score"]

    print(f"\n[CONFIRMED — Certora] ({len(confirmed)})")
    print(confirmed[cols].to_string(index=False) if not confirmed.empty else "  nenhuma")

    print(f"\n[CONFIRMED STATIC — Reentrancia por evidencia] ({len(conf_static)})")
    print(conf_static[cols].to_string(index=False) if not conf_static.empty else "  nenhuma")

    print(f"\n[NOT CONFIRMED — Refinamento dinamico] ({len(not_conf)})")
    print(not_conf[cols].to_string(index=False) if not not_conf.empty else "  nenhuma")

    print(f"\n[SEM CORRESPONDENCIA — Sem log Certora] ({len(sem_corr)})")
    print(sem_corr[cols].to_string(index=False) if not sem_corr.empty else "  nenhuma")


# ─── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Analise de dados do pipeline de auditoria com Pandas"
    )
    parser.add_argument("--vulns",    required=True,  help="slither.min.json")
    parser.add_argument("--logs-dir", required=True,  help="Diretorio com logs do Certora")
    parser.add_argument("--output",   default="relatorio_final.csv", help="CSV de saida")
    args = parser.parse_args()

    print("\n[1/4] Carregando vulnerabilidades...")
    df_vulns = carregar_vulns(args.vulns)
    analise_exploratoria(df_vulns)

    print("\n[2/4] Carregando logs Certora...")
    df_logs = carregar_todos_logs(args.logs_dir)
    analise_certora(df_logs)

    print("\n[3/4] Cruzando dados...")
    df_final = cruzar_dados(df_vulns, df_logs)
    relatorio_final(df_final)

    print("\n[4/4] Exportando CSV...")
    # Remove colunas com listas para CSV limpo
    cols_exportar = [
        c for c in df_final.columns
        if not df_final[c].apply(lambda x: isinstance(x, list)).any()
    ]
    df_final[cols_exportar].to_csv(args.output, index=False, encoding="utf-8")
    print(f"      Exportado → {args.output}")
    print(f"      Linhas: {len(df_final)} | Colunas: {len(cols_exportar)}")


if __name__ == "__main__":
    main()  
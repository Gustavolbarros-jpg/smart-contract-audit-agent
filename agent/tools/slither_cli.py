"""
agent/tools/slither_cli.py
Runs Slither and returns deterministic normalized findings.
"""

import json
import os
import subprocess

from core.slither_normalizer import normalize_slither_json


def run_slither_raw(contract_path: str) -> dict:
    """Run Slither and return the raw JSON output."""
    if not os.path.exists(contract_path):
        raise FileNotFoundError(f"Contrato nao encontrado: {contract_path}")

    cmd = ["slither", contract_path, "--json", "-", "--no-fail-pedantic"]

    try:
        print(f"[Slither] Analisando {contract_path}...")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

        if result.stdout.strip():
            return json.loads(result.stdout.strip())
        return {"success": True, "results": {"detectors": []}, "stderr": result.stderr}

    except subprocess.TimeoutExpired:
        raise TimeoutError("Slither demorou mais de 2 minutos.")
    except json.JSONDecodeError:
        raise ValueError("Slither nao retornou um JSON valido.")


def minificar_resultados(slither_json: dict, contract_path: str) -> list:
    """Backward-compatible wrapper for the older pipeline API."""
    return normalize_slither_json(slither_json, contract_path)["vulnerabilidades"]


def run_slither(contract_path: str) -> list:
    """Run Slither and return deterministic normalized findings."""
    return minificar_resultados(run_slither_raw(contract_path), contract_path)

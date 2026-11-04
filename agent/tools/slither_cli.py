"""
agent/tools/slither_cli.py
Runs Slither and returns deterministic normalized findings.
"""

import json
import os
import re
import subprocess
from pathlib import Path

from core.import_context import solc_remappings
from core.slither_normalizer import normalize_slither_json


class SlitherRunError(RuntimeError):
    """Slither could not analyze the contract.

    Kept distinct from "analyzed and found nothing": a crashed run reported as a
    clean contract is a false negative the pipeline cannot recover from.
    """


def _tail(text: str, max_lines: int = 12) -> str:
    lines = [line for line in (text or "").splitlines() if line.strip()]
    return "\n".join(lines[-max_lines:])


_PROJECT_MARKERS = ("foundry.toml", "remappings.txt", "hardhat.config.ts", "hardhat.config.js")


def project_root(contract_path: str) -> Path | None:
    """Root of the project a contract belongs to, or None for a standalone file.

    The nearest ancestor holding a build marker wins; failing that, the parent of the
    nearest ``src`` directory (solmate ships nothing but ``src``).
    """
    parents = list(Path(contract_path).resolve().parents)
    for parent in parents:
        if any((parent / marker).is_file() for marker in _PROJECT_MARKERS):
            return parent
    for parent in parents:
        if parent.name == "src" and parent.parent != parent:
            return parent.parent
    return None


def pinned_solc(root: Path) -> str:
    """Compiler version the project itself pins (``solc``, ``solc_version`` or ``solc-version``)."""
    try:
        text = (root / "foundry.toml").read_text(encoding="utf-8")
    except OSError:
        return ""
    match = re.search(r"""^\s*solc(?:[_-]version)?\s*=\s*['"]([\d.]+)['"]""", text, re.M)
    return match.group(1) if match else ""


def _project_run_options(contract_path: str) -> dict:
    """``cwd``/``env`` for subprocess.run so a contract is compiled as its project does.

    From outside the project root Slither exits 1 with nothing on either stream: 121 of the
    184 files that failed this way analyze fine once the working directory is the root,
    and so do projects without a foundry.toml (solmate, inverse).
    An explicit SOLC_VERSION from the caller always wins over the project's pin.
    """
    root = project_root(contract_path)
    if root is None:
        return {}
    options: dict = {"cwd": str(root)}
    version = pinned_solc(root)
    if version and "SOLC_VERSION" not in os.environ:
        from core.toolchain import installed_solc_versions

        if version in installed_solc_versions():
            options["env"] = dict(os.environ, SOLC_VERSION=version)
    return options


def run_slither_raw(contract_path: str) -> dict:
    """Run Slither and return the raw JSON output."""
    if not os.path.exists(contract_path):
        raise FileNotFoundError(f"Contrato nao encontrado: {contract_path}")
    
    cmd = ["slither", contract_path, "--json", "-", "--no-fail-pedantic"]
    for remap in solc_remappings(contract_path):
        cmd.extend(["--solc-remaps", remap])

    try:
        print(f"[Slither] Analisando {contract_path}...")
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=120, **_project_run_options(contract_path)
        )
    except subprocess.TimeoutExpired:
        raise TimeoutError("Slither demorou mais de 2 minutos.")

    # With --json -, a successful analysis always writes JSON to stdout, even when it
    # finds nothing. Empty stdout means the run failed (missing solc, unresolved import,
    # parse error) and must not be reported as a clean contract.
    if not result.stdout.strip():
        # Slither can exit non-zero with both streams empty (e.g. crytic-compile cannot
        # obtain the pinned solc), so the reproduction command carries the diagnosis.
        detail = _tail(result.stderr) or "Slither nao escreveu nada em stderr."
        raise SlitherRunError(
            f"Slither nao produziu saida para {contract_path} (exit {result.returncode}).\n"
            f"{detail}\n"
            f"Reproduza com: {' '.join(cmd)}"
        )

    try:
        payload = json.loads(result.stdout.strip())
    except json.JSONDecodeError:
        raise ValueError("Slither nao retornou um JSON valido.")

    if not payload.get("success", True):
        raise SlitherRunError(
            f"Slither falhou em {contract_path}: {payload.get('error') or 'erro nao informado'}"
        )

    return payload


def minificar_resultados(slither_json: dict, contract_path: str) -> list:
    """Backward-compatible wrapper for the older pipeline API."""
    return normalize_slither_json(slither_json, contract_path)["vulnerabilidades"]


def run_slither(contract_path: str) -> list:
    """Run Slither and return deterministic normalized findings."""
    return minificar_resultados(run_slither_raw(contract_path), contract_path)

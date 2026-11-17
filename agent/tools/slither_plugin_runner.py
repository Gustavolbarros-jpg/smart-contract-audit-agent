"""
agent/tools/slither_plugin_runner.py
Runs the project's own Slither detectors through the Python API.

The detectors are registered on a private ``Slither`` instance, never with the global
``slither`` CLI, so the regular pipeline (tools/slither_cli.py) is unaffected until a
reviewed integration step wires them in.
"""

from __future__ import annotations

import os
from pathlib import Path

from core.import_context import solc_remappings
from core.toolchain import (
    extract_solidity_constraint,
    installed_solc_versions,
    version_satisfies_constraint,
)
from tools.slither_cli import SlitherRunError


def _version_key(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in version.split("."))


def select_solc_version(contract_path: str) -> str | None:
    """The compiler to use: ``SOLC_VERSION`` if set, else the newest installed one the pragma accepts.

    Returns None when neither is available, leaving the choice to whatever ``solc`` is on PATH.
    """
    if os.environ.get("SOLC_VERSION"):
        return os.environ["SOLC_VERSION"]
    constraint = extract_solidity_constraint(Path(contract_path).read_text(encoding="utf-8"))
    matching = [v for v in installed_solc_versions() if version_satisfies_constraint(v, constraint)]
    return max(matching, key=_version_key) if matching else None


def run_unrestricted_write(contract_path: str, solc_version: str | None = None) -> list[dict]:
    """Run the ``unrestricted-write`` detector and return Slither-JSON-shaped detector results.

    Each result carries ``check``, ``impact``, ``confidence``, ``description`` and
    ``elements`` (with ``source_mapping.lines``), so it can be placed under
    ``{"results": {"detectors": [...]}}`` and handed to ``normalize_slither_json``.
    Raises SlitherRunError when the contract cannot be compiled, so a failed run is never
    mistaken for a clean contract.
    """
    if not os.path.exists(contract_path):
        raise FileNotFoundError(f"Contrato nao encontrado: {contract_path}")

    # Imported here so the module stays importable (and its callers testable) where
    # Slither is not installed.
    from slither import Slither

    from slither_plugins.unrestricted_write import UnrestrictedWrite

    options: dict = {}
    version = solc_version or select_solc_version(contract_path)
    if version:
        # crytic-compile runs solc with SOLC_VERSION set for that subprocess only.
        options["solc_solcs_select"] = version
    remaps = solc_remappings(contract_path)
    if remaps:
        options["solc_remaps"] = remaps

    try:
        slither = Slither(contract_path, **options)
    except Exception as error:  # crytic-compile raises several unrelated exception types
        raise SlitherRunError(
            f"Slither nao compilou {contract_path} (solc {version or 'padrao'}): {error}"
        ) from error

    slither.register_detector(UnrestrictedWrite)
    return [result for detector_results in slither.run_detectors() for result in detector_results]

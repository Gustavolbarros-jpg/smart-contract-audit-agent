"""Helpers for Solidity import/package context in external projects."""

from __future__ import annotations

import re
from pathlib import Path


IMPORT_RE = re.compile(
    r"^\s*import\s+(?:[^;]*?\s+from\s+)?[\"']([^\"']+)[\"']",
    re.MULTILINE,
)


def solidity_imports(source: str) -> list[str]:
    return IMPORT_RE.findall(source)


def has_imports(source: str) -> bool:
    return bool(solidity_imports(source))


def _package_prefix(import_path: str) -> str | None:
    if import_path.startswith((".", "/")):
        return None
    parts = import_path.split("/")
    if not parts:
        return None
    if parts[0].startswith("@") and len(parts) >= 2:
        return parts[0]
    return parts[0]


def _read_source(contract_path: Path) -> str:
    try:
        return contract_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def find_package_root(contract_path: str | Path) -> Path | None:
    path = Path(contract_path).resolve()
    start = path.parent if path.is_file() or path.suffix else path
    for current in [start, *start.parents]:
        if (current / "node_modules").is_dir():
            return current
    return None


def find_project_root(contract_path: str | Path) -> Path | None:
    path = Path(contract_path).resolve()
    start = path.parent if path.is_file() or path.suffix else path
    for current in [start, *start.parents]:
        if (current / "remappings.txt").is_file() or (current / "foundry.toml").is_file():
            return current
    return None


def _foundry_remappings(contract_path: str | Path) -> list[str]:
    project_root = find_project_root(contract_path)
    if project_root is None:
        return []

    remappings_path = project_root / "remappings.txt"
    if not remappings_path.is_file():
        return []

    remaps = []
    for line in remappings_path.read_text(encoding="utf-8", errors="ignore").splitlines():
        stripped = line.strip().strip('"').strip("'").rstrip(",")
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        prefix, target = stripped.split("=", 1)
        prefix = prefix.strip()
        target = target.strip()
        if not prefix or not target:
            continue
        target_path = Path(target)
        if not target_path.is_absolute():
            target_path = project_root / target_path
        remaps.append(f"{prefix}={target_path.resolve()}")
    return remaps


def solc_remappings(contract_path: str | Path, source: str | None = None) -> list[str]:
    path = Path(contract_path).resolve()
    source = _read_source(path) if source is None else source
    prefixes = sorted({prefix for imp in solidity_imports(source) if (prefix := _package_prefix(imp))})
    foundry_remaps = _foundry_remappings(path)
    matched_foundry = []
    for remap in foundry_remaps:
        remap_prefix = remap.split("=", 1)[0].rstrip("/")
        if any(remap_prefix == prefix for prefix in prefixes):
            matched_foundry.append(remap)
    if not prefixes:
        return foundry_remaps

    package_root = find_package_root(path)
    if package_root is None:
        return matched_foundry

    node_modules = package_root / "node_modules"
    remaps = list(matched_foundry)
    for prefix in prefixes:
        target = node_modules / prefix
        if target.exists():
            remaps.append(f"{prefix}={target}")
    return list(dict.fromkeys(remaps))


def packages_path(contract_path: str | Path) -> Path | None:
    package_root = find_package_root(contract_path)
    if package_root is None:
        return None
    node_modules = package_root / "node_modules"
    return node_modules if node_modules.is_dir() else None

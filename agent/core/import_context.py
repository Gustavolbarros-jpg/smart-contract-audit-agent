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
        resolved = str(target_path.resolve())
        # solc joins the target and the rest of the import verbatim, so a prefix ending in a slash
        # needs a target ending in one: `forge-std/=/x/src` would turn forge-std/Test.sol into /x/srcTest.sol.
        if prefix.endswith("/") and not resolved.endswith("/"):
            resolved += "/"
        remaps.append(f"{prefix}={resolved}")
    return remaps


def _remap_for(import_path: str, remaps: list[str]) -> tuple[str, Path] | None:
    """The remapping with the longest prefix that covers ``import_path``, and the file it points to."""
    best = None
    for remap in remaps:
        prefix, target = remap.split("=", 1)
        if import_path.startswith(prefix) and (best is None or len(prefix) > len(best[0])):
            best = (prefix, target)
    if best is None:
        return None
    prefix, target = best
    return best[0] + "=" + target, Path(target) / import_path[len(prefix):]


def needed_remappings(contract_path: str | Path, remaps: list[str], limit: int = 5000) -> list[str]:
    """Remappings needed by the contract's imports, followed through the files they resolve to.

    A contract rarely imports the package that matters (openzeppelin, solmate) itself; the files
    it imports do. Only direct imports used to be considered, so the Prover could not find them,
    and a prefix with several segments (``@openzeppelin/contracts/``) never matched.
    """
    needed: dict[str, None] = {}
    seen: set[Path] = set()
    queue = [Path(contract_path).resolve()]
    while queue and len(seen) < limit:
        current = queue.pop()
        if current in seen:
            continue
        seen.add(current)
        for import_path in solidity_imports(_read_source(current)):
            if import_path.startswith((".", "/")):
                queue.append((current.parent / import_path).resolve())
                continue
            match = _remap_for(import_path, remaps)
            if match is not None:
                needed[match[0]] = None
                queue.append(match[1].resolve())
    return list(needed)


def solc_remappings(contract_path: str | Path, source: str | None = None) -> list[str]:
    path = Path(contract_path).resolve()
    source = _read_source(path) if source is None else source
    prefixes = sorted({prefix for imp in solidity_imports(source) if (prefix := _package_prefix(imp))})
    foundry_remaps = _foundry_remappings(path)
    matched_foundry = needed_remappings(path, foundry_remaps)
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


def certora_compiler_flags(contract_path: str | Path) -> list[str]:
    """Compiler flags for certoraRun that match how a Foundry project compiles itself.

    Foundry turns the optimizer on by default, and the Prover compiles to bytecode, so without
    these flags a contract that builds fine in its own project can fail with "Stack too deep".
    Returns nothing for a project without a foundry.toml.
    """
    root = find_project_root(contract_path)
    config = root / "foundry.toml" if root else None
    if config is None or not config.is_file():
        return []
    text = "\n".join(
        line for line in config.read_text(encoding="utf-8", errors="ignore").splitlines()
        if not line.strip().startswith("#")
    )

    def value(*names: str) -> str | None:
        for name in names:
            found = re.search(rf"^\s*{re.escape(name)}\s*=\s*[\"']?([\w.]+)[\"']?\s*$", text, re.MULTILINE)
            if found:
                return found.group(1)
        return None

    flags: list[str] = []
    if value("optimizer") != "false":
        flags += ["--solc_optimize", value("optimizer_runs", "optimizer-runs") or "200"]
    if value("via_ir", "via-ir") == "true":
        flags.append("--solc_via_ir")
    return flags

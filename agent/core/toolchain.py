"""Solidity compiler preflight helpers."""

from __future__ import annotations

import re
import subprocess


def extract_solidity_constraint(source: str) -> str:
    match = re.search(r"\bpragma\s+solidity\s+([^;]+);", source)
    return match.group(1).strip() if match else ""


def _version_tuple(version: str) -> tuple[int, int, int]:
    numbers = [int(part) for part in re.findall(r"\d+", version)[:3]]
    while len(numbers) < 3:
        numbers.append(0)
    return tuple(numbers[:3])


def _lower_bound_for_caret(version: tuple[int, int, int]) -> tuple[int, int, int]:
    return version


def _upper_bound_for_caret(version: tuple[int, int, int]) -> tuple[int, int, int]:
    major, minor, patch = version
    if major > 0:
        return major + 1, 0, 0
    if minor > 0:
        return 0, minor + 1, 0
    return 0, 0, patch + 1


def _matches_token(version: tuple[int, int, int], token: str) -> bool:
    token = token.strip()
    if not token:
        return True

    if token.startswith("^"):
        base = _version_tuple(token[1:])
        return _lower_bound_for_caret(base) <= version < _upper_bound_for_caret(base)

    for operator in (">=", "<=", ">", "<", "="):
        if token.startswith(operator):
            other = _version_tuple(token[len(operator):])
            if operator == ">=":
                return version >= other
            if operator == "<=":
                return version <= other
            if operator == ">":
                return version > other
            if operator == "<":
                return version < other
            return version == other

    if re.match(r"^\d+(?:\.\d+){0,2}$", token):
        return version == _version_tuple(token)

    return True


def version_satisfies_constraint(version: str, constraint: str) -> bool:
    if not constraint:
        return True

    version_tuple = _version_tuple(version)
    for alternative in constraint.split("||"):
        tokens = [token for token in re.split(r"\s+", alternative.strip()) if token]
        if tokens and all(_matches_token(version_tuple, token) for token in tokens):
            return True
    return False


def current_solc_version() -> str:
    try:
        result = subprocess.run(["solc", "--version"], capture_output=True, text=True, timeout=10)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return ""

    match = re.search(r"Version:\s*([0-9]+\.[0-9]+\.[0-9]+)", result.stdout + result.stderr)
    return match.group(1) if match else ""


def installed_solc_versions() -> list[str]:
    try:
        result = subprocess.run(["solc-select", "versions"], capture_output=True, text=True, timeout=10)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []

    versions = []
    for line in (result.stdout + result.stderr).splitlines():
        match = re.match(r"\s*([0-9]+\.[0-9]+\.[0-9]+)", line)
        if match:
            versions.append(match.group(1))
    return versions


def check_solidity_toolchain(source: str) -> dict:
    constraint = extract_solidity_constraint(source)
    current = current_solc_version()
    installed = installed_solc_versions()
    matching = [
        version for version in installed
        if version_satisfies_constraint(version, constraint)
    ]

    if not constraint:
        status = "ok"
        reason = "No Solidity pragma found; skipping version preflight."
    elif current and version_satisfies_constraint(current, constraint):
        status = "ok"
        reason = "Current solc version satisfies the contract pragma."
    elif matching:
        status = "current_solc_mismatch"
        reason = (
            f"Current solc {current or 'not found'} does not satisfy pragma "
            f"{constraint}, but installed version(s) do: {', '.join(matching)}."
        )
    else:
        status = "no_matching_solc_installed"
        reason = (
            f"Current solc {current or 'not found'} does not satisfy pragma "
            f"{constraint}, and no installed solc version matches it."
        )

    return {
        "status": status,
        "ok": status == "ok",
        "pragma": constraint,
        "current_solc": current,
        "installed_solc_versions": installed,
        "matching_installed_versions": matching,
        "reason": reason,
    }

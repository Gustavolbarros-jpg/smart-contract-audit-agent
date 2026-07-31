"""Deterministic CVL generation for narrow, mechanical property classes."""

from __future__ import annotations

import re
from typing import Any


def build_deterministic_spec(methods_block: str, selected_rules: list[dict[str, Any]]) -> str | None:
    if not selected_rules:
        return None
    if all(item.get("type") == "missing-zero-check" for item in selected_rules):
        return _build_zero_check_spec(methods_block, selected_rules)
    return None


def _build_zero_check_spec(methods_block: str, selected_rules: list[dict[str, Any]]) -> str | None:
    rules = []
    for item in selected_rules:
        parsed = _parse_signature(str(item.get("function") or ""))
        if not parsed:
            return None
        name, params = parsed
        address_positions = [
            index for index, param_type in enumerate(params)
            if param_type in {"address", "address payable"}
        ]
        if len(address_positions) != 1:
            return None

        args = []
        declarations = ["  env e;", "  address x;", "  require x == 0;"]
        for index, param_type in enumerate(params):
            if index == address_positions[0]:
                args.append("x")
                continue
            var_name = f"arg{index}"
            declarations.append(f"  {_cvl_type(param_type)} {var_name};")
            args.append(var_name)

        rule_name = _rule_name(item, name)
        rules.append(
            "\n".join(
                [
                    f"// {item.get('id', 'VULN_XXX')} - missing-zero-check",
                    f"rule {rule_name} {{",
                    *declarations,
                    f"  {name}@withrevert(e, {', '.join(args)});",
                    "  assert lastReverted;",
                    "}",
                ]
            )
        )

    return methods_block.rstrip() + "\n\n\n" + "\n\n".join(rules) + "\n"


def _parse_signature(signature: str) -> tuple[str, list[str]] | None:
    match = re.match(r"\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)", signature)
    if not match:
        return None
    name, raw_params = match.groups()
    params = []
    for param in [part.strip() for part in raw_params.split(",") if part.strip()]:
        params.append(_solidity_type(param))
    return name, params


def _solidity_type(param: str) -> str:
    cleaned = re.sub(r"\s+(memory|calldata|storage)\b", "", param).strip()
    parts = cleaned.split()
    if len(parts) <= 1:
        return cleaned
    return " ".join(parts[:-1])


def _cvl_type(param_type: str) -> str:
    if param_type == "address payable":
        return "address"
    return param_type


def _rule_name(item: dict[str, Any], function_name: str) -> str:
    names = item.get("rule_names") or []
    if names:
        base = str(names[0])
    else:
        base = f"zero_address_reverts_{function_name}"
    safe = re.sub(r"[^A-Za-z0-9_]", "_", base)
    if re.match(r"^[0-9]", safe):
        safe = f"rule_{safe}"
    return safe

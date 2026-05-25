"""Build token-efficient contract context for the LLM."""

from __future__ import annotations

import re


def _parse_line_range(value: str) -> tuple[int, int] | None:
    numbers = [int(match) for match in re.findall(r"\d+", value or "")]
    if not numbers:
        return None
    return min(numbers), max(numbers)


def _numbered_snippet(lines: list[str], start: int, end: int) -> str:
    start = max(start, 1)
    end = min(end, len(lines))
    return "\n".join(f"{idx:04d}: {lines[idx - 1]}" for idx in range(start, end + 1))


def _merge_ranges(ranges: list[tuple[int, int]]) -> list[tuple[int, int]]:
    if not ranges:
        return []

    merged = []
    for start, end in sorted(ranges):
        if not merged or start > merged[-1][1] + 1:
            merged.append([start, end])
        else:
            merged[-1][1] = max(merged[-1][1], end)
    return [(start, end) for start, end in merged]


def _extract_interface(source: str) -> dict:
    public_state = []
    functions = []
    modifiers = []

    for line in source.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("//"):
            continue

        state_match = re.match(
            r"^(mapping\s*\([^)]+\)|[A-Za-z_][A-Za-z0-9_\[\]]*)\s+"
            r"(?:public|external)\b",
            stripped,
        )
        if state_match and "function " not in stripped:
            public_state.append(stripped.rstrip("{"))
            continue

        if stripped.startswith("function "):
            signature = stripped.split("{", 1)[0].strip()
            functions.append(signature)
            continue

        if stripped.startswith("modifier "):
            modifiers.append(stripped.split("{", 1)[0].strip())

    return {
        "public_state": public_state,
        "functions": functions,
        "modifiers": modifiers,
    }


def _clean_type(value: str) -> str:
    value = value.strip()
    value = value.replace("address payable", "address")
    value = re.sub(r"\s+(memory|calldata|storage)\b", "", value)
    return re.sub(r"\s+", " ", value).strip()


def _is_cvl_primitive_type(value: str) -> bool:
    value = _clean_type(value)
    return bool(
        re.match(r"^(address|bool|string|bytes\d*|uint\d*|int\d*)$", value)
        or re.match(r"^bytes$", value)
    )


def _state_getter_signature(line: str) -> str | None:
    stripped = line.split("//", 1)[0].strip().rstrip(";")
    mapping_match = re.match(
        r"mapping\s*\(([^=]+?)\s*=>\s*([^)]+?)\)\s+public(?:\s+\w+)*\s+([A-Za-z_][A-Za-z0-9_]*)\b",
        stripped,
    )
    if mapping_match:
        key_type, value_type, name = mapping_match.groups()
        value_type = _clean_type(value_type)
        if not _is_cvl_primitive_type(value_type):
            return None
        return f"  function {name}({_clean_type(key_type)}) external returns({value_type}) envfree;"

    simple_match = re.match(
        r"([A-Za-z_][A-Za-z0-9_\[\]]*)\s+public(?:\s+\w+)*\s+([A-Za-z_][A-Za-z0-9_]*)\b",
        stripped,
    )
    if simple_match:
        value_type, name = simple_match.groups()
        value_type = _clean_type(value_type)
        if not _is_cvl_primitive_type(value_type):
            return None
        return f"  function {name}() external returns({value_type}) envfree;"

    return None


def _split_params(params: str) -> list[str]:
    if not params.strip():
        return []
    return [_clean_type(param) for param in params.split(",") if param.strip()]


def _type_without_name(value: str) -> str:
    cleaned = _clean_type(value)
    parts = cleaned.split()
    if len(parts) <= 1:
        return cleaned

    type_candidate = " ".join(parts[:-1])
    if _is_cvl_primitive_type(type_candidate):
        return type_candidate
    return cleaned


def _split_return_types(returns: str) -> list[str]:
    return [_type_without_name(item) for item in returns.split(",") if item.strip()]


def _function_method_signature(line: str) -> str | None:
    stripped = line.split("{", 1)[0].strip().rstrip(";")
    match = re.match(r"function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)\s*(.*)", stripped)
    if not match:
        return None

    name, params, tail = match.groups()
    visibility_match = re.search(r"\b(public|external)\b", tail)
    if not visibility_match:
        return None

    returns = ""
    returns_match = re.search(r"returns\s*\(([^)]*)\)", tail)
    if returns_match:
        returns = f" returns({', '.join(_split_return_types(returns_match.group(1)))})"

    envfree = " envfree" if re.search(r"\b(view|pure)\b", tail) else ""
    params = ", ".join(_split_params(params))
    return f"  function {name}({params}) external{returns}{envfree};"


def _mask_comments_and_strings(source: str) -> str:
    out = []
    i = 0
    state = "code"
    quote = ""

    while i < len(source):
        char = source[i]
        nxt = source[i + 1] if i + 1 < len(source) else ""

        if state == "code":
            if char == "/" and nxt == "/":
                out.extend([" ", " "])
                i += 2
                state = "line_comment"
                continue
            if char == "/" and nxt == "*":
                out.extend([" ", " "])
                i += 2
                state = "block_comment"
                continue
            if char in ("'", '"'):
                out.append(" ")
                quote = char
                i += 1
                state = "string"
                continue
            out.append(char)
            i += 1
            continue

        if state == "line_comment":
            out.append("\n" if char == "\n" else " ")
            if char == "\n":
                state = "code"
            i += 1
            continue

        if state == "block_comment":
            if char == "*" and nxt == "/":
                out.extend([" ", " "])
                i += 2
                state = "code"
                continue
            out.append("\n" if char == "\n" else " ")
            i += 1
            continue

        if state == "string":
            out.append("\n" if char == "\n" else " ")
            if char == "\\" and i + 1 < len(source):
                out.append("\n" if nxt == "\n" else " ")
                i += 2
                continue
            if char == quote:
                state = "code"
            i += 1

    return "".join(out)


def _matching_brace(masked_source: str, open_index: int) -> int:
    depth = 0
    for index in range(open_index, len(masked_source)):
        char = masked_source[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index
    return len(masked_source) - 1


def _function_bodies(source: str) -> dict[str, str]:
    masked = _mask_comments_and_strings(source)
    bodies = {}
    pattern = re.compile(r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^)]*\)[^{;]*{")

    for match in pattern.finditer(masked):
        name = match.group(1)
        brace = masked.find("{", match.end() - 1)
        end = _matching_brace(masked, brace)
        bodies[name] = source[match.start():end + 1]

    return bodies


def _uses_restricted_environment(body: str) -> bool:
    masked = _mask_comments_and_strings(body)
    restricted_patterns = [
        r"\bblock\s*\.\s*(timestamp|number|coinbase|basefee|prevrandao|difficulty|gaslimit|chainid)\b",
        r"\bmsg\s*\.\s*(sender|value|data|sig)\b",
        r"\btx\s*\.\s*(origin|gasprice)\b",
        r"\bgasleft\s*\(",
    ]
    return any(re.search(pattern, masked) for pattern in restricted_patterns)


def extract_primary_contract_name(source: str, preferred: str = "") -> str:
    """Return the Solidity contract name to pass to Certora."""
    masked = _mask_comments_and_strings(source)
    names = [
        match.group(1)
        for match in re.finditer(
            r"\b(?:abstract\s+)?contract\s+([A-Za-z_][A-Za-z0-9_]*)\b",
            masked,
        )
    ]
    if preferred and preferred in names:
        return preferred
    return names[-1] if names else ""


def _function_method_signature_with_body(line: str, body: str = "") -> str | None:
    signature = _function_method_signature(line)
    if not signature or " envfree;" not in signature:
        return signature
    if body and _uses_restricted_environment(body):
        return signature.replace(" envfree;", ";")
    return signature


def _parse_param(param: str, index: int) -> dict:
    cleaned = _clean_type(param)
    if not cleaned:
        return {"type": "", "name": f"arg{index}"}

    parts = cleaned.split()
    if len(parts) == 1:
        return {"type": parts[0], "name": f"arg{index}"}

    return {"type": " ".join(parts[:-1]), "name": parts[-1]}


def _function_info(line: str) -> dict | None:
    stripped = line.split("{", 1)[0].strip().rstrip(";")
    match = re.match(r"function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)\s*(.*)", stripped)
    if not match:
        return None

    name, params, tail = match.groups()
    raw_params = [param.strip() for param in params.split(",") if param.strip()]
    return {
        "name": name,
        "params": [_parse_param(param, index) for index, param in enumerate(raw_params)],
        "tail": tail,
        "signature": line,
    }


def owner_only_functions(source: str) -> list[dict]:
    """Return public/external functions protected by an onlyOwner modifier."""
    functions = []
    for line in _extract_interface(source)["functions"]:
        if "onlyOwner" not in line:
            continue
        info = _function_info(line)
        if info:
            functions.append(info)
    return functions


def choose_auth_probe_function(source: str) -> dict | None:
    """Pick a simple onlyOwner function for tx.origin/auth CVL rules."""
    functions = owner_only_functions(source)
    if not functions:
        return None

    preferred_names = ("pause", "unpause", "setRewardRate", "setMaxWithdraw", "setLockPeriod")
    for name in preferred_names:
        for function in functions:
            if function["name"] == name and not function["params"]:
                return function

    for function in functions:
        if not function["params"]:
            return function

    return functions[0]


def build_methods_block(source: str) -> str:
    """Build a deterministic CVL methods{} block from public/external Solidity API."""
    interface = _extract_interface(source)
    function_bodies = _function_bodies(source)
    entries = []
    seen = set()

    for line in interface["public_state"]:
        signature = _state_getter_signature(line)
        if signature and signature not in seen:
            entries.append(signature)
            seen.add(signature)

    for line in interface["functions"]:
        info = _function_info(line)
        body = function_bodies.get(info["name"], "") if info else ""
        signature = _function_method_signature_with_body(line, body)
        if signature and signature not in seen:
            entries.append(signature)
            seen.add(signature)

    return "methods {\n" + "\n".join(entries) + "\n}"


def _token_ranges(source: str, tokens: list[str], radius: int) -> list[tuple[int, int]]:
    ranges = []
    lines = source.splitlines()
    for idx, line in enumerate(lines, start=1):
        if any(token in line for token in tokens):
            ranges.append((idx - radius, idx + radius))
    return ranges


def build_contract_brief(source: str, selected_vulnerabilities: list[dict], radius: int = 8) -> str:
    """Return interface plus relevant numbered snippets instead of the full contract."""
    lines = source.splitlines()
    interface = _extract_interface(source)
    ranges: list[tuple[int, int]] = []

    for vuln in selected_vulnerabilities:
        parsed = _parse_line_range(vuln.get("line", ""))
        if parsed:
            ranges.append((parsed[0] - radius, parsed[1] + radius))

        vuln_type = vuln.get("type", "")
        if vuln_type == "tx-origin":
            ranges.extend(_token_ranges(source, ["tx.origin"], radius))
        elif vuln_type == "suicidal":
            ranges.extend(_token_ranges(source, ["selfdestruct"], radius))
        elif vuln_type == "arbitrary-send-eth":
            ranges.extend(_token_ranges(source, [".transfer(", ".send(", ".call{"], radius))

    snippets = []
    for start, end in _merge_ranges(ranges):
        snippets.append(_numbered_snippet(lines, start, end))

    return "\n".join(
        [
            "CONTRACT_INTERFACE",
            "public_state:",
            "\n".join(f"- {item}" for item in interface["public_state"]) or "- none detected",
            "functions:",
            "\n".join(f"- {item}" for item in interface["functions"]) or "- none detected",
            "modifiers:",
            "\n".join(f"- {item}" for item in interface["modifiers"]) or "- none detected",
            "",
            "RELEVANT_SNIPPETS",
            "\n\n".join(snippets) or "No line snippets available.",
        ]
    )

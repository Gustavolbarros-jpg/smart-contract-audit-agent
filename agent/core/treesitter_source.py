"""Tree-sitter backend for Solidity parsing.

The regex parser in ``solidity_source`` cannot distinguish two functions sharing a name
and locates definitions by matching their header text, which a multi-line signature or a
modifier in an unusual position defeats. Tree-sitter parses the real grammar, so a
definition is a node with exact byte offsets and a name field.

Following MANDO-LLM (ACM TOSEM 10.1145/3765751), which replaced Slither with tree-sitter
for graph construction precisely because compilation kept failing on version conflicts
and missing libraries: parsing here needs no solc, no remappings and no dependencies on
disk. That matters for contracts we cannot compile.

Import stays optional. ``available()`` reports whether the backend can be used, and
``solidity_source`` falls back to the regex parser when it cannot, so the pipeline keeps
working without the dependency.
"""

from __future__ import annotations

import warnings

_PARSER = None
_IMPORT_ERROR: Exception | None = None

try:  # pragma: no cover - exercised by availability, not by branch
    import tree_sitter as _tree_sitter
    import tree_sitter_solidity as _tree_sitter_solidity
except Exception as exc:  # noqa: BLE001 - any import failure means unavailable
    _tree_sitter = None
    _tree_sitter_solidity = None
    _IMPORT_ERROR = exc


DEFINITION_NODES = {
    "function_definition": "function",
    "modifier_definition": "modifier",
    "constructor_definition": "constructor",
    "fallback_receive_definition": "fallback",
}


def available() -> bool:
    """Whether the tree-sitter backend can parse."""
    return _parser() is not None


def unavailable_reason() -> str:
    return "" if available() else f"{type(_IMPORT_ERROR).__name__}: {_IMPORT_ERROR}"


def _parser():
    global _PARSER
    if _PARSER is not None:
        return _PARSER
    if _tree_sitter is None or _tree_sitter_solidity is None:
        return None
    with warnings.catch_warnings():
        # tree_sitter deprecates the int form its own grammar packages still return.
        warnings.simplefilter("ignore", DeprecationWarning)
        language = _tree_sitter.Language(_tree_sitter_solidity.language())
        _PARSER = _tree_sitter.Parser(language)
    return _PARSER


def _text(node, source: bytes) -> str:
    return source[node.start_byte : node.end_byte].decode("utf-8", errors="ignore")


def _named_child_text(node, field: str, source: bytes) -> str:
    child = node.child_by_field_name(field)
    return _text(child, source) if child is not None else ""


def _enclosing_contract(node, source: bytes) -> str:
    current = node.parent
    while current is not None:
        if current.type == "contract_declaration":
            return _named_child_text(current, "name", source)
        current = current.parent
    return ""


def _unwrap(node):
    """Descend through the grammar's generic ``expression`` wrappers.

    ``call_expression``'s ``function`` field is an ``expression`` node, not the
    identifier itself, so a type check on the field alone never matches.
    """
    while node is not None and node.type == "expression" and node.named_child_count == 1:
        node = node.named_child(0)
    return node


def _walk(node):
    yield node
    for child in node.children:
        yield from _walk(child)


def parse_definitions(source: str) -> list[dict] | None:
    """Definitions as dicts matching ``solidity_source.Definition`` fields.

    Returns None when the backend is unavailable, so the caller can fall back. A source
    with syntax errors still yields whatever parsed: tree-sitter recovers from errors,
    which is the point for contracts that do not compile.
    """
    parser = _parser()
    if parser is None:
        return None

    raw = source.encode("utf-8")
    tree = parser.parse(raw)
    definitions: list[dict] = []

    for node in _walk(tree.root_node):
        kind = DEFINITION_NODES.get(node.type)
        if kind is None:
            continue

        body = node.child_by_field_name("body")
        if body is None:
            continue  # declaration without a body: nothing to expand into

        name = _named_child_text(node, "name", raw)
        if not name:
            # constructor/fallback/receive carry no name field; use the keyword.
            name = _text(node.children[0], raw) if node.children else kind

        header_end = body.start_byte
        definitions.append(
            {
                "name": name,
                "kind": kind,
                "signature": " ".join(raw[node.start_byte : header_end].decode(
                    "utf-8", errors="ignore").split()),
                "start_line": node.start_point[0] + 1,
                "end_line": node.end_point[0] + 1,
                "body": _text(node, raw),
                "contract": _enclosing_contract(node, raw),
            }
        )

    return definitions


def called_names(source: str, start_line: int, end_line: int) -> list[str] | None:
    """Names invoked inside a line range: applied modifiers and call expressions.

    Grammar nodes replace token heuristics for structure: ``modifier_invocation`` is
    explicit, and a value type conversion (``uint256(x)``) is not a ``call_expression``,
    so it never appears here.

    Builtins are a different matter. ``require(...)`` is syntactically an ordinary call
    and the grammar has no reason to mark it otherwise, so names like require, assert
    and revert are returned and the caller filters them — see ``call_expansion``, where
    they also fail to resolve against any defined name.
    """
    parser = _parser()
    if parser is None:
        return None

    raw = source.encode("utf-8")
    tree = parser.parse(raw)
    names: list[str] = []

    for node in _walk(tree.root_node):
        line = node.start_point[0] + 1
        if not (start_line <= line <= end_line):
            continue

        if node.type == "modifier_invocation":
            child = node.child_by_field_name("name")
            names.append(_text(child if child is not None else node.children[0], raw))
            continue

        if node.type == "call_expression":
            target = _unwrap(node.child_by_field_name("function"))
            if target is None:
                continue
            if target.type == "identifier":
                names.append(_text(target, raw))
            elif target.type == "member_expression":
                # this.foo() resolves internally; lib.foo() does not.
                obj = _unwrap(target.child_by_field_name("object"))
                prop = target.child_by_field_name("property")
                if obj is not None and prop is not None and _text(obj, raw) == "this":
                    names.append(_text(prop, raw))

    return list(dict.fromkeys(name for name in names if name))


def has_syntax_errors(source: str) -> bool | None:
    parser = _parser()
    if parser is None:
        return None
    return parser.parse(source.encode("utf-8")).root_node.has_error

"""Propose formal properties from the contract's own shape, with no detector involved.

Everything the pipeline formalises today is indexed by a Slither finding: ETAPA 2 only
considers the catalog classes marked ``formalizable``, and all six of those are simple
(zero check, tx-origin, suicidal, arbitrary-send-eth, over/underflow). The consequence is
measured in ``docs/resultado-oraculo-formal-20261117.md`` §4.6 -- on contracts whose whole
purpose is a complex defect, the pipeline reports success while the defect stays put,
because no detector ever named it.

This module takes the other route. It reads the source and recognises *accounting shapes*:
a function that credits a per-address mapping and a total, one that debits them, one
guarded by a modifier that checks identity against ``msg.sender``. Each shape implies a
property that holds in any correct implementation of it, so the property can be written
without knowing what is wrong -- which is the only way to reach a defect that no pattern
names.

Deliberately mechanical: no LLM, no Slither, no network. A shape either matches or it does
not, and an ambiguous match is dropped rather than guessed, because a wrong property
costs more than a missing one -- it makes a correct contract look broken.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .solidity_source import Definition, mask_comments_and_strings, parse_definitions

# Unsigned integer parameter: the amount a credit or debit moves.
_UINT = re.compile(r"\buint(?:8|16|32|64|128|256)?\b")
_LOCATION = re.compile(r"\b(calldata|memory|storage)\b")
_IDENT = re.compile(r"[A-Za-z_]\w*")
_CONTRACT_DECL = re.compile(r"^\s*(?:abstract\s+)?(?:contract|interface|library)\s+([A-Za-z_]\w*)", re.MULTILINE)
_VALUE_TYPE = re.compile(r"^(u?int(?:8|16|32|64|128|256)?|bool|address|bytes(?:[1-9]|[12]\d|3[0-2])?|string)(\[\])?$")

# `balances[msg.sender] += amount;` / `-=`
_MAP_DELTA = re.compile(r"\b([A-Za-z_]\w*)\s*\[\s*([^\]]+?)\s*\]\s*(\+=|-=)\s*([^;]+);")
# `totalDeposits += amount;` on a plain state variable (no index)
_VAR_DELTA = re.compile(r"(?<![\]\w.])\b([A-Za-z_]\w*)\s*(\+=|-=)\s*([^;]+);")
# `require(msg.sender == owner, ...)` and the reversed spelling
_IDENTITY = re.compile(r"msg\.sender\s*(==|!=)\s*([A-Za-z_]\w*(?:\(\))?)|\b([A-Za-z_]\w*(?:\(\))?)\s*(==|!=)\s*msg\.sender")

# `mapping(address => uint256) public balances;` and `address public owner;`
_PUBLIC_MAPPING = re.compile(
    r"^\s*mapping\s*\(\s*([A-Za-z_]\w*)[^=]*=>\s*([A-Za-z_]\w*)[^)]*\)\s+public\s+([A-Za-z_]\w*)\s*;",
    re.MULTILINE,
)
_PUBLIC_SCALAR = re.compile(
    r"^\s*([A-Za-z_]\w*)\s+public\s+(?:constant\s+|immutable\s+)?([A-Za-z_]\w*)\s*(?:=[^;]*)?;",
    re.MULTILINE,
)
_NUMERIC = re.compile(r"^(u?int(?:8|16|32|64|128|256)?)$")


@dataclass(frozen=True)
class PropertyCandidate:
    """One property, the CVL that states it, and why the shape implies it."""

    name: str
    shape: str
    contract: str
    function: str
    cvl: str
    rationale: str
    reads: tuple[str, ...] = ()          # getters the rule calls envfree
    getters: tuple[tuple[str, str], ...] = ()   # (name, CVL arg type; "" when nullary)
    confidence: str = "mechanical"

    @property
    def rule_name(self) -> str:
        return self.name


@dataclass
class _FnShape:
    definition: Definition
    refs: frozenset[str] = frozenset()
    credits: list[tuple[str, str]] = field(default_factory=list)   # (mapping, delta expr)
    debits: list[tuple[str, str]] = field(default_factory=list)
    total_credits: list[str] = field(default_factory=list)
    total_debits: list[str] = field(default_factory=list)
    gates: list[str] = field(default_factory=list)                 # identity variables


def contract_like_names(source: str) -> frozenset[str]:
    """Contract, interface and library names: usable as `address` in a CVL signature."""
    return frozenset(_CONTRACT_DECL.findall(mask_comments_and_strings(source)))


def _params(signature: str, refs: frozenset[str] = frozenset()) -> list[tuple[str, str]]:
    inner = signature[signature.index("(") + 1: signature.rindex(")")] if "(" in signature else ""
    out = []
    depth = 0
    atual = ""
    for ch in inner:
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(atual)
            atual = ""
        else:
            atual += ch
    if atual.strip():
        out.append(atual)
    pares = []
    for bruto in out:
        texto = _LOCATION.sub(" ", bruto.replace("\n", " ")).strip()
        nomes = _IDENT.findall(texto)
        if len(nomes) < 2:
            # no name, or a type we cannot read: refuse the whole list rather than
            # silently drop a parameter, which would generate a call of wrong arity.
            return []
        nome = nomes[-1]
        tipo = texto[: texto.rindex(nome)].strip()
        cvl = _cvl_param_type(tipo, refs)
        if cvl is None:
            return []
        pares.append((cvl, nome))
    return pares if len(pares) == len(out) else []


def _cvl_param_type(tipo: str, refs: frozenset[str]) -> str | None:
    """The CVL spelling of a Solidity parameter type, or None when we must not guess.

    `address payable` and any contract or interface type are plain `address`; CVL rejects
    an interface name in a signature. A struct or an enum has no safe spelling here, so
    the function it appears in is dropped instead of being given a wrong signature.
    """
    limpo = " ".join(tipo.split())
    if limpo.startswith("address"):
        return "address[]" if limpo.endswith("[]") else "address"
    base = limpo[:-2] if limpo.endswith("[]") else limpo
    if base in refs:
        return "address[]" if limpo.endswith("[]") else "address"
    return limpo if _VALUE_TYPE.match(limpo) else None


def _params_are_complete(signature: str, refs: frozenset[str] = frozenset()) -> bool:
    """False when the parameter list has text we did not turn into a parameter."""
    if "(" not in signature:
        return False
    inner = signature[signature.index("(") + 1: signature.rindex(")")].strip()
    if not inner:
        return True
    return bool(_params(signature, refs))


def _is_external(signature: str) -> bool:
    return bool(re.search(r"\b(external|public)\b", signature))


def _is_payable(signature: str) -> bool:
    return bool(re.search(r"\bpayable\b", signature))


def _is_view(signature: str) -> bool:
    return bool(re.search(r"\b(view|pure)\b", signature))


def _modifiers(signature: str, known: set[str]) -> list[str]:
    cabeca = signature[signature.rindex(")") + 1:] if ")" in signature else ""
    cabeca = re.sub(r"\breturns\s*\([^)]*\)", " ", cabeca)
    return [w for w in re.findall(r"[A-Za-z_]\w*", cabeca) if w in known]


def public_state(source: str) -> dict[str, tuple[str, str]]:
    """Public state variables as the getters Solidity generates: name -> (arg, return).

    The return type has to come from the declaration. Assuming `uint256` for every getter
    is a CVL type error the moment a contract has an `address public owner`, and the
    Prover rejects the whole spec, not just that line.
    """
    masked = mask_comments_and_strings(source)
    decls: dict[str, tuple[str, str]] = {}
    for m in _PUBLIC_MAPPING.finditer(masked):
        chave, valor, nome = m.group(1), m.group(2), m.group(3)
        decls[nome] = (chave, valor)
    for m in _PUBLIC_SCALAR.finditer(masked):
        tipo, nome = m.group(1), m.group(2)
        if tipo in ("function", "event", "return", "emit", "mapping"):
            continue
        decls.setdefault(nome, ("", tipo))
    return decls


def _numeric(tipo: str) -> bool:
    return bool(_NUMERIC.match(tipo))


def _public_state_names(source: str) -> set[str]:
    return set(public_state(source))


def _identity_vars(body: str) -> list[str]:
    achados = []
    for m in _IDENTITY.finditer(mask_comments_and_strings(body)):
        var = m.group(2) or m.group(3) or ""
        var = var.replace("()", "")
        if var and var not in ("msg", "tx", "address"):
            achados.append(var)
    return achados


def _shape_of(d: Definition, modifier_bodies: dict[str, str], refs: frozenset[str] = frozenset()) -> _FnShape:
    shape = _FnShape(definition=d, refs=refs)
    corpo = mask_comments_and_strings(d.body)
    for m in _MAP_DELTA.finditer(corpo):
        mapping, _chave, op, expr = m.group(1), m.group(2), m.group(3), m.group(4).strip()
        (shape.credits if op == "+=" else shape.debits).append((mapping, expr))
    corpo_sem_map = _MAP_DELTA.sub(" ", corpo)
    for m in _VAR_DELTA.finditer(corpo_sem_map):
        var, op, expr = m.group(1), m.group(2), m.group(3).strip()
        (shape.total_credits if op == "+=" else shape.total_debits).append(var)
    for nome in _modifiers(d.signature, set(modifier_bodies)):
        shape.gates.extend(_identity_vars(modifier_bodies[nome]))
    shape.gates.extend(_identity_vars(corpo))
    return shape


def _amount_param(d: Definition, refs: frozenset[str] = frozenset()) -> tuple[str, str] | None:
    """The single unsigned amount this function moves, or None if it is not unambiguous."""
    numericos = [(t, n) for t, n in _params(d.signature, refs) if _UINT.fullmatch(t)]
    return numericos[0] if len(numericos) == 1 else None


def _call_args(d: Definition, refs: frozenset[str] = frozenset()) -> str:
    return ", ".join(n for _t, n in _params(d.signature, refs))


def _decl_args(d: Definition, refs: frozenset[str] = frozenset()) -> str:
    return ", ".join(f"{t} {n}" for t, n in _params(d.signature, refs))


def propose(source: str, contract: str = "") -> list[PropertyCandidate]:
    """Every property the source's shape implies, in declaration order."""
    definicoes = parse_definitions(source)
    modifier_bodies = {d.name: d.body for d in definicoes if d.kind == "modifier"}
    decls = public_state(source)
    refs = contract_like_names(source)
    publicos = set(decls)
    candidatos: list[PropertyCandidate] = []

    for d in definicoes:
        if d.kind != "function" or not _is_external(d.signature) or _is_view(d.signature):
            continue
        if contract and d.contract and d.contract != contract:
            continue
        if not _params_are_complete(d.signature, refs):
            continue
        shape = _shape_of(d, modifier_bodies, refs)
        candidatos.extend(_credit_rules(shape, decls))
        candidatos.extend(_debit_rules(shape, decls))
        candidatos.extend(_gate_rules(shape, decls))

    vistos: set[str] = set()
    unicos = []
    for c in candidatos:
        if c.name not in vistos:
            vistos.add(c.name)
            unicos.append(c)
    return unicos


def _credit_rules(shape: _FnShape, decls: dict[str, tuple[str, str]]) -> list[PropertyCandidate]:
    d = shape.definition
    if not shape.credits:
        return []
    mapping, _expr = shape.credits[0]
    if mapping not in decls or not _numeric(decls[mapping][1]):
        return []

    amount = _amount_param(d, shape.refs)
    paga = _is_payable(d.signature)
    if amount is None and not paga:
        return []
    quantia = amount[1] if amount else "e.msg.value"
    decl = _decl_args(d, shape.refs)
    chamada = _call_args(d, shape.refs)
    chamada = f"e, {chamada}" if chamada else "e"
    assinatura = f"({decl})" if decl else "()"
    guarda = f"    require {quantia} > 0;" if amount else "    require e.msg.value > 0;"

    nome = f"{d.name}_never_credits_zero"
    cvl = f"""rule {nome}{assinatura} {{
    env e;
{guarda}

    uint256 antes = {mapping}(e.msg.sender);
    {d.name}({chamada});
    uint256 depois = {mapping}(e.msg.sender);

    assert depois > antes, "a nonzero {quantia} left the caller's {mapping} untouched";
}}"""
    regras = [PropertyCandidate(
        name=nome,
        shape="credit",
        contract=d.contract,
        function=d.name,
        cvl=cvl,
        rationale=(f"{d.name} credits {mapping}[msg.sender] from a nonzero amount; a credit "
                   f"that can round to nothing leaves value in the contract with no claim on it"),
        reads=(mapping,),
        getters=((mapping, "address"),),
    )]

    for total in dict.fromkeys(shape.total_credits):
        if total not in decls or total == mapping or not _numeric(decls[total][1]):
            continue
        nome_t = f"{d.name}_credits_{total}_by_the_same_amount"
        cvl_t = f"""rule {nome_t}{assinatura} {{
    env e;

    uint256 antes_conta = {mapping}(e.msg.sender);
    uint256 antes_total = {total}();
    {d.name}({chamada});
    uint256 depois_conta = {mapping}(e.msg.sender);
    uint256 depois_total = {total}();

    assert to_mathint(depois_total) - to_mathint(antes_total)
        == to_mathint(depois_conta) - to_mathint(antes_conta),
        "{total} and {mapping}[msg.sender] moved by different amounts";
}}"""
        regras.append(PropertyCandidate(
            name=nome_t,
            shape="credit_total",
            contract=d.contract,
            function=d.name,
            cvl=cvl_t,
            rationale=f"{d.name} moves {mapping}[msg.sender] and {total} together; they must move by the same amount",
            reads=(mapping, total),
            getters=((mapping, "address"), (total, "")),
        ))
    return regras


def _debit_rules(shape: _FnShape, decls: dict[str, tuple[str, str]]) -> list[PropertyCandidate]:
    d = shape.definition
    if not shape.debits:
        return []
    mapping, _expr = shape.debits[0]
    if mapping not in decls or not _numeric(decls[mapping][1]):
        return []
    amount = _amount_param(d, shape.refs)
    if amount is None:
        return []

    decl = _decl_args(d, shape.refs)
    chamada = _call_args(d, shape.refs)
    chamada = f"e, {chamada}" if chamada else "e"
    quantia = amount[1]

    nome = f"{d.name}_debits_exactly"
    cvl = f"""rule {nome}({decl}) {{
    env e;

    uint256 antes = {mapping}(e.msg.sender);
    {d.name}({chamada});
    uint256 depois = {mapping}(e.msg.sender);

    assert to_mathint(depois) == to_mathint(antes) - {quantia},
        "{mapping}[msg.sender] did not fall by exactly {quantia}";
}}"""
    regras = [PropertyCandidate(
        name=nome,
        shape="debit",
        contract=d.contract,
        function=d.name,
        cvl=cvl,
        rationale=f"{d.name} debits {mapping}[msg.sender] by {quantia}; any other delta is an accounting error",
        reads=(mapping,),
        getters=((mapping, "address"),),
    )]

    for total in dict.fromkeys(shape.total_debits):
        if total not in decls or total == mapping or not _numeric(decls[total][1]):
            continue
        nome_t = f"{d.name}_debits_{total}_by_the_same_amount"
        cvl_t = f"""rule {nome_t}({decl}) {{
    env e;

    uint256 antes = {total}();
    {d.name}({chamada});
    uint256 depois = {total}();

    assert to_mathint(depois) == to_mathint(antes) - {quantia},
        "{total} did not fall by exactly {quantia}";
}}"""
        regras.append(PropertyCandidate(
            name=nome_t,
            shape="debit_total",
            contract=d.contract,
            function=d.name,
            cvl=cvl_t,
            rationale=f"{d.name} debits {total} alongside the caller's balance; both must fall by {quantia}",
            reads=(total,),
            getters=((total, ""),),
        ))
    return regras


def _gate_rules(shape: _FnShape, decls: dict[str, tuple[str, str]]) -> list[PropertyCandidate]:
    d = shape.definition
    portoes = [g for g in dict.fromkeys(shape.gates) if g in decls and decls[g][1] == "address"]
    if not portoes:
        return []
    porta = portoes[0]
    decl = _decl_args(d, shape.refs)
    chamada = _call_args(d, shape.refs)
    chamada = f"e, {chamada}" if chamada else "e"
    nome = f"only_{porta}_calls_{d.name}"
    cvl = f"""rule {nome}({decl}) {{
    env e;
    require e.msg.sender != {porta}();

    {d.name}@withrevert({chamada});

    assert lastReverted, "{d.name} went through for a caller that is not {porta}";
}}"""
    return [PropertyCandidate(
        name=nome,
        shape="identity_gate",
        contract=d.contract,
        function=d.name,
        cvl=cvl,
        rationale=f"{d.name} is gated on msg.sender == {porta}; removing the gate must make it revert for anyone else",
        reads=(porta,),
        getters=((porta, ""),),
    )]


# ── montagem da spec ────────────────────────────────────────────────────────

_EXTERNAL_CALL = re.compile(r"\b([A-Za-z_]\w*)\.(transferFrom|transfer|balanceOf)\s*\(")


def _token_summaries(source: str) -> list[str]:
    """Summarise an ERC20 the contract talks to instead of linking it.

    A property about share accounting depends on a balance the contract does not own, so
    the token is left free: `balanceOf` may return anything, which is exactly what a
    donation to the pool produces. `transfer`/`transferFrom` are forced to succeed so a
    failing token cannot mask the property being checked.
    """
    chamadas = {m.group(2) for m in _EXTERNAL_CALL.finditer(mask_comments_and_strings(source))}
    linhas = []
    if "balanceOf" in chamadas:
        linhas.append("    function _.balanceOf(address) external => NONDET;")
    if "transfer" in chamadas:
        linhas.append("    function _.transfer(address, uint256) external => ALWAYS(true);")
    if "transferFrom" in chamadas:
        linhas.append("    function _.transferFrom(address, address, uint256) external => ALWAYS(true);")
    return linhas


def build_spec(source: str, candidates: list[PropertyCandidate], header: str = "") -> str:
    """A complete .spec: methods block, token summaries, then every candidate rule.

    `ALWAYS(v)` takes no `expect` clause -- unlike a function summary, which requires one.
    Getting that wrong is a CVL syntax error, not a verification failure.
    """
    decls = public_state(source)
    usados: set[str] = set()
    for c in candidates:
        for nome, _arg in c.getters:
            usados.add(nome)

    linhas = ["methods {"]
    for nome in sorted(usados):
        arg, ret = decls.get(nome, ("", "uint256"))
        linhas.append(f"    function {nome}({arg}) external returns ({ret}) envfree;")
    linhas.extend(_token_summaries(source))
    linhas.append("}")

    partes = []
    if header:
        partes.append("\n".join(f"// {l}" for l in header.strip().splitlines()))
    partes.append("\n".join(linhas))
    for c in candidates:
        partes.append(f"// {c.shape}: {c.rationale}\n{c.cvl}")
    return "\n\n".join(partes) + "\n"

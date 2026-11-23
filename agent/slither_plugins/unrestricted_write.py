"""Slither detector: externally callable functions that overwrite privileged state unguarded.

Slither 0.11.3 ships no detector for this class. The pipeline approximated it with a
name heuristic (``_find_unprotected_critical_updates`` in core/slither_normalizer.py)
that trusts variable names such as ``owner`` or ``admin``. This detector decides from
how the contract itself treats a variable instead, using Slither's IR:

  authority  - compared against the caller (``msg.sender == X``, ``tx.origin == X``) or a
               mapping indexed by the caller whose boolean value gates execution
               (``require(admin[msg.sender])``, or the deny-list ``require(!blocked[msg.sender])``)
  fund sink  - an address variable that receives ether (transfer/send/call with value)
  admin-set  - every other function that writes it is caller-guarded or a constructor

A function is reported when it is public/external, mutates state, has no caller check on
its path (body, modifiers, internal callees) and overwrites one of those variables.
Writes keyed by the caller (``balances[msg.sender] = ...``) and read-modify-write updates
(``total += x``) are never reported. docs/unrestricted-write-detector.md lists the gaps.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from slither.core.cfg.node import Node, NodeType
from slither.core.declarations import Contract, Function, Modifier, SolidityVariable
from slither.core.solidity_types import ArrayType, MappingType
from slither.core.variables.local_variable import LocalVariable
from slither.core.variables.state_variable import StateVariable
from slither.core.variables.variable import Variable
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.slithir.operations import (
    Assignment,
    Binary,
    BinaryType,
    Delete,
    HighLevelCall,
    Index,
    InternalCall,
    LowLevelCall,
    Member,
    Operation,
    OperationWithLValue,
    Send,
    SolidityCall,
    Transfer,
    Unary,
    UnaryType,
)
from slither.slithir.variables import Constant, ReferenceVariable
from slither.utils.output import Output

_CALLER_IDENTITY = frozenset({"msg.sender", "tx.origin"})
_EQUALITY = frozenset({BinaryType.EQUAL, BinaryType.NOT_EQUAL})
_ORDERING = frozenset(
    {BinaryType.GREATER, BinaryType.GREATER_EQUAL, BinaryType.LESS, BinaryType.LESS_EQUAL}
)

AUTHORITY = "compared against the caller"
FUND_SINK = "receives ether"
ADMIN_SET = "otherwise written only by caller-guarded functions or the constructor"


@dataclass(frozen=True)
class _Context:
    """A function body as reached from an entry point.

    ``caller_parameters`` holds the indices of parameters that receive the caller's
    address at the call site, so ``_check(msg.sender)`` is recognised inside ``_check``.
    """

    function: Function
    caller_parameters: frozenset[int] = frozenset()


@dataclass
class _Write:
    """One overwrite of a state variable on an entry point's path."""

    variable: StateVariable
    node: Node
    keyed_by_caller: bool
    read_modify_write: bool
    constant_value: Constant | None


@dataclass
class _EntryPoint:
    """What the detector learned about one public/external function."""

    function: Function
    caller_checked: bool = False
    payment_gated: bool = False
    one_shot: bool = False
    writes: list[_Write] = field(default_factory=list)
    # Nodes executed only after a caller comparison inside an ``if``, e.g. the body of
    # ``if (msg.sender == owner) { ... }``; writes there are guarded even without require.
    caller_branch_nodes: set[Node] = field(default_factory=set)
    flag_conditions: set[str] = field(default_factory=set)


class _Dataflow:
    """Backward walk from an IR value to what it derives from, across internal calls."""

    def __init__(self) -> None:
        self._definitions: dict[int, dict[int, list[Operation]]] = {}

    def _defining_operations(self, function: Function) -> dict[int, list[Operation]]:
        cached = self._definitions.get(id(function))
        if cached is not None:
            return cached
        table: dict[int, list[Operation]] = {}
        for node in function.nodes:
            for ir in node.irs:
                if not isinstance(ir, OperationWithLValue) or ir.lvalue is None:
                    continue
                # A reference is defined by the Index/Member that creates it; a later
                # assignment through it writes the storage it points to, not the reference.
                if isinstance(ir.lvalue, ReferenceVariable) and not isinstance(ir, (Index, Member)):
                    continue
                table.setdefault(id(ir.lvalue), []).append(ir)
        self._definitions[id(function)] = table
        return table

    def origins(self, value: object, function: Function, active: frozenset = frozenset()) -> list:
        """State variables, Solidity globals and parameters of ``function`` that ``value`` derives from."""
        if isinstance(value, (StateVariable, SolidityVariable)):
            return [value]
        if isinstance(value, LocalVariable) and any(value is p for p in function.parameters):
            return [value]
        key = (id(function), id(value))
        if key in active:
            return []
        active = active | {key}

        found: list = []
        for ir in self._defining_operations(function).get(id(value), []):
            if isinstance(ir, InternalCall) and isinstance(ir.function, Function):
                found.extend(self._call_result_origins(ir, function, active))
            else:
                for read in ir.read:
                    found.extend(self.origins(read, function, active))
        return found

    def _call_result_origins(self, call: InternalCall, caller: Function, active: frozenset) -> list:
        callee = call.function
        found: list = []
        for returned in [*callee.return_values, *callee.returns]:
            for origin in self.origins(returned, callee, active):
                index = _parameter_index(origin, callee)
                if index is None:
                    found.append(origin)
                elif index < len(call.arguments):
                    found.extend(self.origins(call.arguments[index], caller, active))
        return found

    def is_caller(self, value: object, context: _Context) -> bool:
        """Whether ``value`` carries the caller's address (msg.sender, tx.origin or a bound parameter)."""
        for origin in self.origins(value, context.function):
            if isinstance(origin, SolidityVariable) and origin.name in _CALLER_IDENTITY:
                return True
            index = _parameter_index(origin, context.function)
            if index is not None and index in context.caller_parameters:
                return True
        return False

    def depends_on(self, value: object, function: Function, variable: StateVariable) -> bool:
        return any(
            isinstance(origin, StateVariable) and origin.canonical_name == variable.canonical_name
            for origin in self.origins(value, function)
        )

    def storage_target(self, value: object, context: _Context) -> tuple[StateVariable | None, bool]:
        """The state variable a write through ``value`` lands in, and whether it is keyed by the caller.

        Follows Index/Member chains and storage pointers (``Account storage a = accounts[x]``).
        """
        keyed_by_caller = False
        current = value
        visited: set[int] = set()
        while id(current) not in visited:
            visited.add(id(current))
            if isinstance(current, StateVariable):
                return current, keyed_by_caller
            definitions = self._defining_operations(context.function).get(id(current), [])
            if not definitions:
                return None, keyed_by_caller
            definition = definitions[0]
            if isinstance(definition, Index):
                keyed_by_caller = keyed_by_caller or self.is_caller(definition.variable_right, context)
                current = definition.variable_left
            elif isinstance(definition, Member):
                current = definition.variable_left
            elif (
                isinstance(current, LocalVariable)
                and current.is_storage
                and isinstance(definition, Assignment)
            ):
                current = definition.rvalue
            else:
                return None, keyed_by_caller
        return None, keyed_by_caller


def _parameter_index(value: object, function: Function) -> int | None:
    for index, parameter in enumerate(function.parameters):
        if value is parameter:
            return index
    return None


def _is_whole_value(variable: StateVariable) -> bool:
    """Mappings/arrays compared through an arbitrary key express per-resource ownership
    (``campaigns[id].creator == msg.sender``), not a contract-wide role."""
    return not isinstance(variable.type, (MappingType, ArrayType))


def _halts(node: Node | None) -> bool:
    if node is None:
        return False
    if node.type == NodeType.THROW:
        return True
    return any(
        isinstance(ir, SolidityCall) and ir.function.name.startswith("revert") for ir in node.irs
    )


def _is_guard(node: Node, early_return_guards: bool) -> bool:
    """Whether a failing condition at ``node`` stops the code that follows.

    An early ``return`` only guards in the entry point or a modifier; inside a helper it
    merely selects a return value (``_msgSender`` returns early without restricting anyone).
    """
    if node.contains_require_or_assert():
        return True
    if node.type != NodeType.IF:
        return False
    for branch in (node.son_true, node.son_false):
        if _halts(branch):
            return True
        if early_return_guards and branch is not None and branch.type == NodeType.RETURN:
            return True
    return False


def _negated(value: object, node: Node) -> bool:
    return any(
        isinstance(ir, Unary) and ir.type == UnaryType.BANG and any(r is value for r in ir.read)
        for ir in node.irs
    )


def _returns_bool(ir: OperationWithLValue) -> bool:
    return ir.lvalue is not None and str(ir.lvalue.type) == "bool"


def _is_read_only_call(ir: InternalCall | HighLevelCall) -> bool:
    target = ir.function
    if isinstance(target, Function):
        return target.view or target.pure
    return isinstance(target, Variable)  # public getter of another contract's state


class UnrestrictedWrite(AbstractDetector):
    """Report public/external functions that overwrite privileged state without a caller check."""

    ARGUMENT = "unrestricted-write"
    HELP = "Privileged state overwritten by a function without access control"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.MEDIUM

    WIKI = "docs/unrestricted-write-detector.md"
    WIKI_TITLE = "Unrestricted write to privileged state"
    WIKI_DESCRIPTION = (
        "A public or external function overwrites a state variable the contract treats as "
        "privileged (compared against msg.sender, receiving ether, or otherwise written only "
        "by guarded functions) without checking who the caller is."
    )
    WIKI_EXPLOIT_SCENARIO = """
```solidity
contract Vault {
    address public owner;
    constructor() { owner = msg.sender; }
    modifier onlyOwner() { require(msg.sender == owner); _; }
    function setOwner(address newOwner) external { owner = newOwner; }
    function sweep(address payable to) external onlyOwner { to.transfer(address(this).balance); }
}
```
Anyone calls `setOwner` with their own address and then `sweep`, because the modifier
that should restrict `setOwner` is missing."""
    WIKI_RECOMMENDATION = (
        "Restrict the function with the same caller check the contract uses for the variable "
        "(an access-control modifier or `require(msg.sender == ...)`)."
    )

    def _detect(self) -> list[Output]:
        results: list[Output] = []
        for contract in self.compilation_unit.contracts_derived:
            for entry, write, reason in _ContractAnalysis(contract).unrestricted_writes():
                info: list = [
                    entry.function,
                    " overwrites privileged state variable ",
                    write.variable,
                    f" ({reason}) without checking the caller:\n\t- ",
                    write.node,
                    "\n",
                ]
                results.append(self.generate_result(info))
        return results


class _ContractAnalysis:
    """Classifies the state of one contract and the entry points that write it."""

    def __init__(self, contract: Contract) -> None:
        self.contract = contract
        self.dataflow = _Dataflow()
        self.authority: set[str] = set()
        self.fund_sinks: set[str] = set()
        self.entry_points = [self._analyse(f) for f in self._writers()]

    def _writers(self) -> list[Function]:
        """Constructors plus every implemented public/external state-mutating function."""
        writers = []
        for function in self.contract.functions:
            if not function.is_implemented or function.is_constructor_variables:
                continue
            if function.is_constructor:
                writers.append(function)
            elif function.visibility in ("public", "external") and not (function.view or function.pure):
                writers.append(function)
        return writers

    def _reachable(self, function: Function, include_modifiers: bool) -> list[_Context]:
        """Every body executed from ``function`` through internal calls, with caller-bound parameters."""
        queue = [_Context(function)]
        seen: set[tuple[int, frozenset[int]]] = set()
        reached: list[_Context] = []
        while queue:
            context = queue.pop()
            key = (id(context.function), context.caller_parameters)
            if key in seen:
                continue
            seen.add(key)
            reached.append(context)
            for node in context.function.nodes:
                for ir in node.irs:
                    if not isinstance(ir, InternalCall) or not isinstance(ir.function, Function):
                        continue
                    if not ir.function.is_implemented:
                        continue
                    if isinstance(ir.function, Modifier) and not include_modifiers:
                        continue
                    bound = frozenset(
                        i for i, argument in enumerate(ir.arguments)
                        if self.dataflow.is_caller(argument, context)
                    )
                    queue.append(_Context(ir.function, bound))
        return reached

    def _analyse(self, function: Function) -> _EntryPoint:
        entry = _EntryPoint(function)
        guard_scope = self._reachable(function, include_modifiers=True)
        for context in guard_scope:
            in_entry_or_modifier = context.function is function or isinstance(context.function, Modifier)
            for node in context.function.nodes:
                self._scan_condition(node, context, entry, in_entry_or_modifier)
                self._scan_fund_sink(node, context)
        for context in self._reachable(function, include_modifiers=False):
            for node in context.function.nodes:
                entry.writes.extend(self._writes_at(node, context))
        entry.one_shot = self._is_one_shot(entry, guard_scope)
        return entry

    def _scan_condition(
        self, node: Node, context: _Context, entry: _EntryPoint, in_entry_or_modifier: bool
    ) -> None:
        guard = _is_guard(node, early_return_guards=in_entry_or_modifier)
        # Helpers such as ``isOwner(address who) returns (who == owner)`` hold the comparison
        # in a return statement; it counts when the helper was handed the caller.
        predicate = node.type == NodeType.RETURN and bool(context.caller_parameters)
        if not (guard or predicate or node.type == NodeType.IF):
            return

        compares_caller = False
        for ir in node.irs:
            compares_caller |= self._is_caller_comparison(ir, node, context)
            if guard and isinstance(ir, Binary) and ir.type in _ORDERING:
                entry.payment_gated |= self._is_payment_comparison(ir, context.function)
            if guard:
                entry.flag_conditions.update(self._bool_state_read(ir, context.function))

        if not compares_caller:
            return
        if guard or predicate:
            entry.caller_checked = True
        elif node.type == NodeType.IF:
            for branch in (node.son_true, node.son_false):
                if branch is not None:
                    entry.caller_branch_nodes.update(
                        n for n in context.function.nodes if branch in n.dominators
                    )

    def _is_caller_comparison(self, ir: Operation, node: Node, context: _Context) -> bool:
        """Whether ``ir`` compares the caller's identity, recording the authority it names."""
        dataflow = self.dataflow
        if isinstance(ir, Binary) and ir.type in _EQUALITY:
            left_is_caller = dataflow.is_caller(ir.variable_left, context)
            right_is_caller = dataflow.is_caller(ir.variable_right, context)
            if left_is_caller == right_is_caller:
                return False
            other = ir.variable_right if left_is_caller else ir.variable_left
            for origin in dataflow.origins(other, context.function):
                if isinstance(origin, StateVariable) and _is_whole_value(origin):
                    self.authority.add(origin.canonical_name)
            return True
        if isinstance(ir, Index) and _returns_bool(ir):
            if not dataflow.is_caller(ir.variable_right, context):
                return False
            target, _ = dataflow.storage_target(ir.lvalue, context)
            if target is not None:
                self.authority.add(target.canonical_name)
            # A deny-list (``require(!blocked[msg.sender])``) is access-control state, so
            # its writers must be guarded, but passing it does not make a caller privileged.
            return not _negated(ir.lvalue, node)
        if isinstance(ir, (InternalCall, HighLevelCall)) and _returns_bool(ir):
            if _negated(ir.lvalue, node) or not _is_read_only_call(ir):
                return False
            return any(dataflow.is_caller(argument, context) for argument in ir.arguments)
        return False

    def _is_payment_comparison(self, ir: Binary, function: Function) -> bool:
        """``msg.value >= price``: the caller buys the write, as in auctions and King-of-the-hill."""
        sides = [self.dataflow.origins(v, function) for v in (ir.variable_left, ir.variable_right)]
        pays = [any(isinstance(o, SolidityVariable) and o.name == "msg.value" for o in s) for s in sides]
        priced = [any(isinstance(o, StateVariable) for o in s) for s in sides]
        return (pays[0] and priced[1]) or (pays[1] and priced[0])

    def _bool_state_read(self, ir: Operation, function: Function) -> Iterable[str]:
        for read in ir.read:
            for origin in self.dataflow.origins(read, function):
                if isinstance(origin, StateVariable) and str(origin.type) == "bool":
                    yield origin.canonical_name

    def _scan_fund_sink(self, node: Node, context: _Context) -> None:
        for ir in node.irs:
            if isinstance(ir, (Transfer, Send)):
                destination = ir.destination
            elif isinstance(ir, LowLevelCall) and ir.call_value is not None:
                destination = ir.destination
            else:
                continue
            for origin in self.dataflow.origins(destination, context.function):
                if isinstance(origin, StateVariable) and _is_whole_value(origin):
                    self.fund_sinks.add(origin.canonical_name)

    def _writes_at(self, node: Node, context: _Context) -> list[_Write]:
        writes = []
        for ir in node.irs:
            if not isinstance(ir, OperationWithLValue) or ir.lvalue is None:
                continue
            if isinstance(ir, (Index, Member)):
                continue  # creates a reference; the write is the operation that assigns through it
            if isinstance(ir.lvalue, LocalVariable):
                continue  # binding ``Account storage a = accounts[x]`` points at storage, writes nothing
            target, keyed_by_caller = self.dataflow.storage_target(ir.lvalue, context)
            if target is None:
                continue
            values = [] if isinstance(ir, Delete) else [r for r in ir.read if r is not ir.lvalue]
            read_modify_write = any(
                self.dataflow.depends_on(v, context.function, target) for v in values
            ) or (not isinstance(ir, (Assignment, Delete)) and any(r is ir.lvalue for r in ir.read))
            constant = ir.rvalue if isinstance(ir, Assignment) and isinstance(ir.rvalue, Constant) else None
            writes.append(_Write(target, node, keyed_by_caller, read_modify_write, constant))
        return writes

    def _is_one_shot(self, entry: _EntryPoint, guard_scope: list[_Context]) -> bool:
        """An initializer latch: the function checks a boolean flag it then sets, and nothing
        ever sets the flag back, so the function can succeed at most once."""
        scope_writes = [w for c in guard_scope for n in c.function.nodes for w in self._writes_at(n, c)]
        for flag in entry.flag_conditions:
            set_here = [w for w in scope_writes if w.variable.canonical_name == flag and w.constant_value is not None]
            if set_here and self._flag_is_monotone(flag, set_here[0].constant_value):
                return True
        return False

    def _flag_is_monotone(self, flag: str, value: Constant) -> bool:
        for function in self.contract.functions_and_modifiers:
            if function.is_constructor or function.is_constructor_variables or not function.is_implemented:
                continue
            context = _Context(function)
            for node in function.nodes:
                for write in self._writes_at(node, context):
                    if write.variable.canonical_name != flag:
                        continue
                    if write.constant_value is None or write.constant_value.value != value.value:
                        return False
        return True

    def _is_guarded(self, entry: _EntryPoint) -> bool:
        return entry.function.is_constructor or entry.caller_checked

    def _admin_set(self, variable: str, writer: _EntryPoint) -> bool:
        """Every other function writing ``variable`` is guarded, and at least one exists."""
        others = [
            (entry, write)
            for entry in self.entry_points
            if entry is not writer
            for write in entry.writes
            if write.variable.canonical_name == variable and not write.keyed_by_caller
        ]
        return bool(others) and all(
            self._is_guarded(entry) or write.node in entry.caller_branch_nodes for entry, write in others
        )

    def _privilege(self, variable: str, writer: _EntryPoint) -> str | None:
        if variable in self.authority:
            return AUTHORITY
        if variable in self.fund_sinks:
            return FUND_SINK
        if self._admin_set(variable, writer):
            return ADMIN_SET
        return None

    @staticmethod
    def _transient_flags(entry: _EntryPoint) -> set[str]:
        """Variables the function sets to two different constants, like a reentrancy lock
        in the body (``locked = true; ...; locked = false``): no lasting change remains."""
        constants: dict[str, set] = {}
        for write in entry.writes:
            if write.constant_value is not None:
                constants.setdefault(write.variable.canonical_name, set()).add(write.constant_value.value)
        return {name for name, values in constants.items() if len(values) > 1}

    def unrestricted_writes(self) -> list[tuple[_EntryPoint, _Write, str]]:
        found = []
        for entry in self.entry_points:
            if self._is_guarded(entry) or entry.payment_gated or entry.one_shot:
                continue
            # One finding per variable; transient flags never get one.
            settled = self._transient_flags(entry)
            for write in entry.writes:
                name = write.variable.canonical_name
                if write.keyed_by_caller or write.read_modify_write or name in settled:
                    continue
                if write.node in entry.caller_branch_nodes:
                    continue
                reason = self._privilege(name, entry)
                if reason is not None:
                    settled.add(name)
                    found.append((entry, write, reason))
        return found

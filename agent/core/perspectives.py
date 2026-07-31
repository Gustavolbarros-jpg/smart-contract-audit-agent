"""Perspective-guided diagnosis, adapted from CodeXplain (ACM TOSEM 10.1145/3765753).

The paper defines nine fixed perspectives and a vulnerability-to-perspective mapping
(its Table 1), so a model examines the aspects of the code where a given class of bug
actually lives instead of reasoning freely. The prompts here are the paper's nine,
rephrased from "explain the code" to "diagnose this finding".

Why this exists: diagnosis used to be keyed by Slither detector name through
``DETERMINISTIC_REPAIR_HINTS`` (six entries). Measured on five real contracts from the
``inverse`` project, 63% of 108 findings had no catalog entry at all, so the model was
asked to diagnose them with no guidance. Perspectives are selected by *category* and,
failing that, by detector-name shape — an unknown detector still gets useful direction.

Selection never blocks: an unrecognized finding falls back to the general-purpose set.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Perspective:
    key: str
    title: str
    instruction: str


PERSPECTIVES: dict[str, Perspective] = {
    "basic_functionality": Perspective(
        "basic_functionality",
        "Basic Functionality Interpretation",
        "State the purpose of the affected function and which callers can reach it. "
        "Identify externally invokable entry points, since those are the attack surface.",
    ),
    "step_by_step": Perspective(
        "step_by_step",
        "Step-by-Step Analysis",
        "Break the affected code into individual operations and evaluate each one for "
        "unchecked assumptions: operand ranges, rounding, ordering and boundary values.",
    ),
    "logic_and_flow": Perspective(
        "logic_and_flow",
        "Logic and Flow Interpretation",
        "Trace execution from entry to exit, including every branch. Determine which "
        "path reaches the faulty statement and what conditions must hold along it.",
    ),
    "state_management": Perspective(
        "state_management",
        "State Management Analysis",
        "Describe how state variables are read and written, and in what order relative "
        "to external calls. Flag state that is modified after control leaves the contract.",
    ),
    "event_function_interaction": Perspective(
        "event_function_interaction",
        "Event and Function Interaction",
        "Check which state changes emit events and which do not, and whether a privileged "
        "action completes without leaving an observable trace.",
    ),
    "error_handling": Perspective(
        "error_handling",
        "Error Handling and Exceptions",
        "Examine how failures are detected and propagated: return values that are ignored, "
        "missing require/revert, and calls whose success is never checked.",
    ),
    "contract_interaction": Perspective(
        "contract_interaction",
        "Contract Interaction Analysis",
        "Analyze calls to other contracts or external addresses: who chooses the target, "
        "what is trusted about the response, and what an adversarial callee could do.",
    ),
    "ownership_access_control": Perspective(
        "ownership_access_control",
        "Ownership and Access Control",
        "Determine which permissions guard the affected function, how the caller identity "
        "is established, and whether any path reaches a privileged effect unguarded.",
    ),
    "gas_efficiency": Perspective(
        "gas_efficiency",
        "Gas Efficiency Examination",
        "Evaluate operations whose cost grows with attacker-influenced input, and whether "
        "that growth can make the function unusable.",
    ),
}

GENERAL_PURPOSE = ("basic_functionality", "logic_and_flow", "state_management")

# CodeXplain Table 1: the fourteen vulnerability classes and the perspectives that
# matter for each. Keys are our internal class names, not Slither detector names.
CLASS_PERSPECTIVES: dict[str, tuple[str, ...]] = {
    "reentrancy": ("state_management", "logic_and_flow", "basic_functionality"),
    "transaction_ordering": ("step_by_step", "logic_and_flow"),
    "timestamp_dependency": ("logic_and_flow", "basic_functionality"),
    "exception_handling": ("error_handling",),
    "integer_overflow": ("step_by_step",),
    "unchecked_send": ("error_handling",),
    "destroyable": ("ownership_access_control", "basic_functionality", "event_function_interaction"),
    "suicidal": ("ownership_access_control", "event_function_interaction", "basic_functionality"),
    "unrestricted_write": ("ownership_access_control", "state_management", "basic_functionality"),
    "unrestricted_transfer": ("ownership_access_control", "basic_functionality"),
    "non_validated_arguments": ("step_by_step", "contract_interaction"),
    "greedy": ("logic_and_flow", "basic_functionality", "event_function_interaction",
               "contract_interaction"),
    "prodigal": ("ownership_access_control", "state_management", "basic_functionality"),
    "gas_costly": ("gas_efficiency",),
    # Beyond the paper's fourteen: Slither reports missing-event detectors often enough
    # in real projects that routing them to access control would be wrong.
    "missing_events": ("event_function_interaction", "state_management"),
    "comparison_logic": ("step_by_step", "logic_and_flow"),
    # Trusted-forwarder / spoofed calldata context reaching a privileged effect.
    "external_context_trust": (
        "contract_interaction",
        "ownership_access_control",
        "logic_and_flow",
    ),
}

# Slither detector -> CodeXplain class, for detectors we have already seen.
DETECTOR_CLASS: dict[str, str] = {
    "reentrancy-eth": "reentrancy",
    "reentrancy-no-eth": "reentrancy",
    "reentrancy-benign": "reentrancy",
    "reentrancy-events": "reentrancy",
    "reentrancy-unlimited-gas": "reentrancy",
    "timestamp": "timestamp_dependency",
    "block-number": "timestamp_dependency",
    "weak-prng": "timestamp_dependency",
    "unchecked-lowlevel": "unchecked_send",
    "unchecked-send": "unchecked_send",
    "unchecked-transfer": "unchecked_send",
    "unused-return": "exception_handling",
    "integer-overflow": "integer_overflow",
    "integer-underflow": "integer_overflow",
    "divide-before-multiply": "integer_overflow",
    "incorrect-equality": "integer_overflow",
    "suicidal": "suicidal",
    "controlled-delegatecall": "destroyable",
    "delegatecall-loop": "destroyable",
    "arbitrary-send-eth": "unrestricted_transfer",
    "arbitrary-send-erc20": "unrestricted_transfer",
    "tx-origin": "unrestricted_write",
    "unprotected-upgrade": "unrestricted_write",
    "unprotected-critical-update": "unrestricted_write",
    "events-access": "missing_events",
    "events-maths": "missing_events",
    "missing-zero-check": "non_validated_arguments",
    "erc2771-multicall-context": "external_context_trust",
    "costly-loop": "gas_costly",
    "calls-loop": "gas_costly",
}

# Applied to the detector name when it is not in DETECTOR_CLASS. Order matters: the
# first matching token wins, so more specific tokens come first.
_NAME_HINTS: tuple[tuple[str, str], ...] = (
    # "reentrancy-events" contains "event", so reentrancy has to be tested first.
    ("reentran", "reentrancy"),
    # "events-access" is a missing *event* on a privileged action, not a missing access
    # check, so event tokens must still come before "access"/"owner".
    ("event", "missing_events"),
    ("boolean", "comparison_logic"),
    ("delegatecall", "destroyable"),
    ("selfdestruct", "suicidal"),
    ("suicid", "suicidal"),
    ("timestamp", "timestamp_dependency"),
    ("block-number", "timestamp_dependency"),
    ("prng", "timestamp_dependency"),
    ("unchecked", "unchecked_send"),
    ("unused-return", "exception_handling"),
    ("send", "unrestricted_transfer"),
    ("transfer", "unrestricted_transfer"),
    ("arbitrary", "unrestricted_transfer"),
    ("overflow", "integer_overflow"),
    ("underflow", "integer_overflow"),
    ("divide", "integer_overflow"),
    ("equality", "integer_overflow"),
    ("shift", "integer_overflow"),
    ("origin", "unrestricted_write"),
    ("access", "unrestricted_write"),
    ("owner", "unrestricted_write"),
    ("auth", "unrestricted_write"),
    ("protected", "unrestricted_write"),
    ("upgrade", "unrestricted_write"),
    ("zero-check", "non_validated_arguments"),
    ("validat", "non_validated_arguments"),
    ("loop", "gas_costly"),
    ("gas", "gas_costly"),
)

# Used when the detector name says nothing; the catalog category still narrows it.
CATEGORY_PERSPECTIVES: dict[str, tuple[str, ...]] = {
    "security": ("ownership_access_control", "state_management", "logic_and_flow"),
    "validation": ("step_by_step", "logic_and_flow"),
    "design_assumption": ("logic_and_flow", "basic_functionality"),
}


def classify_detector(detector: str) -> str:
    """Map a Slither detector name to a CodeXplain class, or "" when unknown."""
    name = (detector or "").strip().lower()
    if not name:
        return ""
    if name in DETECTOR_CLASS:
        return DETECTOR_CLASS[name]
    for token, vuln_class in _NAME_HINTS:
        if token in name:
            return vuln_class
    return ""


def perspectives_for(finding: dict, category: str = "") -> list[str]:
    """Perspective keys for a finding, most specific source first.

    Resolution order: known detector, detector-name shape, catalog category, then the
    general-purpose set. The result is never empty.
    """
    vuln_class = classify_detector(str(finding.get("type", "")))
    if vuln_class:
        return list(CLASS_PERSPECTIVES.get(vuln_class, GENERAL_PURPOSE))

    if category in CATEGORY_PERSPECTIVES:
        return list(CATEGORY_PERSPECTIVES[category])

    return list(GENERAL_PURPOSE)


def render_perspectives(keys: list[str]) -> str:
    """Render perspective instructions as a numbered checklist."""
    lines = []
    for index, key in enumerate(dict.fromkeys(keys), start=1):
        perspective = PERSPECTIVES.get(key)
        if perspective is None:
            continue
        lines.append(f"{index}. {perspective.title}: {perspective.instruction}")
    return "\n".join(lines)


def build_perspective_guidance(
    findings: list[dict],
    categories: dict[str, str] | None = None,
) -> str:
    """Per-finding analysis directives for the diagnosis prompt.

    Returns "" for an empty finding list so the caller can omit the section entirely.
    """
    if not findings:
        return ""

    categories = categories or {}
    blocks = []

    for finding in findings:
        finding_id = str(finding.get("id") or "").strip()
        detector = str(finding.get("type") or "unknown")
        keys = perspectives_for(finding, categories.get(finding_id, ""))
        vuln_class = classify_detector(detector) or "uncategorized"
        header = f"{finding_id or detector} ({detector} -> {vuln_class}):"
        blocks.append(f"{header}\n{render_perspectives(keys)}")

    return "ANALYSIS_PERSPECTIVES\n" + "\n\n".join(blocks)

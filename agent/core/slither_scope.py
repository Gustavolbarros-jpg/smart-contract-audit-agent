"""Restricting Slither output to the file under analysis."""

from __future__ import annotations

from pathlib import Path

from core.contract_choice import _contract_of, is_harness_contract


def scoped_to_file(raw: dict, contract_path: Path) -> dict:
    """Keep only the detectors whose elements live in ``contract_path``.

    Slither analyzes everything the file imports, so each run also reports the imported
    contracts. Counting those per file recounts them for every importer, and after a patch
    it brings the unpatched original back through a cyclic import, so the fix looked
    unresolved. A detector with no source-mapped element is kept: there is nothing to scope by.
    """
    target = str(contract_path.resolve())

    def located_here(detector: dict) -> bool:
        names = [
            element.get("source_mapping", {}).get("filename_absolute")
            for element in detector.get("elements", [])
            if isinstance(element, dict)
        ]
        names = [name for name in names if name]
        return not names or target in names

    scoped = dict(raw)
    scoped["results"] = dict(raw.get("results", {}))
    scoped["results"]["detectors"] = [
        detector for detector in raw.get("results", {}).get("detectors", []) if located_here(detector)
    ]
    return scoped


def without_harness_contracts(raw: dict) -> dict:
    """Drop detectors that only touch test, exploit or mock contracts.

    A tutorial-style file keeps the exploit beside the vulnerable contract, and its own unchecked
    calls would be reported and "fixed" as if they were the product: 12 of 19 reported repairs in
    the DeFiVulnLabs run landed in ContractTest. A detector with no contract named in its
    elements, or with at least one real contract among them, is kept.
    """
    def only_harness(detector: dict) -> bool:
        names = {_contract_of(e) for e in detector.get("elements", []) if isinstance(e, dict)} - {""}
        return bool(names) and all(is_harness_contract(name) for name in names)

    filtered = dict(raw)
    filtered["results"] = dict(raw.get("results", {}))
    filtered["results"]["detectors"] = [
        detector for detector in raw.get("results", {}).get("detectors", []) if not only_harness(detector)
    ]
    return filtered

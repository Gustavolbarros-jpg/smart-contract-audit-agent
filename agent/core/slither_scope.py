"""Restricting Slither output to the file under analysis."""

from __future__ import annotations

from pathlib import Path


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

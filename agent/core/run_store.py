"""Run artifact storage for reproducible pipeline executions."""

from __future__ import annotations

import json
import shutil
from datetime import datetime
from pathlib import Path


def _slug(value: str) -> str:
    allowed = []
    for char in value:
        if char.isalnum() or char in ("-", "_"):
            allowed.append(char)
        else:
            allowed.append("_")
    return "".join(allowed).strip("_")


def create_run_dir(contract_path: str, root: str = "../runs") -> Path:
    contract_name = Path(contract_path).stem
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_name = f"{timestamp}_{_slug(contract_name)}"

    # Second-granularity timestamps collide when two pipeline runs start in the same
    # second (e.g. a mutant sweep where each failure moves to the next mutant almost
    # instantly). Fall back to a numeric suffix instead of crashing on FileExistsError.
    suffix = 0
    while True:
        candidate = Path(root) / (base_name if suffix == 0 else f"{base_name}_{suffix + 1}")
        try:
            candidate.mkdir(parents=True, exist_ok=False)
            return candidate
        except FileExistsError:
            suffix += 1


def save_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2, ensure_ascii=False)


def save_text(path: Path, data: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(data, encoding="utf-8")


def copy_contract(contract_path: str, run_dir: Path) -> None:
    shutil.copy(contract_path, run_dir / "input_contract.sol")


def write_metadata(
    run_dir: Path,
    contract_path: str,
    model: str,
    internal_contract_name: str = "",
) -> None:
    save_json(
        run_dir / "metadata.json",
        {
            "contract_path": contract_path,
            "contract_name": Path(contract_path).stem,
            "internal_contract_name": internal_contract_name or Path(contract_path).stem,
            "model": model,
            "created_at": datetime.now().isoformat(timespec="seconds"),
        },
    )

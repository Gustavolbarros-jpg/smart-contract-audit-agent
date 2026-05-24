"""Command line entry point for the audit pipeline."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

AGENT_DIR = Path(__file__).resolve().parent
REPO_ROOT = AGENT_DIR.parent
CONTRACTS_DIR = REPO_ROOT / "smart-audt" / "contracts"
sys.path.insert(0, str(AGENT_DIR))

from core.contract_registry import contract_entries, contract_groups


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="audit-agent",
        description="Run the Slither -> LLM -> Certora repair pipeline.",
    )
    parser.add_argument(
        "contract_positional",
        nargs="?",
        help="Solidity contract to analyze. Same as --contract.",
    )
    parser.add_argument(
        "--contract",
        help="Solidity contract to analyze.",
    )
    parser.add_argument(
        "--copy-final",
        action="store_true",
        help="Copy the validated *_FIXED.sol file back into smart-audt/contracts.",
    )
    parser.add_argument(
        "--list-contracts",
        action="store_true",
        help="List local Solidity contracts and exit.",
    )
    parser.add_argument(
        "--list-benchmarks",
        action="store_true",
        help="List default benchmark contracts and exit.",
    )
    parser.add_argument(
        "--contract-group",
        choices=["all", *contract_groups()],
        default="all",
        help="With --list-contracts, filter contracts by registry group.",
    )
    parser.add_argument(
        "--max-lines",
        type=int,
        default=0,
        help="With --list-contracts, show only contracts with at most this many lines.",
    )
    return parser


def _line_count(path: Path) -> int:
    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        return sum(1 for _ in handle)


def _list_contracts(max_lines: int = 0, group: str = "all") -> None:
    if not CONTRACTS_DIR.exists():
        print(f"Contracts directory not found: {CONTRACTS_DIR}")
        return

    rows = []
    registered_paths = {
        REPO_ROOT / entry.path: entry
        for entry in contract_entries(group)
    }
    paths = sorted(registered_paths) if group != "all" else sorted(CONTRACTS_DIR.glob("*.sol"))

    for path in paths:
        entry = registered_paths.get(path)
        lines = _line_count(path)
        if max_lines and lines > max_lines:
            continue
        group_label = entry.group if entry else "unregistered"
        rows.append((lines, group_label, path.relative_to(REPO_ROOT)))

    if not rows:
        print("No contracts matched the requested filter.")
        return

    for lines, group_label, relpath in sorted(rows):
        print(f"{lines:4d}  {group_label:11s}  {relpath}")


def _resolve_contract(args: argparse.Namespace) -> Path | None:
    value = args.contract or args.contract_positional
    if not value:
        return None
    path = Path(value)
    if not path.is_absolute():
        path = (Path.cwd() / path).resolve()
    return path


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.list_contracts or args.list_benchmarks:
        group = "benchmark" if args.list_benchmarks else args.contract_group
        _list_contracts(args.max_lines, group)
        return 0

    contract_path = _resolve_contract(args)
    if not contract_path:
        parser.print_help()
        print("\nLocal small contracts:")
        _list_contracts(max_lines=45)
        return 2

    if not contract_path.exists():
        print(f"Contract not found: {contract_path}")
        return 1

    os.chdir(AGENT_DIR)

    from orchestrator import executar_pipeline

    executar_pipeline(str(contract_path), copy_final=args.copy_final)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

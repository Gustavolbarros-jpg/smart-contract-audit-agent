"""Generate a Markdown summary from existing run artifacts."""

from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path


AGENT_DIR = Path(__file__).resolve().parent
REPO_ROOT = AGENT_DIR.parent
sys.path.insert(0, str(AGENT_DIR))

from core.contract_registry import default_benchmark_contracts
from core.evaluation import render_markdown, summarize_contracts


def _timestamped_output_path() -> Path:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    return REPO_ROOT / "docs" / "evaluations" / f"evaluation-results-{timestamp}.md"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Summarize audit pipeline runs.")
    parser.add_argument("--contracts", nargs="*", default=None)
    parser.add_argument(
        "--include-exploratory",
        action="store_true",
        help="When --contracts is omitted, include exploratory contracts after the core benchmark suite.",
    )
    parser.add_argument("--runs-root", default=str(REPO_ROOT / "runs"))
    parser.add_argument(
        "--output",
        default="",
        help="Optional explicit output path. By default a timestamped report is created.",
    )
    args = parser.parse_args(argv)

    contracts = args.contracts
    if contracts is None:
        contracts = default_benchmark_contracts(include_exploratory=args.include_exploratory)

    rows = summarize_contracts(Path(args.runs_root), contracts)
    if args.output:
        output = Path(args.output)
    else:
        output = _timestamped_output_path()
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(render_markdown(rows), encoding="utf-8")
    print(f"Wrote {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

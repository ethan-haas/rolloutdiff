"""CLI entry point: `python -m rolloutdiff <before> <after>`.

No network, no kubeconfig, no cluster contact — text in (files/dirs on
local disk), text (JSON) out.
"""
from __future__ import annotations

import sys
from typing import List, Optional

from . import coverage_table, self_check
from .differ import diff_all
from .errors import MalformedInputError
from .loader import load_docs
from .reporter import build_report, exit_code_for, render_json


def run(argv: List[str]) -> int:
    if len(argv) != 2:
        sys.stderr.write("usage: python -m rolloutdiff <before-path> <after-path>\n")
        return 2

    before_path, after_path = argv
    try:
        before_objs = load_docs(before_path)
        after_objs = load_docs(after_path)
    except MalformedInputError as exc:
        sys.stderr.write(f"rolloutdiff: malformed input: {exc}\n")
        return 2

    findings = diff_all(before_objs, after_objs)

    coverage_quality = self_check.compute_corpus_rates()
    table_meta = {
        "version": coverage_table.COVERAGE_TABLE_VERSION,
        "source": coverage_table.COVERAGE_TABLE_SOURCE,
        "kinds_covered": sorted(f"{g}/{k}" if g else k for (g, k) in coverage_table.KIND_TABLE),
    }
    report = build_report(findings, coverage_quality, table_meta)
    sys.stdout.write(render_json(report))
    sys.stdout.write("\n")
    return exit_code_for(findings)


def main(argv: Optional[List[str]] = None) -> int:
    return run(sys.argv[1:] if argv is None else argv)


if __name__ == "__main__":
    sys.exit(main())

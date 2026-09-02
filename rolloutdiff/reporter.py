"""Component 5: Reporter + exit codes.

Produces stable, sorted, deterministic JSON to stdout. Three first-class
numbers are always present, kept separate (never averaged/blended):

  unknown_rate      — of THIS run's findings, what fraction fell through the
                       coverage table to 'unknown'. Directly measurable per
                       run; the honest-coverage signal the spec asks not to
                       hide.
  detection_rate,
  false_flag_rate   — these require KNOWN ground truth (a planted change /
                       a known no-op) which an arbitrary live before/after
                       pair does not carry. Rather than fabricate a number
                       for the live pair, we compute both FRESH on every
                       invocation by running the bundled synthetic corpus
                       (rolloutdiff/corpus.py) through this same diff engine
                       and comparing to its recorded expected labels — a
                       real, reproducible measurement, not a hardcoded
                       constant, reported as the tool's self-check
                       "coverage_quality" alongside the live diff.

Exit codes: 0 = no findings above the declared floor (see FLOOR below);
            1 = findings at/above the floor;
            2 = malformed input/usage (raised before reporting is reached).
"""
from __future__ import annotations

import json
from typing import List

from .differ import Finding

# The declared floor: 'no-op' findings never occur in the findings list
# (the differ does not emit a finding for a normalized-equal field), so any
# finding present is, by construction, at or above the floor. FLOOR exists
# as a named constant so this policy is a single documented decision rather
# than an implicit assumption buried in exit-code logic.
FLOOR_CLASSIFICATIONS_THAT_DONT_COUNT = {"no-op"}


def compute_unknown_rate(findings: List[Finding]) -> float:
    if not findings:
        return 0.0
    unknown = sum(1 for f in findings if f.classification == "unknown")
    return unknown / len(findings)


def findings_above_floor(findings: List[Finding]) -> List[Finding]:
    return [f for f in findings if f.classification not in FLOOR_CLASSIFICATIONS_THAT_DONT_COUNT]


def build_report(findings: List[Finding], coverage_quality: dict, table_meta: dict) -> dict:
    sorted_findings = sorted(
        findings,
        key=lambda f: (f.object_ref, f.field_path, f.classification),
    )
    report = {
        "coverage_table": table_meta,
        "findings": [f.to_dict() for f in sorted_findings],
        "summary": {
            "total_findings": len(sorted_findings),
            "unknown_rate": round(compute_unknown_rate(sorted_findings), 6),
            "classification_counts": _counts(sorted_findings),
        },
        "coverage_quality": coverage_quality,
    }
    return report


def _counts(findings: List[Finding]) -> dict:
    counts: dict = {}
    for f in findings:
        counts[f.classification] = counts.get(f.classification, 0) + 1
    return dict(sorted(counts.items()))


def render_json(report: dict) -> str:
    # sort_keys + fixed separators -> byte-identical across processes/seeds
    return json.dumps(report, sort_keys=True, indent=2, separators=(",", ": "))


def exit_code_for(findings: List[Finding]) -> int:
    return 1 if findings_above_floor(findings) else 0

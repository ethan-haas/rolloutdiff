"""Fresh, real measurement of detection_rate / false_flag_rate against the
bundled synthetic corpus (rolloutdiff/corpus.py), run on every CLI
invocation (and by the test suite). Not a hardcoded number: this actually
runs the differ against the corpus and compares to the corpus's own
recorded expected labels.

detection_rate    = planted, non-no-op cases correctly classified /
                     total planted, non-no-op cases
false_flag_rate   = no-op-corpus pairs that produced >=1 non-no-op finding /
                     total no-op-corpus pairs
"""
from __future__ import annotations

from typing import Dict, List

from . import corpus
from .differ import diff_all
from .loader import object_ref_for
from .path_resolve import resolve_field_path


def _ref_for(doc: dict) -> tuple:
    return object_ref_for(doc, "<corpus>")


def check_planted_case(case: "corpus.PlantedCase") -> Dict:
    ref = _ref_for(case.before)
    before_map = {ref: case.before}
    after_map = {ref: case.after}
    findings = diff_all(before_map, after_map)

    if case.verdict == "no-op":
        ok = len(findings) == 0
        return {"id": case.id, "ok": ok, "findings": len(findings)}

    matching = [f for f in findings if f.classification == case.verdict]
    path_ok = False
    for f in matching:
        if f.field_path == case.expected_field_path_prefix or f.field_path.startswith(
            case.expected_field_path_prefix
        ):
            doc_to_check = case.after if case.after is not None else case.before
            found, _ = resolve_field_path(doc_to_check, f.field_path)
            if found:
                path_ok = True
                break
    ok = len(matching) > 0 and path_ok
    return {"id": case.id, "ok": ok, "findings": len(findings), "matching": len(matching)}


def check_noop_case(case: "corpus.NoopCase") -> Dict:
    ref = _ref_for(case.before)
    before_map = {ref: case.before}
    after_map = {ref: case.after}
    findings = diff_all(before_map, after_map)
    false_flagged = len(findings) > 0
    return {"id": case.id, "false_flagged": false_flagged, "findings": len(findings)}


def compute_corpus_rates() -> Dict:
    planted = corpus.build_planted_corpus()
    noop = corpus.build_noop_corpus()

    planted_results = [check_planted_case(c) for c in planted]
    noop_results = [check_noop_case(c) for c in noop]

    non_noop_planted = [r for r, c in zip(planted_results, planted) if c.verdict != "no-op"]
    n_non_noop = len(non_noop_planted)
    n_correct = sum(1 for r in non_noop_planted if r["ok"])
    detection_rate = (n_correct / n_non_noop) if n_non_noop else 0.0

    n_noop = len(noop_results)
    n_false_flagged = sum(1 for r in noop_results if r["false_flagged"])
    false_flag_rate = (n_false_flagged / n_noop) if n_noop else 0.0

    return {
        "detection_rate": round(detection_rate, 6),
        "false_flag_rate": round(false_flag_rate, 6),
        "planted_cases_total": len(planted),
        "planted_non_noop_correct": n_correct,
        "planted_non_noop_total": n_non_noop,
        "noop_cases_total": n_noop,
        "noop_cases_false_flagged": n_false_flagged,
        "note": (
            "detection_rate/false_flag_rate are measured FRESH on this "
            "invocation against the bundled synthetic corpus "
            "(rolloutdiff/corpus.py) via rolloutdiff/self_check.py — not "
            "hardcoded constants."
        ),
    }

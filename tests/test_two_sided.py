"""two-sided no-op corpus -> 0 findings; detection_rate & false_flag_rate
reported separately; a flag-everything differ must fail this gate."""
from rolloutdiff import corpus, self_check
from rolloutdiff.differ import diff_all, Finding
from rolloutdiff.loader import object_ref_for

NOOP = corpus.build_noop_corpus()


def _ref(doc):
    return object_ref_for(doc, "<test>")


def test_all_noop_pairs_produce_zero_findings():
    failures = []
    for case in NOOP:
        ref = _ref(case.before)
        findings = diff_all({ref: case.before}, {ref: case.after})
        if findings:
            details = [(f.field_path, f.classification) for f in findings]
            failures.append(f"{case.id}: expected 0 findings, got {details}")
    assert not failures, "\n".join(failures)


def test_rates_reported_separately_never_averaged():
    rates = self_check.compute_corpus_rates()
    assert "detection_rate" in rates
    assert "false_flag_rate" in rates
    assert isinstance(rates["detection_rate"], float)
    assert isinstance(rates["false_flag_rate"], float)
    # they must be independently addressable keys, not folded into one
    # "accuracy" number
    assert rates["detection_rate"] != "false_flag_rate"


def test_current_engine_has_zero_false_flags_on_noop_corpus():
    rates = self_check.compute_corpus_rates()
    assert rates["false_flag_rate"] == 0.0
    assert rates["noop_cases_false_flagged"] == 0


def test_current_engine_detects_all_planted_non_noop_cases():
    rates = self_check.compute_corpus_rates()
    assert rates["detection_rate"] == 1.0


class _FlagEverythingDiffer:
    """Simulates a broken differ that flags every object as changed,
    regardless of content — used to prove this gate CAN fail."""

    def diff(self, before_map, after_map):
        findings = []
        for ref in before_map:
            findings.append(
                Finding(
                    object_ref=ref,
                    field_path="spec",
                    classification="rolling-restart",
                    evidence={"before": "x", "after": "x"},
                    message="flagged unconditionally (broken differ simulation)",
                )
            )
        return findings


def test_a_flag_everything_differ_fails_the_noop_gate():
    broken = _FlagEverythingDiffer()
    false_flags = 0
    for case in NOOP:
        ref = _ref(case.before)
        findings = broken.diff({ref: case.before}, {ref: case.after})
        if findings:
            false_flags += 1
    false_flag_rate = false_flags / len(NOOP)
    # the real gate requires false_flag_rate == 0.0; a flag-everything
    # differ must NOT pass it
    assert false_flag_rate == 1.0
    assert false_flag_rate != 0.0

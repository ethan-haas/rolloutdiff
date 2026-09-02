"""every planted pair -> correct classification AND resolvable field_path."""
from rolloutdiff import corpus
from rolloutdiff.differ import diff_all
from rolloutdiff.loader import object_ref_for
from rolloutdiff.path_resolve import resolve_field_path

PLANTED = corpus.build_planted_corpus()


def _ref(doc):
    return object_ref_for(doc, "<test>")


def test_at_least_eight_verdict_classes_covered():
    verdicts = {c.verdict for c in PLANTED}
    expected = {
        "no-op", "in-place", "rolling-restart", "recreate", "data-loss",
        "disruption", "privilege-change", "unknown",
    }
    assert expected.issubset(verdicts), f"missing verdicts: {expected - verdicts}"


def test_each_planted_case_classifies_correctly_and_resolves():
    failures = []
    for case in PLANTED:
        ref = _ref(case.before)
        findings = diff_all({ref: case.before}, {ref: case.after})

        if case.verdict == "no-op":
            if findings:
                failures.append(f"{case.id}: expected no findings, got {len(findings)}")
            continue

        matches = [f for f in findings if f.classification == case.verdict]
        if not matches:
            got = sorted({f.classification for f in findings})
            failures.append(f"{case.id}: expected verdict {case.verdict!r}, got classifications {got}")
            continue

        resolvable = []
        for f in matches:
            doc_to_check = case.after if case.after is not None else case.before
            found, _ = resolve_field_path(doc_to_check, f.field_path)
            resolvable.append(found)
        if not any(resolvable):
            failures.append(f"{case.id}: no matching finding had a resolvable field_path")

    assert not failures, "\n".join(failures)


def test_expected_field_path_prefix_itself_resolves_in_after_doc():
    """Sanity: the corpus's own recorded expected path is not a typo."""
    for case in PLANTED:
        if case.verdict == "no-op":
            continue
        doc = case.after if case.after is not None else case.before
        found, _ = resolve_field_path(doc, case.expected_field_path_prefix)
        assert found, f"{case.id}: expected_field_path_prefix {case.expected_field_path_prefix!r} does not resolve"

"""the classifier can go red. Positive control: mutate a rule, the
gate must fail. Proves G3's immutability assertion is not an inert probe."""
import copy

from rolloutdiff import coverage_table, corpus
from rolloutdiff.differ import classify_path


def test_mutating_the_selector_rule_makes_the_immutability_check_fail():
    snapshot = copy.deepcopy(coverage_table.KIND_TABLE)
    try:
        corpus.mutate_table_to_break_immutability_rule(coverage_table.KIND_TABLE)

        cls, _note = classify_path(("apps", "Deployment", "prod", "x"), "spec.selector")
        # This is the mutated (WRONG) behavior the gate must reject:
        assert cls == "in-place", "sanity: mutation did not take effect as expected"

        # Reproduce G3's real assertion against the now-corrupted table --
        # it must FAIL (i.e. NOT be in the non-in-place set), proving the
        # gate is a live check, not an inert probe.
        NON_IN_PLACE_CLASSES = {"recreate", "data-loss", "privilege-change", "disruption"}
        gate_would_pass = cls in NON_IN_PLACE_CLASSES
        assert gate_would_pass is False, (
            "G3's immutability gate did not go red under a known-bad "
            "mutation -- the check cannot fail, so it proves nothing"
        )
    finally:
        coverage_table.KIND_TABLE.clear()
        coverage_table.KIND_TABLE.update(snapshot)

    # confirm restoration: the real gate passes again post-restore
    cls_restored, _ = classify_path(("apps", "Deployment", "prod", "x"), "spec.selector")
    assert cls_restored != "in-place"

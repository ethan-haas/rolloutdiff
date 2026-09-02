"""regression for the mis-declared coverage-table entry found by the
an independent review -- StatefulSet spec.podManagementPolicy was
classified 'in-place' but the field is IMMUTABLE on apps/v1 StatefulSet (the
API server only accepts in-place updates to spec.replicas, spec.template,
spec.updateStrategy, spec.persistentVolumeClaimRetentionPolicy, and
spec.minReadySeconds -- everything else in spec requires delete+recreate).

Covers:
  - podManagementPolicy change classifies 'recreate' with a resolvable
    field_path, end to end through diff_all.
  - control: a genuinely mutable field (spec.replicas, scaled up) keeps its
    correct 'in-place' verdict -- proves the fix did not overcorrect.
  - control: spec.updateStrategy (mutable) stays out of 'recreate'.
  - sweep: no immutable StatefulSet spec field in the declared table
    classifies 'in-place'.
"""
import copy

from rolloutdiff import corpus
from rolloutdiff.differ import classify_path, diff_all
from rolloutdiff.loader import object_ref_for

STS_KIND_KEY = ("apps", "StatefulSet")

# Per apps/v1 StatefulSet immutability: only these spec fields accept an
# in-place update. Everything else under spec is immutable.
_MUTABLE_STS_SPEC_FIELDS = {
    "spec.replicas",
    "spec.template",
    "spec.updateStrategy",
    "spec.persistentVolumeClaimRetentionPolicy",
    "spec.minReadySeconds",
}

# Every StatefulSet spec field this repo's coverage table declares, so the
# sweep below is exhaustive over what's actually in the table (not just the
# one field review flagged).
_DECLARED_STS_SPEC_FIELDS = [
    "spec.replicas",
    "spec.serviceName",
    "spec.selector",
    "spec.volumeClaimTemplates",
    "spec.updateStrategy",
    "spec.podManagementPolicy",
]

NON_IN_PLACE_CLASSES = {"recreate", "data-loss", "privilege-change", "disruption"}


def test_podmanagementpolicy_change_classifies_recreate_end_to_end():
    before = corpus.base_statefulset()
    after = copy.deepcopy(before)
    after["spec"]["podManagementPolicy"] = "Parallel"
    before["spec"]["podManagementPolicy"] = "OrderedReady"

    ref = object_ref_for(before, "<test>")
    findings = diff_all({ref: before}, {ref: after})

    matches = [f for f in findings if f.field_path == "spec.podManagementPolicy"]
    assert len(matches) == 1, (
        f"expected exactly one finding resolvable at spec.podManagementPolicy, got {findings}"
    )
    finding = matches[0]
    assert finding.classification == "recreate", (
        f"spec.podManagementPolicy is immutable on StatefulSet; expected 'recreate', "
        f"got {finding.classification!r}"
    )
    # field_path must resolve concretely (spec section: field_path always
    # resolves into the supplied structure) -- not a generic/pattern path.
    node = after
    for part in finding.field_path.split("."):
        node = node[part]
    assert node == "Parallel"


def test_podmanagementpolicy_unit_classification_is_recreate():
    cls, note = classify_path(STS_KIND_KEY + ("prod", "db"), "spec.podManagementPolicy")
    assert cls == "recreate"
    assert "immutable" in note.lower()


def test_control_replicas_scale_up_stays_in_place():
    """Control: spec.replicas IS mutable on StatefulSet (server just
    adds/removes ordinal pods). Scaling UP (not to zero) must stay the
    correct 'in-place' verdict -- proves the podManagementPolicy fix did not
    overcorrect the whole spec to 'recreate'."""
    before = corpus.base_statefulset()
    after = copy.deepcopy(before)
    before["spec"]["replicas"] = 3
    after["spec"]["replicas"] = 5

    ref = object_ref_for(before, "<test>")
    findings = diff_all({ref: before}, {ref: after})

    matches = [f for f in findings if f.field_path == "spec.replicas"]
    assert len(matches) == 1
    assert matches[0].classification == "in-place", (
        f"spec.replicas is mutable on StatefulSet; scale-up (non-zero) should stay "
        f"'in-place', got {matches[0].classification!r}"
    )


def test_control_updatestrategy_change_is_not_recreate():
    """Control: spec.updateStrategy IS in the API server's mutable-field
    allowlist for StatefulSet; it must never classify 'recreate'."""
    cls, _note = classify_path(STS_KIND_KEY + ("prod", "db"), "spec.updateStrategy")
    assert cls != "recreate"
    assert cls == "in-place"


def test_no_immutable_sts_spec_field_classifies_in_place():
    """Sweep every StatefulSet spec field this repo declares: any field NOT
    in the API server's mutable allowlist must never classify 'in-place'."""
    failures = []
    for path in _DECLARED_STS_SPEC_FIELDS:
        cls, _note = classify_path(STS_KIND_KEY + ("prod", "db"), path)
        is_mutable = path in _MUTABLE_STS_SPEC_FIELDS
        if not is_mutable and cls not in NON_IN_PLACE_CLASSES:
            failures.append(
                f"{path}: immutable per apps/v1 StatefulSet API, but classified "
                f"{cls!r} (expected one of {NON_IN_PLACE_CLASSES})"
            )
        if is_mutable and cls not in ("in-place",) and path != "spec.template":
            # spec.template is mutable but correctly classifies
            # 'rolling-restart' (a distinct, non-'recreate' category), so it
            # is excluded from this half of the check.
            failures.append(
                f"{path}: mutable per apps/v1 StatefulSet API, but classified "
                f"{cls!r} (expected 'in-place')"
            )
    assert not failures, "\n".join(failures)

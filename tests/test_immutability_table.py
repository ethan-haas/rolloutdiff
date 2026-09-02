"""immutability table tested; a genuinely-immutable field change must
never classify 'in-place'; an unknown CRD must NOT silently become
'no-op' (asserts unknown != no-op)."""
import copy

from rolloutdiff import coverage_table, corpus
from rolloutdiff.differ import classify_path, diff_all
from rolloutdiff.loader import object_ref_for

IMMUTABLE_FIELDS = [
    # (kind_key, field_path, description)
    (("apps", "Deployment"), "spec.selector", "Deployment selector is immutable"),
    (("apps", "StatefulSet"), "spec.serviceName", "StatefulSet serviceName is immutable"),
    (("apps", "StatefulSet"), "spec.selector", "StatefulSet selector is immutable"),
    (("", "Service"), "spec.clusterIP", "Service clusterIP is immutable"),
    (("", "PersistentVolumeClaim"), "spec.accessModes", "PVC accessModes immutable after binding"),
    (("", "PersistentVolumeClaim"), "spec.volumeName", "PVC volumeName immutable after binding"),
    (("", "Secret"), "type", "Secret.type is immutable"),
    (("batch", "Job"), "spec.template", "Job pod template is immutable"),
]

NON_IN_PLACE_CLASSES = {"recreate", "data-loss", "privilege-change", "disruption"}


def test_immutable_fields_never_classify_in_place():
    failures = []
    for kind_key, path, desc in IMMUTABLE_FIELDS:
        cls, _note = classify_path(kind_key + ("prod", "x"), path)
        if cls not in NON_IN_PLACE_CLASSES:
            failures.append(f"{kind_key}/{path} ({desc}): classified {cls!r}, expected one of {NON_IN_PLACE_CLASSES}")
    assert not failures, "\n".join(failures)


def test_table_carries_source_and_version():
    assert coverage_table.COVERAGE_TABLE_VERSION
    assert coverage_table.COVERAGE_TABLE_SOURCE
    assert "k8s" in coverage_table.COVERAGE_TABLE_VERSION.lower() or "kubernetes" in coverage_table.COVERAGE_TABLE_SOURCE.lower()


def test_unknown_kind_never_becomes_no_op():
    """A kind absent from the table, with a real semantic field change, must
    classify unknown -- and must NEVER be silently dropped/treated as no-op
    (the exact fail-unsafe bug the SPEC calls out)."""
    crd = corpus.base_unknown_crd()
    crd_after = copy.deepcopy(crd)
    crd_after["spec"]["maxWidgets"] = 999

    ref = object_ref_for(crd, "<test>")
    findings = diff_all({ref: crd}, {ref: crd_after})

    assert len(findings) >= 1, "unknown-CRD field change produced NO finding at all -- this is the fail-unsafe bug"
    classes = {f.classification for f in findings}
    assert "no-op" not in classes
    assert classes == {"unknown"}, f"expected only 'unknown', got {classes}"


def test_unknown_kind_whole_object_added_is_unknown_not_noop():
    crd = corpus.base_unknown_crd()
    ref = object_ref_for(crd, "<test>")
    findings = diff_all({}, {ref: crd})
    assert len(findings) == 1
    assert findings[0].classification == "unknown"


def test_a_kind_not_in_table_has_no_rules_entry_by_construction():
    """Sanity check on the table itself: the deliberately-unknown test kind
    used across this suite (WidgetPolicy) really is absent."""
    assert ("example.com", "WidgetPolicy") not in coverage_table.KIND_TABLE

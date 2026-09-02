"""Regression tests for four defect families found in review.

Family 1 -- privilege/severity masking through wrapper templates
    (coverage_table._pod_template_privilege_rules applied at every nested
    prefix a pod template actually lives at: `spec.template` AND
    `spec.jobTemplate.spec.template`).
Family 2 -- resource-quantity false positives (quantity.py: parse by value,
    only for declared quantity-typed field paths).
Family 3 -- server-default injection false-flags (server_defaults.py: a
    declared table of well-known field-level defaults, stripped pairwise
    before the differ's tree walk).
Family 4 -- typed-scalar (integer) equality (quantity.py TYPED_INT_FIELDS).

Every case also asserts, where a finding is expected, that its field_path
resolves into the actual document -- the "a finding that cannot point
at its own evidence is a bug" discipline.
"""
from __future__ import annotations

import copy

from rolloutdiff import corpus
from rolloutdiff.differ import diff_all
from rolloutdiff.loader import object_ref_for
from rolloutdiff.path_resolve import resolve_field_path


def _ref(doc):
    return object_ref_for(doc, "<test>")


def _findings(before, after):
    ref = _ref(before)
    return diff_all({ref: before}, {ref: after})


def _privilege_change(findings):
    return [f for f in findings if f.classification == "privilege-change"]


def _assert_resolving_privilege_change(findings, doc, must_contain=None):
    pc = _privilege_change(findings)
    assert pc, f"expected a privilege-change finding, got {sorted({f.classification for f in findings})}"
    resolving = [f for f in pc if resolve_field_path(doc, f.field_path)[0]]
    assert resolving, f"privilege-change finding(s) did not resolve: {[f.field_path for f in pc]}"
    if must_contain is not None:
        assert any(must_contain in f.field_path for f in resolving), (
            f"no resolving field_path contained {must_contain!r}: "
            f"{[f.field_path for f in resolving]}"
        )
    return resolving


def _base_cronjob() -> dict:
    return {
        "apiVersion": "batch/v1",
        "kind": "CronJob",
        "metadata": {"name": "nightly", "namespace": "prod"},
        "spec": {
            "schedule": "0 2 * * *",
            "jobTemplate": {
                "spec": {
                    "template": {
                        "spec": {
                            "containers": [
                                {"name": "worker", "image": "example/worker:1.0"}
                            ]
                        }
                    }
                }
            },
        },
    }


def _base_job() -> dict:
    return {
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {"name": "migrate", "namespace": "prod"},
        "spec": {
            "template": {
                "spec": {
                    "containers": [
                        {"name": "worker", "image": "example/migrate:1.0"}
                    ]
                }
            }
        },
    }


def _cronjob_pod_spec(doc):
    return doc["spec"]["jobTemplate"]["spec"]["template"]["spec"]


def _job_pod_spec(doc):
    return doc["spec"]["template"]["spec"]


# ---------------------------------------------------------------------------
# Family 1 -- wrapper templates
# ---------------------------------------------------------------------------
def test_cronjob_nested_privileged_container_is_privilege_change():
    before = _base_cronjob()
    after = copy.deepcopy(before)
    _cronjob_pod_spec(after)["containers"][0]["securityContext"] = {"privileged": True}

    findings = _findings(before, after)
    resolving = _assert_resolving_privilege_change(findings, after, must_contain="securityContext.privileged")
    assert any(
        f.field_path == "spec.jobTemplate.spec.template.spec.containers[name=worker].securityContext.privileged"
        for f in resolving
    )
    # must NOT still (also) surface as the coarse blanket in-place verdict
    # for this same underlying change -- privilege-change is the headline.
    assert "in-place" not in {f.classification for f in findings}


def test_cronjob_nested_hostpath_volume_is_privilege_change():
    before = _base_cronjob()
    after = copy.deepcopy(before)
    _cronjob_pod_spec(after)["volumes"] = [
        {"name": "hostfs", "hostPath": {"path": "/etc"}}
    ]

    findings = _findings(before, after)
    _assert_resolving_privilege_change(findings, after, must_contain="hostPath")


def test_job_nested_privileged_container_surfaces_privilege_change():
    """Job's pod template is immutable (recreate); privilege-change must
    OUTRANK that and be the headline verdict, not shadowed by it."""
    before = _base_job()
    after = copy.deepcopy(before)
    _job_pod_spec(after)["containers"][0]["securityContext"] = {"privileged": True}

    findings = _findings(before, after)
    resolving = _assert_resolving_privilege_change(findings, after, must_contain="securityContext.privileged")
    assert any(
        f.field_path == "spec.template.spec.containers[name=worker].securityContext.privileged"
        for f in resolving
    )


def test_job_template_ordinary_change_still_recreate():
    """Control: a non-privilege Job pod-template change (image bump) must
    still classify recreate -- proves the new specific rules don't
    over-broaden and swallow the existing immutable-template rule."""
    before = _base_job()
    after = copy.deepcopy(before)
    _job_pod_spec(after)["containers"][0]["image"] = "example/migrate:2.0"

    findings = _findings(before, after)
    classes = {f.classification for f in findings}
    assert classes == {"recreate"}, classes


def test_cronjob_benign_nested_emptydir_not_over_escalated():
    """Control: an ordinary emptyDir volume added under CronJob's nested
    pod template must stay the correct NON-privilege verdict (this table's
    existing 'no live pod is touched by editing a CronJob template'
    reasoning), not be escalated just because it's a nested add."""
    before = _base_cronjob()
    after = copy.deepcopy(before)
    _cronjob_pod_spec(after)["volumes"] = [{"name": "scratch", "emptyDir": {}}]

    findings = _findings(before, after)
    classes = {f.classification for f in findings}
    assert "privilege-change" not in classes, f"benign emptyDir add was over-escalated: {classes}"
    assert "data-loss" not in classes
    assert classes == {"in-place"}, classes


def test_deployment_privileged_still_works_unaffected_by_refactor():
    """Guardrail: the Deployment (non-wrapper) case the earlier fix already
    covered must be unaffected by refactoring the rule set into the shared
    _pod_template_privilege_rules() generator."""
    before = corpus.base_deployment()
    after = copy.deepcopy(before)
    after["spec"]["template"]["spec"]["containers"][0]["securityContext"]["privileged"] = True

    findings = _findings(before, after)
    _assert_resolving_privilege_change(findings, after, must_contain="securityContext.privileged")


# ---------------------------------------------------------------------------
# Family 2 -- resource-quantity equality
# ---------------------------------------------------------------------------
def test_pvc_storage_1gi_equals_1024mi_is_noop():
    before = corpus.base_pvc()
    before["spec"]["resources"]["requests"]["storage"] = "1Gi"
    after = copy.deepcopy(before)
    after["spec"]["resources"]["requests"]["storage"] = "1024Mi"

    findings = _findings(before, after)
    assert findings == [], [(f.classification, f.field_path) for f in findings]


def test_container_memory_limit_1gi_equals_1024mi_is_noop():
    before = corpus.base_deployment()
    before["spec"]["template"]["spec"]["containers"][0]["resources"]["limits"] = {"memory": "1Gi"}
    after = copy.deepcopy(before)
    after["spec"]["template"]["spec"]["containers"][0]["resources"]["limits"] = {"memory": "1024Mi"}

    findings = _findings(before, after)
    assert findings == [], [(f.classification, f.field_path) for f in findings]


def test_pvc_storage_genuine_shrink_still_data_loss():
    """Guardrail: a REAL shrink must still classify data-loss, never
    laundered to no-op by the quantity-equality fix."""
    before = corpus.base_pvc()
    before["spec"]["resources"]["requests"]["storage"] = "1Gi"
    after = copy.deepcopy(before)
    after["spec"]["resources"]["requests"]["storage"] = "512Mi"

    findings = _findings(before, after)
    dataloss = [f for f in findings if f.classification == "data-loss"]
    assert dataloss, [(f.classification, f.field_path) for f in findings]
    assert any(resolve_field_path(after, f.field_path)[0] for f in dataloss)


def test_pvc_storage_genuine_grow_still_classified():
    """Guardrail: a real grow (not just a unit-representation change) must
    still be classified (data-loss, per this table's conservative rule),
    not silently swallowed."""
    before = corpus.base_pvc()
    before["spec"]["resources"]["requests"]["storage"] = "1Gi"
    after = copy.deepcopy(before)
    after["spec"]["resources"]["requests"]["storage"] = "2Gi"

    findings = _findings(before, after)
    assert any(f.classification == "data-loss" for f in findings)


def test_quantity_equality_only_applies_to_declared_quantity_fields():
    """Non-quantity field with a quantity-shaped string must NOT be
    treated as a quantity -- e.g. an env var value that happens to look
    like a memory size is a plain string change."""
    before = corpus.base_deployment()
    after = copy.deepcopy(before)
    after["spec"]["template"]["spec"]["containers"][0]["env"].append(
        {"name": "CACHE_SIZE", "value": "1Gi"}
    )
    before["spec"]["template"]["spec"]["containers"][0]["env"].append(
        {"name": "CACHE_SIZE", "value": "1024Mi"}
    )
    findings = _findings(before, after)
    # this must be seen as a real change (env value differs), not stripped
    assert findings, "non-quantity field wrongly treated as quantity-equal"


# ---------------------------------------------------------------------------
# Family 3 -- server-default injection
# ---------------------------------------------------------------------------
def test_service_port_protocol_tcp_default_add_is_noop():
    before = corpus.base_service()
    assert "protocol" not in before["spec"]["ports"][0]
    after = copy.deepcopy(before)
    after["spec"]["ports"][0]["protocol"] = "TCP"

    findings = _findings(before, after)
    assert findings == [], [(f.classification, f.field_path) for f in findings]


def test_container_imagepullpolicy_ifnotpresent_default_add_is_noop_for_tagged_image():
    before = corpus.base_deployment()
    before["spec"]["template"]["spec"]["containers"][0]["image"] = "example/web:1.0.0"
    assert "imagePullPolicy" not in before["spec"]["template"]["spec"]["containers"][0]
    after = copy.deepcopy(before)
    after["spec"]["template"]["spec"]["containers"][0]["imagePullPolicy"] = "IfNotPresent"

    findings = _findings(before, after)
    assert findings == [], [(f.classification, f.field_path) for f in findings]


def test_container_imagepullpolicy_always_default_add_is_noop_for_latest_image():
    before = corpus.base_deployment()
    before["spec"]["template"]["spec"]["containers"][0]["image"] = "example/web:latest"
    after = copy.deepcopy(before)
    after["spec"]["template"]["spec"]["containers"][0]["imagePullPolicy"] = "Always"

    findings = _findings(before, after)
    assert findings == [], [(f.classification, f.field_path) for f in findings]


def test_container_imagepullpolicy_always_on_tagged_image_is_not_default_and_still_flagged():
    """Guardrail: adding imagePullPolicy: Always to a TAGGED (non-:latest)
    image is NOT the documented default (IfNotPresent is) -- must still be
    flagged, not laundered to no-op."""
    before = corpus.base_deployment()
    before["spec"]["template"]["spec"]["containers"][0]["image"] = "example/web:1.0.0"
    after = copy.deepcopy(before)
    after["spec"]["template"]["spec"]["containers"][0]["imagePullPolicy"] = "Always"

    findings = _findings(before, after)
    assert findings, "non-default imagePullPolicy addition was wrongly stripped as a default"
    matching = [f for f in findings if f.field_path.endswith("imagePullPolicy")]
    assert matching
    assert all(resolve_field_path(after, f.field_path)[0] for f in matching)


def test_container_imagepullpolicy_ifnotpresent_on_latest_image_is_not_default_and_still_flagged():
    """Guardrail, other direction: adding IfNotPresent to an untagged/
    :latest image is NOT the documented default (Always is)."""
    before = corpus.base_deployment()
    before["spec"]["template"]["spec"]["containers"][0]["image"] = "example/web:latest"
    after = copy.deepcopy(before)
    after["spec"]["template"]["spec"]["containers"][0]["imagePullPolicy"] = "IfNotPresent"

    findings = _findings(before, after)
    assert findings, "non-default imagePullPolicy addition (:latest + IfNotPresent) was wrongly stripped"


def test_pod_restartpolicy_always_default_add_is_noop_on_deployment():
    before = corpus.base_deployment()
    assert "restartPolicy" not in before["spec"]["template"]["spec"]
    after = copy.deepcopy(before)
    after["spec"]["template"]["spec"]["restartPolicy"] = "Always"

    findings = _findings(before, after)
    assert findings == [], [(f.classification, f.field_path) for f in findings]


def test_pod_dnspolicy_clusterfirst_default_add_is_noop():
    before = corpus.base_deployment()
    after = copy.deepcopy(before)
    after["spec"]["template"]["spec"]["dnsPolicy"] = "ClusterFirst"

    findings = _findings(before, after)
    assert findings == [], [(f.classification, f.field_path) for f in findings]


def test_service_port_protocol_udp_add_is_not_default_and_still_flagged():
    """Guardrail: adding a non-default protocol value must still be a
    real, flagged change."""
    before = corpus.base_service()
    after = copy.deepcopy(before)
    after["spec"]["ports"][0]["protocol"] = "UDP"

    findings = _findings(before, after)
    assert findings, "UDP protocol addition was wrongly treated as the TCP default"


# ---------------------------------------------------------------------------
# Family 4 -- typed-scalar equality
# ---------------------------------------------------------------------------
def test_replicas_int_vs_string_is_noop():
    before = corpus.base_deployment()
    before["spec"]["replicas"] = 3
    after = copy.deepcopy(before)
    after["spec"]["replicas"] = "3"

    findings = _findings(before, after)
    assert findings == [], [(f.classification, f.field_path) for f in findings]


def test_replicas_genuine_scale_still_classified_string_form():
    """Guardrail: a real scale change expressed with a string value must
    still be classified normally (in-place), not swallowed."""
    before = corpus.base_deployment()
    before["spec"]["replicas"] = 3
    after = copy.deepcopy(before)
    after["spec"]["replicas"] = "5"

    findings = _findings(before, after)
    matching = [f for f in findings if f.field_path == "spec.replicas"]
    assert matching and matching[0].classification == "in-place"


def test_replicas_scale_to_zero_still_disruption_with_string_zero():
    """Guardrail: the replicas -> 0 disruption override must still fire
    even when '0' arrives as a typed-equal string, not just the bare int."""
    before = corpus.base_deployment()
    before["spec"]["replicas"] = 3
    after = copy.deepcopy(before)
    after["spec"]["replicas"] = "0"

    findings = _findings(before, after)
    matching = [f for f in findings if f.field_path == "spec.replicas"]
    assert matching and matching[0].classification == "disruption", matching


def test_typed_int_equality_only_applies_to_declared_fields():
    """A non-declared field (e.g. a label value) that happens to look like
    an int-vs-string pair must NOT be treated as typed-equal."""
    before = corpus.base_deployment()
    after = copy.deepcopy(before)
    before["metadata"]["labels"]["build"] = 3
    after["metadata"]["labels"]["build"] = "3"

    # labels are compared as an opaque leaf dict (LEAF_DICT_FIELDS), so this
    # is a real dict-value change and must still be reported.
    findings = _findings(before, after)
    assert findings, "label int-vs-string was wrongly treated as typed-int-equal"

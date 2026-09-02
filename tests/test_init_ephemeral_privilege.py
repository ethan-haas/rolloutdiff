"""regression tests for the fail-unsafe PRIVILEGE-DESCENT-GAP defect a
an independent review found.

Root cause (see rolloutdiff/coverage_table.py:_pod_template_privilege_rules):
the two container-level privilege leaf rules (`securityContext.privileged`,
`securityContext.allowPrivilegeEscalation`) were declared ONLY for the
regular `containers` list, never for `initContainers` or
`ephemeralContainers`. A privileged init/ephemeral container therefore fell
through to whatever generic wrapper rule applied at that pod-template
prefix instead of the security-critical `privilege-change` a regular
container gets for the IDENTICAL leaf:
  - Deployment initContainers[].securityContext.privileged -> was
    `rolling-restart` (shadowed by the generic `spec.template` rule)
  - StatefulSet initContainers[].securityContext.privileged -> was
    `rolling-restart` for the same reason
  - Deployment ephemeralContainers[].securityContext.privileged -> was
    `rolling-restart`
  - CronJob initContainers[].securityContext.privileged -> was `in-place`
    (shadowed by the even coarser `spec.jobTemplate -> in-place` rule)

The fix loops the SAME two container-level leaf rules across
`_CONTAINER_LIST_FIELDS = ("containers", "initContainers",
"ephemeralContainers")` inside the ONE declared generator, at every
pod-template prefix the generator is already called from -- not a
hand-duplicated special case.

Every case asserts field_path resolves into the actual document, per
the "a finding that cannot point at its own evidence is a bug"
discipline.
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
    assert pc, (
        f"expected a privilege-change finding, got "
        f"{sorted({f.classification for f in findings})}"
    )
    resolving = [f for f in pc if resolve_field_path(doc, f.field_path)[0]]
    assert resolving, (
        f"privilege-change finding(s) did not resolve: {[f.field_path for f in pc]}"
    )
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
                            "initContainers": [
                                {"name": "init", "image": "example/init:1.0"}
                            ],
                            "containers": [
                                {"name": "worker", "image": "example/worker:1.0"}
                            ],
                        }
                    }
                }
            },
        },
    }


def _cronjob_pod_spec(doc):
    return doc["spec"]["jobTemplate"]["spec"]["template"]["spec"]


def _pod_spec(doc):
    return doc["spec"]["template"]["spec"]


# ---------------------------------------------------------------------------
# Repro 1: Deployment initContainer privileged: false -> true.
# ---------------------------------------------------------------------------
def test_deployment_init_container_privileged_flip_is_privilege_change():
    before = corpus.base_deployment()
    _pod_spec(before)["initContainers"] = [
        {
            "name": "init",
            "image": "example/init:1.0",
            "securityContext": {"privileged": False},
        }
    ]
    after = copy.deepcopy(before)
    _pod_spec(after)["initContainers"][0]["securityContext"]["privileged"] = True

    findings = _findings(before, after)
    resolving = _assert_resolving_privilege_change(
        findings, after, must_contain="initContainers"
    )
    assert any(
        f.field_path
        == "spec.template.spec.initContainers[name=init].securityContext.privileged"
        for f in resolving
    )
    # must not ALSO surface as the coarser rolling-restart verdict for this
    # same underlying change -- privilege-change is the headline.
    assert "rolling-restart" not in {f.classification for f in findings}


# ---------------------------------------------------------------------------
# Repro 2: StatefulSet initContainer privileged add.
# ---------------------------------------------------------------------------
def test_statefulset_init_container_privileged_add_is_privilege_change():
    before = corpus.base_statefulset()
    _pod_spec(before)["initContainers"] = [
        {"name": "init", "image": "example/init:1.0"}
    ]
    after = copy.deepcopy(before)
    _pod_spec(after)["initContainers"][0]["securityContext"] = {"privileged": True}

    findings = _findings(before, after)
    resolving = _assert_resolving_privilege_change(
        findings, after, must_contain="initContainers"
    )
    assert any(
        f.field_path.endswith(
            "initContainers[name=init].securityContext.privileged"
        )
        for f in resolving
    )
    assert "rolling-restart" not in {f.classification for f in findings}


# ---------------------------------------------------------------------------
# Repro 3: Deployment EPHEMERAL container privileged add.
# ---------------------------------------------------------------------------
def test_deployment_ephemeral_container_privileged_add_is_privilege_change():
    before = corpus.base_deployment()
    after = copy.deepcopy(before)
    _pod_spec(after)["ephemeralContainers"] = [
        {
            "name": "debug",
            "image": "example/debug:1.0",
            "securityContext": {"privileged": True},
        }
    ]

    findings = _findings(before, after)
    resolving = _assert_resolving_privilege_change(
        findings, after, must_contain="ephemeralContainers"
    )
    assert any(
        f.field_path.endswith(
            "ephemeralContainers[name=debug].securityContext.privileged"
        )
        for f in resolving
    )
    assert "rolling-restart" not in {f.classification for f in findings}


# ---------------------------------------------------------------------------
# Repro 4: CronJob nested initContainer privileged: false -> true (must NOT
# be shadowed by the generic `spec.jobTemplate -> in-place` wrapper rule).
# ---------------------------------------------------------------------------
def test_cronjob_nested_init_container_privileged_flip_is_privilege_change():
    before = _base_cronjob()
    _cronjob_pod_spec(before)["initContainers"][0]["securityContext"] = {
        "privileged": False
    }
    after = copy.deepcopy(before)
    _cronjob_pod_spec(after)["initContainers"][0]["securityContext"]["privileged"] = True

    findings = _findings(before, after)
    resolving = _assert_resolving_privilege_change(
        findings, after, must_contain="initContainers"
    )
    assert any(
        f.field_path
        == "spec.jobTemplate.spec.template.spec.initContainers[name=init]"
        ".securityContext.privileged"
        for f in resolving
    )
    assert "in-place" not in {f.classification for f in findings}


# ---------------------------------------------------------------------------
# Control: a BENIGN init-container change (image bump on a non-privileged
# init container) must stay `rolling-restart` on Deployment -- proves the
# fix does not over-escalate every init-container change, only the covered
# privilege leaves.
# ---------------------------------------------------------------------------
def test_benign_init_container_image_bump_stays_rolling_restart():
    before = corpus.base_deployment()
    _pod_spec(before)["initContainers"] = [
        {"name": "init", "image": "example/init:1.0"}
    ]
    after = copy.deepcopy(before)
    _pod_spec(after)["initContainers"][0]["image"] = "example/init:2.0"

    findings = _findings(before, after)
    classes = {f.classification for f in findings}
    assert "privilege-change" not in classes, (
        f"benign init-container image bump was over-escalated: {classes}"
    )
    assert classes == {"rolling-restart"}, classes


# ---------------------------------------------------------------------------
# Control: init hostPath -- volumes.hostPath is pod-spec-level (shared by
# the whole pod, not per-container-list), so it must already flag
# privilege-change regardless of which container list mounts it. This
# confirms the existing pod-level rule needed no change.
# ---------------------------------------------------------------------------
def test_init_container_hostpath_volume_mount_still_flags_privilege_change():
    before = corpus.base_deployment()
    _pod_spec(before)["initContainers"] = [
        {"name": "init", "image": "example/init:1.0"}
    ]
    after = copy.deepcopy(before)
    init = _pod_spec(after)["initContainers"][0]
    init["volumeMounts"] = [{"name": "hostfs", "mountPath": "/host"}]
    _pod_spec(after)["volumes"] = [
        {"name": "hostfs", "hostPath": {"path": "/etc"}}
    ]

    findings = _findings(before, after)
    _assert_resolving_privilege_change(findings, after, must_contain="hostPath")

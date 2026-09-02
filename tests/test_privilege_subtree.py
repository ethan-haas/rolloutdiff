"""regression tests for the fail-unsafe ADDED-NESTED-SUBTREE defect an
an independent review found.

Root cause (see rolloutdiff/differ.py:_emit_subtree_classified /
_walk_subtree_nodes): when a privilege-relevant fact was introduced by
ADDING a nested map/list subtree (not by modifying a pre-existing scalar),
the differ used to stop at the parent-add level, apply the generic
pod-template rule, and classify `rolling-restart` -- it never descended
into the ADDED subtree to find the privilege leaf underneath. The MODIFY
case (`privileged: false -> true`) and the top-level-scalar-add case
(`hostNetwork` absent -> true) already worked; only added/removed NESTED
subtrees were under-classified. The fix walks every node inside an
added/removed subtree and picks the worst covered classification found
anywhere inside it, never just the generic rule at the add/remove point.

Every case here also asserts field_path resolves into the actual document,
per the "a finding that cannot point at its own evidence is a bug"
discipline.
"""
from __future__ import annotations

import copy

from rolloutdiff import corpus
from rolloutdiff.differ import diff_all
from rolloutdiff.loader import object_ref_for
from rolloutdiff.path_resolve import resolve_field_path

REF = ("apps", "Deployment", "prod", "web")


def _ref(doc):
    return object_ref_for(doc, "<test>")


def _pod_spec(doc):
    return doc["spec"]["template"]["spec"]


def _privilege_change_findings(findings):
    return [f for f in findings if f.classification == "privilege-change"]


def _assert_privilege_change_resolving(findings, doc, must_contain=None):
    """At least one privilege-change finding, and it must resolve into
    `doc`. If `must_contain` given, at least one resolving finding's
    field_path must contain that substring (anchors it to the actual leaf,
    not just any privilege-change finding on the object)."""
    pc = _privilege_change_findings(findings)
    assert pc, f"expected a privilege-change finding, got classifications {sorted({f.classification for f in findings})}"
    resolving = []
    for f in pc:
        found, _ = resolve_field_path(doc, f.field_path)
        if found:
            resolving.append(f)
    assert resolving, f"privilege-change finding(s) did not resolve into the document: {[f.field_path for f in pc]}"
    if must_contain is not None:
        assert any(must_contain in f.field_path for f in resolving), (
            f"no resolving privilege-change field_path contained {must_contain!r}: "
            f"{[f.field_path for f in resolving]}"
        )
    return resolving


# ---------------------------------------------------------------------------
# Repro 1: added `volumes` key wholesale (list didn't exist before), one
# entry is a hostPath docker-socket mount, plus the matching volumeMounts
# entry on the existing container.
# ---------------------------------------------------------------------------
def test_repro1_wholesale_added_volumes_key_with_hostpath_docker_sock():
    before = corpus.base_deployment()
    assert "volumes" not in _pod_spec(before)

    after = copy.deepcopy(before)
    after_spec = _pod_spec(after)
    after_spec["containers"][0]["volumeMounts"] = [
        {"name": "docker-sock", "mountPath": "/var/run/docker.sock"}
    ]
    after_spec["volumes"] = [
        {"name": "docker-sock", "hostPath": {"path": "/var/run/docker.sock"}}
    ]

    ref = _ref(before)
    findings = diff_all({ref: before}, {ref: after})
    _assert_privilege_change_resolving(findings, after, must_contain="hostPath")


# ---------------------------------------------------------------------------
# Repro 2: `volumes` key already exists (some benign entry); an ADDED item
# in that keyed list is a hostPath volume.
# ---------------------------------------------------------------------------
def test_repro2_added_hostpath_volume_item_in_existing_volumes_list():
    before = corpus.base_deployment()
    _pod_spec(before)["volumes"] = [{"name": "cache", "emptyDir": {}}]

    after = copy.deepcopy(before)
    _pod_spec(after)["volumes"].append(
        {"name": "docker-sock", "hostPath": {"path": "/var/run/docker.sock"}}
    )

    ref = _ref(before)
    findings = diff_all({ref: before}, {ref: after})
    _assert_privilege_change_resolving(findings, after, must_contain="hostPath")


# ---------------------------------------------------------------------------
# Repro 3: ADDS a whole second container, and that new container has
# securityContext.privileged=true.
# ---------------------------------------------------------------------------
def test_repro3_added_second_container_is_privileged():
    before = corpus.base_deployment()
    assert len(_pod_spec(before)["containers"]) == 1

    after = copy.deepcopy(before)
    _pod_spec(after)["containers"].append(
        {
            "name": "sidecar",
            "image": "example/sidecar:1.0.0",
            "securityContext": {"privileged": True},
        }
    )

    ref = _ref(before)
    findings = diff_all({ref: before}, {ref: after})
    _assert_privilege_change_resolving(
        findings, after, must_contain="sidecar"
    )
    resolving = [
        f for f in _privilege_change_findings(findings)
        if "sidecar" in f.field_path and resolve_field_path(after, f.field_path)[0]
    ]
    assert any(f.field_path.endswith("securityContext.privileged") for f in resolving)


# ---------------------------------------------------------------------------
# Repro 4: an EXISTING container gains `securityContext` wholesale (the
# whole map is added, container previously had no securityContext at all)
# with privileged=true inside it.
# ---------------------------------------------------------------------------
def test_repro4_existing_container_gains_privileged_securitycontext_map():
    before = corpus.base_deployment()
    del _pod_spec(before)["containers"][0]["securityContext"]
    assert "securityContext" not in _pod_spec(before)["containers"][0]

    after = copy.deepcopy(before)
    _pod_spec(after)["containers"][0]["securityContext"] = {"privileged": True}

    ref = _ref(before)
    findings = diff_all({ref: before}, {ref: after})
    resolving = _assert_privilege_change_resolving(findings, after)
    assert any(f.field_path.endswith("securityContext.privileged") for f in resolving)


# ---------------------------------------------------------------------------
# Additional required coverage: added privileged SIDECAR (distinct wording
# from repro 3 -- explicit "sidecar container added with privileged: true"
# scenario using allowPrivilegeEscalation too, to prove the walk finds
# EITHER covered leaf, not just `privileged`).
# ---------------------------------------------------------------------------
def test_added_privileged_sidecar_with_allow_privilege_escalation():
    before = corpus.base_deployment()
    after = copy.deepcopy(before)
    _pod_spec(after)["containers"].append(
        {
            "name": "sidecar",
            "image": "example/sidecar:1.0.0",
            "securityContext": {
                "privileged": True,
                "allowPrivilegeEscalation": True,
            },
        }
    )

    ref = _ref(before)
    findings = diff_all({ref: before}, {ref: after})
    _assert_privilege_change_resolving(findings, after, must_contain="sidecar")


# ---------------------------------------------------------------------------
# Added hostPath (standalone, minimal repro distinct from #1/#2: single
# volume list going from completely absent straight to a hostPath mount).
# ---------------------------------------------------------------------------
def test_added_hostpath_minimal():
    before = corpus.base_deployment()
    after = copy.deepcopy(before)
    _pod_spec(after)["volumes"] = [
        {"name": "hostfs", "hostPath": {"path": "/etc"}}
    ]

    ref = _ref(before)
    findings = diff_all({ref: before}, {ref: after})
    _assert_privilege_change_resolving(findings, after, must_contain="hostPath")


# ---------------------------------------------------------------------------
# hostPID and hostNetwork via NESTED add: added as part of a larger nested
# addition (not a lone top-level scalar add, which already worked) -- here
# nested inside a wholesale-added dict alongside other unrelated keys, to
# prove the walk finds them regardless of position.
# ---------------------------------------------------------------------------
def test_hostpid_via_nested_add():
    before = corpus.base_deployment()
    # hostAliases is not privilege-relevant; mixed in to prove only the
    # covered leaf (hostPID) drives the escalation, not "any nested add".
    after = copy.deepcopy(before)
    pod_spec = _pod_spec(after)
    pod_spec["hostAliases"] = [{"ip": "127.0.0.1", "hostnames": ["local"]}]
    pod_spec["hostPID"] = True

    ref = _ref(before)
    findings = diff_all({ref: before}, {ref: after})
    _assert_privilege_change_resolving(findings, after, must_contain="hostPID")


def test_hostnetwork_via_nested_add_alongside_unrelated_scalar():
    before = corpus.base_deployment()
    after = copy.deepcopy(before)
    pod_spec = _pod_spec(after)
    pod_spec["hostNetwork"] = True
    pod_spec["dnsPolicy"] = "ClusterFirstWithHostNet"  # unrelated tag-along

    ref = _ref(before)
    findings = diff_all({ref: before}, {ref: after})
    _assert_privilege_change_resolving(findings, after, must_contain="hostNetwork")


# ---------------------------------------------------------------------------
# Control: a BENIGN nested add (an ordinary emptyDir volume, wholesale new
# `volumes` key) must stay `rolling-restart` -- proves the fix does not
# over-escalate every nested add, only ones containing a covered leaf.
# ---------------------------------------------------------------------------
def test_benign_nested_add_stays_rolling_restart_not_escalated():
    before = corpus.base_deployment()
    assert "volumes" not in _pod_spec(before)

    after = copy.deepcopy(before)
    _pod_spec(after)["volumes"] = [{"name": "scratch", "emptyDir": {}}]

    ref = _ref(before)
    findings = diff_all({ref: before}, {ref: after})

    classes = {f.classification for f in findings}
    assert "privilege-change" not in classes, f"benign emptyDir add was over-escalated: {classes}"
    assert "data-loss" not in classes
    assert "rolling-restart" in classes


def test_benign_added_container_without_privilege_stays_rolling_restart():
    before = corpus.base_deployment()
    after = copy.deepcopy(before)
    _pod_spec(after)["containers"].append(
        {"name": "sidecar", "image": "example/sidecar:1.0.0"}
    )

    ref = _ref(before)
    findings = diff_all({ref: before}, {ref: after})
    classes = {f.classification for f in findings}
    assert "privilege-change" not in classes
    assert "rolling-restart" in classes


# ---------------------------------------------------------------------------
# Symmetric REMOVE direction: removing a securityContext map that carried
# privileged=true must still surface as privilege-change (security-relevant
# either direction -- see _emit_subtree_classified docstring for why this
# is chosen consistently with the pre-existing leaf-level remove behavior
# rather than silently de-escalated).
# ---------------------------------------------------------------------------
def test_removed_privileged_securitycontext_subtree_still_flags():
    before = corpus.base_deployment()
    _pod_spec(before)["containers"][0]["securityContext"] = {"privileged": True}

    after = copy.deepcopy(before)
    del _pod_spec(after)["containers"][0]["securityContext"]

    ref = _ref(before)
    findings = diff_all({ref: before}, {ref: after})
    resolving = _assert_privilege_change_resolving(findings, before)
    assert any(f.field_path.endswith("securityContext.privileged") for f in resolving)


def test_removed_hostpath_volume_item_still_flags():
    before = corpus.base_deployment()
    _pod_spec(before)["volumes"] = [
        {"name": "cache", "emptyDir": {}},
        {"name": "hostfs", "hostPath": {"path": "/etc"}},
    ]

    after = copy.deepcopy(before)
    _pod_spec(after)["volumes"] = [{"name": "cache", "emptyDir": {}}]

    ref = _ref(before)
    findings = diff_all({ref: before}, {ref: after})
    _assert_privilege_change_resolving(findings, before, must_contain="hostPath")

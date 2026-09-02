"""Component 3: Coverage table — THE core discipline.

A DECLARED, VERSIONED table of known kinds and their fields, mapping each
(kind, field_path_pattern) to a blast-radius classification. This is the
ONLY source of classification used anywhere in this tool.

Anything NOT in this table classifies `unknown`. Never inferred, never
defaulted to `no-op`. (See differ.py:classify_path — the fallback branch
returns "unknown", full stop.)

Source / version
-----------------
Hand-authored from the public Kubernetes API conventions and object docs
for the following API groups, targeting behavior stable since ~v1.19 and
current through v1.29-ish:
  - core/v1              (Service, ConfigMap, Secret, PersistentVolumeClaim,
                           ServiceAccount)
  - apps/v1               (Deployment, StatefulSet, DaemonSet)
  - batch/v1              (Job, CronJob)
  - autoscaling/v2        (HorizontalPodAutoscaler)
  - policy/v1             (PodDisruptionBudget)
  - rbac.authorization.k8s.io/v1  (Role, ClusterRole, RoleBinding,
                           ClusterRoleBinding)
  - networking.k8s.io/v1  (Ingress)

This is a deliberately partial subset (~13 kinds), not a machine-generated
transcription of the full OpenAPI schema. Every kind/field pair listed below
is a specific, citable piece of k8s behavior (documented in field comments);
nothing here is guessed. Anything outside this subset — every other core
kind (Pod, Node, Namespace, ...), every other API group, and every CRD —
falls through to `unknown` by construction.

Table format
------------
KIND_TABLE[(group, kind)] = {
    "rules": [(path_pattern, classification, note), ...],
    "object_added": classification,
    "object_removed": classification,
}

`path_pattern` is a dotted field path with list-bracket segments stripped
(see differ.strip_brackets) — i.e. "spec.template.spec.containers.image",
never "spec.template.spec.containers[name=x].image". Matching is
longest-prefix: a concrete (bracket-stripped) path matches a pattern if it
equals the pattern exactly, or starts with pattern + "." (pattern is then a
subtree root). Among all matching patterns for a kind, the longest one wins
(most specific rule applies).
"""
from __future__ import annotations


# The three pod-spec fields that hold a list of containers, per the k8s pod
# spec (see normalize.KEYED_LIST_KEYS, which already treats all three as
# identity-keyed by `name`). A container-level privilege leaf means the
# exact same thing regardless of which of these three lists the container
# sits in -- a privileged initContainer or ephemeralContainer is exactly as
# capable of breaking out to the host as a privileged regular container.
_CONTAINER_LIST_FIELDS = ("containers", "initContainers", "ephemeralContainers")


def _pod_template_privilege_rules(prefix: str) -> list:
    """Security-relevant fields inside a pod template, declared ONCE and
    applied at every dotted-path prefix a pod template actually lives at
    across this table's covered kinds. `prefix` is the bracket-stripped
    path at which the pod template's own `.spec` sits: `spec.template` for
    Deployment/StatefulSet/DaemonSet/Job (the pod template is a direct
    child of the object's own spec), `spec.jobTemplate.spec.template` for
    CronJob (the pod template lives one level deeper, inside the JobSpec
    the CronJob controller stamps out on each scheduled run).

    ROOT FIX for a wrapper blind spot found in review: these
    rules used to be hand-duplicated only at the flat `spec.template`
    prefix (Deployment/StatefulSet/DaemonSet). CronJob's ONLY rule for
    anything under `spec.jobTemplate` was the coarse
    `spec.jobTemplate -> in-place` catch-all -- so a privileged container
    or hostPath volume added inside `spec.jobTemplate.spec.template` never
    matched anything more specific and silently landed on `in-place`. Job's
    `spec.template -> recreate` rule had the same problem in the other
    direction: a privilege leaf under it was shadowed by the coarser
    immutable-template rule since no MORE SPECIFIC rule existed to win the
    table's longest-prefix match. Declaring the identical rule set at both
    depths -- not a new inference, the SAME table -- closes both gaps: the
    longest-prefix match in differ.classify_path will now prefer these
    specific leaf rules over the generic wrapper/template rule wherever the
    pod template actually is.

    SECOND ROOT FIX for a fail-unsafe gap found in a later review:
    the two container-level privilege leaves below (`privileged`,
    `allowPrivilegeEscalation`) used to be declared ONLY for the regular
    `containers` list, never for `initContainers` or `ephemeralContainers`
    -- so a privileged init/ephemeral container fell through to whatever
    generic wrapper rule applied at that prefix (`rolling-restart` for
    Deployment/StatefulSet/DaemonSet's `spec.template`, `in-place` for
    CronJob's `spec.jobTemplate`, shadowed by `recreate` for Job's
    `spec.template`) instead of the security-critical `privilege-change`
    every regular-container instance of the identical leaf already got.
    Looping the SAME two leaf rules across `_CONTAINER_LIST_FIELDS`
    (containers, initContainers, ephemeralContainers) -- still one declared
    generator, not hand-duplicated per list -- closes that gap identically
    at every pod-template location this function is called from. The other
    leaves here (serviceAccountName, hostNetwork/PID/IPC, volumes.hostPath)
    are pod-spec-level, not per-container-list, so they already cover
    init/ephemeral containers without needing to be repeated.
    """
    rules = [
        (f"{prefix}.spec.serviceAccountName", "privilege-change",
         "Changes the pod identity (and therefore the RBAC grants) the pod "
         f"runs as; more specific than the generic rule covering '{prefix}'."),
        (f"{prefix}.spec.hostNetwork", "privilege-change",
         "Grants the pod the host's network namespace."),
        (f"{prefix}.spec.hostPID", "privilege-change",
         "Grants the pod visibility into host process IDs."),
        (f"{prefix}.spec.hostIPC", "privilege-change",
         "Grants the pod the host's IPC namespace."),
    ]
    for list_field in _CONTAINER_LIST_FIELDS:
        rules.append((
            f"{prefix}.spec.{list_field}.securityContext.privileged",
            "privilege-change",
            f"Container ({list_field}) escapes the container security boundary.",
        ))
        rules.append((
            f"{prefix}.spec.{list_field}.securityContext.allowPrivilegeEscalation",
            "privilege-change",
            f"Widens the container's ({list_field}) privilege ceiling.",
        ))
    rules.append((
        f"{prefix}.spec.volumes.hostPath", "privilege-change",
        "hostPath volumes expose host filesystem paths inside the pod.",
    ))
    return rules


COVERAGE_TABLE_VERSION = "rolloutdiff-coverage-v1 (k8s ~v1.19-v1.29 subset)"
COVERAGE_TABLE_SOURCE = (
    "Hand-authored from public Kubernetes API conventions for: core/v1, "
    "apps/v1, batch/v1, autoscaling/v2, policy/v1, "
    "rbac.authorization.k8s.io/v1, networking.k8s.io/v1. See "
    "rolloutdiff/coverage_table.py module docstring for the full citation "
    "list and field-level notes. 13 kinds covered; anything else is "
    "'unknown' by construction, never inferred."
)

# ---------------------------------------------------------------------------
# apps/v1 Deployment
# ---------------------------------------------------------------------------
_DEPLOYMENT_RULES = [
    ("spec.replicas", "in-place",
     "Scaling a Deployment does not touch existing pod templates; API "
     "server only creates/deletes replicas. Special-cased to 'disruption' "
     "when the new value is 0 (see differ.py replicas-to-zero override)."),
    ("spec.selector", "recreate",
     "spec.selector is immutable on Deployment (API server rejects the "
     "update in place); changing it requires delete+create."),
    ("spec.strategy", "in-place",
     "RollingUpdate/Recreate strategy knobs affect HOW a future rollout "
     "happens, not the currently-running pods."),
    ("spec.minReadySeconds", "in-place", "Rollout pacing knob only."),
    ("spec.paused", "in-place", "Rollout controller flag only."),
    ("spec.progressDeadlineSeconds", "in-place", "Rollout controller flag only."),
    ("spec.template", "rolling-restart",
     "Any change under the pod template causes the Deployment controller "
     "to create a new ReplicaSet and roll pods."),
    *_pod_template_privilege_rules("spec.template"),
    ("metadata.labels", "in-place", "Deployment object's own labels; no pod effect."),
    ("metadata.annotations", "in-place", "Deployment object's own annotations."),
]

# ---------------------------------------------------------------------------
# apps/v1 StatefulSet
# ---------------------------------------------------------------------------
_STATEFULSET_RULES = [
    ("spec.replicas", "in-place",
     "Scaling adds/removes ordinal pods; existing pods untouched. "
     "Special-cased to 'disruption' at 0 (see differ.py)."),
    ("spec.serviceName", "recreate",
     "spec.serviceName is immutable on StatefulSet."),
    ("spec.selector", "recreate", "spec.selector is immutable on StatefulSet."),
    ("spec.volumeClaimTemplates", "data-loss",
     "volumeClaimTemplates is immutable; a change here can only be applied "
     "by deleting and recreating the StatefulSet's PVCs, which drops data."),
    ("spec.updateStrategy", "in-place", "Rollout pacing/partition knob only."),
    ("spec.podManagementPolicy", "recreate",
     "spec.podManagementPolicy is immutable on StatefulSet: the apps/v1 API "
     "server only permits in-place updates to spec.replicas, spec.template, "
     "spec.updateStrategy, spec.persistentVolumeClaimRetentionPolicy, and "
     "spec.minReadySeconds; any other spec field -- including "
     "podManagementPolicy -- is rejected on update and requires delete+"
     "recreate to change."),
    ("spec.template", "rolling-restart",
     "Pod template change causes StatefulSet controller to roll pods "
     "(ordinal by ordinal)."),
    *_pod_template_privilege_rules("spec.template"),
    ("metadata.labels", "in-place", "Object's own labels."),
    ("metadata.annotations", "in-place", "Object's own annotations."),
]

# ---------------------------------------------------------------------------
# apps/v1 DaemonSet
# ---------------------------------------------------------------------------
_DAEMONSET_RULES = [
    ("spec.selector", "recreate", "spec.selector is immutable on DaemonSet."),
    ("spec.updateStrategy", "in-place", "Rollout pacing knob only."),
    ("spec.template", "rolling-restart",
     "Pod template change rolls one pod per node."),
    *_pod_template_privilege_rules("spec.template"),
    ("metadata.labels", "in-place", "Object's own labels."),
    ("metadata.annotations", "in-place", "Object's own annotations."),
]

# ---------------------------------------------------------------------------
# batch/v1 Job — spec.template AND most of spec is immutable on Job
# ---------------------------------------------------------------------------
_JOB_RULES = [
    ("spec.template", "recreate",
     "Job's pod template is immutable after creation; the API server "
     "rejects an in-place update, so the only way to apply this change is "
     "to delete and recreate the Job."),
    # More specific than the blanket 'spec.template -> recreate' rule above:
    # a privilege-relevant leaf inside an immutable pod template is a
    # security-critical fact a 'this just gets recreated' reviewer could
    # otherwise skim past. privilege-change OUTRANKS recreate (see SPEC
    # severity precedence) -- these longer, more specific patterns win the
    # table's longest-prefix match, so the leaf reports as privilege-change
    # (the true recreate impact is still implied by the SAME field being
    # under an immutable pod template; only the headline classification
    # changes to the higher-severity one).
    *_pod_template_privilege_rules("spec.template"),
    ("spec.parallelism", "in-place", "Mutable; controls concurrent pod count."),
    ("spec.backoffLimit", "in-place", "Mutable retry-count knob."),
    ("spec.activeDeadlineSeconds", "in-place", "Mutable timeout knob."),
    ("metadata.labels", "in-place", "Object's own labels."),
    ("metadata.annotations", "in-place", "Object's own annotations."),
]

# ---------------------------------------------------------------------------
# batch/v1 CronJob
# ---------------------------------------------------------------------------
_CRONJOB_RULES = [
    ("spec.schedule", "in-place", "Affects only future scheduled runs."),
    ("spec.suspend", "in-place", "Affects only future scheduled runs."),
    ("spec.concurrencyPolicy", "in-place", "Affects only future scheduled runs."),
    ("spec.jobTemplate", "in-place",
     "Only affects Jobs created by future scheduled runs; no currently "
     "running pod is touched by editing a CronJob's template."),
    # More specific than the blanket 'spec.jobTemplate -> in-place' rule
    # above -- this is the wrapper-nesting root fix: CronJob's pod template
    # lives one level deeper than every other kind's (spec.jobTemplate.spec
    # .template, not spec.template), and prior to this fix NOTHING in this
    # table named that nested prefix, so a privileged container or hostPath
    # volume added under it fell through to the coarse 'no live pod is
    # touched' rule above and was silently under-classified. A privilege
    # escalation baked into a CronJob's template is exactly as
    # security-relevant to a reviewer as one baked into a Deployment's --
    # it just takes effect on the NEXT scheduled run instead of
    # immediately -- so this table names the nested prefix explicitly
    # rather than leaving it to the wrapper-level default.
    *_pod_template_privilege_rules("spec.jobTemplate.spec.template"),
    ("metadata.labels", "in-place", "Object's own labels."),
    ("metadata.annotations", "in-place", "Object's own annotations."),
]

# ---------------------------------------------------------------------------
# core/v1 Service
# ---------------------------------------------------------------------------
_SERVICE_RULES = [
    ("spec.selector", "disruption",
     "Changes which pods receive traffic through this Service — an "
     "immediate routing change for live traffic."),
    ("spec.ports", "disruption",
     "Changes the ports traffic is routed through; live-traffic impacting."),
    ("spec.clusterIP", "recreate",
     "spec.clusterIP is immutable on Service (other than the None <-> "
     "unset special case, which this table conservatively still flags)."),
    ("spec.type", "disruption",
     "Changing Service type (ClusterIP/NodePort/LoadBalancer/ExternalName) "
     "changes how/whether the Service is externally reachable."),
    ("metadata.labels", "in-place", "Object's own labels."),
    ("metadata.annotations", "in-place",
     "Object's own annotations (cloud LB annotations are a documented "
     "exception a real cluster might treat as disruptive; out of scope — "
     "see README boundary note)."),
]

# ---------------------------------------------------------------------------
# core/v1 ConfigMap
# ---------------------------------------------------------------------------
_CONFIGMAP_RULES = [
    ("data", "in-place",
     "A ConfigMap object's own `data` is a plain key/value store; changing "
     "it does not, by itself, restart anything. Documented BOUNDARY: this "
     "tool does not track which pods mount this ConfigMap, so it cannot "
     "know whether a consumer needs a rolling-restart. A bare ConfigMap "
     "data change is reported as in-place ON THE CONFIGMAP OBJECT ITSELF; "
     "propagation to mounting pods is out of scope (see README)."),
    ("binaryData", "in-place", "Same boundary as `data`."),
    ("metadata.labels", "in-place", "Object's own labels."),
    ("metadata.annotations", "in-place", "Object's own annotations."),
]

# ---------------------------------------------------------------------------
# core/v1 Secret
# ---------------------------------------------------------------------------
_SECRET_RULES = [
    ("type", "recreate", "Secret.type is immutable after creation."),
    ("data", "in-place", "Same mount-propagation boundary as ConfigMap.data."),
    ("stringData", "in-place", "Same mount-propagation boundary as ConfigMap.data."),
    ("metadata.labels", "in-place", "Object's own labels."),
    ("metadata.annotations", "in-place", "Object's own annotations."),
]

# ---------------------------------------------------------------------------
# core/v1 PersistentVolumeClaim
# ---------------------------------------------------------------------------
_PVC_RULES = [
    ("spec.accessModes", "recreate", "Immutable after binding."),
    ("spec.volumeName", "recreate", "Immutable after binding."),
    ("spec.storageClassName", "data-loss",
     "Changing storage class after binding cannot be applied in place; "
     "the only path is delete+recreate the PVC, which can drop data."),
    ("spec.resources.requests.storage", "data-loss",
     "Shrinking is rejected/unsupported by most provisioners and growing "
     "requires provisioner support; conservatively treated as data-loss "
     "risk rather than assumed-safe in-place expansion."),
    ("spec.selector", "recreate", "Immutable after binding."),
    ("metadata.labels", "in-place", "Object's own labels."),
    ("metadata.annotations", "in-place", "Object's own annotations."),
]

# ---------------------------------------------------------------------------
# autoscaling/v2 HorizontalPodAutoscaler
# ---------------------------------------------------------------------------
_HPA_RULES = [
    ("spec.minReplicas", "in-place", "HPA bound; affects future scaling decisions only."),
    ("spec.maxReplicas", "in-place", "HPA bound; affects future scaling decisions only."),
    ("spec.metrics", "in-place", "Scaling-signal config; affects future scaling only."),
    ("spec.behavior", "in-place", "Scaling-pacing config; affects future scaling only."),
    ("spec.scaleTargetRef", "in-place",
     "Changes what the HPA targets going forward; does not itself touch "
     "any pod."),
    ("metadata.labels", "in-place", "Object's own labels."),
    ("metadata.annotations", "in-place", "Object's own annotations."),
]

# ---------------------------------------------------------------------------
# policy/v1 PodDisruptionBudget
# ---------------------------------------------------------------------------
_PDB_RULES = [
    ("spec.minAvailable", "in-place", "Changes the eviction-admission bound only."),
    ("spec.maxUnavailable", "in-place", "Changes the eviction-admission bound only."),
    ("spec.selector", "in-place", "Changes which pods the budget covers."),
    ("metadata.labels", "in-place", "Object's own labels."),
    ("metadata.annotations", "in-place", "Object's own annotations."),
]

# ---------------------------------------------------------------------------
# rbac.authorization.k8s.io/v1 Role / ClusterRole
# ---------------------------------------------------------------------------
_ROLE_RULES = [
    # "rules" is handled by a dedicated broaden/narrow comparator in
    # differ.py (RBAC rules are a set, not a keyed or positional list); the
    # table entry documents the default/fallback only.
    ("rules", "privilege-change",
     "Default/fallback classification for a Role/ClusterRole rules change "
     "when the dedicated broaden/narrow comparator (differ.py) cannot "
     "determine direction. See differ.classify_rbac_rules for the actual "
     "broadened-vs-narrowed logic."),
    ("metadata.labels", "in-place", "Object's own labels."),
    ("metadata.annotations", "in-place", "Object's own annotations."),
]

# ---------------------------------------------------------------------------
# rbac.authorization.k8s.io/v1 RoleBinding / ClusterRoleBinding
# ---------------------------------------------------------------------------
_BINDING_RULES = [
    ("roleRef", "privilege-change",
     "roleRef is immutable (API server rejects an in-place update) AND "
     "changes which Role/ClusterRole's permissions are granted — the "
     "'worst applicable' classification per spec section 4 is the "
     "security-relevant one."),
    ("subjects", "privilege-change",
     "Default/fallback; see differ.classify_rbac_subjects for the "
     "added-subject-vs-removed-only comparator."),
    ("metadata.labels", "in-place", "Object's own labels."),
    ("metadata.annotations", "in-place", "Object's own annotations."),
]

# ---------------------------------------------------------------------------
# core/v1 ServiceAccount
# ---------------------------------------------------------------------------
_SERVICEACCOUNT_RULES = [
    ("automountServiceAccountToken", "privilege-change",
     "Controls whether pods using this SA get an auto-mounted API token."),
    ("secrets", "in-place",
     "Legacy secret-linking list; token minting is handled by the "
     "TokenRequest API in modern clusters, so this is treated as a "
     "bookkeeping field rather than a live privilege grant."),
    ("imagePullSecrets", "in-place",
     "Affects future pod scheduling ability to pull images, not a live "
     "privilege change to running pods."),
    ("metadata.labels", "in-place", "Object's own labels."),
    ("metadata.annotations", "in-place", "Object's own annotations."),
]

# ---------------------------------------------------------------------------
# networking.k8s.io/v1 Ingress
# ---------------------------------------------------------------------------
_INGRESS_RULES = [
    ("spec.rules", "disruption", "Changes live traffic routing rules."),
    ("spec.tls", "disruption", "Changes live TLS termination config."),
    ("spec.defaultBackend", "disruption", "Changes live fallback routing."),
    ("metadata.labels", "in-place", "Object's own labels."),
    ("metadata.annotations", "in-place",
     "Ingress controller annotations CAN be routing-relevant in real "
     "clusters (e.g. nginx rewrite-target); out of scope for this subset "
     "table — see README boundary note."),
]

KIND_TABLE = {
    ("apps", "Deployment"): {
        "rules": _DEPLOYMENT_RULES,
        "object_added": "in-place",
        "object_removed": "disruption",
    },
    ("apps", "StatefulSet"): {
        "rules": _STATEFULSET_RULES,
        "object_added": "in-place",
        "object_removed": "disruption",
    },
    ("apps", "DaemonSet"): {
        "rules": _DAEMONSET_RULES,
        "object_added": "in-place",
        "object_removed": "disruption",
    },
    ("batch", "Job"): {
        "rules": _JOB_RULES,
        "object_added": "in-place",
        "object_removed": "disruption",
    },
    ("batch", "CronJob"): {
        "rules": _CRONJOB_RULES,
        "object_added": "in-place",
        "object_removed": "in-place",
    },
    ("", "Service"): {
        "rules": _SERVICE_RULES,
        "object_added": "in-place",
        "object_removed": "disruption",
    },
    ("", "ConfigMap"): {
        "rules": _CONFIGMAP_RULES,
        "object_added": "in-place",
        "object_removed": "in-place",
    },
    ("", "Secret"): {
        "rules": _SECRET_RULES,
        "object_added": "in-place",
        "object_removed": "in-place",
    },
    ("", "PersistentVolumeClaim"): {
        "rules": _PVC_RULES,
        "object_added": "in-place",
        "object_removed": "data-loss",
    },
    ("autoscaling", "HorizontalPodAutoscaler"): {
        "rules": _HPA_RULES,
        "object_added": "in-place",
        "object_removed": "in-place",
    },
    ("policy", "PodDisruptionBudget"): {
        "rules": _PDB_RULES,
        "object_added": "in-place",
        "object_removed": "disruption",
    },
    ("rbac.authorization.k8s.io", "Role"): {
        "rules": _ROLE_RULES,
        "object_added": "privilege-change",
        "object_removed": "privilege-change",
    },
    ("rbac.authorization.k8s.io", "ClusterRole"): {
        "rules": _ROLE_RULES,
        "object_added": "privilege-change",
        "object_removed": "privilege-change",
    },
    ("rbac.authorization.k8s.io", "RoleBinding"): {
        "rules": _BINDING_RULES,
        "object_added": "privilege-change",
        "object_removed": "privilege-change",
    },
    ("rbac.authorization.k8s.io", "ClusterRoleBinding"): {
        "rules": _BINDING_RULES,
        "object_added": "privilege-change",
        "object_removed": "privilege-change",
    },
    ("", "ServiceAccount"): {
        "rules": _SERVICEACCOUNT_RULES,
        "object_added": "in-place",
        "object_removed": "privilege-change",
    },
    ("networking.k8s.io", "Ingress"): {
        "rules": _INGRESS_RULES,
        "object_added": "in-place",
        "object_removed": "disruption",
    },
}


def kind_key_for(object_ref) -> tuple:
    group, kind, _namespace, _name = object_ref
    return (group, kind)


def is_kind_covered(object_ref) -> bool:
    return kind_key_for(object_ref) in KIND_TABLE

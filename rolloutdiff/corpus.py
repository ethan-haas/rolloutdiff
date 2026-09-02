"""Component 6: Corpus synthesizer (in-repo, no network, no cluster).

Generates:
  - planted-change pairs: each carries exactly ONE known change, covering
    every verdict class (>= 8, including no-op).
  - two-sided no-op pairs: reordered keys, injected server defaults,
    whitespace churn, annotation churn, non-semantic list reorder — all
    MUST classify no-op (zero findings).
  - >= 3 input shapes (raw / helm-template-style / kustomize-build-style)
    for the same semantic content, as TEXT. No helm/kustomize binaries are
    invoked anywhere — these are hand-synthesized text shapes.
"""
from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

import yaml


# ---------------------------------------------------------------------------
# Base object factories
# ---------------------------------------------------------------------------
def base_deployment() -> dict:
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {
            "name": "web",
            "namespace": "prod",
            "labels": {"app": "web"},
        },
        "spec": {
            "replicas": 3,
            "selector": {"matchLabels": {"app": "web"}},
            "template": {
                "metadata": {"labels": {"app": "web"}},
                "spec": {
                    "serviceAccountName": "web-sa",
                    "containers": [
                        {
                            "name": "app",
                            "image": "example/web:1.0.0",
                            "env": [
                                {"name": "LOG_LEVEL", "value": "info"},
                                {"name": "PORT", "value": "8080"},
                            ],
                            "resources": {
                                "requests": {"cpu": "100m", "memory": "128Mi"}
                            },
                            "securityContext": {"privileged": False},
                        }
                    ],
                },
            },
        },
    }


def base_statefulset() -> dict:
    return {
        "apiVersion": "apps/v1",
        "kind": "StatefulSet",
        "metadata": {"name": "db", "namespace": "prod"},
        "spec": {
            "serviceName": "db",
            "replicas": 3,
            "selector": {"matchLabels": {"app": "db"}},
            "template": {
                "metadata": {"labels": {"app": "db"}},
                "spec": {"containers": [{"name": "db", "image": "example/db:5.0"}]},
            },
            "volumeClaimTemplates": [
                {
                    "metadata": {"name": "data"},
                    "spec": {"accessModes": ["ReadWriteOnce"], "resources": {"requests": {"storage": "10Gi"}}},
                }
            ],
        },
    }


def base_service() -> dict:
    return {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {"name": "web", "namespace": "prod"},
        "spec": {
            "selector": {"app": "web"},
            "ports": [{"name": "http", "port": 80, "targetPort": 8080}],
            "clusterIP": "10.0.0.5",
        },
    }


def base_configmap() -> dict:
    return {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {"name": "web-config", "namespace": "prod"},
        "data": {"LOG_LEVEL": "info"},
    }


def base_pvc() -> dict:
    return {
        "apiVersion": "v1",
        "kind": "PersistentVolumeClaim",
        "metadata": {"name": "data", "namespace": "prod"},
        "spec": {
            "accessModes": ["ReadWriteOnce"],
            "storageClassName": "standard",
            "resources": {"requests": {"storage": "10Gi"}},
        },
    }


def base_hpa() -> dict:
    return {
        "apiVersion": "autoscaling/v2",
        "kind": "HorizontalPodAutoscaler",
        "metadata": {"name": "web", "namespace": "prod"},
        "spec": {
            "scaleTargetRef": {"apiVersion": "apps/v1", "kind": "Deployment", "name": "web"},
            "minReplicas": 2,
            "maxReplicas": 10,
        },
    }


def base_pdb() -> dict:
    return {
        "apiVersion": "policy/v1",
        "kind": "PodDisruptionBudget",
        "metadata": {"name": "web", "namespace": "prod"},
        "spec": {"minAvailable": 1, "selector": {"matchLabels": {"app": "web"}}},
    }


def base_role() -> dict:
    return {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "Role",
        "metadata": {"name": "reader", "namespace": "prod"},
        "rules": [
            {"apiGroups": [""], "resources": ["pods"], "verbs": ["get", "list"]}
        ],
    }


def base_rolebinding() -> dict:
    return {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "RoleBinding",
        "metadata": {"name": "reader-binding", "namespace": "prod"},
        "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": "reader"},
        "subjects": [{"kind": "ServiceAccount", "name": "web-sa", "namespace": "prod"}],
    }


def base_serviceaccount() -> dict:
    return {
        "apiVersion": "v1",
        "kind": "ServiceAccount",
        "metadata": {"name": "web-sa", "namespace": "prod"},
        "automountServiceAccountToken": False,
    }


def base_ingress() -> dict:
    return {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "Ingress",
        "metadata": {"name": "web", "namespace": "prod"},
        "spec": {
            "rules": [
                {
                    "host": "web.example.com",
                    "http": {
                        "paths": [
                            {
                                "path": "/",
                                "pathType": "Prefix",
                                "backend": {"service": {"name": "web", "port": {"number": 80}}},
                            }
                        ]
                    },
                }
            ]
        },
    }


def base_unknown_crd() -> dict:
    """A kind deliberately absent from the coverage table."""
    return {
        "apiVersion": "example.com/v1alpha1",
        "kind": "WidgetPolicy",
        "metadata": {"name": "widgets", "namespace": "prod"},
        "spec": {"maxWidgets": 5},
    }


# ---------------------------------------------------------------------------
# Planted-change corpus
# ---------------------------------------------------------------------------
@dataclass
class PlantedCase:
    id: str
    verdict: str
    before: dict
    after: dict
    expected_field_path_prefix: str
    note: str


def _mut(doc: dict, path: List[Any], value: Any) -> dict:
    d = copy.deepcopy(doc)
    node = d
    for key in path[:-1]:
        node = node[key]
    node[path[-1]] = value
    return d


def build_planted_corpus() -> List[PlantedCase]:
    cases: List[PlantedCase] = []

    # no-op: reorder a dict's keys via re-construction (Python dict compares
    # equal regardless of insertion order, but this proves the differ agrees)
    dep = base_deployment()
    dep_reordered = {k: dep[k] for k in reversed(list(dep.keys()))}
    cases.append(PlantedCase("noop-key-reorder", "no-op", dep, dep_reordered, "", "top-level key order reversed"))

    # in-place: Deployment replicas 3 -> 5
    dep_after = _mut(dep, ["spec", "replicas"], 5)
    cases.append(PlantedCase("inplace-replicas-up", "in-place", dep, dep_after, "spec.replicas", "scale up"))

    # rolling-restart: Deployment image bump
    dep_after = _mut(dep, ["spec", "template", "spec", "containers", 0, "image"], "example/web:1.1.0")
    cases.append(PlantedCase(
        "rolling-image-bump", "rolling-restart", dep, dep_after,
        "spec.template.spec.containers[name=app].image", "container image change",
    ))

    # recreate: Deployment selector change (immutable)
    dep_after = _mut(dep, ["spec", "selector", "matchLabels", "app"], "web-v2")
    cases.append(PlantedCase(
        "recreate-selector", "recreate", dep, dep_after,
        "spec.selector.matchLabels.app", "immutable selector changed",
    ))

    # data-loss: StatefulSet volumeClaimTemplates storage size change
    sts = base_statefulset()
    sts_after = _mut(sts, ["spec", "volumeClaimTemplates", 0, "spec", "resources", "requests", "storage"], "20Gi")
    cases.append(PlantedCase(
        "dataloss-vct-storage", "data-loss", sts, sts_after,
        "spec.volumeClaimTemplates",
        "volumeClaimTemplates is immutable; only path is recreate, risking data "
        "(positional whole-list finding: volumeClaimTemplates items are not "
        "identity-keyed by a top-level 'name', so this is one finding at the "
        "list path, not a per-index sub-path)",
    ))

    # disruption: Service selector change (live traffic routing)
    svc = base_service()
    svc_after = _mut(svc, ["spec", "selector", "app"], "web-canary")
    cases.append(PlantedCase(
        "disruption-svc-selector", "disruption", svc, svc_after,
        "spec.selector.app", "Service selector changed, retargets live traffic",
    ))

    # privilege-change: container securityContext.privileged flips true
    dep_priv = base_deployment()
    dep_priv_after = _mut(
        dep_priv,
        ["spec", "template", "spec", "containers", 0, "securityContext", "privileged"],
        True,
    )
    cases.append(PlantedCase(
        "privilege-container-privileged", "privilege-change", dep_priv, dep_priv_after,
        "spec.template.spec.containers[name=app].securityContext.privileged",
        "container flips to privileged",
    ))

    # unknown: an unrecognized CRD field changes
    crd = base_unknown_crd()
    crd_after = _mut(crd, ["spec", "maxWidgets"], 50)
    cases.append(PlantedCase(
        "unknown-crd-field", "unknown", crd, crd_after,
        "spec.maxWidgets", "kind not in coverage table -> must be unknown, never no-op",
    ))

    # -- extra cases beyond the required 8, for broader table coverage --
    role = base_role()
    role_after = copy.deepcopy(role)
    role_after["rules"][0]["verbs"] = ["get", "list", "delete"]
    cases.append(PlantedCase(
        "privilege-rbac-broaden", "privilege-change", role, role_after,
        "rules", "Role rule broadened with 'delete' verb",
    ))

    role_narrow = base_role()
    role_narrow_after = copy.deepcopy(role_narrow)
    role_narrow_after["rules"][0]["verbs"] = ["get"]
    cases.append(PlantedCase(
        "inplace-rbac-narrow", "in-place", role_narrow, role_narrow_after,
        "rules", "Role rule strictly narrowed",
    ))

    job = {
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {"name": "migrate", "namespace": "prod"},
        "spec": {"template": {"spec": {"containers": [{"name": "migrate", "image": "example/migrate:1.0"}]}}},
    }
    job_after = _mut(job, ["spec", "template", "spec", "containers", 0, "image"], "example/migrate:2.0")
    cases.append(PlantedCase(
        "recreate-job-template", "recreate", job, job_after,
        "spec.template.spec.containers[name=migrate].image",
        "Job pod template is immutable -> recreate",
    ))

    pdb = base_pdb()
    pdb_after = _mut(pdb, ["spec", "minAvailable"], 2)
    cases.append(PlantedCase("inplace-pdb-bound", "in-place", pdb, pdb_after, "spec.minAvailable", "PDB bound changed"))

    dep_zero = base_deployment()
    dep_zero_after = _mut(dep_zero, ["spec", "replicas"], 0)
    cases.append(PlantedCase(
        "disruption-replicas-zero", "disruption", dep_zero, dep_zero_after,
        "spec.replicas", "scale to zero",
    ))

    return cases


# ---------------------------------------------------------------------------
# Two-sided no-op corpus
# ---------------------------------------------------------------------------
@dataclass
class NoopCase:
    id: str
    before: dict
    after: dict
    note: str


def build_noop_corpus() -> List[NoopCase]:
    cases: List[NoopCase] = []

    # reordered keys at multiple levels
    dep = base_deployment()
    dep2 = {k: dep[k] for k in reversed(list(dep.keys()))}
    dep2["metadata"] = {k: dep["metadata"][k] for k in reversed(list(dep["metadata"].keys()))}
    cases.append(NoopCase("noop-reorder-deep", dep, dep2, "keys reordered at top + metadata level"))

    # injected server defaults / status / identity fields
    dep3 = base_deployment()
    dep3_after = copy.deepcopy(dep3)
    dep3_after["metadata"]["creationTimestamp"] = "2026-01-01T00:00:00Z"
    dep3_after["metadata"]["generation"] = 4
    dep3_after["metadata"]["resourceVersion"] = "123456"
    dep3_after["metadata"]["uid"] = "abc-123"
    dep3_after["status"] = {"replicas": 3, "readyReplicas": 3, "conditions": [{"type": "Available"}]}
    cases.append(NoopCase("noop-server-defaults", dep3, dep3_after, "server-owned metadata/status injected"))

    # annotation churn
    dep4 = base_deployment()
    dep4_after = copy.deepcopy(dep4)
    dep4_after["metadata"]["annotations"] = {
        "kubectl.kubernetes.io/last-applied-configuration": '{"apiVersion":"apps/v1", ...}',
        "deployment.kubernetes.io/revision": "7",
    }
    cases.append(NoopCase("noop-annotation-churn", dep4, dep4_after, "last-applied-configuration + revision annotation added"))

    # whitespace churn in a multi-line ConfigMap value
    cm = base_configmap()
    cm_after = copy.deepcopy(cm)
    cm["data"]["script.sh"] = "#!/bin/sh\necho hi\n"
    cm_after["data"]["script.sh"] = "#!/bin/sh   \necho hi\n\n\n"
    cases.append(NoopCase("noop-whitespace", cm, cm_after, "trailing whitespace + trailing blank lines"))

    # non-semantic list reorder: env vars reordered by name (order-insensitive)
    dep5 = base_deployment()
    dep5_after = copy.deepcopy(dep5)
    env = dep5_after["spec"]["template"]["spec"]["containers"][0]["env"]
    dep5_after["spec"]["template"]["spec"]["containers"][0]["env"] = list(reversed(env))
    cases.append(NoopCase("noop-env-reorder", dep5, dep5_after, "env vars reordered (identity = name)"))

    # non-semantic container list reorder (identity = name)
    dep6 = base_deployment()
    dep6_after = copy.deepcopy(dep6)
    dep6_after["spec"]["template"]["spec"]["containers"][0]["env"] = list(
        reversed(dep6["spec"]["template"]["spec"]["containers"][0]["env"])
    )
    cases.append(NoopCase("noop-container-list-stable", dep6, dep6_after, "container list (single elem) stable identity"))

    return cases


# ---------------------------------------------------------------------------
# Positive-control mutation: the classifier must be able to go red
# ---------------------------------------------------------------------------
def mutate_table_to_break_immutability_rule(kind_table: dict) -> None:
    """Corrupts the loaded coverage table IN PLACE so that Deployment
    spec.selector (a genuinely immutable field) is misclassified as
    'in-place'. Used ONLY by the positive-control test to prove the suite
    can fail; never called by the CLI or by any non-test code path."""
    entry = kind_table[("apps", "Deployment")]
    entry["rules"] = [
        (pattern, ("in-place" if pattern == "spec.selector" else cls), note)
        for pattern, cls, note in entry["rules"]
    ]


# ---------------------------------------------------------------------------
# Multi-shape rendering — text only, no helm/kustomize binaries
# ---------------------------------------------------------------------------
def render_raw(docs: List[dict]) -> str:
    return "---\n".join(yaml.dump(d, default_flow_style=False, sort_keys=True) for d in docs)


def render_helm_style(docs: List[dict], chart_name: str = "mychart") -> str:
    parts = [f"# Source: {chart_name}/templates/00-namespace.yaml\n# rendered by `helm template` (synthesized text, no helm binary invoked)\n"]
    for d in docs:
        kind = d.get("kind", "object").lower()
        name = d.get("metadata", {}).get("name", "obj")
        parts.append(f"---\n# Source: {chart_name}/templates/{kind}-{name}.yaml\n")
        parts.append(yaml.dump(d, default_flow_style=False, sort_keys=True))
    return "\n".join(parts)


def render_kustomize_style(docs: List[dict]) -> str:
    parts = ["# generated by kustomize build (synthesized text, no kustomize binary invoked)\n"]
    for i, d in enumerate(docs):
        if i > 0:
            parts.append("---")
        parts.append(yaml.dump(d, default_flow_style=False, sort_keys=False))
    return "\n".join(parts)

"""Component 2: Semantic normalizer.

Makes semantically-identical inputs compare equal:
  - dict key order: irrelevant by construction (Python dict equality/recursion
    below never depends on insertion order).
  - whitespace inside scalar strings: normalized for multi-line string values
    (trailing whitespace per line + trailing blank lines stripped) — this
    only affects things like multi-line ConfigMap data blobs, command
    scripts, etc. It does NOT touch semantic content.
  - annotation churn: kubectl.kubernetes.io/last-applied-configuration and
    common timestamp/identity annotations are dropped before compare.
  - server-defaulted / server-owned fields: metadata.creationTimestamp,
    .generation, .resourceVersion, .uid, .selfLink, .managedFields, and the
    entire `status` subtree are stripped — these never carry a declarative
    semantic change a rollout could act on.
  - list reordering: ignored ONLY for lists whose element identity is
    established by a `name` key AND that field name is in KEYED_LIST_KEYS
    (containers, initContainers, ephemeralContainers, volumes, env,
    volumeMounts, envFrom is positional-only so excluded). All other lists
    (args, command, ports, ingress rules, RBAC subjects/rules, ...) are
    order-SENSITIVE by default — conservative: unsure means NOT a no-op.
"""
from __future__ import annotations

import copy
from typing import Any, Dict

IGNORED_ANNOTATIONS = {
    "kubectl.kubernetes.io/last-applied-configuration",
    "deployment.kubernetes.io/revision",
    "kubernetes.io/change-cause",
}

# metadata fields that are entirely server-owned / non-declarative
IGNORED_METADATA_FIELDS = {
    "creationTimestamp",
    "generation",
    "resourceVersion",
    "uid",
    "selfLink",
    "managedFields",
}

# field name (dict key) -> key used to establish element identity for
# order-insensitive comparison. Applies wherever that key name occurs,
# regardless of full path (sufficiently specific for the k8s pod-spec
# vocabulary this tool covers).
KEYED_LIST_KEYS = {
    "containers": "name",
    "initContainers": "name",
    "ephemeralContainers": "name",
    "volumes": "name",
    "env": "name",
    "volumeMounts": "name",
}


def _strip_multiline_whitespace(s: str) -> str:
    if "\n" not in s:
        return s
    lines = [line.rstrip() for line in s.split("\n")]
    # strip trailing blank lines
    while lines and lines[-1] == "":
        lines.pop()
    return "\n".join(lines)


def normalize_scalar(v: Any) -> Any:
    if isinstance(v, str):
        return _strip_multiline_whitespace(v)
    return v


def normalize_value(v: Any, field_name: str | None = None) -> Any:
    """Recursively normalize a value. `field_name` is the dict key this value
    was stored under in its parent (used to decide keyed-list handling)."""
    if isinstance(v, dict):
        return normalize_doc_subtree(v)
    if isinstance(v, list):
        normalized_items = [normalize_value(item) for item in v]
        key = KEYED_LIST_KEYS.get(field_name or "")
        if key and all(isinstance(item, dict) and key in item for item in normalized_items):
            # order-insensitive: canonicalize by sorting on the key
            try:
                normalized_items = sorted(normalized_items, key=lambda d: str(d[key]))
            except TypeError:
                pass
        return normalized_items
    return normalize_scalar(v)


def normalize_doc_subtree(d: dict) -> dict:
    out = {}
    for k, v in d.items():
        out[k] = normalize_value(v, field_name=k)
    return out


def normalize_doc(doc: dict) -> dict:
    """Top-level normalization entry point for one k8s object document."""
    doc = copy.deepcopy(doc)
    doc.pop("status", None)

    metadata = doc.get("metadata")
    if isinstance(metadata, dict):
        for f in IGNORED_METADATA_FIELDS:
            metadata.pop(f, None)
        annotations = metadata.get("annotations")
        if isinstance(annotations, dict):
            for a in IGNORED_ANNOTATIONS:
                annotations.pop(a, None)
            if not annotations:
                metadata.pop("annotations", None)
        labels = metadata.get("labels")
        if isinstance(labels, dict) and not labels:
            metadata.pop("labels", None)

    return normalize_doc_subtree(doc)

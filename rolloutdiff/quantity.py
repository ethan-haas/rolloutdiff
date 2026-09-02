"""Component: Kubernetes resource-quantity comparison (Family 2 fix) and
typed-scalar equality (Family 4 fix).

Both escapes share one root cause: the differ compared these fields as raw
STRINGS, so two textually different but semantically identical values
(`1Gi` vs `1024Mi`; `3` vs `"3"`) were flagged as changes. Per SPEC's
DESIGN RULE ("no natural-language recognition, and no guessing outside a
declared table"), the fix is a DECLARED table of exactly which field-path
SUFFIXES are quantity-typed / integer-typed -- never a guess based on a
value's shape alone. Any field not in one of these two declared sets below
still compares as a raw string, byte-for-byte, unchanged from prior
behavior.
"""
from __future__ import annotations

import re
from decimal import Decimal, InvalidOperation
from typing import Optional

# ---------------------------------------------------------------------------
# Family 2 -- k8s resource.Quantity comparison
# ---------------------------------------------------------------------------
# Declared: a bracket-stripped field path is quantity-typed iff its tail is
# `resources.requests.<name>` or `resources.limits.<name>`.
# Source: https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.29/#resourcerequirements-v1-core
# This single pattern covers container `resources.requests`/`resources.limits`
# (cpu/memory/ephemeral-storage/custom resources) AND PersistentVolumeClaim /
# StatefulSet volumeClaimTemplates `spec.resources.requests.storage` -- both
# are literally the same nested `resources: {requests: {...}, limits: {...}}`
# shape in the k8s API, so one declared pattern covers both without
# special-casing PVC separately.
_QUANTITY_PATH_RE = re.compile(r"(^|\.)resources\.(requests|limits)\.[^.\[\]]+$")

# k8s resource.Quantity suffixes: binary (1024^n) and decimal (1000^n).
# Source: https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.29/#quantity-resource-core
_BINARY_SUFFIXES = {
    "Ki": 1024, "Mi": 1024 ** 2, "Gi": 1024 ** 3,
    "Ti": 1024 ** 4, "Pi": 1024 ** 5, "Ei": 1024 ** 6,
}
_DECIMAL_SUFFIXES = {
    "k": 1000, "M": 1000 ** 2, "G": 1000 ** 3,
    "T": 1000 ** 4, "P": 1000 ** 5, "E": 1000 ** 6,
}

# Longest suffixes first so e.g. "Mi" is tried before a spurious partial "M"
# match; Python re backtracks correctly regardless, this order is just
# documentation of intent.
_QUANTITY_RE = re.compile(
    r"^([+-]?[0-9]+(?:\.[0-9]+)?)(Ei|Pi|Ti|Gi|Mi|Ki|E|P|T|G|M|k|m)?$"
)


def is_quantity_path(pattern_path: str) -> bool:
    """True iff `pattern_path` (bracket-stripped) is declared quantity-typed."""
    return bool(_QUANTITY_PATH_RE.search(pattern_path))


def parse_quantity(value) -> Optional[Decimal]:
    """Parse a k8s resource.Quantity into a Decimal of its base unit
    (bytes for memory/storage, cores for cpu, etc). Returns None if `value`
    is not a parseable quantity -- the caller must then fall back to a
    plain (unequal) comparison; an unparseable value is NEVER guessed
    equal."""
    if isinstance(value, bool):
        return None  # bool is a distinct JSON type; never treated as a quantity
    if isinstance(value, (int, float)):
        try:
            return Decimal(str(value))
        except InvalidOperation:
            return None
    if not isinstance(value, str):
        return None
    m = _QUANTITY_RE.match(value.strip())
    if not m:
        return None
    num_str, suffix = m.groups()
    try:
        num = Decimal(num_str)
    except InvalidOperation:
        return None
    if suffix is None:
        return num
    if suffix in _BINARY_SUFFIXES:
        return num * _BINARY_SUFFIXES[suffix]
    if suffix in _DECIMAL_SUFFIXES:
        return num * _DECIMAL_SUFFIXES[suffix]
    if suffix == "m":
        return num / 1000
    return None  # unreachable: every group the regex can capture is handled


def quantities_equal(before, after) -> bool:
    """True iff both sides parse as k8s quantities AND are numerically
    equal (e.g. `1Gi` == `1024Mi`). False -- never guessed -- if either
    side fails to parse, so an unparseable value is always treated as a
    real (unequal) change rather than silently accepted."""
    qb = parse_quantity(before)
    qa = parse_quantity(after)
    if qb is None or qa is None:
        return False
    return qb == qa


# ---------------------------------------------------------------------------
# Family 4 -- typed-scalar (integer) equality
# ---------------------------------------------------------------------------
# Declared: field-path suffixes whose k8s OpenAPI schema type is a bare
# `integer` -- deliberately NOT the IntOrString union type. Fields like
# PodDisruptionBudget `minAvailable`/`maxUnavailable` accept a percentage
# STRING ("50%") as a genuinely different value shape from an integer count,
# so they are excluded here rather than risk conflating "50%" with the
# integer 50 (see README "typed-scalar equality" boundary note).
# Source: apps/v1 DeploymentSpec.replicas / StatefulSetSpec.replicas;
# autoscaling/v2 HorizontalPodAutoscalerSpec.minReplicas/.maxReplicas;
# batch/v1 JobSpec.parallelism/.backoffLimit -- all declared `integer` (not
# IntOrString) in the OpenAPI schema.
TYPED_INT_FIELDS = {
    "spec.replicas",
    "spec.minReplicas",
    "spec.maxReplicas",
    "spec.parallelism",
    "spec.backoffLimit",
}


def is_typed_int_path(pattern_path: str) -> bool:
    return pattern_path in TYPED_INT_FIELDS


def as_declared_int(value) -> Optional[int]:
    """Parse `value` as a plain (non-IntOrString) integer. Returns None if
    it isn't one -- callers must never guess past that None."""
    if isinstance(value, bool):
        return None  # bool is JSON-distinct from int; never conflated
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        s = value.strip()
        core = s[1:] if s[:1] == "-" else s
        if core.isdigit():
            return int(s)
    return None


def typed_scalars_equal(before, after) -> bool:
    """`3 == "3"` -> True for a declared-integer field: these are
    already-rendered manifests, so a quoted vs. bare integer is the same
    value, not a semantic change (see README for the alternative
    considered -- malformed-input exit(2) -- and why value-equality was
    chosen instead)."""
    bi, ai = as_declared_int(before), as_declared_int(after)
    return bi is not None and ai is not None and bi == ai

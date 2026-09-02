"""Component 4: Differ.

Walks normalized before/after object trees and produces findings:
    {object_ref, field_path, classification, evidence, message}

field_path always resolves into the supplied (normalized-but-structurally-
equivalent) documents — list segments carry either a positional index
`[N]` or, for identity-keyed lists, `[key=value]`, both of which are
literal, followable addresses into the original YAML.

Classification comes ONLY from coverage_table.KIND_TABLE (component 3) plus
a small number of explicitly-documented value-aware overrides listed below.
Nothing here infers a classification outside those two sources; the
fallback for anything not covered is always "unknown".
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from . import coverage_table, server_defaults
from .normalize import KEYED_LIST_KEYS, normalize_doc
from .quantity import (
    as_declared_int,
    is_quantity_path,
    is_typed_int_path,
    quantities_equal,
    typed_scalars_equal,
)

_BRACKET_RE = re.compile(r"\[[^\]]*\]")

# Free-form string-keyed maps: compared as a single opaque leaf rather than
# recursed key-by-key. Two reasons: (1) semantically we only care THAT the
# bag changed, not which string key inside it did (annotations/labels are
# opaque metadata; ConfigMap/Secret data is an opaque blob per the
# documented mount-propagation boundary — see coverage_table.py); (2) it
# keeps field_path resolvable — arbitrary annotation/label keys can contain
# '.' or '/' (e.g. "app.kubernetes.io/name"), which would break the
# dot-separated path grammar path_resolve.py depends on.
LEAF_DICT_FIELDS = {"annotations", "labels", "data", "binaryData", "stringData"}

# severity used only to decide which of several *independently applicable*
# classifications for the SAME field_path is "worst" (spec section 4). It is
# NOT used to merge classifications across different field paths.
_SEVERITY = {
    "no-op": 0,
    "in-place": 1,
    "rolling-restart": 2,
    "recreate": 3,
    "disruption": 4,
    "privilege-change": 5,
    "data-loss": 6,
    "unknown": -1,  # unknown is a coverage statement, not a severity rank
}


@dataclass
class Finding:
    object_ref: Tuple[str, str, str, str]
    field_path: str
    classification: str
    evidence: Dict[str, Any]
    message: str

    def to_dict(self) -> dict:
        group, kind, namespace, name = self.object_ref
        return {
            "object_ref": {
                "group": group,
                "kind": kind,
                "namespace": namespace,
                "name": name,
            },
            "field_path": self.field_path,
            "classification": self.classification,
            "evidence": self.evidence,
            "message": self.message,
        }


def strip_brackets(path: str) -> str:
    """spec.template.spec.containers[name=app].image ->
       spec.template.spec.containers.image"""
    return _BRACKET_RE.sub("", path)


def _path_field_name(path: str) -> Optional[str]:
    """The dict key `value` (the thing living at `path`) was stored under in
    ITS OWN parent -- used only to decide, in `_walk_subtree_nodes` below,
    whether `value` (if itself a list) is one of the identity-keyed lists
    (KEYED_LIST_KEYS) or `value` (if itself a dict) is one of the opaque
    free-form maps (LEAF_DICT_FIELDS).

    A path ending in a bracket segment (e.g. "...volumes[name=sock]") names
    a LIST ITEM, not a value stored under a field name of its own -- keyed-
    list items are always dicts (the identity field lives ON the item, never
    on the list itself), so there is no field_name to recover there and this
    correctly returns None.
    """
    if not path or path.endswith("]"):
        return None
    return path.rsplit(".", 1)[-1]


def _walk_subtree_nodes(field_name: Optional[str], path: str, value: Any):
    """Pre-order walk of every node inside an added/removed subtree,
    yielding (concrete_field_path, value_at_that_path) for the node itself
    before recursing into it. Mirrors the exact tree-shape conventions the
    rest of the differ already uses -- LEAF_DICT_FIELDS opacity,
    KEYED_LIST_KEYS list-identity bracket notation, positional brackets for
    everything else -- so every path yielded here is guaranteed to resolve
    with the same grammar path_resolve.py expects (dots between dict-key
    hops, bracket groups only ever attached to the key segment naming the
    list they index into).

    This is the root-cause fix for the add/remove-subtree blind spot: the
    generic add/remove finding used to classify ONLY the field_path at the
    add/remove point itself (e.g. "spec.template.spec.volumes"), which is
    coarser than -- and therefore never matches -- the coverage table's
    more specific descendant rules (e.g.
    "spec.template.spec.volumes.hostPath"). Walking every node inside the
    added/removed value and classifying each one lets the caller pick the
    worst (highest-severity) covered classification found anywhere in the
    subtree, not just at its root.
    """
    yield path, value
    if field_name in LEAF_DICT_FIELDS and isinstance(value, dict):
        return  # opaque leaf (annotations/labels/data/...): do not descend
    if isinstance(value, dict):
        for key in sorted(value.keys()):
            child_path = f"{path}.{key}" if path else key
            yield from _walk_subtree_nodes(key, child_path, value[key])
        return
    if isinstance(value, list):
        key = KEYED_LIST_KEYS.get(field_name or "")
        if key and value and all(isinstance(it, dict) and key in it for it in value):
            for item in value:
                child_path = f"{path}[{key}={item.get(key)}]"
                yield from _walk_subtree_nodes(None, child_path, item)
        else:
            for idx, item in enumerate(value):
                child_path = f"{path}[{idx}]"
                yield from _walk_subtree_nodes(None, child_path, item)
        return
    # scalar: already yielded above, nothing further to descend into


def classify_path(object_ref, field_path: str) -> Tuple[str, str]:
    """Return (classification, note) for a concrete field_path on the given
    object, using ONLY the coverage table. Longest-prefix match wins.
    Unmatched (unknown kind OR unmatched field) -> ('unknown', ...)."""
    kind_key = coverage_table.kind_key_for(object_ref)
    table_entry = coverage_table.KIND_TABLE.get(kind_key)
    if table_entry is None:
        return "unknown", f"kind {kind_key} is not in the coverage table"

    pattern_path = strip_brackets(field_path)
    best_match: Optional[Tuple[str, str, str]] = None  # (pattern, cls, note)
    for pattern, cls, note in table_entry["rules"]:
        if pattern_path == pattern or pattern_path.startswith(pattern + "."):
            if best_match is None or len(pattern) > len(best_match[0]):
                best_match = (pattern, cls, note)
    if best_match is None:
        return "unknown", (
            f"field '{pattern_path}' on kind {kind_key} is not in the "
            "coverage table"
        )
    return best_match[1], best_match[2]


def _expand_atomic_grants(rule: dict) -> set:
    """Expand one PolicyRule into its atomic (apiGroup, resource, verb,
    resourceNames) grants (cross-product) plus nonResourceURL grants, so
    that "verbs: [get, list] -> [get]" compares as ONE grant removed rather
    than "whole rule replaced" (which would otherwise look like an add+
    remove and misclassify a pure narrowing as broadened).

    Boundary: resourceNames is kept as its own tuple dimension rather than
    treated as a further restriction on an unnamed grant — a rule WITH
    resourceNames and a rule WITHOUT are literally different atomic grants
    here, not compared as narrower/wider variants of each other. Documented
    simplification; see README.
    """
    if not isinstance(rule, dict):
        return set()
    api_groups = rule.get("apiGroups") or [""]
    resources = rule.get("resources") or []
    verbs = rule.get("verbs") or []
    resource_names = tuple(sorted(str(v) for v in (rule.get("resourceNames") or [])))
    non_resource_urls = rule.get("nonResourceURLs") or []

    grants = set()
    for ag in api_groups:
        for res in resources:
            for v in verbs:
                grants.add(("resource", str(ag), str(res), str(v), resource_names))
    for url in non_resource_urls:
        for v in verbs:
            grants.add(("nonResourceURL", str(url), str(v)))
    return grants


def classify_rbac_rules(before_rules: list, after_rules: list) -> Tuple[str, str]:
    """Role/ClusterRole `rules` is a set of PolicyRule, not ordered and not
    identity-keyed. Compared at the ATOMIC GRANT level (see
    _expand_atomic_grants) so that narrowing one verb out of a multi-verb
    rule is correctly seen as a removal, not a whole-rule replace.
    Broadened (any atomic grant added) -> privilege-change. Strictly
    narrowed (only grants removed) -> in-place. Anything ambiguous
    (both added and removed) defaults to privilege-change (conservative:
    unsure is never the less-severe read for a security-relevant field)."""
    before_grants = set()
    for r in (before_rules or []):
        before_grants |= _expand_atomic_grants(r)
    after_grants = set()
    for r in (after_rules or []):
        after_grants |= _expand_atomic_grants(r)

    added = after_grants - before_grants
    removed = before_grants - after_grants
    if not added and not removed:
        return "no-op", "rules unchanged after canonicalization"
    if added:
        return "privilege-change", (
            f"{len(added)} grant(s) added and {len(removed)} removed: RBAC "
            "grant broadened"
        )
    return "in-place", f"{len(removed)} grant(s) removed only: RBAC grant narrowed"


def classify_rbac_subjects(before_subjs: list, after_subjs: list) -> Tuple[str, str]:
    def key(s):
        if not isinstance(s, dict):
            return str(s)
        return (s.get("kind"), s.get("namespace", ""), s.get("name"))

    before_set = {key(s) for s in (before_subjs or [])}
    after_set = {key(s) for s in (after_subjs or [])}
    added = after_set - before_set
    removed = before_set - after_set
    if not added and not removed:
        return "no-op", "subjects unchanged"
    if added:
        return "privilege-change", (
            f"{len(added)} subject(s) added and {len(removed)} removed: "
            "grant broadened"
        )
    return "in-place", f"{len(removed)} subject(s) removed only: grant narrowed"


class Differ:
    def __init__(self):
        self.findings: List[Finding] = []

    # -- value-level helpers -------------------------------------------------
    def _is_keyed_list(self, field_name: Optional[str], items: list) -> Optional[str]:
        key = KEYED_LIST_KEYS.get(field_name or "")
        if key and all(isinstance(it, dict) and key in it for it in items):
            return key
        return None

    def _emit(self, object_ref, path: str, classification: str, before, after, message: str):
        self.findings.append(
            Finding(
                object_ref=object_ref,
                field_path=path,
                classification=classification,
                evidence={"before": before, "after": after},
                message=message,
            )
        )

    def _emit_classified(self, object_ref, path: str, before, after, verb: str):
        cls, note = classify_path(object_ref, path)
        msg = f"{verb} at '{path}': {note}"
        self._emit(object_ref, path, cls, before, after, msg)

    def _emit_subtree_classified(self, object_ref, path: str, before, after, verb: str):
        """Classify an added/removed subtree by the WORST covered leaf
        found anywhere inside it, not just the generic rule at the add/
        remove point (see `_walk_subtree_nodes`).

        Direction (add vs remove) is treated the same way the coverage
        table already treats it for a plain scalar leaf change today (see
        `classify_path`, which is called identically from `_diff_added` and
        `_diff_removed` for a leaf): the table's classification for a given
        field is direction-agnostic. Removing a `privileged: true` flag is a
        de-escalation in practice, but it is still a security-relevant
        change a reviewer wants surfaced -- exactly as a bare leaf-level
        removal of `privileged` already gets classified `privilege-change`
        today. This keeps add and remove symmetric instead of introducing a
        new, unrequested special case for the subtree-remove direction only.

        Guarantee: this can only ESCALATE the classification found at
        `path` itself, never downgrade it -- `best` starts at the generic
        (base) classification and is only replaced by a strictly
        higher-severity leaf, so an added/removed subtree can never surface
        as a class less severe than treating it as a single opaque change
        would have (the fail-unsafe invariant the task asks to guard).
        """
        value = after if after is not None else before
        base_cls, base_note = classify_path(object_ref, path)
        best_cls, best_path, best_note = base_cls, path, base_note
        best_severity = _SEVERITY.get(base_cls, -1)

        if isinstance(value, (dict, list)):
            field_name = _path_field_name(path)
            for leaf_path, _leaf_value in _walk_subtree_nodes(field_name, path, value):
                if leaf_path == path:
                    continue
                leaf_cls, leaf_note = classify_path(object_ref, leaf_path)
                leaf_severity = _SEVERITY.get(leaf_cls, -1)
                if leaf_severity > best_severity:
                    best_severity = leaf_severity
                    best_cls, best_path, best_note = leaf_cls, leaf_path, leaf_note

        if best_path != path:
            msg = (
                f"{verb} at '{path}': subtree contains covered field "
                f"'{best_path}' ({best_note}) -- classification is the "
                "worst covered leaf found inside the added/removed "
                "subtree, not the generic rule at the add/remove point "
                "(an added/removed subtree must never downgrade a covered "
                "high-severity leaf to a generic classification)"
            )
        else:
            msg = f"{verb} at '{path}': {best_note}"
        self._emit(object_ref, best_path, best_cls, before, after, msg)

    # -- special-cased fields --------------------------------------------------
    def _handle_special(self, object_ref, path: str, before, after) -> bool:
        """Value-aware overrides that the flat coverage table cannot express.
        Returns True if this call fully handled emitting a finding for the
        (before,after) pair at `path` (caller should not also run the
        generic table-driven path)."""
        kind = object_ref[1]
        pattern_path = strip_brackets(path)

        if pattern_path == "spec.replicas" and kind in ("Deployment", "StatefulSet"):
            if before != after:
                # Use the declared-integer parse when both sides parse
                # (Family 4): a string "0" must trigger the same
                # scale-to-zero override as the integer 0 does, since they
                # are the same value on an already-typed field.
                after_int = as_declared_int(after)
                before_int = as_declared_int(before)
                after_is_zero = (after_int == 0) if after_int is not None else (after == 0)
                before_is_zero = (before_int == 0) if before_int is not None else (before == 0)
                if after_is_zero and not before_is_zero:
                    self._emit(
                        object_ref, path, "disruption", before, after,
                        f"spec.replicas {before} -> 0: scales the workload "
                        "to zero running pods (disruption override on the "
                        "in-place replicas rule)",
                    )
                else:
                    self._emit_classified(object_ref, path, before, after, "replicas changed")
            return True

        if pattern_path == "rules" and kind in ("Role", "ClusterRole"):
            cls, note = classify_rbac_rules(before, after)
            if cls != "no-op":
                self._emit(object_ref, path, cls, before, after, f"rules changed: {note}")
            return True

        if pattern_path == "subjects" and kind in ("RoleBinding", "ClusterRoleBinding"):
            cls, note = classify_rbac_subjects(before, after)
            if cls != "no-op":
                self._emit(object_ref, path, cls, before, after, f"subjects changed: {note}")
            return True

        return False

    # -- recursive tree walk ---------------------------------------------------
    def _diff_dict(self, object_ref, before: dict, after: dict, path: str):
        for key in sorted(set(before.keys()) | set(after.keys())):
            child_path = f"{path}.{key}" if path else key
            in_before = key in before
            in_after = key in after
            if in_before and not in_after:
                self._diff_removed(object_ref, child_path, before[key])
            elif in_after and not in_before:
                self._diff_added(object_ref, child_path, after[key])
            else:
                self._diff_value(object_ref, before[key], after[key], child_path, field_name=key)

    def _diff_removed(self, object_ref, path: str, value):
        if self._handle_special(object_ref, path, value, None):
            return
        self._emit_subtree_classified(object_ref, path, value, None, "removed")

    def _diff_added(self, object_ref, path: str, value):
        if self._handle_special(object_ref, path, None, value):
            return
        self._emit_subtree_classified(object_ref, path, None, value, "added")

    def _diff_value(self, object_ref, before, after, path: str, field_name: Optional[str] = None):
        if before == after:
            return

        pattern_path = strip_brackets(path)

        # Family 4: typed-scalar (declared-integer) equality -- 3 vs "3" is
        # the same value on a field the table knows is an OpenAPI `integer`
        # (never IntOrString; see quantity.TYPED_INT_FIELDS). Checked before
        # the raw before/after values ever reach a classification rule.
        if is_typed_int_path(pattern_path) and typed_scalars_equal(before, after):
            return

        # Family 2: k8s resource.Quantity equality -- 1Gi vs 1024Mi is the
        # same value on a field the table knows is quantity-typed (see
        # quantity.is_quantity_path). A genuine shrink/grow still differs
        # numerically and falls through unchanged to the generic path below.
        if is_quantity_path(pattern_path) and quantities_equal(before, after):
            return

        if self._handle_special(object_ref, path, before, after):
            return

        if field_name in LEAF_DICT_FIELDS and isinstance(before, dict) and isinstance(after, dict):
            self._emit_classified(object_ref, path, before, after, "changed")
            return

        if isinstance(before, dict) and isinstance(after, dict):
            self._diff_dict(object_ref, before, after, path)
            return

        if isinstance(before, list) and isinstance(after, list):
            key = self._is_keyed_list(field_name, before) or self._is_keyed_list(field_name, after)
            if key:
                self._diff_keyed_list(object_ref, before, after, path, key)
            else:
                # positional / order-sensitive: whole-list is one finding
                self._emit_classified(object_ref, path, before, after, "list changed")
            return

        # scalar (or dict-vs-list type mismatch, treated as a leaf change)
        self._emit_classified(object_ref, path, before, after, "changed")

    def _diff_keyed_list(self, object_ref, before: list, after: list, path: str, key: str):
        before_by_key = {str(item.get(key)): item for item in before}
        after_by_key = {str(item.get(key)): item for item in after}
        for k in sorted(set(before_by_key) | set(after_by_key)):
            child_path = f"{path}[{key}={k}]"
            if k in before_by_key and k not in after_by_key:
                self._diff_removed(object_ref, child_path, before_by_key[k])
            elif k in after_by_key and k not in before_by_key:
                self._diff_added(object_ref, child_path, after_by_key[k])
            else:
                self._diff_value(object_ref, before_by_key[k], after_by_key[k], child_path)

    # -- entry points ------------------------------------------------------
    def diff_object(self, object_ref, before_doc: Optional[dict], after_doc: Optional[dict]):
        if before_doc is None and after_doc is not None:
            kind_key = coverage_table.kind_key_for(object_ref)
            table_entry = coverage_table.KIND_TABLE.get(kind_key)
            cls = table_entry["object_added"] if table_entry else "unknown"
            note = "new object" if table_entry else f"kind {kind_key} not in coverage table"
            self._emit(object_ref, "", cls, None, after_doc, f"object added: {note}")
            return
        if after_doc is None and before_doc is not None:
            kind_key = coverage_table.kind_key_for(object_ref)
            table_entry = coverage_table.KIND_TABLE.get(kind_key)
            cls = table_entry["object_removed"] if table_entry else "unknown"
            note = "object removed" if table_entry else f"kind {kind_key} not in coverage table"
            self._emit(object_ref, "", cls, before_doc, None, f"object removed: {note}")
            return
        if before_doc is None and after_doc is None:
            return
        before_norm = normalize_doc(before_doc)
        after_norm = normalize_doc(after_doc)
        # Family 3: strip any field ADDED in `after_norm` whose value
        # matches a declared server-injected default (see
        # server_defaults.SERVER_DEFAULTS) -- pairwise, because deciding
        # "was this injected" needs both sides, and some defaults
        # (imagePullPolicy) depend on a sibling field's value in `after`.
        after_norm = server_defaults.strip_injected_defaults(object_ref, before_norm, after_norm)
        if before_norm == after_norm:
            return
        self._diff_dict(object_ref, before_norm, after_norm, "")


def diff_all(before_objs: Dict[tuple, dict], after_objs: Dict[tuple, dict]) -> List[Finding]:
    d = Differ()
    all_refs = sorted(set(before_objs.keys()) | set(after_objs.keys()))
    for ref in all_refs:
        d.diff_object(ref, before_objs.get(ref), after_objs.get(ref))
    return d.findings

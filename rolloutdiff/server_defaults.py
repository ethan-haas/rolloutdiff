"""Component: declared table of well-known Kubernetes field-level
server-injected defaults (Family 3 fix).

The two-sided contract promises: "injected server defaults ... MUST
classify no-op". An `after` document that only ADDS a field the API server
would have injected anyway (a documented default) is not a semantic
change -- exactly like key reordering or annotation churn, which
`normalize.py` already treats as no-op. Per THE DESIGN RULE, this is a
DECLARED, versioned table -- never inferred from a field's name or shape,
and a field not listed here is never touched no matter what value it has.

`strip_injected_defaults` runs on the two NORMALIZED docs, right after
`normalize.py`'s per-doc pass and before the differ's tree walk. A
default-only addition is removed from the `after` copy entirely, so it
never reaches the differ and produces literally zero findings -- the same
no-op discipline every other non-semantic difference in this tool gets.
"""
from __future__ import annotations

import copy
import re
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from .normalize import KEYED_LIST_KEYS

_BRACKET_RE = re.compile(r"\[[^\]]*\]")

Resolver = Union[str, Callable[[dict], Optional[str]]]


def _strip_brackets(path: str) -> str:
    return _BRACKET_RE.sub("", path)


def _image_pull_policy_default(image: Optional[str]) -> Optional[str]:
    """core/v1 Container.imagePullPolicy: defaults to 'Always' when the tag
    is omitted or is `:latest`, 'IfNotPresent' otherwise.
    Source: https://kubernetes.io/docs/concepts/containers/images/#imagepullpolicy-defaulting
    """
    if not isinstance(image, str) or not image:
        return None
    last_segment = image.rsplit("/", 1)[-1]  # drop registry host/path, keep name:tag
    if ":" in last_segment:
        tag = last_segment.rsplit(":", 1)[-1]
        return "Always" if tag == "latest" else "IfNotPresent"
    return "Always"  # no tag at all -> implicit :latest


def _resolve_image_pull_policy(sibling_after: dict) -> Optional[str]:
    if not isinstance(sibling_after, dict):
        return None
    return _image_pull_policy_default(sibling_after.get("image"))


# entry: (kinds, path_suffix, resolver, source)
#   kinds:       None = applies to any covered kind, else a set of literal
#                `kind` strings this rule is restricted to.
#   path_suffix: matched against the bracket-stripped field path's TAIL
#                (pattern_path == suffix, or pattern_path.endswith("."+suffix))
#                -- suffix matching (not full-path matching) is what makes
#                one declared entry apply correctly under EVERY wrapper
#                prefix a pod template can live at (spec.template vs
#                spec.jobTemplate.spec.template) without duplicating rows.
#   resolver:    a literal default value, or callable(sibling_after_dict)
#                -> value | None (value-dependent default, e.g.
#                imagePullPolicy depends on the sibling `image` tag).
#   source:      citation for the default.
SERVER_DEFAULTS: List[Tuple[Optional[set], str, Resolver, str]] = [
    ({"Service"}, "spec.ports.protocol", "TCP",
     "core/v1 ServicePort.protocol defaults to 'TCP' when omitted -- "
     "https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.29/#serviceport-v1-core"),
    (None, "containers.imagePullPolicy", _resolve_image_pull_policy,
     "core/v1 Container.imagePullPolicy defaulting rule -- "
     "https://kubernetes.io/docs/concepts/containers/images/#imagepullpolicy-defaulting"),
    (None, "containers.terminationMessagePath", "/dev/termination-log",
     "core/v1 Container.terminationMessagePath defaults to "
     "'/dev/termination-log' -- "
     "https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.29/#container-v1-core"),
    (None, "containers.terminationMessagePolicy", "File",
     "core/v1 Container.terminationMessagePolicy defaults to 'File' -- "
     "same source as terminationMessagePath."),
    ({"Deployment", "StatefulSet", "DaemonSet"}, "spec.restartPolicy", "Always",
     "core/v1 PodSpec.restartPolicy: the API server requires/defaults this "
     "to 'Always' for pods owned by a Deployment/StatefulSet/DaemonSet "
     "controller. Job/CronJob pod templates have NO default here (the API "
     "server requires an explicit OnFailure/Never) -- deliberately "
     "excluded from this rule's `kinds`, see README."),
    (None, "spec.dnsPolicy", "ClusterFirst",
     "core/v1 PodSpec.dnsPolicy defaults to 'ClusterFirst' -- "
     "https://kubernetes.io/docs/concepts/services-networking/dns-pod-service/#pod-s-dns-policy"),
]


def resolve_default(kind: str, pattern_path: str, sibling_after: dict):
    """Return the declared default for (kind, pattern_path) given the
    AFTER-side sibling dict (the dict this field lives directly inside),
    or None if no declared entry matches -- callers must treat None as
    "not a documented default", never guess further."""
    for kinds, suffix, resolver, _source in SERVER_DEFAULTS:
        if kinds is not None and kind not in kinds:
            continue
        if pattern_path == suffix or pattern_path.endswith("." + suffix):
            value = resolver(sibling_after) if callable(resolver) else resolver
            if value is not None:
                return value
    return None


def _field_name_for(path: str) -> Optional[str]:
    if not path or path.endswith("]"):
        return None
    return path.rsplit(".", 1)[-1]


def _strip_value(kind: str, before: Any, after: Any, path: str) -> Any:
    """Mirror-walk `after` against `before` (same shape conventions as
    differ.py: dotted dict-key hops, KEYED_LIST_KEYS identity brackets for
    order-insensitive lists, positional brackets otherwise), dropping any
    scalar field that was ADDED in `after` (absent at the same path in
    `before`) and whose value matches this table's declared default."""
    if isinstance(after, dict):
        if not isinstance(before, dict):
            return after  # whole subtree added/type-mismatched: out of scope, leave as-is
        out: Dict[str, Any] = {}
        for k, v in after.items():
            child_path = f"{path}.{k}" if path else k
            if k not in before:
                pattern_path = _strip_brackets(child_path)
                default = resolve_default(kind, pattern_path, after)
                if default is not None and v == default:
                    continue  # drop: server-injected default, not a real semantic add
                out[k] = v
            else:
                out[k] = _strip_value(kind, before[k], v, child_path)
        return out

    if isinstance(after, list) and isinstance(before, list):
        field_name = _field_name_for(path)
        key = KEYED_LIST_KEYS.get(field_name or "")
        if key and after and all(isinstance(it, dict) and key in it for it in after):
            before_by_key = {str(it.get(key)): it for it in before if isinstance(it, dict)}
            out_list = []
            for item in after:
                k = str(item.get(key))
                child_path = f"{path}[{key}={k}]"
                out_list.append(_strip_value(kind, before_by_key.get(k, {}), item, child_path))
            return out_list
        # positional (order-sensitive) list: walk index-wise so a
        # default-only addition INSIDE one item (e.g. Service ports[0]
        # gaining `protocol: TCP`) is still recognized even though the
        # list as a whole is compared positionally elsewhere in the differ.
        out_list = []
        for idx, item in enumerate(after):
            child_path = f"{path}[{idx}]"
            b_item = before[idx] if idx < len(before) else {}
            out_list.append(_strip_value(kind, b_item, item, child_path))
        return out_list

    return after


def strip_injected_defaults(object_ref, before_doc: dict, after_doc: dict) -> dict:
    """Return a deep copy of `after_doc` with every field that is (a)
    absent at the same path in `before_doc` and (b) equal to this table's
    documented default for (kind, path) removed. Declared-table only: a
    field not in SERVER_DEFAULTS is never touched regardless of its
    value."""
    kind = object_ref[1]
    return _strip_value(kind, before_doc, copy.deepcopy(after_doc), "")

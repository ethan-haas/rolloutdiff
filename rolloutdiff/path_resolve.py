"""field_path resolution — proves a finding's field_path is not a dangling
claim: it must walk into the actual supplied document.

Path grammar produced by differ.py:
    seg := key ("[" index_or_keyed "]")*
    path := "" | seg ("." seg)*
    index_or_keyed := DIGITS | KEY "=" VALUE

Dots only ever separate dict-key hops; bracket groups always attach
directly to the key segment that names the list (e.g.
"containers[name=app]"), never introduce their own dot. This holds because
differ.py never recurses element-by-element into free-form string-keyed
maps (annotations/labels/data/binaryData/stringData are compared as opaque
leaves — see differ.LEAF_DICT_FIELDS) and only builds keyed-list segments
from identity fields (container/volume/env `name`) that are plain
identifiers, never containing '.'.
"""
from __future__ import annotations

import re
from typing import Any, Tuple

_SEG_RE = re.compile(r"^([^\[\]]*)((?:\[[^\]]*\])*)$")
_BRACKET_RE = re.compile(r"\[([^\]]*)\]")


class PathResolutionError(Exception):
    pass


def resolve_field_path(doc: Any, field_path: str) -> Tuple[bool, Any]:
    """Returns (found, value_at_path). found=False if the path does not
    resolve into `doc` (dangling / malformed finding)."""
    if field_path == "":
        return True, doc
    node = doc
    for raw_seg in field_path.split("."):
        m = _SEG_RE.match(raw_seg)
        if not m:
            return False, None
        key, brackets = m.group(1), m.group(2)
        if key:
            if not isinstance(node, dict) or key not in node:
                return False, None
            node = node[key]
        for b in _BRACKET_RE.findall(brackets):
            if "=" in b:
                bkey, bval = b.split("=", 1)
                if not isinstance(node, list):
                    return False, None
                match = None
                for item in node:
                    if isinstance(item, dict) and str(item.get(bkey)) == bval:
                        match = item
                        break
                if match is None:
                    return False, None
                node = match
            else:
                if not isinstance(node, list) or not b.isdigit() or int(b) >= len(node):
                    return False, None
                node = node[int(b)]
    return True, node

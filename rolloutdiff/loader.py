"""Component 1: Loader.

Parses multi-doc YAML (files or directories) into a mapping of object_ref ->
document. NO network, NO kubeconfig, NO cluster contact anywhere in this
module or anything it calls. One dependency: PyYAML.

object_ref = (group, kind, namespace, name)
  group     = the "group" segment of apiVersion ("" for core/v1, "apps" for
              apps/v1, etc). Extracted from text only, never looked up
              against a live API server.
  namespace = metadata.namespace if present, else "" (cluster-scoped or
              unspecified). We do NOT default unset namespace to "default" —
              that would be a guess this tool does not make; it is reported
              as the literal empty string, matching "not specified" rather
              than asserting a value the input never stated.
"""
from __future__ import annotations

import os
from typing import Dict, Iterable, Iterator, List, Tuple

import yaml

from .errors import MalformedInputError

ObjectRef = Tuple[str, str, str, str]


def _group_from_api_version(api_version: str) -> str:
    if "/" in api_version:
        return api_version.split("/", 1)[0]
    return ""


def object_ref_for(doc: dict, source_desc: str) -> ObjectRef:
    if not isinstance(doc, dict):
        raise MalformedInputError(f"{source_desc}: document is not a mapping")
    api_version = doc.get("apiVersion")
    kind = doc.get("kind")
    if not api_version or not isinstance(api_version, str):
        raise MalformedInputError(f"{source_desc}: missing/invalid apiVersion")
    if not kind or not isinstance(kind, str):
        raise MalformedInputError(f"{source_desc}: missing/invalid kind")
    metadata = doc.get("metadata")
    if not isinstance(metadata, dict):
        raise MalformedInputError(f"{source_desc}: missing/invalid metadata")
    name = metadata.get("name")
    if not name or not isinstance(name, str):
        raise MalformedInputError(f"{source_desc}: missing/invalid metadata.name")
    namespace = metadata.get("namespace") or ""
    group = _group_from_api_version(api_version)
    return (group, kind, namespace, name)


def _iter_yaml_files(path: str) -> Iterator[str]:
    if os.path.isdir(path):
        for root, _dirs, files in sorted(os.walk(path)):
            for fname in sorted(files):
                if fname.endswith((".yaml", ".yml")):
                    yield os.path.join(root, fname)
    elif os.path.isfile(path):
        yield path
    else:
        raise MalformedInputError(f"path does not exist: {path}")


def load_docs_from_text(text: str, source_desc: str) -> List[dict]:
    """Parse a multi-doc YAML string (raw / helm-template / kustomize-build
    shaped — all are plain YAML streams with `---` separators and `#`
    comments, which yaml.safe_load_all already ignores)."""
    try:
        raw_docs = list(yaml.safe_load_all(text))
    except yaml.YAMLError as exc:
        raise MalformedInputError(f"{source_desc}: YAML parse error: {exc}") from exc
    docs = []
    for doc in raw_docs:
        if doc is None:
            continue  # empty doc between '---' separators, not an error
        if not isinstance(doc, dict):
            raise MalformedInputError(
                f"{source_desc}: top-level YAML document is not a mapping"
            )
        # List-shaped resources (e.g. a "List" kind wrapping items) are out
        # of scope; we only accept single-object docs. Anything with a
        # "items" list AND kind == "List" is unwrapped for convenience.
        if doc.get("kind") == "List" and isinstance(doc.get("items"), list):
            for item in doc["items"]:
                if isinstance(item, dict):
                    docs.append(item)
            continue
        docs.append(doc)
    return docs


def load_docs(path: str) -> Dict[ObjectRef, dict]:
    """Load all k8s object docs found under `path` (file or directory).

    Returns object_ref -> doc. Raises MalformedInputError on duplicate
    object_ref (ambiguous input) or unparsable content.
    """
    result: Dict[ObjectRef, dict] = {}
    for fpath in _iter_yaml_files(path):
        with open(fpath, "r", encoding="utf-8") as fh:
            text = fh.read()
        docs = load_docs_from_text(text, fpath)
        for doc in docs:
            ref = object_ref_for(doc, fpath)
            if ref in result:
                raise MalformedInputError(
                    f"{fpath}: duplicate object_ref {ref} (already loaded)"
                )
            result[ref] = doc
    if not result:
        raise MalformedInputError(f"no k8s object documents found under: {path}")
    return result

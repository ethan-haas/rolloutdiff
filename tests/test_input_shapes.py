""">= 3 input shapes per rule produce IDENTICAL classification for the
same semantic change. Raw multi-doc YAML, helm-template-shaped output,
kustomize-build-shaped output. No helm/kustomize binaries invoked anywhere
-- these are hand-synthesized text shapes (see corpus.render_* docstrings)."""
import copy

from rolloutdiff import corpus
from rolloutdiff.loader import load_docs_from_text
from rolloutdiff.differ import diff_all

SHAPES = {
    "raw": corpus.render_raw,
    "helm": corpus.render_helm_style,
    "kustomize": corpus.render_kustomize_style,
}


def _classify_via_shape(shape_fn, before_docs, after_docs):
    before_text = shape_fn(before_docs)
    after_text = shape_fn(after_docs)
    before_parsed = load_docs_from_text(before_text, "<before>")
    after_parsed = load_docs_from_text(after_text, "<after>")
    assert len(before_parsed) == len(before_docs)
    assert len(after_parsed) == len(after_docs)

    from rolloutdiff.loader import object_ref_for

    before_map = {object_ref_for(d, "<before>"): d for d in before_parsed}
    after_map = {object_ref_for(d, "<after>"): d for d in after_parsed}
    return diff_all(before_map, after_map)


def test_same_semantic_change_classifies_identically_across_three_shapes():
    dep = corpus.base_deployment()
    dep_after = copy.deepcopy(dep)
    dep_after["spec"]["template"]["spec"]["containers"][0]["image"] = "example/web:9.9.9"

    results = {}
    for shape_name, fn in SHAPES.items():
        findings = _classify_via_shape(fn, [dep], [dep_after])
        classes = sorted(f.classification for f in findings)
        results[shape_name] = classes

    assert len(SHAPES) >= 3
    unique_results = {tuple(v) for v in results.values()}
    assert len(unique_results) == 1, f"classification differs by input shape: {results}"
    assert list(unique_results)[0] == ("rolling-restart",)


def test_noop_stays_noop_across_three_shapes():
    dep = corpus.base_deployment()
    dep_reordered = {k: dep[k] for k in reversed(list(dep.keys()))}

    for shape_name, fn in SHAPES.items():
        findings = _classify_via_shape(fn, [dep], [dep_reordered])
        assert findings == [], f"shape {shape_name} produced findings for a no-op change: {findings}"


def test_multi_object_stream_parses_identically_across_shapes():
    docs = [corpus.base_deployment(), corpus.base_service(), corpus.base_configmap()]
    counts = {}
    for shape_name, fn in SHAPES.items():
        text = fn(docs)
        parsed = load_docs_from_text(text, "<test>")
        counts[shape_name] = len(parsed)
    assert set(counts.values()) == {3}

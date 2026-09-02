"""Unit coverage for the loader (component 1) and normalizer (component 2)
independent of the acceptance-gate corpus tests."""
import os
import tempfile

import pytest
import yaml

from rolloutdiff import corpus
from rolloutdiff.errors import MalformedInputError
from rolloutdiff.loader import load_docs, load_docs_from_text, object_ref_for
from rolloutdiff.normalize import normalize_doc


def test_object_ref_extracts_group_kind_namespace_name():
    dep = corpus.base_deployment()
    ref = object_ref_for(dep, "<test>")
    assert ref == ("apps", "Deployment", "prod", "web")


def test_object_ref_core_group_is_empty_string():
    svc = corpus.base_service()
    ref = object_ref_for(svc, "<test>")
    assert ref[0] == ""


def test_load_docs_from_text_skips_empty_docs_between_separators():
    text = "---\n\n---\n" + yaml.dump(corpus.base_service())
    docs = load_docs_from_text(text, "<test>")
    assert len(docs) == 1


def test_load_docs_from_text_rejects_non_mapping_top_level():
    with pytest.raises(MalformedInputError):
        load_docs_from_text("- 1\n- 2\n", "<test>")


def test_load_docs_missing_kind_raises_malformed():
    bad = {"apiVersion": "v1", "metadata": {"name": "x"}}
    with pytest.raises(MalformedInputError):
        object_ref_for(bad, "<test>")


def test_load_docs_duplicate_object_ref_raises():
    dep = corpus.base_deployment()
    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "a.yaml"), "w") as fh:
            yaml.dump(dep, fh)
        with open(os.path.join(d, "b.yaml"), "w") as fh:
            yaml.dump(dep, fh)
        with pytest.raises(MalformedInputError):
            load_docs(d)


def test_load_docs_nonexistent_path_raises():
    with pytest.raises(MalformedInputError):
        load_docs("/definitely/does/not/exist/rolloutdiff-test")


def test_normalize_strips_status_and_server_metadata():
    dep = corpus.base_deployment()
    dep["status"] = {"replicas": 3}
    dep["metadata"]["resourceVersion"] = "999"
    dep["metadata"]["uid"] = "xyz"
    norm = normalize_doc(dep)
    assert "status" not in norm
    assert "resourceVersion" not in norm["metadata"]
    assert "uid" not in norm["metadata"]


def test_normalize_drops_last_applied_configuration_annotation():
    dep = corpus.base_deployment()
    dep["metadata"]["annotations"] = {
        "kubectl.kubernetes.io/last-applied-configuration": "{...}",
    }
    norm = normalize_doc(dep)
    assert "annotations" not in norm["metadata"]


def test_normalize_env_list_is_order_insensitive():
    dep = corpus.base_deployment()
    env = dep["spec"]["template"]["spec"]["containers"][0]["env"]
    reversed_dep = corpus.copy.deepcopy(dep)
    reversed_dep["spec"]["template"]["spec"]["containers"][0]["env"] = list(reversed(env))
    assert normalize_doc(dep) == normalize_doc(reversed_dep)


def test_normalize_multiline_whitespace_ignored():
    from rolloutdiff.normalize import normalize_scalar

    a = "line1\nline2\n"
    b = "line1   \nline2\n\n\n"
    assert normalize_scalar(a) == normalize_scalar(b)

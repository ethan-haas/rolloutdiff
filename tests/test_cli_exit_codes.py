"""CLI exit codes: 0 no findings, 1 findings, 2 malformed input/usage."""
import copy
import os
import tempfile

import yaml

from rolloutdiff import corpus
from rolloutdiff.cli import main


def _write(dirpath, docs):
    for i, d in enumerate(docs):
        with open(os.path.join(dirpath, f"o{i}.yaml"), "w") as fh:
            yaml.dump(d, fh)


def test_exit_0_when_no_findings(capsys):
    dep = corpus.base_deployment()
    with tempfile.TemporaryDirectory() as b, tempfile.TemporaryDirectory() as a:
        _write(b, [dep])
        _write(a, [copy.deepcopy(dep)])
        code = main([b, a])
    assert code == 0


def test_exit_1_when_findings(capsys):
    dep = corpus.base_deployment()
    dep_after = copy.deepcopy(dep)
    dep_after["spec"]["replicas"] = 9
    with tempfile.TemporaryDirectory() as b, tempfile.TemporaryDirectory() as a:
        _write(b, [dep])
        _write(a, [dep_after])
        code = main([b, a])
    assert code == 1
    out = capsys.readouterr().out
    assert '"classification": "in-place"' in out


def test_exit_2_on_bad_usage(capsys):
    code = main(["only-one-arg"])
    assert code == 2


def test_exit_2_on_malformed_input(capsys):
    with tempfile.TemporaryDirectory() as b, tempfile.TemporaryDirectory() as a:
        with open(os.path.join(b, "bad.yaml"), "w") as fh:
            fh.write("apiVersion: v1\nkind: Service\n")  # missing metadata.name
        with open(os.path.join(a, "bad.yaml"), "w") as fh:
            fh.write("apiVersion: v1\nkind: Service\nmetadata:\n  name: x\n")
        code = main([b, a])
    assert code == 2


def test_report_includes_all_three_first_class_numbers(capsys):
    dep = corpus.base_deployment()
    dep_after = copy.deepcopy(dep)
    dep_after["spec"]["replicas"] = 9
    with tempfile.TemporaryDirectory() as b, tempfile.TemporaryDirectory() as a:
        _write(b, [dep])
        _write(a, [dep_after])
        main([b, a])
    out = capsys.readouterr().out
    assert '"unknown_rate"' in out
    assert '"detection_rate"' in out
    assert '"false_flag_rate"' in out

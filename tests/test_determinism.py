"""determinism across PROCESSES. >= 3 subprocesses, differing
PYTHONHASHSEED, byte-identical stdout. In-process repetition cannot test
this (dict/set iteration order effects from hash randomization only show up
across fresh interpreter processes)."""
import os
import subprocess
import sys
import tempfile

import yaml

from rolloutdiff import corpus

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def _write_docs(dirpath, docs):
    for i, d in enumerate(docs):
        with open(os.path.join(dirpath, f"obj{i}.yaml"), "w", encoding="utf-8") as fh:
            yaml.dump(d, fh)


def test_three_subprocesses_differing_hashseed_byte_identical_stdout():
    dep = corpus.base_deployment()
    import copy
    dep_after = copy.deepcopy(dep)
    dep_after["spec"]["template"]["spec"]["containers"][0]["image"] = "example/web:2.0.0"
    dep_after["spec"]["replicas"] = 5
    svc = corpus.base_service()
    svc_after = copy.deepcopy(svc)
    svc_after["spec"]["selector"]["app"] = "web-canary"
    unknown = corpus.base_unknown_crd()
    unknown_after = copy.deepcopy(unknown)
    unknown_after["spec"]["maxWidgets"] = 42

    with tempfile.TemporaryDirectory() as before_dir, tempfile.TemporaryDirectory() as after_dir:
        _write_docs(before_dir, [dep, svc, unknown])
        _write_docs(after_dir, [dep_after, svc_after, unknown_after])

        outputs = []
        seeds = ["0", "1", "42"]
        for seed in seeds:
            env = dict(os.environ)
            env["PYTHONHASHSEED"] = seed
            proc = subprocess.run(
                [sys.executable, "-m", "rolloutdiff", before_dir, after_dir],
                cwd=REPO_ROOT,
                env=env,
                capture_output=True,
                timeout=60,
            )
            assert proc.returncode == 1, f"seed={seed}: expected exit 1 (findings present), got {proc.returncode}, stderr={proc.stderr!r}"
            outputs.append(proc.stdout)

        assert len(outputs) == 3
        assert outputs[0] == outputs[1] == outputs[2], (
            "stdout differs across subprocesses with different "
            f"PYTHONHASHSEED: lens={[len(o) for o in outputs]}"
        )
        assert len(outputs[0]) > 0

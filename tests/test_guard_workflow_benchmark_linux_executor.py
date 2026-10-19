"""Controller conformance only; actual controls run through the owned Linux VM."""
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ci.gauntlet.benchmark.developer_oracles import DeveloperEvidenceError, probe_plan
from ci.gauntlet.benchmark.linux_executor import PodmanLinuxExecutor


def test_executor_refuses_host_candidate_execution_before_subprocess(monkeypatch):
    import ci.gauntlet.benchmark.linux_executor as executor_module

    monkeypatch.setattr(executor_module.sys, "platform", "darwin")

    def forbidden(*_, **__):
        pytest.fail("host constructor attempted process execution")

    monkeypatch.setattr(executor_module.subprocess, "Popen", forbidden)
    monkeypatch.setattr(executor_module.subprocess, "run", forbidden)
    plan = probe_plan("fix-failing-node-test", candidate_tree_digest="a" * 64)
    with pytest.raises(DeveloperEvidenceError, match="actual Linux VM root"):
        PodmanLinuxExecutor(Path("/candidate"), plan, image_id="sha256:" + "b" * 64,
                            signing_key=Ed25519PrivateKey.generate(), staging_parent=Path("/var/tmp"))


def test_private_umask_keeps_answers_private_and_public_bridges_traversable(tmp_path,monkeypatch):
    import os
    import stat
    from ci.gauntlet.benchmark import linux_executor as module
    from ci.gauntlet.benchmark.developer_oracles import source_tree_digest
    source=tmp_path/'candidate';source.mkdir(mode=0o700)
    (source/'code.js').write_text('export const fixture = 1;\n')
    stage=tmp_path/'stage';stage.mkdir(mode=0o700)
    executor=object.__new__(PodmanLinuxExecutor)
    executor.stage=stage
    executor.plan=probe_plan('fix-failing-node-test',candidate_tree_digest=source_tree_digest(source))
    monkeypatch.setattr(module.os,'chown',lambda *args,**kwargs:None)
    previous=os.umask(0o077)
    try:
        executor._stage(source)
        assert os.umask(0o077)==0o077
    finally:
        os.umask(previous)
    modes=lambda p:stat.S_IMODE(p.stat().st_mode)
    assert modes(stage)==modes(source)==0o700
    assert modes(stage/'trusted')==modes(stage/'trusted/public')==0o755
    assert modes(stage/'trusted/probes')==modes(stage/'trusted/package')==0o700
    assert modes(stage/'trusted/public/developer_node_bridge.mjs')==0o644
    assert modes(stage/'trusted/probes/developer_oracles.py')==0o600
    assert modes(stage/'trusted/package/ci/gauntlet/benchmark/json_data.py')==0o600

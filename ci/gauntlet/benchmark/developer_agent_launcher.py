"""Controller launch seams for the actual isolated developer SDK process."""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from .contracts import canonical_json
from .developer_sdk_gate import DeveloperSdkGate


class SdkLaunchError(RuntimeError):
    """A failed launch whose actual controller subprocess has already been reaped."""
    def __init__(self, process, original_exception):
        super().__init__(str(original_exception))
        self.process = process
        self.original_exception = original_exception


def stage_public_episode(public, config, *, copy_helpers=False):
    """Set public-file modes explicitly without changing caller or private umask."""
    if copy_helpers:
        from .mcp_agent_profile import config_profile
        names = ('developer_omp_episode.ts', 'developer_model_relay.py', 'developer_provider_relay.py',
                 'service_relay.py') + (('mcp_agent_surfaces.ts',) if config_profile(config) else ())
        for name in names:
            target = public / name
            shutil.copyfile(Path(__file__).with_name(name), target)
            target.chmod(0o644)
    episode = public / 'episode.json'
    episode.write_text(canonical_json(config))
    episode.chmod(0o644)


def prepare_product(*, root, public, inputs, python, source_sha, prefix_digest, bwrap_sha256,
                    executor_image_id, checkout, remote, home, git_root, prompt, deadline, tool_limit, bun,
                    provider,private_cell=None,package_version=None):
    if any(value is None for value in (python, source_sha, prefix_digest, bwrap_sha256, executor_image_id)):
        raise ValueError('protected developer requires frozen native prefix, source, bwrap, and executor image')
    product = None
    try:
        from .developer_product_runtime import DeveloperProductRuntime
        backend_options={} if private_cell is None else {'private_cell':private_cell}
        if package_version is not None:
            backend_options['package_version'] = package_version
        product = DeveloperProductRuntime(root=root / 'product', upstream=inputs.supervisor,
            public_mcp_directory=root / 'front', public_hook_directory=root / 'hooks',
            python=python, source_sha=source_sha, prefix_digest=prefix_digest, bwrap_sha256=bwrap_sha256,
            workspace_source=checkout, workspace_custody_root=git_root,
            provider_mounts=(remote, home), provider_custody_root=root, public_prompt=prompt,
            controller_session_id=root.name, deadline_seconds=deadline, max_tool_calls=tool_limit,
            executor_image_id=executor_image_id,**backend_options)
        helpers = product.stage_public_helpers(public)
        gate = DeveloperSdkGate(root / 'sdk-gate', bun=bun, product=product)
        gate.prepare()
    except BaseException:
        try:
            if product is not None:
                product.close()
        finally:
            try:
                provider.close()
            finally:
                inputs.close()
        raise
    return product, gate, helpers


def launch_sdk(*, name, events_path, errors_path, deadline, gate=None):
    with events_path.open('xb') as output, errors_path.open('xb') as errors:
        process = subprocess.Popen(['/usr/bin/podman', 'exec', name, '/runtime/bun',
            '/runtime/public/developer_omp_episode.ts', '/runtime/public/episode.json'],
            stdout=output, stderr=errors, stdin=subprocess.DEVNULL,
            env={'PATH': '/usr/bin:/bin', 'HOME': '/root'}, close_fds=True)
        try:
            process.wait(timeout=deadline + 45)
        except BaseException as error:
            # Container/cgroup cleanup remains the caller's mandatory finally path.
            process.kill()
            process.wait(timeout=5)
            if isinstance(error, subprocess.TimeoutExpired):
                raise SdkLaunchError(process, error) from error
            raise
    if gate is not None and (not gate.bound.is_set() or gate.error):
        error = ValueError('actual SDK was not controller bound before inference: ' + str(gate.error))
        raise SdkLaunchError(process, error) from error
    return process

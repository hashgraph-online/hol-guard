"""Local SDK fixtures; native post review uses the production HookWorker."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def write_fixture(directory: Path, fixtures: Path, compiled: bool, marker: str) -> None:
    for name in ("maintenance.sh", "fixture-registry"):
        target = directory / name
        target.write_bytes((fixtures / name).read_bytes())
        target.chmod(0o700)
    if compiled:
        compile_hardened_helper(directory, marker)
        (directory / "maintenance.sh").write_text("#!/bin/bash\ncompiled-helper value\n")


def externalize_script(script: Path, directory: Path) -> Path:
    directory.mkdir()
    external = directory / script.name
    external.write_bytes(script.read_bytes())
    external.chmod(0o700)
    return external


def compile_hardened_helper(directory: Path, marker: str) -> Path:
    source = directory / "compiled-helper.c"
    image = directory / "compiled-helper"
    source.write_text(
        "#include <stdio.h>\n"
        "int main(int argc, char **argv) {\n"
        f'  printf("{marker} argv0=%s arg=%s\\n", argv[0], argc > 1 ? argv[1] : "");\n'
        "  return 0;\n"
        "}\n"
    )
    subprocess.run(
        ["/usr/bin/clang", "-O0", "-Wl,-no_uuid", str(source), "-o", str(image)],
        check=True,
        capture_output=True,
        text=True,
    )
    subprocess.run(
        [
            "/usr/bin/codesign",
            "--force",
            "--sign",
            "-",
            "--options",
            "runtime",
            "--identifier",
            "guard.bash-broker-sdk-test",
            str(image),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return image


def write_cli_wrapper(path: Path, binary: Path, *, bootstrap: str, pause: str) -> None:
    path.write_text(
        f"#!{sys.executable}\nimport os, sys\n" + bootstrap + "os.environ['HOL_GUARD_NATIVE'] = 'force'\n"
        f"os.environ['HOL_GUARD_NATIVE_BINARY'] = {str(binary)!r}\n"
        + pause
        + "from codex_plugin_scanner.cli import main\nraise SystemExit(main())\n"
    )
    path.chmod(0o700)


def post_review_source(
    *,
    native: bool,
    directory: Path,
    guard: Path,
    home: Path,
    workspace: Path,
    harness: str,
    package_bootstrap: str,
) -> str:
    if not native:
        return """
// Delivery-only cases model an allowed result; native-post cases do not.
pi.on("tool_result", (event) => {
  const exit = boundBashObservedExit(event);
  if (exit !== 0 && exit !== 7) return undefined;
  const digest = boundBashContextDigest(event.content);
  const details = digest ? markBoundBashResultDelivery(event, digest) : undefined;
  return details ? { details } : undefined;
});
"""
    for repository in ("alpha", "beta"):
        sentinel = home / "fixture-registry" / repository / "obsolete"
        sentinel.parent.mkdir(parents=True)
        sentinel.write_text(f"protected {repository}\n")
    reviewer = directory / "native-post-review"
    reviewer.write_text(
        f"#!{sys.executable}\nimport json, sys, time\nfrom pathlib import Path\n"
        + package_bootstrap
        + "from codex_plugin_scanner.guard.daemon.hook_worker import HookWorker\n"
        "from codex_plugin_scanner.guard.store import GuardStore\n"
        f"guard, home, workspace = Path({str(guard)!r}), Path({str(home)!r}), Path({str(workspace)!r})\n"
        "worker = HookWorker(store=GuardStore(guard), workspace=workspace, home_dir=home, "
        "wait_for_native_policy=False)\n"
        "try:\n"
        "    assert worker.prepare_workspace_policy(workspace, deadline=time.monotonic() + 25) is not None\n"
        "    payload = json.loads(Path(sys.argv[1]).read_text())\n"
        "    response = worker.review_http_payload(payload=payload, params={}, "
        f"default_harness={harness!r}, workspace=workspace, home_dir=home, guard_home=guard)\n"
        "    print(json.dumps(response))\n"
        "finally:\n"
        "    worker.close()\n"
    )
    reviewer.chmod(0o700)
    return (
        f"const NATIVE_POST_REVIEWER = {json.dumps(str(reviewer))};\n"
        + r"""
pi.on("tool_result", async (event, ctx) => {
  const input = event.input ?? event.toolInput ?? event.arguments ?? {};
  const observation = boundBashPostObservation(event, input);
  const digest = boundBashContextDigest(event.content);
  const payload = { hook_event_name: "PostToolUse", tool_name: event.toolName,
    tool_call_id: event.toolCallId, tool_input: input, tool_response: event.content,
    is_error: event.isError === true, cwd: ctx.sessionManager.getCwd(),
    ...(observation ? { guard_bash_owner_delivery: observation } : {}),
  };
  const directory = mkdtempSync(join(tmpdir(), "hol-guard-sdk-native-post-"));
  try {
    chmodSync(directory, 0o700);
    const request = join(directory, "request.json");
    writeFileSync(request, JSON.stringify(payload), { mode: 0o600 });
    const result = await pi.exec(NATIVE_POST_REVIEWER, [request],
      { cwd: ctx.sessionManager.getCwd(), timeout: 30000 });
    if (result.code !== 0) throw Error(`native post fixture failed: ${result.stderr}`);
    const response = JSON.parse(result.stdout);
    const review = { reason_code: response.reason_code, decision: response.decision,
      policy_action: response.policy_action, model_output_action: response.model_output_action,
      reviewed_output_sha256: response.reviewed_output_sha256, observation: observation !== undefined };
    const original = response.decision === "allow" && response.model_output_action === "allow_original"
      && digest !== null && response.reviewed_output_sha256 === digest;
    const delivery = original && response.reason_code === "native_bash_owner_result_allow"
      ? markBoundBashResultDelivery(event, digest) : undefined;
    const details = { ...(delivery ?? event.details ?? {}), nativeSdkPostReview: review };
    if (!original) return { content: [{type:"text", text:`Native post withheld: ${response.reason_code}`}], details };
    return { details };
  } finally { rmSync(directory, { recursive: true, force: true }); }
});
"""
    )


def assert_native_post_review(decoded: dict, call_id: str, home: Path, compiled: bool, seen: set[str]) -> None:
    review = decoded["result"]["details"]["nativeSdkPostReview"]
    assert review["observation"] is True, review
    assert review["reason_code"] == "native_bash_owner_result_allow", review
    for repository in ("alpha", "beta"):
        sentinel = home / "fixture-registry" / repository / "obsolete"
        assert sentinel.read_text() == f"protected {repository}\n", "dry mode reached deletion"
    if not compiled and call_id not in seen:
        expected = "".join(
            f"{repository}/current\n{repository}/obsolete\n{repository}\tlocal metadata\n"
            for repository in ("alpha", "beta")
        )
        assert (home / "maintenance-report.tsv").read_text() == expected, "dry report is incomplete or changed"
    seen.add(call_id)

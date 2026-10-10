"""The Pi probe's evidence reader must not hold up the response under test."""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path

import pytest

from ci.native_runtime import probe_installed_pi_output as probe


def test_evidence_reader_does_not_gate_extension_response(tmp_path: Path) -> None:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node is required for the generated extension boundary")
    bootstrap = tmp_path / "fetch-fixture.mjs"
    bootstrap.write_text(
        """\
let finishEvidence;
globalThis.finishEvidence = () => finishEvidence?.();
globalThis.fetch = async () => ({
  status: 200,
  async text() {
    globalThis.finishEvidence();
    return JSON.stringify({ decision: "allow" });
  },
  clone() {
    return {
      json() {
        return new Promise(resolve => {
          finishEvidence = () => resolve({
            decision: "allow",
            model_output_action: "allow_original",
            reviewed_output_sha256: "75884cb89878f8c291a656516abe968b76ce5dcaa19c9504a1e688190312cbf3",
          });
        });
      },
    };
  },
});
""",
        encoding="utf-8",
    )
    extension = tmp_path / "extension.mjs"
    extension.write_text(
        """\
export default function (pi) {
  pi.on("tool_result", async () => {
    let timer;
    const deadline = new Promise(resolve => {
      timer = setTimeout(() => resolve({ isError: true }), 1000);
    });
    try {
      return await Promise.race([
        fetch("http://127.0.0.1/v1/hooks/omp", { method: "POST" })
          .then(response => response.text())
          .then(() => undefined),
        deadline,
      ]);
    } finally {
      clearTimeout(timer);
      globalThis.finishEvidence();
    }
  });
}
""",
        encoding="utf-8",
    )
    runner = tmp_path / "runner.mjs"
    probe._write_node_runner(runner)
    cases = probe._cases()[:1]
    case_path = tmp_path / "cases.json"
    case_path.write_text(json.dumps(cases), encoding="utf-8")
    results, fetches = probe._run_node_cases(
        node=[node, "--import", str(bootstrap)],
        extension=extension,
        runner=runner,
        cases=case_path,
        cwd=tmp_path,
        env=os.environ,
    )
    assert probe._assert_real_results(results, cases)["small"]["preserved"] is True
    assert probe._assert_fetch_evidence(fetches, results, cases)["small"]["status"] == 200


def _run_delayed_capture(tmp_path: Path, mode: str) -> tuple[list[dict], list[dict]]:
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node is required for the generated extension boundary")
    cases = probe._cases()
    proofs = {
        case["id"]: {
            "decision": "allow",
            "model_output_action": "allow_original",
            "reviewed_output_sha256": probe._text_digest(case["content"])[0],
        }
        for case in cases
    }
    bootstrap = tmp_path / "delayed-fetch.mjs"
    bootstrap.write_text(
        "const proofs = " + json.dumps(proofs) + ";\nconst mode = " + json.dumps(mode) + ";\n"
        """\
globalThis.fetch = async (_input, init) => {
  const id = JSON.parse(init.body).tool_call_id;
  return {
    status: mode === "bad-status" ? 503 : 200,
    async text() { return JSON.stringify({ decision: "allow" }); },
    clone() {
      if (mode === "clone-error") throw new Error("private capture error");
      return {
        json() {
          if (mode === "stalled") return new Promise(() => {});
          return new Promise((resolve, reject) => setTimeout(() => {
            if (mode === "malformed") return reject(new Error("private response body"));
            const proof = { ...proofs[id] };
            if (mode === "missing-proof") delete proof.reviewed_output_sha256;
            if (mode === "wrong-proof") proof.reviewed_output_sha256 = "0".repeat(64);
            resolve(proof);
          }, 25));
        },
      };
    },
  };
};
""",
        encoding="utf-8",
    )
    extension = tmp_path / "extension.mjs"
    extension.write_text(
        """\
export default function (pi) {
  pi.on("tool_result", async event => {
    const response = await fetch("http://127.0.0.1/v1/hooks/omp?guard-home=private", {
      method: "POST",
      body: JSON.stringify({ tool_call_id: event.toolCallId }),
    });
    await response.text();
    return undefined;
  });
}
""",
        encoding="utf-8",
    )
    runner = tmp_path / "runner.mjs"
    probe._write_node_runner(runner)
    case_path = tmp_path / "cases.json"
    case_path.write_text(json.dumps(cases), encoding="utf-8")
    return probe._run_node_cases(
        node=[node, "--import", str(bootstrap)],
        extension=extension,
        runner=runner,
        cases=case_path,
        cwd=tmp_path,
        env=os.environ,
    )


def test_delayed_evidence_is_complete_and_correlated_before_validation(tmp_path: Path) -> None:
    results, fetches = _run_delayed_capture(tmp_path, "valid")
    evidence = probe._assert_fetch_evidence(fetches, results, probe._cases())
    assert set(evidence) == {case["id"] for case in probe._cases()}
    assert all(row["preserved"] for row in probe._assert_real_results(results, probe._cases()).values())
    assert "private" not in json.dumps(fetches)


@pytest.mark.parametrize("mode", ["malformed", "missing-proof", "wrong-proof", "bad-status", "clone-error"])
def test_failed_or_incomplete_observer_evidence_cannot_pass(tmp_path: Path, mode: str) -> None:
    results, fetches = _run_delayed_capture(tmp_path, mode)
    assert all(row["preserved"] for row in results)
    with pytest.raises(probe.ProbeError, match=r"daemon (response proof mismatch|hook response was not successful)"):
        probe._assert_fetch_evidence(fetches, results, probe._cases())


def test_stalled_evidence_capture_is_bounded_and_fatal(tmp_path: Path) -> None:
    with pytest.raises(probe.ProbeError, match="daemon evidence capture timed out"):
        _run_delayed_capture(tmp_path, "stalled")


def test_failure_diagnostic_excludes_content_tokens_and_arbitrary_error_values() -> None:
    secret = "private-output-or-token"
    case = probe._cases()[0]
    results = [{"id": case["id"], "preserved": False, "result": {"isError": True, "content": secret}}]
    response = {
        "case_id": case["id"],
        "status": True,
        "decision": secret,
        "model_output_action": secret,
        "reason_code": secret,
        "reviewed_output_sha256": secret,
        "url": "http://127.0.0.1/?token=" + secret,
    }
    summary = probe._positive_failure_diagnostic(results, [response], [case])
    assert secret not in json.dumps(summary)
    assert summary["cases"][0]["is_error"] is True
    assert summary["cases"][0]["daemon_responses"] == [
        {
            "status": None,
            "decision": "unknown",
            "model_output_action": "unknown",
            "reason_code": "other_or_missing",
            "reviewed_output_matches": False,
        }
    ]
    response["reason_code"] = "native_review_deadline_exceeded"
    summary = probe._positive_failure_diagnostic(results, [response] * 5, [case])
    assert len(summary["cases"][0]["daemon_responses"]) == 3
    assert summary["cases"][0]["daemon_responses"][0]["reason_code"] == "native_review_deadline_exceeded"
    assert summary["fetch_count"] == 5

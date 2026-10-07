from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path

from tests.pi_extension_response_callback_support import _run_generated_callback_payload
from tests.pi_extension_response_runtime_support import _run_generated_preprocessing_fixture
from tests.pi_extension_response_source_support import _generated_source


def _run_generated_reference_fixture(source: str) -> dict[str, object]:
    helper_start = source.index("function base64Url(")
    helper_end = source.index("/* HOL Guard bounded preprocessing begins */", helper_start)
    helper = source[helper_start:helper_end]
    helper = helper.replace("function base64Url(value: Buffer): string", "function base64Url(value)")
    helper = helper.replace(
        "function encryptedPayload(serializedPayload: string)",
        "function encryptedPayload(serializedPayload)",
    )
    helper = helper.replace(
        "function referencedPayload(payload: Record<string, unknown>, serializedPayload: string)",
        "function referencedPayload(payload, serializedPayload)",
    )
    helper = helper.replace("const referencePayload: Record<string, unknown>", "const referencePayload")
    javascript = f"""\
import {{ createCipheriv, createHash, randomBytes }} from "node:crypto";
import {{ chmodSync, mkdtempSync, rmSync, writeFileSync }} from "node:fs";
import {{ tmpdir }} from "node:os";
import {{ join }} from "node:path";

{helper}

const metadata = {{
  path: "/outer/bin",
  environment_names: ["GIT_PAGER", "PATH"],
  environment_digest: "caller-digest",
  xdg_config_home: "/outer/config",
  git_config_no_system: false,
  home: "/outer/home",
  git_pager_disabled: true,
  pager_disabled: false,
}};
const payload = {{
  hook_event_name: "PostToolUse",
  config_path: "/guard/config.toml",
  tool_name: "bash",
  is_error: false,
  large_field: "must-stay-encrypted",
  guard_execution_environment: metadata,
}};
const serializedPayload = JSON.stringify(payload);
const referenced = referencedPayload(payload, serializedPayload);
const wrapper = referenced.payload;
console.log(JSON.stringify({{
  context: wrapper.guard_execution_environment,
  keys: Object.keys(wrapper).sort(),
  hasLargeField: Object.prototype.hasOwnProperty.call(wrapper, "large_field"),
  hasPlaintext: JSON.stringify(wrapper).includes("must-stay-encrypted"),
  serializedChars: wrapper.guard_payload_ref.serialized_chars,
  inputChars: serializedPayload.length,
}}));
referenced.cleanup();
"""
    with tempfile.NamedTemporaryFile("w", suffix=".mjs", prefix="omp-reference-", delete=False) as fixture:
        fixture.write(javascript)
        fixture_path = Path(fixture.name)
    try:
        completed = subprocess.run(["node", str(fixture_path)], capture_output=True, text=True, check=False)
    finally:
        fixture_path.unlink(missing_ok=True)
    assert completed.returncode == 0, completed.stderr
    return json.loads(completed.stdout)


def test_generated_astral_excerpts_obey_code_unit_limits_without_splitting_pairs(tmp_path: Path) -> None:
    result = _run_generated_preprocessing_fixture(
        _generated_source(tmp_path),
        r"""
const text = '😀'.repeat(7000);
const excerpt = boundedOutputText(text);
const truncated = safeTruncateText(text, 7).split('\n')[0];
const digestPrefix = boundedCodePointPrefix(text, 7, createTraversalBudget());
const oddPrefix = boundedCodePointPrefix('a😀b', 2, createTraversalBudget(), 'code_units');
console.log(JSON.stringify({
  excerptUnits: excerpt.value.length,
  excerptPoints: Array.from(excerpt.value).length,
  truncatedUnits: truncated.length,
  truncatedPoints: Array.from(truncated).length,
  digestUnits: digestPrefix.text.length,
  digestPoints: digestPrefix.chars,
  oddPrefix: oddPrefix.text,
}));
""",
    )
    assert result == {
        "excerptUnits": 12_000,
        "excerptPoints": 6_000,
        "truncatedUnits": 6,
        "truncatedPoints": 3,
        "digestUnits": 14,
        "digestPoints": 7,
        "oddPrefix": "a",
    }


def test_generated_large_non_source_result_fails_closed_before_serialization(tmp_path: Path) -> None:
    source = _generated_source(tmp_path)
    large_text = "x" * (5 * 1024 * 1024 + 1)
    content = [{"type": "text", "text": large_text}]
    captured = _run_generated_callback_payload(
        source,
        content,
        {"decision": "deny", "reason": "capture"},
    )
    assert captured["serialized_payload"] is None
    assert captured["payload"] is None
    result = captured["result"]
    assert isinstance(result, dict)
    assert result["isError"] is True
    assert "blocked" in result["content"][0]["text"]


def test_generated_preprocessing_rejects_oversized_single_text_before_hash(tmp_path: Path) -> None:
    source = _generated_source(tmp_path)
    result = _run_generated_preprocessing_fixture(
        source,
        """
const content = [{ type: "text", text: "x".repeat(5 * 1024 * 1024 + 1) }];
const digest = digestOutputText(content, Date.now() + 10_000);
const bounded = boundValue(content, 0, new WeakSet(), createTraversalBudget(Date.now() + 10_000));
const excerpt = boundedOutputText(content, Date.now() + 10_000);
console.log(JSON.stringify({
  digest: {
    sha256: digest.sha256,
    chars: digest.chars,
    excerptChars: digest.textForExcerpt.length,
    traversalTruncated: digest.traversalTruncated,
  },
  bounded: { truncated: bounded.truncated },
  excerpt: { chars: excerpt.value.length, truncated: excerpt.truncated },
}));
""",
    )

    assert result["digest"] == {
        "sha256": None,
        "chars": 0,
        "excerptChars": 12_000,
        "traversalTruncated": True,
    }
    assert result["bounded"] == {"truncated": True}
    assert result["excerpt"] == {"chars": 12_000, "truncated": True}


def test_generated_preprocessing_caps_branching_traversal_work(tmp_path: Path) -> None:
    source = _generated_source(tmp_path)
    result = _run_generated_preprocessing_fixture(
        source,
        """
const branching = Array.from({ length: 24 }, () =>
  Array.from({ length: 24 }, () => ({ type: "text", text: "x" })));
const digest = digestOutputText(branching);
const bounded = boundValue(branching);
const excerpt = boundedOutputText(branching);
console.log(JSON.stringify({
  digest: {
    sha256: digest.sha256,
    traversalTruncated: digest.traversalTruncated,
    chars: digest.chars,
  },
  bounded: { truncated: bounded.truncated },
  excerpt: { truncated: excerpt.truncated, chars: excerpt.value.length },
}));
""",
    )

    assert result["digest"]["sha256"] is None
    assert result["digest"]["traversalTruncated"] is True
    assert result["digest"]["chars"] < 24 * 24
    assert result["bounded"] == {"truncated": True}
    assert result["excerpt"]["truncated"] is True


def test_generated_preprocessing_withholds_when_deadline_is_already_expired(tmp_path: Path) -> None:
    source = _generated_source(tmp_path)
    result = _run_generated_preprocessing_fixture(
        source,
        """
const branching = Array.from({ length: 24 }, () =>
  Array.from({ length: 24 }, () => ({ type: "text", text: "x" })));
const deadlineAt = Date.now() - 1;
const digest = digestOutputText(branching, deadlineAt);
const bounded = boundValue(branching, 0, new WeakSet(), createTraversalBudget(deadlineAt));
const excerpt = boundedOutputText(branching, deadlineAt);
console.log(JSON.stringify({
  digest: { sha256: digest.sha256, traversalTruncated: digest.traversalTruncated },
  bounded: { truncated: bounded.truncated },
  excerpt: { truncated: excerpt.truncated },
}));
""",
    )

    assert result == {
        "digest": {"sha256": None, "traversalTruncated": True},
        "bounded": {"truncated": True},
        "excerpt": {"truncated": True},
    }


def test_generated_payload_budget_rejects_large_tool_input_before_json_stringify(tmp_path: Path) -> None:
    source = _generated_source(tmp_path)
    result = _run_generated_preprocessing_fixture(
        source,
        """
const payload = {
  hook_event_name: "PostToolUse",
  tool_input: { command: "x".repeat(5 * 1024 * 1024 + 1) },
  tool_response: [{ type: "text", text: "small" }],
};
console.log(JSON.stringify({ bounded: payloadWithinSerializedBudget(payload, Date.now() + 10_000) }));
""",
    )
    assert result == {"bounded": False}


def test_generated_payload_budget_accepts_valid_reference_sized_json(tmp_path: Path) -> None:
    source = _generated_source(tmp_path)
    result = _run_generated_preprocessing_fixture(
        source,
        r"""
const samples = [
  "x".repeat(25_000),
  "\t\n\r\b\f\u0000\"\\".repeat(4_000),
  "\u00e9\u4e2d\ud83e\uddea\ud800".repeat(4_000),
];
const cases = samples.map((text) => {
  const payload = { tool_response: [{ type: "text", text }] };
  const actualBytes = Buffer.byteLength(JSON.stringify(payload), "utf8");
  const measuredBytes = boundedJsonSize(payload, createTraversalBudget(Date.now() + 10_000),
    0, new WeakSet(), false);
  return {
    exactBytes: actualBytes === measuredBytes,
    usesReference: JSON.stringify(payload).length > GUARD_MAX_SERIALIZED_PAYLOAD_CHARS,
    bounded: payloadWithinSerializedBudget(payload, Date.now() + 10_000),
  };
});
console.log(JSON.stringify({ cases }));
""",
    )
    assert result == {"cases": [{"exactBytes": True, "usesReference": True, "bounded": True}] * 3}


def test_generated_reference_wrapper_preserves_caller_environment_metadata(tmp_path: Path) -> None:
    result = _run_generated_reference_fixture(_generated_source(tmp_path))

    assert result["context"] == {
        "path": "/outer/bin",
        "environment_names": ["GIT_PAGER", "PATH"],
        "environment_digest": "caller-digest",
        "xdg_config_home": "/outer/config",
        "git_config_no_system": False,
        "home": "/outer/home",
        "git_pager_disabled": True,
        "pager_disabled": False,
    }
    assert result["keys"] == [
        "config_path",
        "guard_execution_environment",
        "guard_payload_ref",
        "hook_event_name",
        "is_error",
        "tool_name",
    ]
    assert result["hasLargeField"] is False
    assert result["hasPlaintext"] is False
    assert result["serializedChars"] == result["inputChars"]


def test_generated_payload_budget_accepts_ordinary_shape_below_reference_limit(tmp_path: Path) -> None:
    source = _generated_source(tmp_path)
    result = _run_generated_preprocessing_fixture(
        source,
        """
const toolInput = Object.fromEntries(Array.from({ length: 25 }, (_, index) => [`field_${index}`, index]));
const payload = {
  hook_event_name: "PostToolUse",
  tool_input: toolInput,
  tool_response: Array.from({ length: 85 }, () => ({ type: "text", text: "small" })),
};
const serialized = JSON.stringify(payload);
console.log(JSON.stringify({
  bounded: payloadWithinSerializedBudget(payload, Date.now() + 10_000),
  belowReferenceLimit: Buffer.byteLength(serialized, "utf8") < GUARD_MAX_REFERENCE_JSON_BYTES,
}));
""",
    )
    assert result == {"bounded": True, "belowReferenceLimit": True}


def test_generated_payload_budget_has_independent_reference_node_cap(tmp_path: Path) -> None:
    source = _generated_source(tmp_path)
    result = _run_generated_preprocessing_fixture(
        source,
        """
const ordinary = { tool_response: Array.from({ length: 4096 }, () => '') };
const exhausted = { tool_response: Array.from({ length: 100001 }, () => '') };
console.log(JSON.stringify({
  ordinary: payloadWithinSerializedBudget(ordinary),
  exhausted: payloadWithinSerializedBudget(exhausted),
}));
""",
    )
    assert result == {"ordinary": True, "exhausted": False}


def test_generated_payload_budget_rejects_array_serialization_hook_without_invoking_it(tmp_path: Path) -> None:
    source = _generated_source(tmp_path)
    result = _run_generated_preprocessing_fixture(
        source,
        """
const content = [];
let hookCalls = 0;
content.toJSON = () => {
  hookCalls += 1;
  return "x".repeat(GUARD_MAX_REFERENCE_JSON_BYTES + 1);
};
const bounded = payloadWithinSerializedBudget({ tool_response: content }, Date.now() + 10_000);
console.log(JSON.stringify({ bounded, hookCalls }));
""",
    )
    assert result == {"bounded": False, "hookCalls": 0}


def test_generated_payload_budget_rejects_inherited_array_serialization_hook(tmp_path: Path) -> None:
    source = _generated_source(tmp_path)
    result = _run_generated_preprocessing_fixture(
        source,
        """
const original = Object.getOwnPropertyDescriptor(Array.prototype, "toJSON");
let hookCalls = 0;
Object.defineProperty(Array.prototype, "toJSON", {
  configurable: true,
  value: () => {
    hookCalls += 1;
    return "x".repeat(GUARD_MAX_REFERENCE_JSON_BYTES + 1);
  },
});
let bounded;
try {
  bounded = payloadWithinSerializedBudget({ tool_response: ["small"] }, Date.now() + 10_000);
} finally {
  if (original) Object.defineProperty(Array.prototype, "toJSON", original);
  else delete Array.prototype.toJSON;
}
console.log(JSON.stringify({ bounded, hookCalls }));
""",
    )
    assert result == {"bounded": False, "hookCalls": 0}


def test_generated_payload_budget_rejects_sparse_array_inherited_accessor(tmp_path: Path) -> None:
    source = _generated_source(tmp_path)
    result = _run_generated_preprocessing_fixture(
        source,
        """
const original = Object.getOwnPropertyDescriptor(Array.prototype, "0");
let getterCalls = 0;
Object.defineProperty(Array.prototype, "0", {
  configurable: true,
  get: () => {
    getterCalls += 1;
    return "unexpected";
  },
});
let bounded;
try {
  bounded = payloadWithinSerializedBudget({ tool_response: new Array(1) }, Date.now() + 10_000);
} finally {
  if (original) Object.defineProperty(Array.prototype, "0", original);
  else delete Array.prototype["0"];
}
console.log(JSON.stringify({ bounded, getterCalls }));
""",
    )
    assert result == {"bounded": False, "getterCalls": 0}


def test_generated_payload_budget_rejects_custom_prototype_data(tmp_path: Path) -> None:
    source = _generated_source(tmp_path)
    result = _run_generated_preprocessing_fixture(
        source,
        """
const custom = Object.create({ inherited: true });
custom.value = "small";
console.log(JSON.stringify({
  bounded: payloadWithinSerializedBudget({ tool_response: custom }, Date.now() + 10_000),
}));
""",
    )
    assert result == {"bounded": False}


def test_generated_payload_budget_rejects_reference_overflow_before_stringify(tmp_path: Path) -> None:
    source = _generated_source(tmp_path)
    result = _run_generated_preprocessing_fixture(
        source,
        """
const payload = { text: "\\ud83e\\uddea".repeat(Math.ceil((5 * 1024 * 1024) / 4)) };
const originalStringify = JSON.stringify;
let payloadSerializationCalls = 0;
JSON.stringify = (value, ...args) => {
  if (value === payload) payloadSerializationCalls += 1;
  return originalStringify(value, ...args);
};
const bounded = payloadWithinSerializedBudget(payload, Date.now() + 10_000);
JSON.stringify = originalStringify;
console.log(JSON.stringify({ bounded, payloadSerializationCalls }));
""",
    )
    assert result == {"bounded": False, "payloadSerializationCalls": 0}

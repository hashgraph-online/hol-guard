from __future__ import annotations

from pathlib import Path

from tests.pi_extension_response_runtime_support import _run_generated_preprocessing_fixture
from tests.pi_extension_response_source_support import _generated_source


def test_generated_response_reader_withholds_completion_after_deadline(tmp_path: Path) -> None:
    source = _generated_source(tmp_path)
    result = _run_generated_preprocessing_fixture(
        source,
        """
const originalNow = Date.now;
const cases = [];
try {
  for (const done of [false, true]) {
    let now = 100;
    let cancelled = false;
    let released = false;
    Date.now = () => now;
    const reader = {
      async read() {
        now = 201;
        return { done, value: new TextEncoder().encode('late') };
      },
      async cancel() { cancelled = true; },
      releaseLock() { released = true; },
    };
    const text = await boundedResponseText({ body: { getReader: () => reader } }, 100, 200);
    cases.push({ text, cancelled, released });
  }
} finally {
  Date.now = originalNow;
}
console.log(JSON.stringify({ cases }));
""",
    )
    assert result == {"cases": [{"text": None, "cancelled": True, "released": True}] * 2}


def test_generated_response_reader_bounds_ensure_ascii_reviewed_excerpts(tmp_path: Path) -> None:
    source = _generated_source(tmp_path)
    result = _run_generated_preprocessing_fixture(
        source,
        """
const makeResponse = (body) => {
  const state = { cancelled: false, released: false, used: false };
  const reader = {
    async read() {
      if (state.used) return { done: true, value: undefined };
      state.used = true;
      return { done: false, value: new TextEncoder().encode(body) };
    },
    async cancel() { state.cancelled = true; },
    releaseLock() { state.released = true; },
  };
  return { response: { body: { getReader: () => reader } }, state };
};
const bodyFor = (text) => `{"content":[{"type":"text","text":"${text}"}]}`;
const samples = [
  { label: "bmp", text: "b".repeat(12_000) },
  { label: "astral_ensure_ascii", text: String.raw`\\ud83e\\uddea`.repeat(12_000) },
];
const cases = [];
for (const sample of samples) {
  const body = bodyFor(sample.text);
  const fixture = makeResponse(body);
  const received = await boundedResponseText(
    fixture.response,
    GUARD_MAX_SERIALIZED_RESPONSE_CHARS,
    Date.now() + 10_000,
  );
  cases.push({
    label: sample.label,
    accepted: received === body,
    cancelled: fixture.state.cancelled,
    released: fixture.state.released,
  });
}
const oversized = makeResponse("x".repeat(GUARD_MAX_SERIALIZED_RESPONSE_CHARS + 1));
const rejected = await boundedResponseText(
  oversized.response,
  GUARD_MAX_SERIALIZED_RESPONSE_CHARS,
  Date.now() + 10_000,
);
cases.push({
  label: "over_cap",
  accepted: rejected !== null,
  cancelled: oversized.state.cancelled,
  released: oversized.state.released,
});
console.log(JSON.stringify({ cases }));
""",
    )
    assert result == {
        "cases": [
            {"label": "bmp", "accepted": True, "cancelled": False, "released": True},
            {"label": "astral_ensure_ascii", "accepted": True, "cancelled": False, "released": True},
            {"label": "over_cap", "accepted": False, "cancelled": True, "released": True},
        ],
    }


def test_generated_payload_budget_matches_exact_encrypted_reference_boundary(tmp_path: Path) -> None:
    source = _generated_source(tmp_path)
    result = _run_generated_preprocessing_fixture(
        source,
        """
const emptyBytes = Buffer.byteLength(JSON.stringify({ text: '' }), 'utf8');
const cases = [0, 1].map((overflow) => {
  const payload = { text: 'x'.repeat(GUARD_MAX_REFERENCE_JSON_BYTES - emptyBytes + overflow) };
  return {
    ciphertextBytes: Buffer.byteLength(JSON.stringify(payload), 'utf8') + 16,
    bounded: payloadWithinSerializedBudget(payload, Date.now() + 10_000),
  };
});
console.log(JSON.stringify({ cases }));
""",
    )
    assert result == {
        "cases": [
            {"ciphertextBytes": 5 * 1024 * 1024, "bounded": True},
            {"ciphertextBytes": 5 * 1024 * 1024 + 1, "bounded": False},
        ],
    }

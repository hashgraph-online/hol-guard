from __future__ import annotations

import re
from pathlib import Path

from codex_plugin_scanner.guard.adapters.pi_extension_source import managed_extension_source


def _generated_source(tmp_path: Path, *, harness: str = "omp") -> str:
    return managed_extension_source(
        guard_home=tmp_path / "guard-home",
        home_dir=tmp_path / "home",
        settings_path=tmp_path / "settings.json",
        harness=harness,
        display_name="Oh My Pi",
    )


def _strip_generated_types(fragment: str) -> str:
    replacements = {
        "const errorPayload = JSON.parse(errorBody) as { error?: unknown };": (
            "const errorPayload = JSON.parse(errorBody);"
        ),
        "function compactHookEventName(value: unknown): string {": "function compactHookEventName(value) {",
        "function normalizeGuardResponse(value: unknown): GuardResponse | null {": (
            "function normalizeGuardResponse(value) {"
        ),
        """function daemonResponseCanReturn(
  payload: Record<string, unknown>,
  response: GuardResponse,
): boolean {""": """function daemonResponseCanReturn(
  payload,
  response,
) {""",
        "  payload: Record<string, unknown>,": "  payload,",
        "  cwd?: string,": "  cwd,",
        "  options?: { enforceSizeCap?: boolean; deadlineAt?: number },": "  options,",
        "  reasonCode: string,": "  reasonCode,",
        "  reason: string,": "  reason,",
        "): GuardResponse {": ") {",
        "): Promise<GuardDaemonAttempt> {": ") {",
        "): Promise<GuardResponse> {": ") {",
        """async function daemonGuardResponse(
  serializedPayload: string,
  cwd?: string,
  timeoutMs: number = GUARD_DAEMON_TIMEOUT_MS,
  deadlineAt?: number,
): Promise<GuardDaemonAttempt> {""": """async function daemonGuardResponse(
  serializedPayload,
  cwd,
  timeoutMs = GUARD_DAEMON_TIMEOUT_MS,
  deadlineAt,
) {""",
        """async function runGuard(
  payload: Record<string, unknown>,
  cwd?: string,
  options?: { enforceSizeCap?: boolean; deadlineAt?: number },
): Promise<GuardResponse> {""": """async function runGuard(
  payload,
  cwd,
  options,
) {""",
        "let result: GuardCliResult | null = null;": "let result = null;",
        " as unknown": "",
        " as Record<string, unknown>": "",
        " as GuardResponse": "",
        " as { decision?: unknown }": "",
        """ as {
          error?: unknown;
        }""": "",
    }
    for old, new in replacements.items():
        fragment = fragment.replace(old, new)
    fragment = fragment.replace("  serializedPayload: string,", "  serializedPayload,")
    fragment = fragment.replace(
        "  timeoutMs: number = GUARD_DAEMON_TIMEOUT_MS,",
        "  timeoutMs = GUARD_DAEMON_TIMEOUT_MS,",
    )
    fragment = fragment.replace("  deadlineAt?: number,", "  deadlineAt,")
    return fragment


def _generated_digest_helper(source: str) -> str:
    return _generated_preprocessing_helper(source)


def _generated_preprocessing_helper(source: str) -> str:
    start = source.index("/* HOL Guard bounded preprocessing begins */")
    end = source.index("/* HOL Guard bounded preprocessing ends */", start)
    helper = source[start:end]
    helper = re.sub(r"/\* HOL Guard bounded preprocessing begins \*/\n?", "", helper, count=1)
    helper = re.sub(r"type TraversalBudget = \{.*?\};\n", "", helper, count=1, flags=re.DOTALL)
    helper = helper.replace(
        "type BoundedCodePointPrefix = { text: string; chars: number; complete: boolean };\n",
        "",
    )
    for old, new in {
        "function createTraversalBudget(deadlineAt?: number): TraversalBudget {": (
            "function createTraversalBudget(deadlineAt) {"
        ),
        "function traversalBudgetReady(budget: TraversalBudget): boolean {": "function traversalBudgetReady(budget) {",
        "function consumeTraversalNode(budget: TraversalBudget): boolean {": "function consumeTraversalNode(budget) {",
        "function hasCallableSerializationHook(value: object): boolean {": (
            "function hasCallableSerializationHook(value) {"
        ),
        "function safeEnumerableDataKeys(record: Record<string, unknown>): string[] | null {": (
            "function safeEnumerableDataKeys(record) {"
        ),
        "    let owner: object | null = value;": "    let owner = value;",
        "function digestOutputText(\n  value: unknown,\n  deadlineAt?: number,\n  budget = createTraversalBudget(deadlineAt),\n): OutputDigest {":  # noqa: E501
        "function digestOutputText(value, deadlineAt, budget = createTraversalBudget(deadlineAt)) {",
        "function boundValue(\n  value: unknown,\n  depth = 0,\n  seen = new WeakSet<object>(),\n  budget = createTraversalBudget(),\n): BoundedValue {":  # noqa: E501
        "function boundValue(value, depth = 0, seen = new WeakSet(), budget = createTraversalBudget()) {",
        "function boundedOutputText(\n  value: unknown,\n  deadlineAt?: number,\n  budget = createTraversalBudget(deadlineAt),\n): BoundedValue {":  # noqa: E501
        "function boundedOutputText(value, deadlineAt, budget = createTraversalBudget(deadlineAt)) {",
        "function boundedCodePointPrefix(\n  value: string,\n  limit: number,\n  budget: TraversalBudget,\n  limitKind: 'code_points' | 'code_units' = 'code_points',\n): BoundedCodePointPrefix {":  # noqa: E501
        "function boundedCodePointPrefix(value, limit, budget, limitKind = 'code_points') {",
        "function appendSafeExcerpt(\n  accumulator: { text: string; truncated: boolean },\n  value: string,\n  budget: TraversalBudget,\n): void {":  # noqa: E501
        "function appendSafeExcerpt(accumulator, value, budget) {",
        "function safeTruncateText(\n  value: string,\n  limit = GUARD_TEXT_LIMIT_CHARS,\n  budget: TraversalBudget = createTraversalBudget(),\n): string {":  # noqa: E501
        "function safeTruncateText(value, limit = GUARD_TEXT_LIMIT_CHARS, budget = createTraversalBudget()) {",
        "function safeCollectOutputText(\n  value: unknown,\n  accumulator: { text: string; truncated: boolean; itemCount: number },\n  depth: number,\n  seen: WeakSet<object>,\n  budget: TraversalBudget,\n): void {":  # noqa: E501
        "function safeCollectOutputText(value, accumulator, depth, seen, budget) {",
        (
            "function boundedResponseText(\n  response: Response,\n"
            "  maxChars: number,\n  deadlineAt?: number,\n): Promise<string | null> {"
        ): "function boundedResponseText(response, maxChars, deadlineAt) {",
        "function boundedJsonStringSize(value: string, budget: TraversalBudget): number | null {": (
            "function boundedJsonStringSize(value, budget) {"
        ),
        (
            "function boundedJsonSize(\n  value: unknown,\n  budget: TraversalBudget,\n"
            "  depth: number,\n  seen: WeakSet<object>,\n  inArray: boolean,\n): number | null {"
        ): "function boundedJsonSize(value, budget, depth, seen, inArray) {",
        "function payloadWithinSerializedBudget(payload: Record<string, unknown>, deadlineAt?: number): boolean {": (
            "function payloadWithinSerializedBudget(payload, deadlineAt) {"
        ),
        "function traverse(val: unknown, depth: number): void {": "function traverse(val, depth) {",
        "const refuse = (): void => {": "const refuse = () => {",
        "  function update(text: string): void {": "  function update(text) {",
        "const seen = new WeakSet<object>();": "const seen = new WeakSet();",
        "const chunk = next.value as Uint8Array;": "const chunk = next.value;",
        "return (async (): Promise<string | null> => {": "return (async () => {",
        "new WeakSet<object>()": "new WeakSet()",
        "const obj = val as object;": "const obj = val;",
        "const objectValue = value as object;": "const objectValue = value;",
        "const record = value as Record<string, unknown>;": "const record = value;",
        "const record = val as Record<string, unknown>;": "const record = val;",
        "const nextItems: unknown[] = [];": "const nextItems = [];",
        "const nextRecord: Record<string, unknown> = {};": "const nextRecord = {};",
    }.items():
        helper = helper.replace(old, new)
    helper = re.sub(r"\s+as (?:object|Record<string, unknown>)", "", helper)
    return helper


def _generated_structured_helper(source: str) -> str:
    start = source.index("function structuredOutputJsonForPostToolUse(")
    end = source.index("\n\nfunction sourcePathFromToolInput(", start)
    helper = source[start:end]
    for old, new in {
        "function structuredOutputJsonForPostToolUse(value: unknown, deadlineAt?: number): string | null {": (
            "function structuredOutputJsonForPostToolUse(value, deadlineAt) {"
        ),
        "  function hasUnpairedSurrogate(text: string): boolean {": "  function hasUnpairedSurrogate(text) {",
        "  function canonicalize(item: unknown, depth: number): unknown {": "  function canonicalize(item, depth) {",
        "  function canonicalStringify(item: unknown): string {": "  function canonicalStringify(item) {",
        "const entries: string[] = [];": "const entries = [];",
        "  const deadlineExceeded = (): boolean => deadlineAt !== undefined && Date.now() >= deadlineAt;": (
            "  const deadlineExceeded = () => deadlineAt !== undefined && Date.now() >= deadlineAt;"
        ),
        "  const checkDeadline = (): void => {": "  const checkDeadline = () => {",
        "const seen = new WeakSet<object>();": "const seen = new WeakSet();",
        "const record = item as Record<string, unknown>;": "const record = item;",
        "const blockRecord = block as Record<string, unknown>;": "const blockRecord = block;",
        "const parsed = JSON.parse(structuredText) as unknown;": "const parsed = JSON.parse(structuredText);",
        "const normalized = Object.create(null) as Record<string, unknown>;": "const normalized = Object.create(null);",
    }.items():
        helper = helper.replace(old, new)
    return helper


def _generated_output_text_keys(source: str) -> str:
    """Use the installed extension's actual key order, never a fixture copy."""
    match = re.search(r"const OUTPUT_TEXT_KEYS = (\[.*?\]) as const;", source, re.DOTALL)
    assert match is not None, "Generated extension output key contract is missing"
    return "const OUTPUT_TEXT_KEYS = " + match.group(1) + ";"

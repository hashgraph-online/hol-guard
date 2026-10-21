"""Ask an Oh My Pi agent to re-run a call the user approved after a block.

In `safe-alternative` mode a reviewed tool call is blocked at once and queued
in the inbox, and the agent moves on. When the daemon says an approval can
release the identical retry (`approval_resume`), the active OMP extension
waits for that decision in the background, as it already does for a blocked
prompt. On an approval it starts a new turn that asks the model to run the
same call with the same arguments. This is a retry, not a continuation: the
one-time approval binding still rejects any call that is not identical.

The watchers have their own lifecycle:
- At most `TOOL_APPROVAL_RESUME_WATCHERS` poll at once. A call past that is
  left to the user, who is told so.
- A resume's own agent turn does not cancel the others. Only the user's own
  input, a session start, switch, branch, tree move or shutdown, a cwd change
  or a replaced daemon does.
- A request whose decision was acted on is never acted on again.
- A watcher that times out, loses the daemon or sees it replaced tells the
  user the retry will not come; one the user moved on from ends silently.
"""

from __future__ import annotations

TOOL_APPROVAL_RESUME_SOURCE = (
    "  const TOOL_APPROVAL_RESUME_ARGUMENT_CHARS = 8_000;\n"
    "  const TOOL_APPROVAL_RESUME_WATCHERS = 4;\n"
    "  const TOOL_APPROVAL_RESUME_SETTLED = 256;\n"
    "  type ToolApprovalResumeBinding = {\n"
    "    generation: number;\n"
    "    sessionId: string;\n"
    "    cwd: string;\n"
    "    daemonStateId: string;\n"
    "  };\n"
    "  const toolApprovalResumeWatchers = new Map<string, ToolApprovalResumeBinding>();\n"
    "  // Kept for the extension's lifetime, not per session, so a response that\n"
    "  // arrives late or twice cannot start a second turn for one approval.\n"
    "  const settledToolApprovalResumes = new Set<string>();\n"
    "  // Moves on the user's own input and on any move to another session or to\n"
    "  // another point in this one. The turn a resume starts itself fires\n"
    "  // `agent_start`, which this deliberately ignores.\n"
    "  let toolApprovalResumeGeneration = 0;\n"
    "  const invalidateToolApprovalResumes = () => { toolApprovalResumeGeneration += 1; };\n"
    '  pi.on("session_start", () => { invalidateToolApprovalResumes(); });\n'
    '  pi.on("session_switch", () => { invalidateToolApprovalResumes(); });\n'
    '  pi.on("session_branch", () => { invalidateToolApprovalResumes(); });\n'
    '  pi.on("session_tree", () => { invalidateToolApprovalResumes(); });\n'
    '  pi.on("session_shutdown", () => { invalidateToolApprovalResumes(); });\n'
    "  const settleToolApprovalResume = (requestId: string): void => {\n"
    "    settledToolApprovalResumes.add(requestId);\n"
    "    if (settledToolApprovalResumes.size > TOOL_APPROVAL_RESUME_SETTLED) {\n"
    "      const oldest = settledToolApprovalResumes.values().next().value;\n"
    "      if (oldest !== undefined) settledToolApprovalResumes.delete(oldest);\n"
    "    }\n"
    "  };\n"
    "  const captureToolApprovalResumeBinding = (ctx: unknown): ToolApprovalResumeBinding | null => {\n"
    "    const sessionId = contextSessionId(ctx);\n"
    "    const cwd = contextCwd(ctx);\n"
    "    const daemonStateId = loadGuardDaemonConnection()?.stateId ?? null;\n"
    "    if (!sessionId || !cwd || !daemonStateId) return null;\n"
    "    return { generation: toolApprovalResumeGeneration, sessionId, cwd, daemonStateId };\n"
    "  };\n"
    "  // An approval read from a replaced daemon is not one this session can act on.\n"
    "  const toolApprovalResumeBindingIsActive = (ctx: unknown, binding: ToolApprovalResumeBinding): boolean =>\n"
    "    binding.generation === toolApprovalResumeGeneration &&\n"
    "    contextSessionId(ctx) === binding.sessionId &&\n"
    "    contextCwd(ctx) === binding.cwd &&\n"
    "    (loadGuardDaemonConnection()?.stateId ?? null) === binding.daemonStateId;\n"
    "  function toolApprovalResumeMessage(toolName: string, toolInput: unknown): string {\n"
    "    let argumentsText: string | null = null;\n"
    "    try {\n"
    "      argumentsText = canonicalJson(toolInput);\n"
    "    } catch {\n"
    "      argumentsText = null;\n"
    "    }\n"
    "    const fence = '```';\n"
    "    const exact = argumentsText !== null && argumentsText.length <= TOOL_APPROVAL_RESUME_ARGUMENT_CHARS\n"
    "      ? `Run that ${toolName} call again now with exactly these arguments, unchanged:"
    "\\n\\n${fence}json\\n${argumentsText}\\n${fence}`\n"
    "      : `Run that ${toolName} call again now with exactly the same arguments, unchanged.`;\n"
    "    return [\n"
    "      `HOL Guard: the user approved the ${toolName} call that was blocked earlier in this session.`,\n"
    "      exact,\n"
    "      'The approval covers one identical call. A changed argument is a new action that needs a new approval.',\n"
    "    ].join('\\n\\n');\n"
    "  }\n"
    "  function scheduleToolApprovalResume(\n"
    "    response: GuardResponse,\n"
    "    ctx: { ui: { notify(message: string, kind?: 'info' | 'warning'): void } },\n"
    "    snapshot: { payload: Record<string, unknown> },\n"
    "  ): void {\n"
    "    const resume = (response as { approval_resume?: unknown }).approval_resume;\n"
    "    if (!resume || typeof resume !== 'object' || !ompInteractiveContext(ctx)) return;\n"
    "    const record = resume as { request_id?: unknown; poll_path?: unknown };\n"
    "    const requestId = typeof record.request_id === 'string' ? record.request_id.trim() : '';\n"
    "    if (!requestId || settledToolApprovalResumes.has(requestId)) return;\n"
    "    // A watcher the user has moved on from stops at its next poll. It holds no\n"
    "    // slot, and the same request blocked again since then is watched afresh.\n"
    "    for (const [watchedId, watched] of toolApprovalResumeWatchers) {\n"
    "      if (!toolApprovalResumeBindingIsActive(ctx, watched)) toolApprovalResumeWatchers.delete(watchedId);\n"
    "    }\n"
    "    if (toolApprovalResumeWatchers.has(requestId)) return;\n"
    "    if (toolApprovalResumeWatchers.size >= TOOL_APPROVAL_RESUME_WATCHERS) {\n"
    "      ctx.ui.notify(\n"
    "        `HOL Guard is already watching ${TOOL_APPROVAL_RESUME_WATCHERS} blocked requests, so Oh My Pi `\n"
    "          + 'will not rerun this one on its own. After you approve it, ask Oh My Pi to run it again.',\n"
    "        'warning',\n"
    "      );\n"
    "      return;\n"
    "    }\n"
    "    const binding = captureToolApprovalResumeBinding(ctx);\n"
    "    if (binding === null) return;\n"
    "    const isActive = () => toolApprovalResumeBindingIsActive(ctx, binding);\n"
    "    // Only the request's current watcher acts; one dropped from the map stays silent.\n"
    "    const mayAct = () => toolApprovalResumeWatchers.get(requestId) === binding && isActive();\n"
    "    // The user has not moved on: same watcher, prompt generation, session and cwd.\n"
    "    // The daemon is left out, so its loss or replacement is still reported.\n"
    "    const userStillWaiting = () => toolApprovalResumeWatchers.get(requestId) === binding &&\n"
    "      binding.generation === toolApprovalResumeGeneration &&\n"
    "      contextSessionId(ctx) === binding.sessionId &&\n"
    "      contextCwd(ctx) === binding.cwd;\n"
    "    const pollPath = typeof record.poll_path === 'string' && record.poll_path.startsWith('/v1/requests/')\n"
    "      ? record.poll_path\n"
    "      : `/v1/requests/${encodeURIComponent(requestId)}`;\n"
    "    const toolName = typeof snapshot.payload.tool_name === 'string' && snapshot.payload.tool_name\n"
    "      ? snapshot.payload.tool_name\n"
    "      : 'tool';\n"
    "    const content = toolApprovalResumeMessage(toolName, snapshot.payload.tool_input);\n"
    "    toolApprovalResumeWatchers.set(requestId, binding);\n"
    "    void (async () => {\n"
    "      try {\n"
    "        const action = await pollApprovalResolution(requestId, pollPath, undefined, isActive);\n"
    "        if (action === 'allow' && mayAct()) {\n"
    "          // Settled before the turn starts, so nothing that turn triggers can resume it again.\n"
    "          settleToolApprovalResume(requestId);\n"
    "          pi.sendMessage(\n"
    "            {\n"
    "              customType: 'hol_guard_approval_resume',\n"
    "              content,\n"
    "              display: false,\n"
    "              details: { requestId, toolName },\n"
    "              attribution: 'agent',\n"
    "            },\n"
    "            { triggerTurn: true, deliverAs: 'nextTurn' },\n"
    "          );\n"
    "          ctx.ui.notify('HOL Guard approved this request. Oh My Pi is running it again.', 'info');\n"
    "        } else if (action === 'block' && mayAct()) {\n"
    "          settleToolApprovalResume(requestId);\n"
    "          ctx.ui.notify('HOL Guard kept this request blocked. Oh My Pi will not run it.', 'warning');\n"
    "        } else if (userStillWaiting()) {\n"
    "          // Timed out, lost the daemon, or read a decision from a replaced one:\n"
    "          // the user still expects a retry, so say it will not come. Not settled,\n"
    "          // so the same request blocked again is watched afresh.\n"
    "          ctx.ui.notify(\n"
    "            'HOL Guard stopped watching this request, so Oh My Pi will not rerun it on its own. '\n"
    "              + 'Once it is approved, ask Oh My Pi to run it again.',\n"
    "            'warning',\n"
    "          );\n"
    "        }\n"
    "      } finally {\n"
    "        if (toolApprovalResumeWatchers.get(requestId) === binding) {\n"
    "          toolApprovalResumeWatchers.delete(requestId);\n"
    "        }\n"
    "      }\n"
    "    })();\n"
    "  }\n"
)

_BLOCK_WITHOUT_REQUEST = (
    "      if (!requestId) {\n"
    '        ctx.ui.notify(reason, "warning");\n'
    "        return { block: true, reason };\n"
    "      }\n"
)
_BLOCK_WITH_RESUME = (
    "      if (!requestId) {\n"
    "        scheduleToolApprovalResume(response, ctx, snapshot);\n"
    '        ctx.ui.notify(reason, "warning");\n'
    "        return { block: true, reason };\n"
    "      }\n"
)
# The user's own prompt ends pending resumes; a message an extension sends does not.
_USER_INPUT = (
    '    if (event.source === "extension") return { action: "continue" };\n    invalidateInputApprovalResumes();\n'
)
_USER_INPUT_ENDS_RESUMES = _USER_INPUT + "    invalidateToolApprovalResumes();\n"


def with_tool_approval_resume(shared_source: str, *, harness: str) -> str:
    """Extend the active OMP variant, keeping the previous v1 text frozen."""
    if harness != "omp":
        return shared_source
    if shared_source.count(_BLOCK_WITHOUT_REQUEST) != 1 or shared_source.count(_USER_INPUT) != 1:
        raise ValueError("OMP tool approval resume insertion point changed")
    return TOOL_APPROVAL_RESUME_SOURCE + shared_source.replace(_BLOCK_WITHOUT_REQUEST, _BLOCK_WITH_RESUME, 1).replace(
        _USER_INPUT, _USER_INPUT_ENDS_RESUMES, 1
    )

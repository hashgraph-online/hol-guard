"""Bounded prompt setup for the active Pi-family extension."""

INPUT_HANDLER_SOURCE = r"""  async function inputWorkspaceReadiness(cwd, deadlineAt) {
    let timeout;
    try {
      return await Promise.race([
        ensureGuardWorkspaceReady(cwd),
        new Promise((resolve) => {
          timeout = setTimeout(() => resolve({ready: false, reasonCode: 'prompt_setup_pending'}),
            Math.max(1, deadlineAt - Date.now()));
        }),
      ]);
    } catch {
      return {ready: false, reasonCode: 'prompt_setup_failed'};
    } finally {
      clearTimeout(timeout);
    }
  }

  pi.on("input", async (event, ctx) => {
    if (event.source === "extension") return { action: "continue" };
    invalidateInputApprovalResumes();
    const inputBinding = captureInputApprovalResumeBinding(ctx);
    const generation = inputApprovalResumeGeneration;
    const prompt = event.text;
    const cwd = ctx.cwd;
    const deadlineAt = Date.now() + GUARD_TIMEOUT_MS - GUARD_DEADLINE_RESERVE_MS;
    const isActive = () => generation === inputApprovalResumeGeneration &&
      ctx.cwd === cwd && event.text === prompt && !handlerAbortSignal(ctx)?.aborted &&
      (inputBinding === null || inputApprovalResumeBindingIsActive(ctx, inputBinding));
    const readiness = await inputWorkspaceReadiness(cwd, deadlineAt);
    if (!isActive()) return { action: "handled", handled: true };
    if (readiness.reasonCode === 'prompt_setup_pending') {
      if (inputBinding === null) {
        ctx.ui.notify("HOL Guard could not bind this pending prompt to the session. Retry the prompt.", "warning");
        return { action: "handled", handled: true };
      }
      ctx.ui.notify("HOL Guard is preparing protection. This prompt will resume when ready.", "info");
      void ensureGuardWorkspaceReady(cwd).then(async (prepared) => {
        if (!isActive()) return;
        if (!prepared.ready) {
          ctx.ui.notify("HOL Guard could not prepare protection for this prompt. "
            + "Retry the prompt to reconnect (" + (prepared.reasonCode ?? "native_workspace_not_ready") + ").",
            "warning");
          return;
        }
        const response = await runGuard(
          { hook_event_name: "UserPromptSubmit", prompt, config_path: GUARD_CONFIG_PATH },
          cwd,
          { deadlineAt: Date.now() + GUARD_TIMEOUT_MS - GUARD_DEADLINE_RESERVE_MS },
        );
        if (!isActive()) return;
        if (response.decision !== "allow") {
          scheduleApprovalResume(response, ctx, { kind: 'input', prompt }, inputBinding);
          const reason = approvalBlockedReason(response, response.reason ?? "Blocked by HOL Guard.", "input");
          ctx.ui.notify(reason, "warning");
          return;
        }
        pi.sendUserMessage(prompt, { deliverAs: "followUp" });
      }).catch(() => {
        if (isActive()) {
          ctx.ui.notify("HOL Guard could not prepare protection for this prompt. Retry the prompt.", "warning");
        }
      });
      return { action: "handled", handled: true };
    }
    if (!readiness.ready) {
      ctx.ui.notify("HOL Guard could not prepare protection for this prompt. "
        + "Retry the prompt to reconnect (" + readiness.reasonCode + ").", "warning");
      return { action: "handled", handled: true };
    }
    const response = await runGuard(
      { hook_event_name: "UserPromptSubmit", prompt, config_path: GUARD_CONFIG_PATH },
      cwd,
      { deadlineAt },
    );
    if (!isActive()) return { action: "handled", handled: true };
    if (response.decision === "deny") {
      const reason = approvalBlockedReason(response, response.reason ?? "Blocked by HOL Guard.", "input");
      scheduleApprovalResume(response, ctx, { kind: 'input', prompt }, inputBinding);
      ctx.ui.notify(reason, "warning");
      return { action: "handled", handled: true };
    }
    return { action: "continue" };
  });
"""

"""Generation-bound, bounded workspace setup for long-lived Pi sessions."""

WORKSPACE_READINESS_CACHE_SOURCE = r"""  let workspaceReadiness = null;
  const ensureGuardWorkspaceReady = (cwd, allowSetup = true, retryFailed = false) => {
    const workspace = typeof cwd === 'string' && cwd ? cwd : process.cwd();
    if (workspaceReadiness?.cwd === workspace) {
      const currentConnection = loadGuardDaemonConnection();
      if (workspaceReadiness.daemonStateId === null && !workspaceReadiness.settled) {
        return workspaceReadiness.result;
      }
      if ((currentConnection?.stateId ?? null) === workspaceReadiness.daemonStateId &&
          (!workspaceReadiness.settled || workspaceReadiness.ready || !allowSetup ||
            (!retryFailed && Date.now() < workspaceReadiness.retryAfter))) {
        return workspaceReadiness.result;
      }
      if (!allowSetup) {
        return Promise.resolve({ ready: false, reasonCode: "daemon_restarted_requires_session_setup" });
      }
      if (workspaceReadiness.daemonStateId !== null &&
          currentConnection?.stateId !== workspaceReadiness.daemonStateId) {
        // Old pending approvals must not resume under a replacement daemon.
        invalidateApprovalContinuations();
      }
      workspaceReadiness = null;
    }
    if (!allowSetup) {
      return Promise.resolve({ ready: false, reasonCode: "native_workspace_setup_required" });
    }
    const daemonStateId = loadGuardDaemonConnection()?.stateId ?? null;
    const result = daemonWorkspaceReadiness(workspace).then((readiness) => {
      // An ACK from a daemon replaced during setup cannot admit a tool.
      const currentStateId = loadGuardDaemonConnection()?.stateId ?? null;
      if (readiness.ready && (typeof readiness.daemonStateId !== 'string' ||
          readiness.daemonStateId !== currentStateId)) {
        readiness = { ready: false, reasonCode: 'daemon_changed_during_workspace_setup' };
      }
      readinessEntry.settled = true;
      readinessEntry.ready = readiness.ready === true;
      readinessEntry.retryAfter = Date.now() + 1_000;
      if (workspaceReadiness === readinessEntry && typeof readiness.daemonStateId === 'string') {
        readinessEntry.daemonStateId = readiness.daemonStateId;
      }
      return readiness;
    }).catch(() => {
      readinessEntry.settled = true;
      readinessEntry.retryAfter = Date.now() + 1_000;
      return { ready: false, reasonCode: 'native_workspace_setup_failed' };
    });
    const readinessEntry = { cwd: workspace, result, daemonStateId,
      settled: false, ready: false, retryAfter: 0 };
    workspaceReadiness = readinessEntry;
    return result;
  };
  const prepareGuardWorkspaceForTurn = async (cwd) => {
    workspaceReadiness = null;
    return ensureGuardWorkspaceReady(cwd, true);
  };
  async function toolWorkspaceReadiness(cwd, deadlineAt) {
    let timeout;
    try {
      return await Promise.race([
        ensureGuardWorkspaceReady(cwd),
        new Promise((resolve) => {
          timeout = setTimeout(() => resolve({ready: false, reasonCode: 'workspace_setup_pending'}),
            Math.max(1, deadlineAt - Date.now() - GUARD_DAEMON_READINESS_RESPONSE_RESERVE_MS));
        }),
      ]);
    } finally {
      clearTimeout(timeout);
    }
  }
  const readinessFailureReason = (readiness) =>
    `HOL Guard blocked this tool call because native workspace readiness was not confirmed ` +
    `(${readiness.reasonCode ?? "native_workspace_not_ready"}).`;
"""

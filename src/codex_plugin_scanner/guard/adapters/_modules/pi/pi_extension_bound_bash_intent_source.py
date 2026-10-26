"""Pi-family session entries preserve a logical user intent across retries."""

BOUND_BASH_INTENT_SOURCE = r"""
  const boundBashIntentType = "hol-guard-bash-user-intent-v1";
  const failedBoundBashIntentSessions = new Set<string>();
  function boundBashSessionManager(ctx: unknown): Record<string, unknown> | null {
    if (!ctx || typeof ctx !== "object") return null;
    const manager = Reflect.get(ctx, "sessionManager");
    return manager && typeof manager === "object" ? manager : null;
  }
  pi.on("input", (event, ctx) => {
    // Approval continuations do not create a new human intent.
    if (event.source === "extension") return undefined;
    const manager = boundBashSessionManager(ctx);
    const getSessionId = manager && Reflect.get(manager, "getSessionId");
    let session: unknown;
    try { session = typeof getSessionId === "function" ? getSessionId.call(manager) : null; }
    catch { return undefined; }
    if (typeof session !== "string" || !session) return undefined;
    failedBoundBashIntentSessions.add(session);
    try {
      pi.appendEntry(boundBashIntentType, {
        schema: "guard-bash-user-intent.v1", session_id: session,
        intent_id: randomBytes(32).toString("hex"),
      });
      failedBoundBashIntentSessions.delete(session);
    } catch { /* A missing durable intent leaves the owner route denied. */ }
    return undefined;
  });
  function boundBashIntentFor(ctx: unknown, session: string): string | null {
    if (failedBoundBashIntentSessions.has(session)) return null;
    const manager = boundBashSessionManager(ctx);
    const getBranch = manager && Reflect.get(manager, "getBranch");
    if (typeof getBranch !== "function") return null;
    try {
      const branch = getBranch.call(manager);
      if (!Array.isArray(branch)) return null;
      // Bound inspection; absence never falls back to the tool-call id.
      for (let index = branch.length - 1; index >= Math.max(0, branch.length - 4096); index -= 1) {
        const entry = branch[index];
        if (entry?.type !== "custom" || entry.customType !== boundBashIntentType) continue;
        const data = entry.data;
        return data?.schema === "guard-bash-user-intent.v1" && data.session_id === session &&
          typeof data.intent_id === "string" && /^[0-9a-f]{64}$/.test(data.intent_id)
          ? data.intent_id : null;
      }
      // OMP print mode records its initial user turn but emits no `input`.
      // Later sendUserMessage calls can also default to attribution:user;
      // they must not mint a new intent or override an observed input marker.
      // Once history exceeds the inspection bound, absence of a recent marker
      // cannot prove that no older observed user intent exists.
      if ((boundBashHarness as string) === "omp" && branch.length <= 4096) {
        const getSessionId = manager && Reflect.get(manager, "getSessionId");
        if (typeof getSessionId !== "function" || getSessionId.call(manager) !== session) return null;
        for (let index = 0; index < Math.min(branch.length, 4096); index += 1) {
          const entry = branch[index];
          if (entry?.type !== "message" || entry.message?.role !== "user" ||
              entry.message.attribution !== "user") continue;
          if (typeof entry.id !== "string" || !/^[A-Za-z0-9_-]{1,128}$/.test(entry.id)) return null;
          return createHash("sha256").update(JSON.stringify({
            schema: "guard-bash-host-user-intent.v1", harness: "omp", session, entry_id: entry.id,
          }), "utf8").digest("hex");
        }
      }
    } catch { return null; }
    return null;
  }
"""

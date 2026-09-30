"""OpenCode V2 registration for the shared managed pretool reviewer."""

OPENCODE_V2_ENTRYPOINT = """
type OpenCodeV2ToolEvent = {
  tool: string;
  input: Record<string, unknown>;
};

// Keep the V1 server entrypoint while registering the V2 hook explicitly.
export default {
  id: "hol-guard-pretool",
  server: HolGuardPretoolPlugin,
  async setup(ctx: {
    location: { directory: string };
    tool: {
      hook: (
        name: "execute.before",
        handler: (event: OpenCodeV2ToolEvent) => Promise<void>,
      ) => Promise<unknown>;
    };
  }) {
    const hooks = await HolGuardPretoolPlugin({ directory: ctx.location.directory });
    await ctx.tool.hook("execute.before", async (event) => {
      await hooks["tool.execute.before"]({ tool: event.tool }, { args: event.input });
    });
  },
};
"""

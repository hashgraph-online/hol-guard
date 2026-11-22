// Oh My Pi registers its `goal` tool for every session but keeps it inactive
// until goal mode starts, and goal mode only starts from the interactive
// `/goal` command or an RPC client. A `--print` run with `--tools goal`
// therefore offers the model no tools at all, and a goal scenario can never be
// exercised. Turning the registered tool on at session start offers the model
// the same `goal` tool an interactive goal session does; the Guard extension
// still mediates every call.
type GoalToolAPI = {
  on(event: "session_start", handler: () => unknown): void;
  getActiveTools(): string[];
  setActiveTools(toolNames: string[]): Promise<void>;
};

export default function goalTool(pi: GoalToolAPI): void {
  pi.on("session_start", async () => {
    const active = pi.getActiveTools();
    if (!active.includes("goal")) await pi.setActiveTools([...active, "goal"]);
  });
}

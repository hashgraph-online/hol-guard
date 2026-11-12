import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { createInterface } from "node:readline";
import { resolve } from "node:path";

export class ContextAgentProbe {
  private child: ChildProcessWithoutNullStreams;
  private nextId = 0;
  private pending = new Map<number, { resolve: (value: any) => void; reject: (error: Error) => void; timer: ReturnType<typeof setTimeout> }>();
  private exited: Promise<void>;
  private diagnostics = "";

  constructor(python: string, guardHome: string) {
    this.child = spawn(python, ["-B", resolve(import.meta.dirname, "../../../scripts/ci/dashboard_context_agent_probe.py"), "--guard-home", guardHome]);
    this.child.stderr.on("data", (data: Buffer) => { this.diagnostics = (this.diagnostics + data.toString()).slice(-8192); });
    createInterface({ input: this.child.stdout }).on("line", (line) => {
      const message = JSON.parse(line);
      const job = this.pending.get(message.id);
      if (job) { clearTimeout(job.timer); this.pending.delete(message.id); job.resolve(message.result); }
    });
    const fail = (error: Error) => {
      for (const job of this.pending.values()) { clearTimeout(job.timer); job.reject(error); }
      this.pending.clear();
    };
    this.child.on("error", fail);
    this.exited = new Promise((done) => this.child.on("exit", (code, signal) => {
      fail(new Error(`MCP browser probe exited (${code ?? signal}): ${this.diagnostics}`)); done();
    }));
  }

  request(method: string, arguments_: Record<string, unknown> = {}): Promise<any> {
    const id = ++this.nextId;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => { this.pending.delete(id); reject(new Error(`MCP browser probe timed out: ${method}: ${this.diagnostics}`)); }, 15_000);
      this.pending.set(id, { resolve, reject, timer });
      this.child.stdin.write(`${JSON.stringify({ id, method, arguments: arguments_ })}\n`);
    });
  }

  async close(): Promise<void> {
    this.child.stdin.end();
    const timer = setTimeout(() => this.child.kill("SIGTERM"), 10_000);
    await this.exited;
    clearTimeout(timer);
  }
}

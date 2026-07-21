interface ImportMeta {
  readonly dir: string;
  main: boolean;
}

declare namespace Bun {
  const env: NodeJS.ProcessEnv;

  class Glob {
    constructor(pattern: string);
    scan(options: { cwd: string; onlyFiles?: boolean }): AsyncIterable<string>;
  }

  function file(path: string): { text(): Promise<string> };
  function sleep(milliseconds: number): Promise<void>;
  function spawn(
    command: string[],
    options: {
      cwd?: string;
      env?: Record<string, string | undefined>;
      stderr: "pipe";
      stdout: "pipe";
    },
  ): {
    exited: Promise<number>;
    stderr: ReadableStream<Uint8Array>;
    stdout: ReadableStream<Uint8Array>;
  };
}

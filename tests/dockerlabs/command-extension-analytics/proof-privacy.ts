import { extname } from "node:path";

const SENTINEL = "guard-private-command-sentinel";

export async function assertProofArtifactsPrivate(proofDir: string, session: string): Promise<void> {
  for await (const relative of new Bun.Glob("**/*").scan({ cwd: proofDir, onlyFiles: true })) {
    if (extname(relative) === ".zip") throw new Error("trace archive retained in installed dashboard proof");
    const artifact = Bun.file(`${proofDir}/${relative}`);
    const content = await artifact.text();
    if (content.includes(session) || content.includes(SENTINEL)) {
      throw new Error("private value retained in installed dashboard proof");
    }
  }
}

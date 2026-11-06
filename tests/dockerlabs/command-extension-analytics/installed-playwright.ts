import { resolve } from "node:path";

import { REPO_ROOT, requireSuccess, type CommandRunner } from "./lab-process";
import { assertProofArtifactsPrivate } from "./proof-privacy";

type ProofVerifier = (proofDir: string, session: string) => Promise<void>;

function safeFailure(error: unknown, session: string): string {
  let message = error instanceof Error ? error.message : "installed dashboard proof failed";
  for (const secret of [session, "guard-private-command-sentinel", Bun.env.GUARD_INSTALLED_APPROVAL_PASSWORD]) {
    if (secret) message = message.replaceAll(secret, "[REDACTED]");
  }
  return message.slice(-6_000);
}

export async function runInstalledPlaywright(
  origin: string,
  session: string,
  expectedActivityCount: number,
  proofDir: string,
  runner: CommandRunner,
  verifyProof: ProofVerifier = assertProofArtifactsPrivate,
): Promise<void> {
  let playwrightFailure: unknown;
  try {
    requireSuccess(
      await runner(["bun", "install", "--frozen-lockfile", "--ignore-scripts"], {
        cwd: resolve(REPO_ROOT, "dashboard"),
      }),
      "dashboard dependency install",
    );
    const playwright = await runner(["bun", "run", "test:e2e:installed"], {
      cwd: resolve(REPO_ROOT, "dashboard"),
      env: {
        GUARD_INSTALLED_ACTIVITY_COUNT: String(expectedActivityCount),
        GUARD_INSTALLED_DASHBOARD_SESSION: session,
        GUARD_INSTALLED_ORIGIN: origin,
        PLAYWRIGHT_PROOF_DIR: proofDir,
      },
    });
    if (playwright.exitCode !== 0) {
      throw new Error(
        `installed dashboard Playwright failed (${playwright.exitCode})\n${playwright.stdout}\n${playwright.stderr}`,
      );
    }
  } catch (error) {
    playwrightFailure = error;
  }
  try {
    await verifyProof(proofDir, session);
  } catch (error) {
    const proofFailure = safeFailure(error, session);
    if (playwrightFailure !== undefined) {
      throw new Error(`${proofFailure}\n${safeFailure(playwrightFailure, session)}`);
    }
    throw new Error(proofFailure);
  }
  if (playwrightFailure !== undefined) {
    throw new Error(safeFailure(playwrightFailure, session));
  }
}

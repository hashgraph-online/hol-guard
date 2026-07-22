import { resolve } from "node:path";

import { REPO_ROOT, requireSuccess, type CommandRunner } from "./lab-process";
import { assertProofArtifactsPrivate } from "./proof-privacy";

type ProofVerifier = (proofDir: string, session: string) => Promise<void>;

export async function runInstalledPlaywright(
  origin: string,
  session: string,
  expectedActivityCount: number,
  proofDir: string,
  runner: CommandRunner,
  verifyProof: ProofVerifier = assertProofArtifactsPrivate,
): Promise<void> {
  try {
    requireSuccess(
      await runner(["bun", "install", "--frozen-lockfile", "--ignore-scripts"], {
        cwd: resolve(REPO_ROOT, "dashboard"),
      }),
      "dashboard dependency install",
    );
    requireSuccess(
      await runner(["bun", "run", "test:e2e:installed"], {
        cwd: resolve(REPO_ROOT, "dashboard"),
        env: {
          GUARD_INSTALLED_ACTIVITY_COUNT: String(expectedActivityCount),
          GUARD_INSTALLED_DASHBOARD_SESSION: session,
          GUARD_INSTALLED_ORIGIN: origin,
          PLAYWRIGHT_PROOF_DIR: proofDir,
        },
      }),
      "installed dashboard Playwright",
    );
  } finally {
    await verifyProof(proofDir, session);
  }
}

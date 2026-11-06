import { resolve } from "node:path";

export function resolveProofDir(): string {
  const configured = process.env.SCRG_PROOF_DIR ?? process.env.PLAYWRIGHT_PROOF_DIR;
  if (configured && configured.trim().length > 0) {
    return resolve(configured);
  }
  return resolve("e2e/proofs");
}

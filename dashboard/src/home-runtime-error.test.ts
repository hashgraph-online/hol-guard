import { buildDaemonErrorCopy, buildHomeRuntimeErrorCopy } from "./home-runtime-error";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

const daemonErrorCopy = buildDaemonErrorCopy();
assert(
  daemonErrorCopy.primaryCta === "Retry" && daemonErrorCopy.secondaryCta === "Go to Settings",
  "daemon error copy gives recoverable Home actions",
);

const sessionErrorCopy = buildHomeRuntimeErrorCopy("unauthorized (401)");
assert(
  sessionErrorCopy.kind === "session" &&
    sessionErrorCopy.primaryCta === "Reconnect" &&
    sessionErrorCopy.secondaryCta === "Open review queue",
  "home 401 errors reconnect the signed session instead of claiming Guard is down",
);
assert(
  !sessionErrorCopy.body.toLowerCase().includes("not reachable"),
  "home 401 copy must not tell the operator the local service is down",
);

const unreachableErrorCopy = buildHomeRuntimeErrorCopy("Failed to fetch");
assert(
  unreachableErrorCopy.kind === "daemon" && unreachableErrorCopy.primaryCta === "Retry",
  "unreachable Home errors keep a Retry action",
);

console.log("home-runtime-error.test.ts: all assertions passed");

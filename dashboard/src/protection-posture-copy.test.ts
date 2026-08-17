import {
  deriveProtectionPosture,
  resolveProtectionPostureCopy,
  WATCH_BANNER_COPY,
} from "./protection-posture-copy";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

assert(resolveProtectionPostureCopy("protected").label === "Protected", "protected label");
assert(
  resolveProtectionPostureCopy("extra_careful").help.includes("new site"),
  "extra careful explains additional asks",
);
assert(WATCH_BANNER_COPY === "Protection is off. Guard is only recording.", "watch banner copy");
assert(deriveProtectionPosture("observe", "balanced") === "watch", "observe migrates to watch");
assert(deriveProtectionPosture("enforce", "strict") === "extra_careful", "strict migrates to extra careful");
assert(deriveProtectionPosture("enforce", "balanced") === "protected", "balanced migrates to protected");

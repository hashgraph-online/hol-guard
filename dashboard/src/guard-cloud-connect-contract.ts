/** A missing connection flag cannot establish an authenticated connection. */
export function assertGuardCloudConnectStatus(
  value: unknown,
): asserts value is Record<string, unknown> & { connect_required: boolean } {
  if (
    typeof value !== "object" || value === null || Array.isArray(value)
    || !("connect_required" in value) || typeof value.connect_required !== "boolean"
  ) {
    throw new Error("Guard returned an invalid connection status. Try again.");
  }
}

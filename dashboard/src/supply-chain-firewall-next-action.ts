import type { PackageFirewallStatusResponse } from "./guard-types";

export type PackageFirewallNextAction = {
  detail: string;
  label: string;
  manager: string | null;
  op: "install" | "repair" | "test" | "sync" | null;
};

export function resolvePackageFirewallNextAction(
  data: PackageFirewallStatusResponse | null,
): PackageFirewallNextAction {
  if (data === null) {
    return {
      detail: "Refresh status to see the next package firewall step on this machine.",
      label: "Check package firewall status",
      manager: null,
      op: null,
    };
  }

  const protection = data.protection;
  const shims = data.package_shims;

  const unprotectedDetected = shims.find(
    (entry) => entry.detected && !entry.installed && entry.activation_state === "uninstalled",
  );
  if (unprotectedDetected) {
    return {
      detail: `${unprotectedDetected.manager} is on this machine but not protected yet.`,
      label: `Protect ${unprotectedDetected.manager}`,
      manager: unprotectedDetected.manager,
      op: "install",
    };
  }

  const pathBroken = shims.find((entry) => entry.path_broken);
  if (pathBroken) {
    return {
      detail: `${pathBroken.manager} shim PATH order needs repair before installs are intercepted.`,
      label: `Repair ${pathBroken.manager} PATH`,
      manager: pathBroken.manager,
      op: "repair",
    };
  }

  if (protection?.path_status === "restart_required" || protection?.restart_shell_required) {
    const protectedManager =
      shims.find((entry) => entry.activation_state === "protected")?.manager ??
      protection?.protected_managers[0] ??
      null;
    return {
      detail: "Restart your shell so updated PATH exports load before testing intercepts.",
      label: "Restart shell, then test intercept",
      manager: protectedManager,
      op: "test",
    };
  }

  const untested = shims.find(
    (entry) => entry.activation_state === "protected" && entry.last_intercept_proof_at === null,
  );
  if (untested) {
    return {
      detail: `${untested.manager} is protected but has no recent intercept proof.`,
      label: `Run intercept test for ${untested.manager}`,
      manager: untested.manager,
      op: "test",
    };
  }

  if (data.detected_managers.length === 0) {
    return {
      detail: "Guard did not detect package managers on this machine yet.",
      label: "Install a package manager, then refresh",
      manager: null,
      op: null,
    };
  }

  return {
    detail: "Cloud intel and local shims look healthy. Sync if advisory bundles are stale.",
    label: "Sync Cloud intel",
    manager: null,
    op: "sync",
  };
}

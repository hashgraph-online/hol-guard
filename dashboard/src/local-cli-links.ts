import { parseExtensionRoute, type ExtensionRoute } from "./extension-control-center-model";

const LOCAL_CLI_ID_PATTERN = /^local-cli\.[a-z0-9]+(?:-[a-z0-9]+){0,8}$/;

export type ProtectionRoute =
  | ExtensionRoute
  | { kind: "local-cli"; cliId: string }
  | { kind: "add-custom" };

export function addCustomExtensionHref(): string {
  return "/extensions/add";
}

export function parseProtectionRoute(pathname: string): ProtectionRoute {
  if (pathname === "/extensions/add" || pathname === "/extensions/add/") {
    return { kind: "add-custom" };
  }
  if (pathname.startsWith("/extensions/local-cli/")) {
    try {
      const cliId = decodeURIComponent(pathname.slice("/extensions/local-cli/".length)).trim().toLowerCase();
      if (cliId && !cliId.includes("/") && LOCAL_CLI_ID_PATTERN.test(cliId)) {
        return { kind: "local-cli", cliId };
      }
    } catch {
      return { kind: "invalid" };
    }
    return { kind: "invalid" };
  }
  return parseExtensionRoute(pathname);
}

export function localCliHref(cliId: string): string {
  return `/extensions/local-cli/${encodeURIComponent(cliId)}`;
}

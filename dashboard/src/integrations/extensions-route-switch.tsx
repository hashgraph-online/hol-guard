import { useEffect, useState, type ComponentProps } from "react";

import { ProtectionCenterWorkspace } from "../protection-center/protection-center-workspace";
import { parseIntegrationsRoute } from "./integrations-route";
import { IntegrationsWorkspace } from "./integrations-workspace";

/**
 * `/extensions` routes: the Integrations pages for `/extensions/integrations` and
 * `/extensions/provider.<slug>`, the Protection Center for everything else.
 */
export function ExtensionsRouteSwitch(props: ComponentProps<typeof ProtectionCenterWorkspace>) {
  const [route, setRoute] = useState(() => parseIntegrationsRoute(window.location.pathname));
  useEffect(() => {
    const onPopState = () => setRoute(parseIntegrationsRoute(window.location.pathname));
    window.addEventListener("popstate", onPopState);
    return () => window.removeEventListener("popstate", onPopState);
  }, []);
  return route ? <IntegrationsWorkspace route={route} /> : <ProtectionCenterWorkspace {...props} />;
}

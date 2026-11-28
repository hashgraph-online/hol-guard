import { followExtensionsLink, INTEGRATIONS_HREF } from "./integrations-route";

/** The Extensions header's way into the Integrations page. */
export function IntegrationsHeaderLink() {
  return (
    <a
      className="guard-extensions-chip"
      data-testid="integrations-action"
      href={INTEGRATIONS_HREF}
      onClick={(event) => followExtensionsLink(event, INTEGRATIONS_HREF)}
    >
      Integrations
    </a>
  );
}

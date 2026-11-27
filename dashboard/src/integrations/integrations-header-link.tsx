import { INTEGRATIONS_HREF, navigateExtensions } from "./integrations-route";

/** The Extensions header's way into the Integrations page. */
export function IntegrationsHeaderLink() {
  return (
    <a
      className="guard-extensions-chip"
      data-testid="integrations-action"
      href={INTEGRATIONS_HREF}
      onClick={(event) => {
        event.preventDefault();
        navigateExtensions(INTEGRATIONS_HREF);
      }}
    >
      Integrations
    </a>
  );
}

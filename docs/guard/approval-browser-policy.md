# Automatic approval pages

**Settings → Where Guard asks → Ask surface → Never open a browser** is a
global preference, stored as `approval_surface_policy = "native-only"`.
It applies to automatic approval-page opening from the shared daemon/CLI
surface, MCP reviews, the Codex native bridge, Pi and Oh My Pi.

Guard still pauses the action and exposes the approval request. The preference
does not approve it or change enforcement. Native review surfaces remain
available. An explicit user action to open a request or dashboard can still
open the browser.

Pi and Oh My Pi read the setting at each pause that could open a page, so a
setting change takes effect without restarting the session. If that settings
read fails or exceeds 1.5 seconds, they retain their previous browser-opening
behavior. Other policies retain their existing timing and deduplication rules.

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
setting change takes effect without restarting the session. Every Pi-family
open can therefore wait up to 1.5 seconds for that read. If it fails or times
out, they retain their previous browser-opening behavior. Other policies retain
their existing timing and deduplication rules.

## While an agent drives your browser

When an agent drives a browser through your own profile, an approval page that
opens on its own would land in the browser the agent controls. The agent could
then read or click it. So while any browser session Guard recorded in the last
two hours uses a `shared`, `remote-debugging` or `unknown` profile, Guard opens
no approval page automatically, whatever the setting above says. Sessions with
an `isolated` or `dedicated` profile do not hold the page.

Guard still pauses the action. The request stays on every surface that is not a
browser, and the hook prints the approval link so you can open it yourself.
Opening a request or the dashboard by hand still works. The Codex native bridge,
the shared daemon, the attention timer, Pi and Oh My Pi all check the same
sessions table. Pi and Oh My Pi read it through the `approval_page_held` field
of `/v1/settings`, so the page opens again at the next pause once the session
goes idle.

# How Guard Cloud protects connected services

Guard Cloud lets an AI tool act in services such as Gmail, Slack or Outlook through one connection. You connect each
service once. Guard checks every action before it is sent, asks you first where your rules say to, and keeps a
receipt.

This page explains how each kind of connection works, what every label on the **Connect a service** screen means,
and what our sign-in partner holds.

## The four labels

Each service on the **Connect a service** screen carries one label. The label tells you who holds the sign-in and
what Guard does with each action.

| Label | Who holds the sign-in | What Guard does |
| --- | --- | --- |
| **Protected** | Guard | Guard holds the sign-in and sends each action itself after checking it. |
| **Protected · via Composio** | Composio, our sign-in partner | Guard checks each action and writes the exact request; Composio adds the sign-in and sends it. |
| **Checked** | The service's own server | Guard checks each request before passing it to the vendor's own server, which carries it out. |
| **Ask for this** | Nobody yet | No route exists yet. Asking records the request, and we count requests when we choose what to add next. |

If a workspace admin has turned partner sign-in off, services that sign in through Composio show **Turned off**
instead. They can't be connected until an admin turns partner sign-in back on.

### Protected

| Service | |
| --- | --- |
| Slack, GitHub, Notion | Guard holds the sign-in. |
| Gmail, Google Drive, Google Calendar | Guard holds the sign-in. |

### Protected · via Composio

| Service | Notes |
| --- | --- |
| Outlook, OneDrive, Microsoft Teams | |
| Dropbox, HubSpot, Figma, Linear | |
| Trello, Airtable, monday.com, Zoom | |
| Discord | Composio connects a bot to your server, and Guard's Discord actions post and delete messages as that bot. |
| Intercom, ClickUp, Calendly | These services offer no narrower sign-in, so Composio holds access to everything the account can do. Guard still sends only the actions it lists, after checking each one. The connect button says so before you sign in. |
| Zendesk, Mailchimp, QuickBooks | Each account lives at its own address. After connecting, you add one detail: the Zendesk subdomain, the Mailchimp data centre, or the QuickBooks company ID. |

### Checked

Under **Add a tool server**, you can add a vendor's own MCP server by its HTTPS address. Guard checks each request before it reaches that server,
and the vendor's server carries out the action.

## What is the same on every route

The route changes who holds the sign-in. It never changes how Guard decides.

- **One decision.** Guard reads the same facts about an action (who it reaches, what it changes, whether it can be
  undone) and applies the same rules, whatever the route.
- **The same review.** An action your rules hold for review offers **Allow once** and **Always allow** on every
  route. Saved approvals stay when a service moves from one route to another. See the
  [approval invariant](approval-invariant.md).
- **Only listed actions.** The AI tool can only call the actions Guard publishes for a service. It never receives a
  sign-in, a partner session, or a way to run the partner's own tools.
- **The exact request.** Guard writes the full request for each action from a reviewed
  [action pack](cloud-action-packs.md). A request can only go to that pack's own hosts, and Guard checks the host
  again just before sending.
- **The same receipt.** Every action leaves a receipt, whatever the route.

## What Composio holds

For services labelled **Protected · via Composio**:

- **The sign-in.** Composio keeps the sign-in for your account with that service. Guard stores Composio's reference
  to the account, never the sign-in itself.
- **The request and the reply.** Composio sees the exact request Guard wrote, which it adds the sign-in to and sends, and the
  service's reply. Whether it keeps a copy depends on its retention settings, and we disclose those for each service
  before switching it on.
- **Opaque IDs only.** Guard sends Composio random IDs for the connection and its owner. It does not send workspace
  names, email addresses or your rules.

Composio's own checks are a second layer only. Guard checks the destination host itself before every call, and does
not follow redirects from the reply.

The design behind this route is in [ADR 0016](adr/0016-brokered-sign-in-transport.md).

## Details a connection needs

Zendesk, Mailchimp and QuickBooks serve each customer at its own address, so Guard needs one more detail after you
sign in:

| Service | Detail | Example |
| --- | --- | --- |
| Zendesk | Subdomain | `acme` for `acme.zendesk.com` |
| Mailchimp | Data centre | `us21`, the start of your Mailchimp web address |
| QuickBooks | Company ID | `9130` |

Only the person who connected the account can set it. Before saving, Guard makes one fixed read through the account
to check that the account can reach that address, so a typo or someone else's address is never stored. Until the
detail is set, actions for that account wait and nothing is sent. Other members can see whether it is set.

## Turning partner sign-in off

A workspace admin can turn **Partner sign-in** off under **Settings › Integrations › Connected accounts**. While it
is off:

- Services labelled **Protected · via Composio** can't be connected.
- Accounts Composio already holds are paused, and their actions are not sent.
- Nothing is deleted. Turning it back on resumes those accounts.

Services labelled **Protected** and **Checked** aren't affected.

## Costs

Connecting through Composio and each action sent through it cost Guard Cloud credits. The connect button shows the cost before you sign in, and the billing page lists partner use by
service. Plans include a partner allowance, and you can buy more credits if you need them.

## Related docs

- [Cloud action packs](cloud-action-packs.md)
- [Cloud action evaluator](cloud-action-evaluator.md)
- [Cloud policy presets](cloud-policy-presets.md)
- [Approval invariant](approval-invariant.md)
- [Local Guard vs Guard Cloud](local-vs-cloud.md)

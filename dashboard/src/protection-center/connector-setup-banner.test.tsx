import assert from "node:assert/strict";

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";

import { ConnectorSetupBanner } from "./connector-setup-banner";

const held = "a".repeat(64);
const current = "b".repeat(64);
const render = (props: Partial<Parameters<typeof ConnectorSetupBanner>[0]>) => renderToStaticMarkup(createElement(ConnectorSetupBanner, {
  name: "lanectl", heldIdentityHash: held, currentIdentityHash: held, match: "ready", busy: false, outcome: null, onSetUp: () => undefined,
  ...props,
}));

// Ready: the held identity and the one-tap setup, no second identity.
const ready = render({});
assert.match(ready, /Held identity/);
assert.match(ready, />aaaaaaaaaaaa</);
assert.doesNotMatch(ready, /Current identity/);
assert.match(ready, /Set up with recommended/);

// Changed binary: both identities, no setup button.
const changed = render({ currentIdentityHash: current, match: "identity_changed" });
assert.match(changed, />aaaaaaaaaaaa</);
assert.match(changed, /Current identity/);
assert.match(changed, />bbbbbbbbbbbb</);
assert.doesNotMatch(changed, /Set up with recommended/);

// Already decided: no setup button.
assert.doesNotMatch(render({ match: "decided" }), /Set up with recommended/);

// After the setup: the outcome replaces the button.
const done = render({ match: "decided", outcome: "Set up. Guard approved 1 held request once." });
assert.match(done, /lanectl is set up/);
assert.match(done, /role="status"/);
assert.doesNotMatch(done, /Set up with recommended/);

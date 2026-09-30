import { renderToStaticMarkup } from "react-dom/server";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { ConfirmDialogPanel } from "./confirm-dialog";

function assert(condition: boolean, message: string): void {
  if (!condition) throw new Error(message);
}

const srcRoot = fileURLToPath(new URL(".", import.meta.url));

function* sourceFiles(dir: string): Generator<string> {
  for (const entry of readdirSync(dir)) {
    const path = join(dir, entry);
    if (statSync(path).isDirectory()) {
      yield* sourceFiles(path);
    } else if (/\.(ts|tsx)$/.test(entry) && !/\.test\.(ts|tsx)$/.test(entry)) {
      yield path;
    }
  }
}

for (const file of sourceFiles(srcRoot)) {
  assert(
    !/window\.confirm\(/.test(readFileSync(file, "utf8")),
    `window.confirm must not be used in ${file} — it silently returns false in HOL Guard Desktop`,
  );
}

const noop = () => undefined;
const markup = renderToStaticMarkup(
  <ConfirmDialogPanel
    title="Clear the evidence log permanently?"
    description="Local audit history on this machine is deleted. This cannot be undone."
    confirmLabel="Clear evidence"
    cancelLabel="Keep editing"
    tone="destructive"
    descriptionId="confirm-desc"
    onConfirm={noop}
    onCancel={noop}
  />,
);

assert(markup.includes("Clear the evidence log permanently?"), "panel renders the title");
assert(markup.includes("Local audit history on this machine is deleted."), "panel renders the description");
assert(markup.includes("Clear evidence"), "panel renders the confirm label");
assert(markup.includes("Keep editing"), "panel renders the cancel label");
assert(/<button[^>]*type="button"[^>]*>Clear evidence<\/button>/.test(markup), "confirm is a type=button button");
assert(markup.includes('id="confirm-desc"'), "panel renders the description id it was given");
assert(!markup.includes("aria-describedby"), "aria-describedby lives on the dialog layer, not the panel");

const defaultMarkup = renderToStaticMarkup(
  <ConfirmDialogPanel
    title="Repair the approval center?"
    description="Guard clears stale approval-center discovery state."
    confirmLabel="Repair"
    onConfirm={noop}
    onCancel={noop}
  />,
);
assert(defaultMarkup.includes(">Cancel<"), "cancel label defaults to Cancel");
assert(defaultMarkup.includes("bg-brand-blue"), "default tone uses the brand-blue accent");

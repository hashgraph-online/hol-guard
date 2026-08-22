import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";

import {
  CHUNK_LOAD_ERROR_BODY,
  CHUNK_LOAD_ERROR_HEADLINE,
  DASHBOARD_GO_HOME_LABEL,
  DASHBOARD_RELOAD_LABEL,
  DASHBOARD_TRY_AGAIN_LABEL,
  ErrorBoundary,
  GENERIC_ERROR_BODY,
  GENERIC_ERROR_HEADLINE,
  dashboardErrorCopy,
} from "./error-boundary";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

const chunkError = new TypeError(
  "Failed to fetch dynamically imported module: http://127.0.0.1:5474/assets/chunks/extensions-workspace.js",
);
const chunkCopy = dashboardErrorCopy(chunkError);
assert(chunkCopy.kind === "chunk", "dynamic import failures use the chunk-load recovery copy");
assert(chunkCopy.headline === CHUNK_LOAD_ERROR_HEADLINE, "chunk-load headline names the failed screen");
assert(chunkCopy.body === CHUNK_LOAD_ERROR_BODY, "chunk-load body tells the operator to reload Guard");
assert(!chunkCopy.body.toLowerCase().includes("typeerror"), "chunk-load copy hides the raw exception type");
assert(!chunkCopy.body.includes("5474"), "chunk-load copy hides local ports");
assert(!chunkCopy.body.includes("extensions-workspace.js"), "chunk-load copy hides bundle filenames");

const genericCopy = dashboardErrorCopy(new Error("Cannot read properties of undefined"));
assert(genericCopy.kind === "generic", "render failures use generic recovery copy");
assert(genericCopy.headline === GENERIC_ERROR_HEADLINE, "generic headline stays non-technical");
assert(genericCopy.body === GENERIC_ERROR_BODY, "generic body offers reload or home");
assert(!genericCopy.body.includes("Cannot read properties"), "generic copy hides the raw exception");

const markup = renderToStaticMarkup(
  createElement(
    ErrorBoundary,
    { onReset: () => undefined },
    createElement("p", null, "workspace"),
  ),
);
assert(markup.includes("workspace"), "error boundary renders children while healthy");
assert(!markup.includes(CHUNK_LOAD_ERROR_HEADLINE), "healthy tree does not show the chunk-load headline");

const source = readFileSync(join(dirname(fileURLToPath(import.meta.url)), "error-boundary.tsx"), "utf8");
assert(source.includes(DASHBOARD_RELOAD_LABEL), "error boundary offers a dashboard reload action");
assert(source.includes(DASHBOARD_GO_HOME_LABEL), "error boundary offers a go-home action");
assert(source.includes(DASHBOARD_TRY_AGAIN_LABEL), "error boundary keeps in-place retry for generic failures");
assert(source.includes("role=\"alert\""), "error boundary announces the failure");
assert(!source.includes("this.state.error?.message"), "error boundary does not dump raw exception text");
assert(source.includes("copy.kind === \"generic\""), "in-place retry stays off for cached chunk-load failures");

console.log("error-boundary.test.ts: all assertions passed");

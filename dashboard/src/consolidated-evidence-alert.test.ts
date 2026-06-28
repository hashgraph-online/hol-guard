import { describe, it, expect } from "node:test";
import { strict as assert } from "node:assert";
import { renderToString } from "react-dom/server";
import { createElement } from "react";
import { ConsolidatedEvidenceAlert, type EvidenceItem } from "./consolidated-evidence-alert";

function makeItem(id: string, title: string, content?: string): EvidenceItem {
  return {
    id,
    title,
    tone: "blue",
    content: content ? createElement("p", null, content) : null,
  };
}

describe("ConsolidatedEvidenceAlert", () => {
  it("returns null for empty items", () => {
    const html = renderToString(createElement(ConsolidatedEvidenceAlert, { items: [] }));
    assert.ok(html.includes("<!-- -->") || html === "<!-- -->" || html.trim() === "");
  });

  it("renders single item without Next button", () => {
    const items = [makeItem("scanner", "Scanner evidence", "Found 2 signals")];
    const html = renderToString(createElement(ConsolidatedEvidenceAlert, { items }));
    assert.ok(html.includes("Scanner evidence"));
    assert.ok(html.includes("Found 2 signals"));
    assert.ok(!html.includes("Next"));
    assert.ok(!html.includes("1 of 1"));
  });

  it("renders multiple items with Next button and counter", () => {
    const items = [
      makeItem("scanner", "Scanner evidence", "Signals found"),
      makeItem("data-flow", "Data flow detected", "Source to sink"),
    ];
    const html = renderToString(createElement(ConsolidatedEvidenceAlert, { items }));
    assert.ok(html.includes("Scanner evidence"));
    assert.ok(html.includes("Next"));
    assert.ok(/1.*of.*2/.test(html));
  });

  it("renders only the first item initially", () => {
    const items = [
      makeItem("scanner", "Scanner evidence", "First content"),
      makeItem("data-flow", "Data flow detected", "Second content"),
    ];
    const html = renderToString(createElement(ConsolidatedEvidenceAlert, { items }));
    assert.ok(html.includes("First content"));
    assert.ok(!html.includes("Second content"));
  });
});

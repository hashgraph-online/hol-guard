import type { CSSProperties } from "react";
import { isNearBlackBrand } from "../protection-center/model/extension-brand";
import { mcpBrandFor } from "./mcp-brand";

export type McpAppMarkSize = "sm" | "md" | "lg";

// Steady colours for services without a logo, picked from the name so the same app always looks the same.
const LETTER_COLORS = ["2563eb", "0f766e", "7c3aed", "b45309", "be123c", "0369a1"];

function letterColor(name: string): string {
  let hash = 0;
  for (const char of name) hash = (hash * 31 + char.charCodeAt(0)) % LETTER_COLORS.length;
  return LETTER_COLORS[hash];
}

function tileStyle(color: string): CSSProperties {
  return { ["--extension-brand" as string]: `#${isNearBlackBrand(color) ? "3f4174" : color}` };
}

/**
 * The app an MCP call goes to, drawn like an extension's mark in the review
 * sidebar: its logo on a tile tinted with its colour, an icon for its kind of
 * tool, or its first letter. Decorative: the name is always written beside it.
 */
export function McpAppMark({ name, size = "md" }: { name: string; size?: McpAppMarkSize }) {
  const brand = mcpBrandFor(name);
  if (brand !== null) {
    const Icon = brand.icon;
    return (
      <span
        className="guard-extension-mark"
        data-size={size}
        data-kind="mcp-app"
        data-mcp-app={brand.label}
        style={tileStyle(brand.color)}
        aria-hidden="true"
      >
        <Icon />
      </span>
    );
  }
  const letter = name.trim().charAt(0).toUpperCase() || "?";
  return (
    <span
      className="guard-extension-mark"
      data-size={size}
      data-kind="letter"
      data-mcp-app="letter"
      style={tileStyle(letterColor(name))}
      aria-hidden="true"
    >
      {letter}
    </span>
  );
}

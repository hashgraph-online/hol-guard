---
name: HOL Guard Dashboard
description: Calm operational controls for local protection decisions.
colors:
  brand-blue: "#5599fe"
  brand-dark: "#3f4174"
  brand-white: "#ffffff"
  surface-1: "#f5f7fc"
  surface-2: "#eef1f8"
typography:
  body:
    fontFamily: 'system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif'
  mono:
    fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace'
rounded:
  control: "12px"
  container: "16px"
spacing:
  sm: "8px"
  md: "16px"
  lg: "24px"
components:
  button-primary:
    backgroundColor: "{colors.brand-blue}"
    textColor: "{colors.brand-white}"
    rounded: "{rounded.control}"
    height: "44px"
---

# Design System: HOL Guard Dashboard

## Overview

The dashboard follows the product's commitment to trustworthy, precise and calm operational clarity. Protection decisions use plain consequence statements, readable controls and a clear next action.

This records the incumbent dashboard system. The normative source remains `src/styles.css`, the responsive shell styles and the shared components. It does not introduce a replacement visual identity.

## Colors

Brand blue identifies primary actions and selected controls. Brand dark provides the text color; white and the existing surface tones separate content without loud security chrome. Selected permission controls use the same blue treatment for each choice; risk meaning comes from the label and explanation.

## Typography

Operational text inherits the existing body stack. Use the monospace stack for exact command and tool identifiers when those identifiers help the operator choose a permission. Keep explanations in ordinary body text. Existing headings establish hierarchy through size and weight.

## Layout

Use a readable content column with the existing dashboard shell. At phone widths, tool rows stack their description and permission controls. Keep controls reachable above fixed navigation and verify both the top of a flow and its action area in viewport captures.

## Elevation & Depth

Content rows rely on light borders and surface tones. Preserve the shell's existing depth treatments; additional decorative shadows are unnecessary for permission controls.

## Shapes

Controls use rounded corners and touch targets of at least 44px. Group related rows within a quiet bordered container, with dividers separating individual choices.

## Components

Use the existing segmented radio controls for mutually exclusive permission settings, including keyboard navigation and visible selected states. Search fields filter the visible catalog without discarding choices. Preserve the existing local approval confirmation before saving authority changes.

## Do's and Don'ts

- Do describe the scope and consequence of each permission plainly.
- Do distinguish detected tool catalogs from complete server inventories.
- Do keep exact identifiers available without allowing long names to widen a phone layout.
- Don't imply that unlisted tools inherit an approval.
- Don't replace product explanations with protocol or transport details.
- Don't use decorative security chrome to communicate a decision that needs a clear label.

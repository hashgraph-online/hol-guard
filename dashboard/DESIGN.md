---
name: HOL Guard Dashboard
description: Calm operational controls for local protection decisions.
colors:
  brand-blue: "#5599fe"
  brand-dark: "#3f4174"
  brand-white: "#ffffff"
  surface-1: "#f5f7fc"
  surface-2: "#eef1f8"
  brand-attention: "#7c8cfd"
  brand-attention-bg: "#eef0ff"
  ink-secondary: "rgb(63 65 116 / 0.75)"
  hairline: "rgb(63 65 116 / 0.10)"
  frame: "rgb(63 65 116 / 0.25)"
typography:
  body:
    fontFamily: 'system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif'
  mono:
    fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Consolas, monospace'
  display:
    fontSize: "2.25rem"
    fontWeight: 700
    lineHeight: 1.1
    letterSpacing: "-0.03em"
  title:
    fontSize: "1.5rem"
    fontWeight: 600
    lineHeight: 1.33
    letterSpacing: "-0.02em"
  lead:
    fontSize: "1.125rem"
    fontWeight: 400
    lineHeight: 1.75
  body-sm:
    fontSize: "0.875rem"
    fontWeight: 400
    lineHeight: 1.71
  label:
    fontSize: "0.875rem"
    fontWeight: 600
    lineHeight: 1.43
  caption:
    fontSize: "0.75rem"
    fontWeight: 400
    lineHeight: 1.67
  micro:
    fontSize: "0.6875rem"
    fontWeight: 600
    lineHeight: 1
rounded:
  sm: "8px"
  control: "12px"
  container: "16px"
  full: "9999px"
spacing:
  sm: "8px"
  md: "16px"
  lg: "24px"
  xl: "32px"
  section: "64px"
  section-wide: "80px"
components:
  button-primary:
    backgroundColor: "{colors.brand-blue}"
    textColor: "{colors.brand-white}"
    typography: "{typography.label}"
    rounded: "{rounded.sm}"
    padding: "8px 16px"
    height: "44px"
  button-secondary:
    backgroundColor: "{colors.brand-white}"
    textColor: "{colors.brand-dark}"
    typography: "{typography.label}"
    rounded: "{rounded.sm}"
    padding: "10px 16px"
    height: "44px"
  device-frame:
    backgroundColor: "{colors.brand-white}"
    textColor: "{colors.brand-dark}"
    rounded: "{rounded.container}"
    padding: "24px"
  figure-node:
    backgroundColor: "{colors.surface-1}"
    textColor: "{colors.brand-dark}"
    typography: "{typography.body-sm}"
    rounded: "{rounded.control}"
    padding: "14px"
  sync-gate:
    backgroundColor: "{colors.brand-white}"
    textColor: "{colors.brand-dark}"
    rounded: "{rounded.control}"
    padding: "12px"
  figure-callout:
    backgroundColor: "{colors.brand-dark}"
    textColor: "{colors.brand-white}"
    typography: "{typography.micro}"
    rounded: "{rounded.full}"
    size: "20px"
---

# Design System: HOL Guard Dashboard

## Overview

**Creative North Star: "Operational Clarity"**

The dashboard follows the product's commitment to trustworthy, precise and calm operational clarity. Protection decisions use plain consequence statements, readable controls and a clear next action.

This records the incumbent dashboard system. The normative source remains `src/styles.css`, the responsive shell styles and the shared components. It does not introduce a replacement visual identity. The About page (`src/about/`) is the first surface to draw a diagram in this system; its figure and divider-row conventions are recorded below so later explanatory surfaces inherit them.

**Key Characteristics:**
- Brand-dark ink on white and pale surfaces; brand blue reserved for the one active path or primary action.
- Depth from hairline borders and tonal surfaces, never from shadow.
- System type with a short ramp; hierarchy from size and weight.
- Explanatory surfaces prove a claim with a labeled figure and state read from the install, not decoration.

## Colors

Brand blue identifies primary actions and selected controls. Brand dark provides the text color; white and the existing surface tones separate content without loud security chrome. Selected permission controls use the same blue treatment for each choice; risk meaning comes from the label and explanation.

Secondary text is brand dark at 75% (ink-secondary). Hairlines that separate rows and outline nodes are brand dark at 10-12%; a boundary frame or an outside-the-boundary outline is brand dark at 25%. Attention (indigo, with its pale background) marks a transitional state such as a pending count or a first sync, as a small pill behind the value; it never signals danger.

**The One Active Path Rule.** In a diagram, brand blue draws only the path that is live: the rail, its arrowheads, an open gate and the line that crosses it. Everything inert, closed or outside the boundary is dashed brand dark at 30-40%. Blue never encodes risk.

## Typography

Operational text inherits the existing body stack. Use the monospace stack for exact command and tool identifiers when those identifiers help the operator choose a permission, and for counts read from the install (semibold, tabular figures). Keep explanations in ordinary body text. Existing headings establish hierarchy through size and weight.

### Hierarchy
- **Display** (700, 30px on phones, 36px from 640px, tight tracking): the one page title.
- **Title** (600, 24px, -0.02em): every section heading, one shape for all of them. A lead sentence follows at 16px on 28px line height, in ink-secondary, capped near 68ch.
- **Label** (600, 14px): node titles, claim titles, button text.
- **Body** (400, 14px on 24px line height, ink-secondary): node and claim descriptions. Page lead text is 16px, 18px from 640px.
- **Caption** (12px on 20px): figure captions, gate notes, disclosures.
- **Micro** (11px semibold): the number inside a callout marker only.

**The Name-Once Rule.** A section says its name once, in the title style, and its landmark is labelled by that heading. A small label line standing above or in place of a heading is not a heading.

## Layout

Use a readable content column with the existing dashboard shell. At phone widths, tool rows stack their description and permission controls. Keep controls reachable above fixed navigation and verify both the top of a flow and its action area in viewport captures.

About-style pages stack sections 64px apart (80px from 1024px). Body measure is 60ch for the page title block and 68ch for section leads and captions. Peer lists run as one column, two from 640px, and four from 1280px when the items are short claims; side-by-side headings and lists are allowed where they break an otherwise stacked rhythm. Source order is reading order: the figure precedes the page actions, and on wide screens the actions are lifted beside the title without changing keyboard order.

**The Divider Row Rule.** Peer content (claims, standards, paths, program levels, terms) is a heading over ruled rows: a top hairline on the list, a bottom hairline per row, and hairline column dividers on wide screens. Do not box each item as a card. Tables keep one hairline container with a pale header row on wide screens and restructure into labelled stacked rows on phones.

## Elevation & Depth

Content rows rely on light borders and surface tones. Preserve the shell's existing depth treatments; additional decorative shadows are unnecessary for permission controls. Figures and diagrams are flat: frames, nodes and gates are separated by hairlines, solid versus dashed outlines and the pale surface tone. Only the shared primary action button carries its soft blue lift.

## Shapes

Controls use rounded corners and touch targets of at least 44px. Group related rows within a quiet bordered container, with dividers separating individual choices.

Action buttons and fields are 8px. Figure nodes, gates, outside nodes and bordered tables are 12px. A device frame or other containing boundary is 16px. Callout markers are circles. Rails and crossing lines are 2px strokes; arrowheads are 10px solid triangles in the rail color.

## Components

### Native Business Review

The native business review is display-only: show the request title, `From` line, `Read-only` status and factual saved-request summary without a `Saved request` kicker. Keep queue search, filter and pagination controls at least 44px. On phones, keep Inbox in its dedicated scroll pane above the fixed bottom navigation. Error and recovery states use truthful copy such as `Request details are unavailable` and `Review is not connected yet`, with refresh/retry affordances; neither state certifies provider-account verification or execution.

Use the existing segmented radio controls for mutually exclusive permission settings, including keyboard navigation and visible selected states. Search fields filter the visible catalog without discarding choices. Preserve the existing local approval confirmation before saving authority changes.

### Buttons

Primary is brand blue with white label, 8px corners, 44px minimum height and a visible focus ring (brand blue at 40%, 2px, offset 2px). Secondary is white with a light brand-dark border and brand-dark label, same height and radius, tinted to surface-1 on hover. External text links and program buttons in a page body show a small trailing arrow-out icon at 60% opacity. A link that cannot be verified renders as inert text at 50% opacity rather than a dead button.

### Brand Hero

Home, About and Supply chain each open on the same branded surface (`brand-hero.tsx`), so every first viewport reads as the same product. It is the dark `guard-hero` gradient with white type, a state badge, one title and one line of detail, then at most two actions (the primary one white) and a row of dot-led facts. The HOL particle mark sits in the right column with a mono live label under it.

- **Tone:** clear, review or setup, read from the install. The tone sets the accent glow, the badge tint, the live dot and the particle mood. A state Guard cannot report is setup and claims nothing.
- **Compact:** task pages whose work sits under the hero (Supply chain) use a 260px mark column instead of 380px.
- **Phones:** task pages replace the particle stage below 1024px with a 44px flat mark in the top-right corner, so the work under the hero stays in the first viewport. About and Home keep the stage.
- **Facts:** short, countable, and consistent with the badge and live label. Name what a number counts ("3 tools unprotected", never "3 open" next to "2 to fix").

### Labeled Device Figure

A figure draws a boundary the page is making claims about. It is a `figure` labelled by its caption, with no focusable elements inside.

- **Boundary:** the device is a 16px frame in the 25% outline whose name sits on the top edge over a white mask, set in 12px semibold.
- **Nodes:** pale surface-1 nodes with a hairline border and 12px corners, title left and callout right. The node that does the work (Guard) gets a brand-blue outline at 50% and a pale blue tint.
- **Rail:** one continuous 2px brand-blue rail runs through the nodes in order. On phones it runs down their left side with a tick into each node's title line; from 768px it runs beneath three equal columns and rises into each node. An arrowhead lands only where the rail enters a node.
- **Fork:** a short vertical brand-blue stem with a tick per outcome shows a decision splitting (runs, or waits for you).
- **Gate:** a gate that guards the boundary is a white 12px panel straddling the frame edge, breaking the line it stands on. Open: 2px brand-blue border and solid crossing line. Closed or unavailable: dashed brand-dark border and dashed crossing line. Its text states what would or does cross, in the tense the state allows.
- **Outside:** things beyond the boundary are dashed 12px nodes in the 25% outline, with a one-line statement of what they receive.
- **Readouts:** a label left and its value right at 12px, values semibold with tabular figures; a transitional value sits in a pale attention pill.
- **Caption:** "Fig. N" in semibold, then one sentence on what the figure shows and one on the live state, at 14px, ink-secondary, within 68ch.

**The Truthful Figure Rule.** Every state a figure shows is read from the install. A state Guard cannot report claims nothing: the gate is drawn closed and the caption says Guard could not report it.

### Callout Markers

A 20px brand-dark circle with a white semibold number, with a screen-reader-only "Claim" prefix. The marker sits at the end of the node's title line. Each number matches a claim in the legend that follows the figure, and the legend repeats the same marker beside the claim title, so figure and promise are read together. Numbers are assigned by the order of the legend.

### Motion

The one orchestrated moment on the About page is the rail drawing itself once on load. It scales on its axis (vertical on phones, horizontal from 768px) over 500ms with a symmetric ease (0.65, 0, 0.35, 1), staggered so each segment starts as the previous one lands; ticks and arrowheads fade in over 200ms as the rail reaches them. All of it runs only under `prefers-reduced-motion: no-preference`; otherwise the rail is drawn complete and static. Animate transform and opacity only.

## Do's and Don'ts

### Do:
- **Do** describe the scope and consequence of each permission plainly.
- **Do** distinguish detected tool catalogs from complete server inventories.
- **Do** keep exact identifiers available without allowing long names to widen a phone layout.
- **Do** show where data lives with a labeled boundary figure, and tie each numbered callout to a stated claim.
- **Do** keep a figure's live state truthful, and dash everything that is closed, outside or unknown.
- **Do** put a phone's figure before its actions, and wrap any entrance motion in a reduced-motion guard.

### Don't:
- **Don't** imply that unlisted tools inherit an approval.
- **Don't** replace product explanations with protocol or transport details.
- **Don't** use decorative security chrome to communicate a decision that needs a clear label.
- **Don't** use blue to rank or color-code risk; it marks only the active path, the selected choice or the primary action.
- **Don't** box peer items into a grid of identical cards; use divider rows.
- **Don't** put a kicker, eyebrow or small caps label line above a heading.
- **Don't** animate layout properties, or let a figure show a state it did not read.

/**
 * The HOL brand mark as geometry: a hexagonal lattice of 13 nodes and 24 bars.
 * Measured from public/brand/Logo_Icon_Dark.png; the outer ring radius is 1.
 * Shared by the Home hero particle logo and its static SVG fallback.
 */

export type BrandMarkDisc = {
  x: number;
  y: number;
  r: number;
  kind: "outer" | "inner" | "core";
};

export type BrandMarkBar = {
  x1: number;
  y1: number;
  x2: number;
  y2: number;
  w: number;
  len: number;
  kind: "ring" | "inner" | "spoke" | "radial";
};

export type BrandMarkGeometry = {
  discs: BrandMarkDisc[];
  bars: BrandMarkBar[];
};

const ANGLES = [90, 30, -30, -90, -150, 150].map((deg) => (deg * Math.PI) / 180);
const OUTER_NODE_RADIUS = 0.128;
const INNER_NODE_RADIUS = 0.156;
const INNER_RING_RADIUS = 0.59;
const INNER_RING_CENTER = { x: 0, y: -0.044 };
const CORE_CENTER = { x: 0, y: -0.009 };
const THICK_BAR = 0.163;
const THIN_BAR = 0.062;
const BAR_GAP = 0.055;
const MIN_BAR_LENGTH = 0.012;

export function buildBrandMarkGeometry(): BrandMarkGeometry {
  const outer: BrandMarkDisc[] = ANGLES.map((a) => ({ x: Math.cos(a), y: Math.sin(a), r: OUTER_NODE_RADIUS, kind: "outer" }));
  const inner: BrandMarkDisc[] = ANGLES.map((a) => ({
    x: INNER_RING_CENTER.x + INNER_RING_RADIUS * Math.cos(a),
    y: INNER_RING_CENTER.y + INNER_RING_RADIUS * Math.sin(a),
    r: INNER_NODE_RADIUS,
    kind: "inner",
  }));
  const core: BrandMarkDisc = { x: CORE_CENTER.x, y: CORE_CENTER.y, r: INNER_NODE_RADIUS, kind: "core" };
  const bars: BrandMarkBar[] = [];

  function addBar(a: BrandMarkDisc, b: BrandMarkDisc, w: number, kind: BrandMarkBar["kind"]): void {
    const dx = b.x - a.x;
    const dy = b.y - a.y;
    const length = Math.hypot(dx, dy);
    const ux = dx / length;
    const uy = dy / length;
    const s0 = a.r + BAR_GAP;
    const s1 = length - (b.r + BAR_GAP);
    if (s1 - s0 < MIN_BAR_LENGTH) return;
    bars.push({ x1: a.x + ux * s0, y1: a.y + uy * s0, x2: a.x + ux * s1, y2: a.y + uy * s1, w, len: s1 - s0, kind });
  }

  for (let i = 0; i < 6; i += 1) {
    addBar(outer[i], outer[(i + 1) % 6], THICK_BAR, "ring");
    addBar(inner[i], inner[(i + 1) % 6], THIN_BAR, "inner");
    addBar(core, inner[i], THIN_BAR, "spoke");
    addBar(outer[i], inner[i], THIN_BAR, "radial");
  }

  return { discs: [...outer, ...inner, core], bars };
}

export const BRAND_MARK = buildBrandMarkGeometry();

export type BrandMarkParticleKind = 0 | 1 | 2 | 3; // bar, outer node, inner node, core

/** Returns which part of the mark contains the point, or -1 when the point is outside it. */
export function brandMarkKindAt(geometry: BrandMarkGeometry, x: number, y: number): BrandMarkParticleKind | -1 {
  for (const disc of geometry.discs) {
    const dx = x - disc.x;
    const dy = y - disc.y;
    if (dx * dx + dy * dy <= disc.r * disc.r) {
      return disc.kind === "core" ? 3 : disc.kind === "inner" ? 2 : 1;
    }
  }
  for (const bar of geometry.bars) {
    const ux = (bar.x2 - bar.x1) / bar.len;
    const uy = (bar.y2 - bar.y1) / bar.len;
    const dx = x - bar.x1;
    const dy = y - bar.y1;
    const along = dx * ux + dy * uy;
    if (along < 0 || along > bar.len) continue;
    const across = -dx * uy + dy * ux;
    if (Math.abs(across) <= bar.w / 2) return 0;
  }
  return -1;
}

export type BrandMarkParticles = {
  count: number;
  /** x, y pairs in mark units */
  home: Float32Array;
  kinds: Uint8Array;
};

/**
 * Samples the mark on an evenly spaced, lightly jittered grid so the resting
 * logo reads as a clean dot-screen with no clumps or ragged edges.
 */
export function sampleBrandMarkParticles(
  geometry: BrandMarkGeometry,
  spacing: number,
  random: () => number = Math.random,
): BrandMarkParticles {
  const home: number[] = [];
  const kinds: number[] = [];
  const extent = 1.2;
  for (let gy = -extent; gy <= extent; gy += spacing) {
    for (let gx = -extent; gx <= extent; gx += spacing) {
      const x = gx + (random() - 0.5) * spacing * 0.7;
      const y = gy + (random() - 0.5) * spacing * 0.7;
      const kind = brandMarkKindAt(geometry, x, y);
      if (kind < 0) continue;
      home.push(x, y);
      kinds.push(kind);
    }
  }
  return { count: kinds.length, home: Float32Array.from(home), kinds: Uint8Array.from(kinds) };
}

/** Static SVG markup of the mark, used as the no-WebGL fallback and in small inline uses. */
export function brandMarkSvg(color: string, className = ""): string {
  const c = 50;
  const k = 42;
  const bars = BRAND_MARK.bars
    .map(
      (bar) =>
        `<line class="bm-bar-${bar.kind}" x1="${(c + bar.x1 * k).toFixed(2)}" y1="${(c - bar.y1 * k).toFixed(2)}" x2="${(c + bar.x2 * k).toFixed(2)}" y2="${(c - bar.y2 * k).toFixed(2)}" stroke="${color}" stroke-width="${(bar.w * k).toFixed(2)}"/>`,
    )
    .join("");
  const discs = BRAND_MARK.discs
    .map(
      (disc) =>
        `<circle class="bm-node-${disc.kind}" cx="${(c + disc.x * k).toFixed(2)}" cy="${(c - disc.y * k).toFixed(2)}" r="${(disc.r * k).toFixed(2)}" fill="${color}"/>`,
    )
    .join("");
  return `<svg viewBox="0 0 100 100" class="${className}" aria-hidden="true">${bars}${discs}</svg>`;
}

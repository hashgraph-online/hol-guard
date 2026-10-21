import { r as reactExports, j as jsxRuntimeExports } from "../guard-dashboard.js";
const ANGLES = [90, 30, -30, -90, -150, 150].map((deg) => deg * Math.PI / 180);
const OUTER_NODE_RADIUS = 0.128;
const INNER_NODE_RADIUS = 0.156;
const INNER_RING_RADIUS = 0.59;
const INNER_RING_CENTER = { x: 0, y: -0.044 };
const CORE_CENTER = { x: 0, y: -9e-3 };
const THICK_BAR = 0.163;
const THIN_BAR = 0.062;
const BAR_GAP = 0.055;
const MIN_BAR_LENGTH = 0.012;
function buildBrandMarkGeometry() {
  const outer = ANGLES.map((a) => ({ x: Math.cos(a), y: Math.sin(a), r: OUTER_NODE_RADIUS, kind: "outer" }));
  const inner = ANGLES.map((a) => ({
    x: INNER_RING_CENTER.x + INNER_RING_RADIUS * Math.cos(a),
    y: INNER_RING_CENTER.y + INNER_RING_RADIUS * Math.sin(a),
    r: INNER_NODE_RADIUS,
    kind: "inner"
  }));
  const core = { x: CORE_CENTER.x, y: CORE_CENTER.y, r: INNER_NODE_RADIUS, kind: "core" };
  const bars = [];
  function addBar(a, b, w, kind) {
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
const BRAND_MARK = buildBrandMarkGeometry();
function brandMarkKindAt(geometry, x, y) {
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
function sampleBrandMarkParticles(geometry, spacing, random = Math.random) {
  const home = [];
  const kinds = [];
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
function brandMarkSvg(color, className = "") {
  const c = 50;
  const k = 42;
  const bars = BRAND_MARK.bars.map(
    (bar) => `<line class="bm-bar-${bar.kind}" x1="${(c + bar.x1 * k).toFixed(2)}" y1="${(c - bar.y1 * k).toFixed(2)}" x2="${(c + bar.x2 * k).toFixed(2)}" y2="${(c - bar.y2 * k).toFixed(2)}" stroke="${color}" stroke-width="${(bar.w * k).toFixed(2)}"/>`
  ).join("");
  const discs = BRAND_MARK.discs.map(
    (disc) => `<circle class="bm-node-${disc.kind}" cx="${(c + disc.x * k).toFixed(2)}" cy="${(c - disc.y * k).toFixed(2)}" r="${(disc.r * k).toFixed(2)}" fill="${color}"/>`
  ).join("");
  return `<svg viewBox="0 0 100 100" class="${className}" aria-hidden="true">${bars}${discs}</svg>`;
}
const BRAND_BLUE = "#5599fe";
const BRAND_PURPLE = "#b56cff";
const BRAND_GREEN = "#48df7b";
const BRAND_NAVY = "#3f4174";
const BRAND_AMBER = "#f59e0b";
const VIEW_EXTENT = 1.3;
const PARTICLE_SPACING = 0.0125;
const CURSOR_RADIUS = 0.3;
const SPRING = 0.055;
const DAMPING = 0.84;
const SHIMMER = 35e-4;
const ASSEMBLY_MS = 1500;
const VERTEX_SHADER = `
precision mediump float;
attribute vec2 aPosition; attribute vec2 aHome; attribute float aSize; attribute vec3 aColor; attribute float aKind;
uniform float uExtent; uniform float uScale; uniform vec2 uMouse; uniform float uMouseR; uniform vec3 uTint;
uniform float uPulseR; uniform float uPulseW; uniform float uPulseAmt; uniform vec3 uPulseColor;
uniform float uCoreGlow; uniform vec3 uGlowColor;
varying vec3 vColor; varying float vAlpha;
void main() {
  gl_Position = vec4(aPosition / uExtent, 0.0, 1.0);
  float near = 1.0 - smoothstep(0.0, uMouseR, distance(aPosition, uMouse));
  float dc = length(aHome - vec2(0.0, -0.02));
  float pulse = (1.0 - smoothstep(0.0, uPulseW, abs(dc - uPulseR))) * uPulseAmt;
  vec3 c = aColor;
  if (aKind > 2.5) { c = mix(c, uGlowColor, uCoreGlow * 0.35); }
  c = mix(c, uPulseColor, pulse);
  c = mix(c, uTint, near * 0.85);
  vColor = c;
  float disp = length(aPosition - aHome);
  vAlpha = clamp(1.0 - disp * 0.7, 0.3, 1.0);
  gl_PointSize = aSize * uScale * (1.0 + near * 0.5 + pulse * 0.6 + (aKind > 2.5 ? uCoreGlow * 0.4 : 0.0));
}`;
const FRAGMENT_SHADER = `
precision mediump float;
varying vec3 vColor; varying float vAlpha; uniform float uAlpha;
void main() {
  float d = length(gl_PointCoord - 0.5) * 2.0;
  float a = 1.0 - smoothstep(0.62, 1.0, d);
  if (a < 0.02) discard;
  gl_FragColor = vec4(vColor, a * vAlpha * uAlpha);
}`;
function hexToRgb(hex) {
  const value = parseInt(hex.slice(1), 16);
  return [(value >> 16 & 255) / 255, (value >> 8 & 255) / 255, (value & 255) / 255];
}
function lerpRgb(a, b, t) {
  return [a[0] + (b[0] - a[0]) * t, a[1] + (b[1] - a[1]) * t, a[2] + (b[2] - a[2]) * t];
}
function lighten(c, amount) {
  const target = amount >= 0 ? [1, 1, 1] : [0, 0, 0];
  return lerpRgb(c, target, Math.min(1, Math.abs(amount)));
}
function brandGradientAt(x, y) {
  const t = Math.min(1, Math.max(0, (x - y) / 2.6 + 0.5));
  return t < 0.5 ? lerpRgb(hexToRgb(BRAND_BLUE), hexToRgb(BRAND_PURPLE), t * 2) : lerpRgb(hexToRgb(BRAND_PURPLE), hexToRgb(BRAND_GREEN), (t - 0.5) * 2);
}
function easeOutExpo(t) {
  return t >= 1 ? 1 : 1 - Math.pow(2, -10 * t);
}
function compileShader(gl, type, source) {
  const shader = gl.createShader(type);
  if (!shader) return null;
  gl.shaderSource(shader, source);
  gl.compileShader(shader);
  if (!gl.getShaderParameter(shader, gl.COMPILE_STATUS)) {
    gl.deleteShader(shader);
    return null;
  }
  return shader;
}
function createParticleScene(canvas, stage, onContextLost) {
  const gl = canvas.getContext("webgl", { alpha: true, antialias: false, premultipliedAlpha: false, powerPreference: "high-performance" });
  if (!gl) return null;
  const vertex = compileShader(gl, gl.VERTEX_SHADER, VERTEX_SHADER);
  const fragment = compileShader(gl, gl.FRAGMENT_SHADER, FRAGMENT_SHADER);
  const program = gl.createProgram();
  if (!vertex || !fragment || !program) return null;
  gl.attachShader(program, vertex);
  gl.attachShader(program, fragment);
  gl.linkProgram(program);
  if (!gl.getProgramParameter(program, gl.LINK_STATUS)) return null;
  gl.useProgram(program);
  const particles = sampleBrandMarkParticles(BRAND_MARK, PARTICLE_SPACING);
  const count = particles.count;
  const home = particles.home;
  const position = new Float32Array(count * 2);
  const velocity = new Float32Array(count * 2);
  const start = new Float32Array(count * 2);
  const sizes = new Float32Array(count);
  const colors = new Float32Array(count * 3);
  const kinds = new Float32Array(count);
  const phase = new Float32Array(count);
  const order = new Float32Array(count);
  for (let i = 0; i < count; i += 1) {
    const sparkle = Math.random() < 0.03;
    sizes[i] = sparkle ? 0.019 + Math.random() * 6e-3 : 0.0105 + Math.random() * 5e-3;
    phase[i] = Math.random() * Math.PI * 2;
    kinds[i] = particles.kinds[i];
    order[i] = Math.hypot(home[i * 2], home[i * 2 + 1] + 0.02) / 1.15;
    const angle = Math.random() * Math.PI * 2;
    const radius = 1.6 + Math.random() * 1.2;
    start[i * 2] = Math.cos(angle) * radius;
    start[i * 2 + 1] = Math.sin(angle) * radius;
    position[i * 2] = start[i * 2];
    position[i * 2 + 1] = start[i * 2 + 1];
  }
  const buffers = [];
  function attribute(name, data, size, usage) {
    const buffer = gl.createBuffer();
    const location = gl.getAttribLocation(program, name);
    if (buffer) buffers.push(buffer);
    if (!buffer || location < 0) return null;
    gl.bindBuffer(gl.ARRAY_BUFFER, buffer);
    gl.bufferData(gl.ARRAY_BUFFER, data, usage);
    gl.enableVertexAttribArray(location);
    gl.vertexAttribPointer(location, size, gl.FLOAT, false, 0, 0);
    return buffer;
  }
  const positionBuffer = attribute("aPosition", position, 2, gl.DYNAMIC_DRAW);
  attribute("aHome", home, 2, gl.STATIC_DRAW);
  attribute("aSize", sizes, 1, gl.STATIC_DRAW);
  const colorBuffer = attribute("aColor", colors, 3, gl.STATIC_DRAW);
  attribute("aKind", kinds, 1, gl.STATIC_DRAW);
  const uniform = (name) => gl.getUniformLocation(program, name);
  const uExtent = uniform("uExtent");
  const uScale = uniform("uScale");
  const uAlpha = uniform("uAlpha");
  const uMouse = uniform("uMouse");
  const uMouseR = uniform("uMouseR");
  const uTint = uniform("uTint");
  const uPulseR = uniform("uPulseR");
  const uPulseW = uniform("uPulseW");
  const uPulseAmt = uniform("uPulseAmt");
  const uPulseColor = uniform("uPulseColor");
  const uCoreGlow = uniform("uCoreGlow");
  const uGlowColor = uniform("uGlowColor");
  gl.uniform1f(uExtent, VIEW_EXTENT);
  gl.uniform1f(uMouseR, CURSOR_RADIUS);
  gl.uniform1f(uPulseW, 0.07);
  gl.enable(gl.BLEND);
  gl.disable(gl.DEPTH_TEST);
  const state = {
    mood: "clear",
    finish: "navy",
    motion: true,
    assembling: true,
    assemblyStart: performance.now(),
    visible: true,
    frame: 0,
    last: performance.now(),
    pulseRadius: -1,
    pulseAmount: 0,
    pulseCountdown: 1800,
    glow: 0,
    size: 0
  };
  const mouse = { x: 99, y: 99, lastX: 99, lastY: 99, active: false };
  function applyFinish() {
    const finish = state.finish;
    for (let i = 0; i < count; i += 1) {
      const j = phase[i] / (Math.PI * 2);
      let color;
      if (finish === "navy") {
        color = lighten(hexToRgb(BRAND_NAVY), (j - 0.5) * 0.32);
        if (j > 0.955) color = hexToRgb(BRAND_BLUE);
        else if (j < 0.02) color = hexToRgb(BRAND_PURPLE);
      } else if (finish === "white") {
        color = lighten([1, 1, 1], -j * 0.12);
        if (j > 0.96) color = hexToRgb("#dbe8ff");
      } else {
        color = lighten(brandGradientAt(home[i * 2], home[i * 2 + 1]), (j - 0.5) * 0.2);
      }
      colors[i * 3] = color[0];
      colors[i * 3 + 1] = color[1];
      colors[i * 3 + 2] = color[2];
    }
    gl.bindBuffer(gl.ARRAY_BUFFER, colorBuffer);
    gl.bufferData(gl.ARRAY_BUFFER, colors, gl.STATIC_DRAW);
    if (finish === "white") gl.blendFunc(gl.SRC_ALPHA, gl.ONE);
    else gl.blendFunc(gl.SRC_ALPHA, gl.ONE_MINUS_SRC_ALPHA);
    gl.uniform1f(uAlpha, finish === "white" ? 0.85 : 0.96);
    const tint = hexToRgb(finish === "navy" ? BRAND_BLUE : "#ffffff");
    gl.uniform3f(uTint, tint[0], tint[1], tint[2]);
    applyMood();
  }
  function applyMood() {
    const pulse = hexToRgb(state.mood === "review" ? BRAND_AMBER : state.finish === "white" ? "#ffffff" : BRAND_BLUE);
    const glow = hexToRgb(state.mood === "review" ? "#ffd58a" : state.mood === "setup" ? "#dbe8ff" : BRAND_GREEN);
    gl.uniform3f(uPulseColor, pulse[0], pulse[1], pulse[2]);
    gl.uniform3f(uGlowColor, glow[0], glow[1], glow[2]);
    requestFrame();
  }
  function step(now) {
    const dt = Math.min(0.05, (now - state.last) / 1e3);
    state.last = now;
    const t = now / 1e3;
    const frames = dt * 60;
    const damping = Math.pow(DAMPING, frames);
    const radius2 = CURSOR_RADIUS * CURSOR_RADIUS;
    const mouseVx = mouse.active ? mouse.x - mouse.lastX : 0;
    const mouseVy = mouse.active ? mouse.y - mouse.lastY : 0;
    mouse.lastX = mouse.x;
    mouse.lastY = mouse.y;
    const drag = Math.min(0.08, Math.hypot(mouseVx, mouseVy)) * 0.9;
    const shimmer = state.motion ? SHIMMER : 0;
    if (state.assembling) {
      const elapsed = (now - state.assemblyStart) / ASSEMBLY_MS;
      let done = true;
      for (let i = 0; i < count; i += 1) {
        const p = Math.min(1, Math.max(0, (elapsed - order[i] * 0.55) / 0.75));
        if (p < 1) done = false;
        const e = easeOutExpo(p);
        position[i * 2] = start[i * 2] + (home[i * 2] - start[i * 2]) * e;
        position[i * 2 + 1] = start[i * 2 + 1] + (home[i * 2 + 1] - start[i * 2 + 1]) * e;
      }
      if (done) {
        state.assembling = false;
        velocity.fill(0);
      }
    } else {
      for (let i = 0; i < count; i += 1) {
        const ix = i * 2;
        let px = position[ix];
        let py = position[ix + 1];
        let vx = velocity[ix];
        let vy = velocity[ix + 1];
        const hx = home[ix] + Math.sin(t * 0.8 + phase[i]) * shimmer;
        const hy = home[ix + 1] + Math.cos(t * 0.65 + phase[i] * 1.7) * shimmer;
        if (mouse.active) {
          const dx = px - mouse.x;
          const dy = py - mouse.y;
          const d2 = dx * dx + dy * dy;
          if (d2 < radius2) {
            const d = Math.sqrt(d2) + 1e-4;
            const s = 1 - d / CURSOR_RADIUS;
            const force = s * s * 0.028 * frames;
            vx += dx / d * force + mouseVx * s * drag * 0.35;
            vy += dy / d * force + mouseVy * s * drag * 0.35;
          }
        }
        vx += (hx - px) * SPRING * frames;
        vy += (hy - py) * SPRING * frames;
        vx *= damping;
        vy *= damping;
        px += vx * frames;
        py += vy * frames;
        position[ix] = px;
        position[ix + 1] = py;
        velocity[ix] = vx;
        velocity[ix + 1] = vy;
      }
    }
    gl.bindBuffer(gl.ARRAY_BUFFER, positionBuffer);
    gl.bufferSubData(gl.ARRAY_BUFFER, 0, position);
    if (state.motion && !state.assembling && state.mood !== "review") {
      state.pulseCountdown -= dt * 1e3;
      if (state.pulseCountdown <= 0 && state.pulseAmount <= 0) {
        state.pulseRadius = 1.18;
        state.pulseAmount = 0.55;
        state.pulseCountdown = state.mood === "setup" ? 3200 + Math.random() * 1500 : 2200 + Math.random() * 1200;
      }
      if (state.pulseAmount > 0) {
        state.pulseRadius -= dt * 1.05;
        if (state.pulseRadius < 0.02) {
          state.pulseAmount = 0;
          state.glow = 1;
        }
      }
    }
    state.glow = Math.max(0, state.glow - dt * 1.4);
    gl.uniform1f(uPulseR, state.pulseAmount > 0 ? state.pulseRadius : -5);
    gl.uniform1f(uPulseAmt, state.pulseAmount);
    gl.uniform1f(uCoreGlow, state.mood === "review" ? 0.25 + 0.2 * Math.sin(t * 2.4) : state.glow);
    gl.uniform2f(uMouse, mouse.active ? mouse.x : 99, mouse.active ? mouse.y : 99);
    gl.clearColor(0, 0, 0, 0);
    gl.clear(gl.COLOR_BUFFER_BIT);
    gl.drawArrays(gl.POINTS, 0, count);
  }
  function loop(now) {
    state.frame = 0;
    step(now);
    if (state.motion && state.visible) state.frame = requestAnimationFrame(loop);
  }
  function requestFrame() {
    if (!state.frame && !lost) state.frame = requestAnimationFrame(loop);
  }
  function toMarkUnits(event) {
    const rect = canvas.getBoundingClientRect();
    return {
      x: ((event.clientX - rect.left) / rect.width - 0.5) * 2 * VIEW_EXTENT,
      y: -((event.clientY - rect.top) / rect.height - 0.5) * 2 * VIEW_EXTENT
    };
  }
  const onPointerMove = (event) => {
    if (!state.motion) return;
    const p = toMarkUnits(event);
    if (!mouse.active) {
      mouse.lastX = p.x;
      mouse.lastY = p.y;
    }
    mouse.x = p.x;
    mouse.y = p.y;
    mouse.active = true;
    requestFrame();
  };
  const onPointerLeave = () => {
    mouse.active = false;
    requestFrame();
  };
  const onPointerDown = (event) => {
    if (!state.motion || state.assembling) return;
    const p = toMarkUnits(event);
    for (let i = 0; i < count; i += 1) {
      const dx = position[i * 2] - p.x;
      const dy = position[i * 2 + 1] - p.y;
      const d = Math.hypot(dx, dy) + 1e-4;
      if (d < 0.75) {
        const s = 1 - d / 0.75;
        velocity[i * 2] += dx / d * s * (0.06 + Math.random() * 0.05);
        velocity[i * 2 + 1] += dy / d * s * (0.06 + Math.random() * 0.05);
      }
    }
    state.glow = 1;
    requestFrame();
  };
  canvas.addEventListener("pointermove", onPointerMove);
  canvas.addEventListener("pointerleave", onPointerLeave);
  canvas.addEventListener("pointerdown", onPointerDown);
  let lost = false;
  const onWebglContextLost = (event) => {
    event.preventDefault();
    lost = true;
    if (state.frame) cancelAnimationFrame(state.frame);
    state.frame = 0;
    onContextLost();
  };
  canvas.addEventListener("webglcontextlost", onWebglContextLost);
  function resize() {
    const width = stage.clientWidth || 320;
    if (width === state.size) return;
    state.size = width;
    const ratio = Math.min(window.devicePixelRatio || 1, 2);
    canvas.width = Math.round(width * ratio);
    canvas.height = Math.round(width * ratio);
    gl.viewport(0, 0, canvas.width, canvas.height);
    gl.uniform1f(uScale, canvas.width / (2 * VIEW_EXTENT));
    requestFrame();
  }
  const resizeObserver = new ResizeObserver(resize);
  resizeObserver.observe(stage);
  resize();
  const visibilityObserver = new IntersectionObserver(
    (entries) => {
      state.visible = entries[0]?.isIntersecting ?? true;
      if (state.visible) requestFrame();
    },
    { threshold: 0.05 }
  );
  visibilityObserver.observe(stage);
  applyFinish();
  requestFrame();
  return {
    setMood(mood) {
      state.mood = mood;
      applyMood();
    },
    setFinish(finish) {
      state.finish = finish;
      applyFinish();
    },
    setMotion(enabled) {
      state.motion = enabled;
      mouse.active = false;
      if (!enabled) {
        state.assembling = false;
        state.pulseAmount = 0;
        state.glow = 0;
        velocity.fill(0);
        position.set(home);
      }
      requestFrame();
    },
    destroy() {
      if (state.frame) cancelAnimationFrame(state.frame);
      canvas.removeEventListener("pointermove", onPointerMove);
      canvas.removeEventListener("pointerleave", onPointerLeave);
      canvas.removeEventListener("pointerdown", onPointerDown);
      canvas.removeEventListener("webglcontextlost", onWebglContextLost);
      resizeObserver.disconnect();
      visibilityObserver.disconnect();
      if (!lost && !gl.isContextLost()) {
        for (const buffer of buffers) gl.deleteBuffer(buffer);
        if (program) gl.deleteProgram(program);
        if (vertex) gl.deleteShader(vertex);
        if (fragment) gl.deleteShader(fragment);
      }
    }
  };
}
function getReducedMotion() {
  if (typeof window === "undefined") return false;
  return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}
function subscribe(callback) {
  const mql = window.matchMedia("(prefers-reduced-motion: reduce)");
  mql.addEventListener("change", callback);
  return () => mql.removeEventListener("change", callback);
}
function useReducedMotion() {
  return reactExports.useSyncExternalStore(subscribe, getReducedMotion, () => false);
}
function HeroParticleLogo(props) {
  const stageRef = reactExports.useRef(null);
  const canvasRef = reactExports.useRef(null);
  const sceneRef = reactExports.useRef(null);
  const reducedMotion = useReducedMotion();
  const finish = props.finish ?? "navy";
  const settingsRef = reactExports.useRef({ finish, mood: props.mood, motion: !reducedMotion });
  settingsRef.current = { finish, mood: props.mood, motion: !reducedMotion };
  reactExports.useEffect(() => {
    const stage = stageRef.current;
    const canvas = canvasRef.current;
    if (!stage || !canvas) return;
    let scene = null;
    const teardown = () => {
      scene?.destroy();
      scene = null;
      sceneRef.current = null;
    };
    const build = () => {
      try {
        scene = createParticleScene(canvas, stage, () => {
          teardown();
          stage.classList.add("guard-hero-stage--fallback");
        });
      } catch {
        scene = null;
      }
      if (!scene) {
        stage.classList.add("guard-hero-stage--fallback");
        return;
      }
      stage.classList.remove("guard-hero-stage--fallback");
      const settings = settingsRef.current;
      scene.setFinish(settings.finish);
      scene.setMood(settings.mood);
      scene.setMotion(settings.motion);
      sceneRef.current = scene;
    };
    const onContextRestored = () => {
      teardown();
      build();
    };
    canvas.addEventListener("webglcontextrestored", onContextRestored);
    build();
    return () => {
      canvas.removeEventListener("webglcontextrestored", onContextRestored);
      teardown();
    };
  }, []);
  reactExports.useEffect(() => {
    sceneRef.current?.setFinish(finish);
  }, [finish]);
  reactExports.useEffect(() => {
    sceneRef.current?.setMood(props.mood);
  }, [props.mood]);
  reactExports.useEffect(() => {
    sceneRef.current?.setMotion(!reducedMotion);
  }, [reducedMotion]);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { ref: stageRef, className: `guard-hero-stage${props.className ? ` ${props.className}` : ""}`, "aria-hidden": "true", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "guard-hero-halo" }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("canvas", { ref: canvasRef, className: "guard-hero-canvas" }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "guard-hero-fallback", dangerouslySetInnerHTML: { __html: brandMarkSvg(finish === "white" ? "#ffffff" : BRAND_NAVY) } })
  ] });
}
export {
  HeroParticleLogo as H,
  brandMarkSvg as b,
  useReducedMotion as u
};

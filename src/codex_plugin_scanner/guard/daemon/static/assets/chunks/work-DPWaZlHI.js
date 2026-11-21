const PROGRAMS = { codex: "codex", claude: "claude-code" };
const MODEL = /^[A-Za-z0-9._:/-]{1,128}$/;
const PATH = /^[A-Za-z0-9._\-/*@+]{1,256}$/;
const SECRET_PATHS = ["**/.env", "**/.env.*", "**/*.pem", "**/*.key"];
const MAX_BLOCKED = 32;
function parseCommand(command, installed) {
  const words = command.trim().split(/\s+/).filter(Boolean);
  if (!words.length) return { error: "Type the command to run, such as codex or claude." };
  const program = words[0].split("/").pop() ?? "";
  const harness = PROGRAMS[program];
  if (!harness) return { error: "Swarm can run codex or claude. Start the command with one of them." };
  if (!installed.includes(harness)) return { error: `${program} is not installed where Guard can find it. Install it, then restart Guard.` };
  let model = null;
  for (let i = 1; i < words.length; i++) {
    const word = words[i];
    let value;
    if (word === "--model" || word === "-m") value = words[++i];
    else if (word.startsWith("--model=")) value = word.slice("--model=".length);
    else return { error: `Only --model can be added to the command. Swarm sets everything else and never turns off the CLI's safety checks (${word} was not used).` };
    if (!value || value.startsWith("-") || !MODEL.test(value)) return { error: "Give --model a model name, such as --model sonnet." };
    model = value;
  }
  return { harness, model };
}
function blockedPaths(text, secrets) {
  const paths = [];
  const bad = [];
  for (const raw of text.split(/[\n,]/)) {
    if (!raw.trim()) continue;
    const path = raw.trim().replace(/^(\.\/)+/, "");
    const parts = path.replace(/\/+$/, "").split("/");
    if (!PATH.test(path) || /^[-~]/.test(path) || parts.some((p) => p === "" || p === "." || p === "..")) bad.push(raw.trim());
    else if (!paths.includes(path)) paths.push(path);
  }
  if (secrets) {
    for (const path of SECRET_PATHS) if (!paths.includes(path)) paths.push(path);
  }
  return { paths, bad };
}
function workText(work, blocked) {
  const lines = [`Goal: ${work.goal.trim()}`];
  if (work.scope.trim()) lines.push(`Files in scope: ${work.scope.trim()}`);
  if (work.done.trim()) lines.push(`Done when: ${work.done.trim()}`);
  if (work.avoid.trim()) lines.push(`Not allowed: ${work.avoid.trim()}`);
  if (blocked.length) lines.push(`You cannot open these paths, so do not try: ${blocked.join(", ")}`);
  return lines.join("\n");
}
function goalOf(task) {
  if (!task) return null;
  const first = task.split("\n", 1)[0].trim();
  return first.startsWith("Goal: ") ? first.slice("Goal: ".length) : first;
}
export {
  MAX_BLOCKED as M,
  blockedPaths as b,
  goalOf as g,
  parseCommand as p,
  workText as w
};

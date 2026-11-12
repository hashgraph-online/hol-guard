import { useState } from "react";
import { CIGAR_TUTORIALS, cigarTutorial, type CigarTutorialId } from "./tutorial-content";

export type CigarTutorialProgress = { schema: 1; tutorial: CigarTutorialId; step: number };
const key = "hol-guard:cigar-tutorial:v1";
const initial: CigarTutorialProgress = { schema: 1, tutorial: "first-brief", step: 0 };

export function parseTutorialProgress(value: unknown): CigarTutorialProgress {
  if (!value || typeof value !== "object") return initial;
  const item = value as Record<string, unknown>;
  const tutorial = CIGAR_TUTORIALS.find((entry) => entry.id === item.tutorial);
  if (item.schema !== 1 || !tutorial || !Number.isSafeInteger(item.step)
      || Number(item.step) < 0 || Number(item.step) >= tutorial.steps.length) return initial;
  return { schema: 1, tutorial: tutorial.id, step: Number(item.step) };
}

function readProgress(): CigarTutorialProgress {
  try {
    return typeof window === "undefined" ? initial : parseTutorialProgress(JSON.parse(window.sessionStorage.getItem(key) ?? "null"));
  } catch { return initial; }
}

/** Browser-session learning progress only; never stores context, access or settings. */
export function useCigarTutorial() {
  const [progress, setProgress] = useState<CigarTutorialProgress>(readProgress);
  const [active, setActive] = useState(false);
  function save(value: CigarTutorialProgress) {
    setProgress(value);
    try { window.sessionStorage.setItem(key, JSON.stringify(value)); } catch { /* Reading a lesson also works without browser storage. */ }
    return value;
  }
  function begin(id: CigarTutorialId, resume = false) {
    const next = save({ schema: 1, tutorial: id, step: resume && progress.tutorial === id ? progress.step : 0 });
    setActive(true);
    return next;
  }
  function move(step: number) {
    return save(parseTutorialProgress({ ...progress, step }));
  }
  return { active, progress, tutorial: cigarTutorial(progress.tutorial), begin, move, exit: () => setActive(false) };
}

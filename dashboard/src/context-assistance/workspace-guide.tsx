import type { ReactNode } from "react";
import { HiMiniArrowRight } from "react-icons/hi2";
import type { CigarTab } from "./workspace-model";
import { CIGAR_FULL_NAME } from "./tutorial-content";

type Props = { onSelect: (tab: CigarTab) => void; walkthroughs?: ReactNode };

export function CigarGuide({ onSelect, walkthroughs }: Props) {
  return <div className="cigar-guide">
    <section className="cigar-card" aria-labelledby="cigar-explained-heading">
      <h2 id="cigar-explained-heading">CIGAR in one minute</h2>
      <p>When CIGAR is on, each prompt you send in Claude Code, Codex, Pi or Oh My Pi gets the few parts of your project that match it. Ask about the header color and your AI gets the header and its styles. Ask something that matches nothing, like &ldquo;build a to-do app&rdquo; in an empty folder, and nothing is added.</p>
      <p>CIGAR works out the project from the folder your AI app is open in, so there is nothing to set up for each app. Secrets, keys, hidden files, build folders and anything your .gitignore leaves out are always skipped. To stop it, use the button at the top of this page.</p>
      <p className="cigar-caption">CIGAR stands for {CIGAR_FULL_NAME}.</p>
    </section>
    <section className="cigar-card cigar-faq" aria-labelledby="cigar-faq-heading">
      <h2 id="cigar-faq-heading">Common questions</h2>
      <details><summary>Do I need to install anything?</summary>
        <p>No. The Turn on CIGAR button gets everything ready: Guard sets up its own copy of Python, downloads the CIGAR version it checked for this computer, confirms the download is the real one and starts it. The Python you already use is left alone.</p>
        <p>If the button says it is waiting for Guard's safety check, a new CIGAR exists but Guard has not finished checking it. Guard never installs a version it has not checked.</p>
        <button type="button" className="cigar-text-button" onClick={() => onSelect("versions")}>Choose a version in Updates<HiMiniArrowRight aria-hidden="true" /></button>
      </details>
      <details><summary>Can CIGAR see all my files?</summary><p>No. It only looks inside the project your AI app is open in, and it always skips secrets, keys, hidden files, build folders and anything your .gitignore leaves out.</p></details>
      <details><summary>Do I have to add my projects?</summary>
        <p>No. CIGAR finds the project each app is open in by itself. Add a project only when you want to choose exactly which files it reads. That choice counts for every app.</p>
        <button type="button" className="cigar-text-button" onClick={() => onSelect("access")}>Open Projects<HiMiniArrowRight aria-hidden="true" /></button>
      </details>
      <details><summary>Why did a prompt get no files?</summary><p>CIGAR adds only files that match the prompt. A vague prompt, or an empty or brand-new folder, matches nothing, so nothing is added. Name a file, a feature or a word from your project and try again. If the top of this page asks to let CIGAR read project files, click that button.</p></details>
      <details><summary>Does my AI read less?</summary><p>Usually. CIGAR hands over the few pieces that match your prompt instead of whole files, and says where each piece came from. How much less depends on your project and your prompts, so CIGAR makes no promise about it.</p></details>
      <details><summary>What if CIGAR is off or stops?</summary><p>Guard keeps protecting you exactly as before. Prompts just get no extra files until CIGAR is back. Projects you added come back when you turn it on again.</p></details>
      <details><summary>What does CIGAR save on my computer?</summary><p>By default, only your settings and the projects you added. Its notes live in memory and vanish when it stops. You can choose to save notes in Privacy. Saved notes are private files on this computer, not encrypted by Guard, and you can delete them there at any time.</p></details>
    </section>
    {walkthroughs}
  </div>;
}

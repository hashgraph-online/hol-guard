import type { ReactNode } from "react";
import { HiMiniArrowRight } from "react-icons/hi2";
import type { CigarTab } from "./workspace-model";
import { CIGAR_FULL_NAME } from "./tutorial-content";

type Props = { onSelect: (tab: CigarTab) => void; walkthroughs?: ReactNode };

export function CigarGuide({ onSelect, walkthroughs }: Props) {
  return <div className="cigar-guide">
    <section className="cigar-card" aria-labelledby="cigar-explained-heading">
      <h2 id="cigar-explained-heading">How CIGAR works</h2>
      <p>With CIGAR on, and Context for AI apps and workspace documents turned on in Settings, every prompt you send in Claude Code or Codex gets the few project files that match it. The Turn on CIGAR button sets both up on a fresh install. CIGAR finds your project from the folder your AI app runs in. A prompt about the header color brings the header and its styles. A prompt that matches nothing, like &ldquo;build a to-do app&rdquo; in an empty folder, adds nothing.</p>
      <p>Secrets, keys, hidden files, generated folders and anything your project's .gitignore files leave out are always skipped. To stop it, turn off CIGAR, or turn off Context for AI apps in Settings.</p>
      <p className="cigar-caption">CIGAR stands for {CIGAR_FULL_NAME}.</p>
    </section>
    <section className="cigar-card cigar-faq" aria-labelledby="cigar-faq-heading">
      <h2 id="cigar-faq-heading">Common questions</h2>
      <details><summary>Do I need to install anything?</summary>
        <p>No. When you click Turn on CIGAR, Guard gets its own copy of Python 3.14 ready, downloads the CIGAR version it approved for this computer, checks its fingerprint and starts it. The Python you already use stays as it is.</p>
        <p>If the button says it is waiting for Guard's safety check, a CIGAR version exists for your computer but Guard has not approved it yet. Guard never installs a version it has not checked.</p>
        <button type="button" className="cigar-text-button" onClick={() => onSelect("versions")}>Choose a version in Updates<HiMiniArrowRight aria-hidden="true" /></button>
      </details>
      <details><summary>Does turning on CIGAR give it access to all my files?</summary><p>No. CIGAR only looks at the project your AI app is working in, and it skips secrets, keys, hidden files, generated folders and anything .gitignore leaves out. Starting CIGAR grants no access to anything else.</p></details>
      <details><summary>Do I have to pick a project folder?</summary>
        <p>No. Without one, CIGAR uses the files that match each prompt. Pick a folder if you want to choose exactly which files it uses for that project.</p>
        <button type="button" className="cigar-text-button" onClick={() => onSelect("access")}>Open Projects &amp; AI apps<HiMiniArrowRight aria-hidden="true" /></button>
      </details>
      <details><summary>Why did a prompt get no files?</summary><p>CIGAR adds only files that match the prompt. A vague prompt, or an empty or brand-new folder, matches nothing, so nothing is added. Name a file, a feature or a term from your project and try again. Also check that Context for AI apps and Allow selected workspace documents are on in Settings.</p></details>
      <details><summary>Does CIGAR save me tokens or make my AI faster?</summary><p>CIGAR does not promise either. It hands over the few pieces that match your prompt instead of whole files, and shows where each piece came from.</p></details>
      <details><summary>What happens when CIGAR is stopped or unavailable?</summary><p>Guard keeps protecting commands under its existing policy and approvals. Prompts simply get no extra files until CIGAR is back. Turn off CIGAR to cancel context work. Memory context and active access end when it stops.</p></details>
      <details><summary>What is saved on disk?</summary><p>Memory is the default. Optional saved evidence uses private local SQLite files without Guard encryption and can outlive a runtime. Privacy provides retention, diagnostics, and removal controls. Restoring evidence never restores app access or approvals.</p></details>
    </section>
    {walkthroughs}
  </div>;
}

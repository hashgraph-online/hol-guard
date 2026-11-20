import type { ReactNode } from "react";
import { HiMiniAcademicCap, HiMiniArrowRight, HiMiniChatBubbleLeftEllipsis, HiMiniCheck, HiMiniDocumentMagnifyingGlass,
  HiMiniFolderPlus, HiMiniPower, HiMiniQuestionMarkCircle, HiMiniShieldCheck, HiMiniEyeSlash, HiMiniCpuChip } from "react-icons/hi2";
import type { CigarTab } from "./workspace-model";

/** Apps whose prompts get matching files on their own. Other apps Guard protects can ask once connected. */
export const CIGAR_PROMPT_APPS = ["Claude Code", "Codex", "Pi", "Oh My Pi"] as const;

const STEPS = [
  { icon: HiMiniChatBubbleLeftEllipsis, title: "You ask", text: "Type a prompt in your AI app, the way you always do." },
  { icon: HiMiniDocumentMagnifyingGlass, title: "CIGAR finds the parts that match", text: "It looks through the project your app is open in and picks the few parts your prompt is about." },
  { icon: HiMiniCheck, title: "Your AI gets just those", text: "Each part comes with the file and lines it came from, so you can check it. When nothing matches, nothing is added." },
] as const;

const PROMISES = [
  { icon: HiMiniPower, text: "Off until you turn it on, and off again with one click." },
  { icon: HiMiniEyeSlash, text: "Never reads secrets, keys, hidden files or anything your .gitignore leaves out." },
  { icon: HiMiniCpuChip, text: "Runs on this computer and keeps its notes in memory unless you choose to save them." },
  { icon: HiMiniShieldCheck, text: "Guard still decides what your AI may do. CIGAR only adds context." },
] as const;

type Props = { onSelect: (tab: CigarTab) => void };

/** The Home section: how CIGAR helps, where it works, and what it never does. */
export function CigarStory({ onSelect }: Props) {
  return <div className="cigar-story">
    <section className="cigar-how" aria-labelledby="cigar-how-heading">
      <h2 id="cigar-how-heading">How it works</h2>
      <ol className="cigar-steps">
        {STEPS.map(({ icon: Icon, title, text }) => <li key={title}>
          <span className="cigar-step-icon" aria-hidden="true"><Icon /></span>
          <h3>{title}</h3>
          <p>{text}</p>
        </li>)}
      </ol>
    </section>

    <div className="cigar-story-pair">
      <section aria-labelledby="cigar-apps-heading">
        <h2 id="cigar-apps-heading">Works in your apps</h2>
        <p>No setup for each app. Once CIGAR is on, every prompt in these apps gets the files that match it.</p>
        <ul className="cigar-apps">{CIGAR_PROMPT_APPS.map((app) => <li key={app}><HiMiniCheck aria-hidden="true" />{app}</li>)}</ul>
        <p className="cigar-story-aside">Projects you add here count for all of them. Other apps Guard protects, like Cursor, can ask CIGAR for files after you connect them in Projects.</p>
      </section>
      <section aria-labelledby="cigar-charge-heading">
        <h2 id="cigar-charge-heading">You stay in charge</h2>
        <ul className="cigar-promises">{PROMISES.map(({ icon: Icon, text }) => <li key={text}><Icon aria-hidden="true" />{text}</li>)}</ul>
      </section>
    </div>

    <section className="cigar-explore" aria-labelledby="cigar-explore-heading">
      <h2 id="cigar-explore-heading">Go further</h2>
      <ul>
        <ExploreRow icon={<HiMiniFolderPlus />} title="Pick the exact files for a project" text="Choose what CIGAR reads in one folder. Your choice counts for every app." onClick={() => onSelect("access")} />
        <ExploreRow icon={<HiMiniAcademicCap />} title="Take a short walkthrough" text="Try CIGAR on your own project, one step at a time." onClick={() => onSelect("guide")} />
        <ExploreRow icon={<HiMiniQuestionMarkCircle />} title="Read common questions" text="What it reads, what it saves, and why a prompt got no files." onClick={() => onSelect("guide")} />
      </ul>
    </section>
  </div>;
}

function ExploreRow({ icon, title, text, onClick }: { icon: ReactNode; title: string; text: string; onClick: () => void }) {
  return <li><button type="button" className="cigar-explore-row" onClick={onClick}>
    <span className="cigar-explore-icon" aria-hidden="true">{icon}</span>
    <span className="cigar-explore-text"><strong>{title}</strong><span>{text}</span></span>
    <HiMiniArrowRight aria-hidden="true" className="cigar-explore-arrow" />
  </button></li>;
}

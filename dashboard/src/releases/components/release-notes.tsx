import { useCallback, useMemo, useState } from "react";
import { HiMiniCheck, HiMiniClipboard } from "react-icons/hi2";

import { parseReleaseInline, parseReleaseMarkdown } from "../release-markdown";
import type { ReleaseBlock, ReleaseInline, ReleaseListItem } from "../release-markdown";

/**
 * Release notes as the maintainer wrote them.
 *
 * The parser hands over data, never markup, and this file turns that data into
 * elements one node at a time. There is no HTML string anywhere in the path,
 * so a release note cannot inject anything into the dashboard however it is
 * written upstream.
 */

export function InlineNodes({ nodes }: { nodes: readonly ReleaseInline[] }) {
  return (
    <>
      {nodes.map((node, position) => {
        const key = `${node.kind}-${position}`;
        switch (node.kind) {
          case "text":
            return <span key={key}>{node.text}</span>;
          case "break":
            return <br key={key} />;
          case "code":
            return (
              <code
                key={key}
                className="rounded-md bg-brand-dark/[0.06] px-1.5 py-0.5 font-mono text-[0.85em] text-brand-dark"
              >
                {node.text}
              </code>
            );
          case "strong":
            return (
              <strong key={key} className="font-semibold text-brand-dark">
                <InlineNodes nodes={node.children} />
              </strong>
            );
          case "emphasis":
            return (
              <em key={key}>
                <InlineNodes nodes={node.children} />
              </em>
            );
          case "link":
            return (
              <a
                key={key}
                href={node.href}
                target="_blank"
                rel="noopener noreferrer"
                className="rounded-sm font-medium text-brand-blue underline decoration-brand-blue/35 underline-offset-[3px] transition-colors duration-150 hover:decoration-brand-blue focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/30 motion-reduce:transition-none"
              >
                <InlineNodes nodes={node.children} />
              </a>
            );
        }
      })}
    </>
  );
}

function ListItems({ items, depth }: { items: readonly ReleaseListItem[]; depth: number }) {
  return (
    <>
      {items.map((item, position) => (
        <li key={position} className="pl-1 marker:text-brand-blue/45">
          <InlineNodes nodes={item.children} />
          {item.items.length > 0 ? (
            <ul className="mt-1.5 list-[circle] space-y-1.5 pl-5">
              <ListItems items={item.items} depth={depth + 1} />
            </ul>
          ) : null}
        </li>
      ))}
    </>
  );
}

/** A command in release notes is there to be run, so it is there to be copied. */
function CodeBlock({ block }: { block: Extract<ReleaseBlock, { kind: "code" }> }) {
  const [copied, setCopied] = useState(false);
  const copy = useCallback(() => {
    void navigator.clipboard
      ?.writeText(block.text)
      .then(() => {
        setCopied(true);
        window.setTimeout(() => setCopied(false), 1_800);
      })
      .catch(() => {
        // Clipboard access can be refused; the text is selectable either way.
      });
  }, [block.text]);
  return (
    <div className="group/code relative my-4 overflow-hidden rounded-xl bg-brand-dark">
      <pre className="overflow-x-auto px-4 py-3.5 pr-14 font-mono text-[13px] leading-6 text-white/90">
        <code>{block.text}</code>
      </pre>
      <button
        type="button"
        onClick={copy}
        className="absolute right-2 top-2 flex size-9 items-center justify-center rounded-lg text-white/55 opacity-0 transition-opacity duration-150 hover:bg-white/10 hover:text-white focus-visible:opacity-100 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-white/40 group-hover/code:opacity-100 motion-reduce:transition-none"
        aria-label={copied ? "Copied" : "Copy this command"}
      >
        {copied ? (
          <HiMiniCheck className="size-4 text-emerald-300" aria-hidden="true" />
        ) : (
          <HiMiniClipboard className="size-4" aria-hidden="true" />
        )}
      </button>
    </div>
  );
}

/** Headings inside the notes sit below the panel's own, so the outline reads
 * in order however deep the upstream Markdown went. */
const HEADING_CLASS: Record<1 | 2 | 3, string> = {
  1: "mt-7 text-[15px] font-semibold tracking-[-0.01em] text-brand-dark first:mt-0",
  2: "mt-6 text-sm font-semibold tracking-[-0.01em] text-brand-dark first:mt-0",
  3: "mt-5 text-sm font-semibold text-brand-dark/80 first:mt-0",
};

function Block({ block }: { block: ReleaseBlock }) {
  switch (block.kind) {
    case "heading": {
      const Tag = (block.level === 1 ? "h4" : block.level === 2 ? "h5" : "h6") as "h4" | "h5" | "h6";
      return (
        <Tag className={`mb-2 ${HEADING_CLASS[block.level]}`}>
          <InlineNodes nodes={block.children} />
        </Tag>
      );
    }
    case "paragraph":
      return (
        <p className="my-3 text-sm leading-6 text-brand-dark/80 first:mt-0">
          <InlineNodes nodes={block.children} />
        </p>
      );
    case "quote":
      return (
        <blockquote className="my-4 border-l border-brand-blue/40 pl-4 text-sm italic leading-6 text-brand-dark/70">
          <InlineNodes nodes={block.children} />
        </blockquote>
      );
    case "list":
      return block.ordered ? (
        <ol className="my-3 list-decimal space-y-1.5 pl-5 text-sm leading-6 text-brand-dark/80">
          <ListItems items={block.items} depth={0} />
        </ol>
      ) : (
        <ul className="my-3 list-disc space-y-1.5 pl-5 text-sm leading-6 text-brand-dark/80">
          <ListItems items={block.items} depth={0} />
        </ul>
      );
    case "code":
      return <CodeBlock block={block} />;
    case "rule":
      return <hr className="my-5 border-brand-dark/10" />;
  }
}

/** Rendered release notes, held to a readable measure. */
export function ReleaseNotes({ source }: { source: string }) {
  const blocks = useMemo(() => parseReleaseMarkdown(source), [source]);
  if (blocks.length === 0) return null;
  return (
    <div className="max-w-[68ch]">
      {blocks.map((block, position) => (
        <Block key={`${block.kind}-${position}`} block={block} />
      ))}
    </div>
  );
}

/** One line of the same grammar, for a list item or a label. */
export function ReleaseInlineText({ source }: { source: string }) {
  const nodes = useMemo(() => parseReleaseInline(source), [source]);
  return <InlineNodes nodes={nodes} />;
}

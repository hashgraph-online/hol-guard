/**
 * One heading shape for every About section.
 *
 * The page used to open each section with a mono, uppercase, wide-tracked
 * line that looked like a label but was the heading — a paragraph, so the
 * sections had no structure to navigate by, and on the hero it sat above the
 * real title as a second, competing one. A section says its name once, in the
 * page's own type, and the shell points its landmark at it.
 */
export function AboutSectionHeading(props: { id: string; title: string; lead?: string }) {
  return (
    <div className="max-w-[68ch]">
      <h2
        id={props.id}
        className="text-2xl font-semibold tracking-[-0.02em] text-brand-dark"
      >
        {props.title}
      </h2>
      {props.lead ? (
        <p className="mt-2 text-base leading-7 text-brand-dark/75">{props.lead}</p>
      ) : null}
    </div>
  );
}

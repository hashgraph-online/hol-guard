import { useEffect, useId, useState, type ReactNode } from "react";

import type { GuardActionExplanationV1 } from "./guard-types";
import { defaultTechnicalDisclosure } from "./presentation-mode";
import { usePresentationMode } from "./presentation-mode-provider";

export type EverydayMessageVariables = Readonly<Record<string, string | number>>;

export function EverydayText({
  messageId,
  text,
  variables = {},
  as: Component = "span",
}: {
  messageId: string;
  text: string;
  variables?: EverydayMessageVariables;
  as?: "span" | "p" | "strong";
}) {
  let rendered = text;
  for (const [key, value] of Object.entries(variables)) {
    rendered = rendered.replaceAll(`{${key}}`, String(value));
  }
  return <Component data-everyday-message-id={messageId}>{rendered}</Component>;
}

export function TechnicalDisclosure({
  children,
  label = "Technical details",
  required = false,
  disclosureKey,
}: {
  children: ReactNode;
  label?: string;
  required?: boolean;
  disclosureKey: string;
}) {
  const { resolved } = usePresentationMode();
  const defaultState = defaultTechnicalDisclosure(resolved.value, required);
  const [open, setOpen] = useState(defaultState.open);
  const panelId = useId();

  useEffect(() => {
    if (required) setOpen(true);
  }, [required]);

  return (
    <section data-technical-disclosure={disclosureKey}>
      <button
        type="button"
        aria-expanded={open}
        aria-controls={panelId}
        onClick={() => {
          if (!required) setOpen((value) => !value);
        }}
      >
        {label}
      </button>
      <div id={panelId} hidden={!open}>
        {children}
      </div>
    </section>
  );
}

export function ExactActionDisclosure({ explanation }: { explanation: GuardActionExplanationV1 }) {
  if (!explanation.technical.available) {
    const reason = explanation.technical.unavailable_reason;
    return (
      <div role="note" data-exact-action-unavailable={reason ?? "unavailable"}>
        Exact technical details are unavailable{reason === "not_retained" ? " because they were not retained" : " on this surface"}.
      </div>
    );
  }
  return (
    <TechnicalDisclosure disclosureKey={`exact-action:${explanation.action_identity}`} label="Exact action">
      <pre data-exact-action>{explanation.technical.command_display ?? explanation.technical.normalized_command_display}</pre>
    </TechnicalDisclosure>
  );
}

export function ConsequenceList({ explanation }: { explanation: GuardActionExplanationV1 }) {
  const items = explanation.everyday.consequences;
  if (items.length === 0) return null;
  return (
    <ul aria-label="What could happen" data-consequence-list>
      {items.map((item) => (
        <li key={`${item.message_id}:${item.message}`} data-severity={item.severity}>
          <EverydayText messageId={item.message_id} text={item.message} />
          {item.confirmed ? <span className="sr-only"> Confirmed.</span> : <span className="sr-only"> Possible outcome.</span>}
        </li>
      ))}
    </ul>
  );
}

export function TargetSummary({ explanation }: { explanation: GuardActionExplanationV1 }) {
  if (explanation.everyday.targets.length === 0) return null;
  return (
    <ul aria-label="Targets" data-target-summary>
      {explanation.everyday.targets.map((target, index) => (
        <li key={`${target.kind}:${target.label}:${index}`} data-target-kind={target.kind} data-sensitivity={target.sensitivity}>
          {target.label}
          {target.scope ? ` (${target.scope})` : ""}
        </li>
      ))}
    </ul>
  );
}

export function ExplanationConfidenceNotice({ explanation }: { explanation: GuardActionExplanationV1 }) {
  if (explanation.confidence === "exact") return null;
  return (
    <div role="note" data-explanation-confidence={explanation.confidence}>
      {explanation.confidence === "limited"
        ? "Guard could not confirm every technical detail. Review the exact action when available."
        : "This explanation is derived from verified action facts."}
    </div>
  );
}

export function ExplanationIdentityMismatchAlert({
  explanation,
  actionIdentity,
  canonicalIdentity,
}: {
  explanation: GuardActionExplanationV1;
  actionIdentity: string;
  canonicalIdentity?: string | null;
}) {
  const actionMismatch = explanation.action_identity !== actionIdentity;
  const canonicalMismatch = canonicalIdentity != null && explanation.canonical_identity !== canonicalIdentity;
  if (!actionMismatch && !canonicalMismatch) return null;
  return (
    <div role="alert" data-explanation-identity-mismatch>
      The explanation no longer matches this action. Reload the request before making a decision.
    </div>
  );
}

export function SaferAlternatives({ explanation }: { explanation: GuardActionExplanationV1 }) {
  if (explanation.everyday.safer_alternatives.length === 0) return null;
  return (
    <ul aria-label="Safer options" data-safer-alternatives>
      {explanation.everyday.safer_alternatives.map((item) => (
        <li key={`${item.message_id}:${item.kind}`} data-alternative-kind={item.kind}>
          <EverydayText messageId={item.message_id} text={item.message} />
        </li>
      ))}
    </ul>
  );
}

export function ActionExplanation({
  explanation,
  actionIdentity,
  canonicalIdentity,
}: {
  explanation: GuardActionExplanationV1;
  actionIdentity: string;
  canonicalIdentity?: string | null;
}) {
  const { resolved } = usePresentationMode();
  return (
    <article data-action-explanation data-presentation-mode={resolved.value} data-action-identity={actionIdentity}>
      <ExplanationIdentityMismatchAlert
        explanation={explanation}
        actionIdentity={actionIdentity}
        canonicalIdentity={canonicalIdentity}
      />
      <h2>
        <EverydayText messageId={explanation.everyday.headline_message_id} text={explanation.everyday.headline} />
      </h2>
      <EverydayText as="p" messageId={explanation.everyday.summary_message_id} text={explanation.everyday.summary} />
      <TargetSummary explanation={explanation} />
      <ConsequenceList explanation={explanation} />
      <ExplanationConfidenceNotice explanation={explanation} />
      {explanation.everyday.recommendation && explanation.everyday.recommendation_message_id ? (
        <EverydayText
          as="p"
          messageId={explanation.everyday.recommendation_message_id}
          text={explanation.everyday.recommendation}
        />
      ) : null}
      <SaferAlternatives explanation={explanation} />
      <ExactActionDisclosure explanation={explanation} />
    </article>
  );
}

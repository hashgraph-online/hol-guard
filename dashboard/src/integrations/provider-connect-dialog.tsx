import { useCallback, useEffect, useRef, useState } from "react";
import { HiMiniArrowTopRightOnSquare, HiMiniXMark } from "react-icons/hi2";

import { ActionButton, SectionLabel } from "../approval-center-primitives";
import { GuardModalLayer } from "../guard-modal-layer";
import { ErrorNote, Field, PULSE_INPUT_CLASS as INPUT_CLASS, PULSE_LABEL_CLASS as LABEL_CLASS } from "../pulse-setup-parts";
import { factDescription, providerErrorMessage } from "./integrations-copy";
import { getKeyHref, OUTCOME_TEXT, runProviderConnect, type ConnectOutcome } from "./provider-connect-flow";
import {
  connectProvider,
  previewProviderConnect,
  ProviderIntegrationApiError,
  type ProviderConnectPreview,
  type ProviderDetail,
} from "./provider-integrations-api";

type Step =
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "review"; preview: ProviderConnectPreview; spent: boolean; outcome: ConnectOutcome | null; changed: boolean }
  | { kind: "sending"; preview: ProviderConnectPreview }
  | { kind: "connected"; detail: ProviderDetail };

/** One fact the person may choose to share, off until they turn it on. */
function OptInToggle(props: { fact: string; checked: boolean; onChange: (checked: boolean) => void }) {
  return (
    <label className="flex min-h-11 items-start gap-3 text-sm text-brand-dark">
      <input
        type="checkbox"
        className="mt-1 size-4"
        checked={props.checked}
        onChange={(event) => props.onChange(event.target.checked)}
      />
      <span>{factDescription(props.fact)}</span>
    </label>
  );
}

export function ConnectReview(props: {
  name: string;
  preview: ProviderConnectPreview;
  obtainUrl: string | null;
  optIn: readonly string[];
  onOptInChange: (fact: string, checked: boolean) => void;
  keyValue: string;
  onKeyChange: (value: string) => void;
  outcome: ConnectOutcome | null;
  changed: boolean;
  pending: boolean;
  onSubmit: () => void;
}) {
  const getKey = getKeyHref(props.obtainUrl);
  const ready = props.keyValue.trim().length > 0 && !props.pending;
  return (
    <form
      className="space-y-5 p-6"
      onSubmit={(event) => {
        event.preventDefault();
        if (ready) props.onSubmit();
      }}
    >
      {props.changed ? (
        <p role="alert" className="text-sm font-medium text-brand-dark">
          {props.name} changed what it asks for since you opened this window. Review it before you connect.
        </p>
      ) : null}
      <div>
        <p className={LABEL_CLASS}>What leaves this device</p>
        <ul className="mt-2 list-disc space-y-1 pl-5 text-sm text-brand-dark">
          {props.preview.shares.map((fact) => (
            <li key={fact}>{factDescription(fact)}</li>
          ))}
        </ul>
        <p className="mt-2 text-xs text-slate-500">
          Sent only to <span className="font-mono break-all">{props.preview.hosts.join(", ")}</span>
        </p>
      </div>
      {props.preview.optInFacts.length > 0 ? (
        <fieldset>
          <legend className={LABEL_CLASS}>Also share (optional)</legend>
          <div className="mt-1">
            {props.preview.optInFacts.map((fact) => (
              <OptInToggle
                key={fact}
                fact={fact}
                checked={props.optIn.includes(fact)}
                onChange={(checked) => props.onOptInChange(fact, checked)}
              />
            ))}
          </div>
        </fieldset>
      ) : null}
      <Field label="API key" hint="Guard stores the key encrypted on this device and never shows it again.">
        <input
          type="password"
          autoComplete="off"
          spellCheck={false}
          value={props.keyValue}
          onChange={(event) => props.onKeyChange(event.target.value)}
          className={INPUT_CLASS}
        />
      </Field>
      {getKey ? (
        <a href={getKey} target="_blank" rel="noopener noreferrer" referrerPolicy="no-referrer"
          className="inline-flex min-h-11 items-center gap-1 text-sm font-medium text-brand-blue">
          Get a key from {props.name}
          <HiMiniArrowTopRightOnSquare className="size-4" aria-hidden="true" />
        </a>
      ) : null}
      <ErrorNote message={props.outcome && props.outcome !== "connected" ? OUTCOME_TEXT[props.outcome] : null} />
      <ActionButton type="submit" disabled={!ready}>
        {props.pending ? "Checking the key..." : "Connect and verify"}
      </ActionButton>
    </form>
  );
}

/** Connect one provider: review the shares, paste the key, verify with the provider. */
export function ProviderConnectDialog(props: {
  providerId: string;
  name: string;
  obtainUrl: string | null;
  onClose: () => void;
}) {
  const [step, setStep] = useState<Step>({ kind: "loading" });
  const [keyValue, setKeyValue] = useState("");
  const [optIn, setOptIn] = useState<string[]>([]);
  const open = useRef(true);

  useEffect(() => {
    open.current = true;
    previewProviderConnect(props.providerId).then(
      (preview) => open.current && setStep({ kind: "review", preview, spent: false, outcome: null, changed: false }),
      (error: unknown) => open.current && setStep({
        kind: "error",
        message: providerErrorMessage(error instanceof ProviderIntegrationApiError ? error.code : "provider_request_failed"),
      }),
    );
    return () => {
      open.current = false;
    };
  }, [props.providerId]);

  const submit = useCallback(async () => {
    if (step.kind !== "review") return;
    const key = keyValue.trim();
    const facts = optIn.filter((fact) => step.preview.optInFacts.includes(fact));
    // The key leaves page memory as soon as it is sent; the field is write-only.
    setKeyValue("");
    setStep({ kind: "sending", preview: step.preview });
    const shown = step.spent ? { ...step.preview, expiresAtMs: 0 } : step.preview;
    const result = await runProviderConnect(shown, {
      now: () => Date.now(),
      preview: () => previewProviderConnect(props.providerId),
      connect: (proof) => connectProvider(props.providerId, { key, proof, enabledOptInFacts: facts }),
    });
    if (!open.current) return;
    if (result.kind === "changed") {
      setStep({ kind: "review", preview: result.preview, spent: false, outcome: null, changed: true });
    } else if (result.outcome === "connected" && result.detail) {
      setStep({ kind: "connected", detail: result.detail });
    } else {
      // A refused connect still spends its proof, so the next try asks for a new one.
      setStep({ kind: "review", preview: step.preview, spent: true, outcome: result.outcome, changed: false });
    }
  }, [keyValue, optIn, props, step]);

  const canClose = step.kind !== "sending";
  const close = () => {
    if (canClose) props.onClose();
  };
  return (
    <GuardModalLayer ariaLabel={`Connect ${props.name}`} onClose={close} panelClassName="w-full max-w-2xl">
      <div className="max-h-[90vh] overflow-y-auto rounded-3xl border border-brand-blue/15 bg-white shadow-2xl">
        <div className="flex items-start justify-between gap-4 border-b border-slate-100 px-6 py-5">
          <div>
            <SectionLabel>Provider integration</SectionLabel>
            <h3 className="mt-2 text-2xl font-semibold tracking-tight text-brand-dark">Connect {props.name}</h3>
          </div>
          <button
            type="button"
            onClick={close}
            hidden={!canClose}
            className="inline-flex size-11 items-center justify-center rounded-full border border-slate-200 bg-white text-slate-500 hover:bg-slate-50 hover:text-brand-dark"
            aria-label={`Close Connect ${props.name}`}
          >
            <HiMiniXMark className="size-5" aria-hidden="true" />
          </button>
        </div>
        {step.kind === "loading" ? <p role="status" className="p-6 text-sm text-slate-600">Loading what this provider receives...</p> : null}
        {step.kind === "error" ? (
          <div className="space-y-4 p-6">
            <ErrorNote message={step.message} />
            <ActionButton variant="outline" onClick={props.onClose}>Close</ActionButton>
          </div>
        ) : null}
        {step.kind === "review" || step.kind === "sending" ? (
          <ConnectReview
            name={props.name}
            preview={step.preview}
            obtainUrl={props.obtainUrl}
            optIn={optIn}
            onOptInChange={(fact, checked) =>
              setOptIn((current) => (checked ? [...current.filter((item) => item !== fact), fact] : current.filter((item) => item !== fact)))
            }
            keyValue={keyValue}
            onKeyChange={setKeyValue}
            outcome={step.kind === "review" ? step.outcome : null}
            changed={step.kind === "review" && step.changed}
            pending={step.kind === "sending"}
            onSubmit={() => void submit()}
          />
        ) : null}
        {step.kind === "connected" ? (
          <div className="space-y-4 p-6">
            <p role="status" className="text-sm text-brand-dark">{OUTCOME_TEXT.connected}</p>
            <ActionButton onClick={props.onClose}>Done</ActionButton>
          </div>
        ) : null}
      </div>
    </GuardModalLayer>
  );
}

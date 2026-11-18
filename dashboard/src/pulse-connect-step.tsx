import QRCode from "react-qr-code";
import { ActionButton } from "./approval-center-primitives";
import { PULSE_FACE_SCAN_OPTIONS, type PulseMinTier } from "./pulse-approval";
import {
  ErrorNote,
  Field,
  PULSE_INPUT_CLASS,
  PULSE_SITE_URL,
  pulseCooldownLabel,
} from "./pulse-setup-parts";
import { buildTotpQrImageOptions } from "./totp-enrollment-qr-panel";

export type PulseCooldown = 0 | 900 | 3600;

/** Agent keys start with `yak_`. A hint, not a gate: Guard's refusal is the source of truth. */
export function pulseAgentKeyHint(value: string): string | null {
  const key = value.trim();
  if (key.length === 0 || key.startsWith("yak_")) return null;
  return "Agent keys start with yak_. Check that you copied the whole key from the YID app.";
}

/** What the collapsed settings row shows, so the choices stay visible without opening it. */
export function pulseApprovalSettingsSummary(minTier: PulseMinTier, cooldown: PulseCooldown): string {
  const faceScan = PULSE_FACE_SCAN_OPTIONS.find((option) => option.value === minTier)?.label ?? "Standard face scan";
  return `${faceScan.replace(" (recommended)", "")} · ${pulseCooldownLabel(cooldown).replace(" (recommended)", "")}`;
}

/**
 * The QR code for the YID app page, drawn here so the user never leaves HOL
 * Guard to find it. It encodes only the public page link: no key, no secret.
 */
export function PulseQrPanel() {
  const qr = buildTotpQrImageOptions();
  return (
    <div className="rounded-2xl border border-brand-blue/15 bg-gradient-to-br from-brand-blue/[0.08] via-white to-white p-4 text-center">
      <div className="mx-auto flex w-fit rounded-2xl border border-white bg-white p-3 shadow-sm">
        <QRCode
          value={PULSE_SITE_URL}
          size={qr.size}
          level={qr.level}
          bgColor={qr.bgColor}
          fgColor={qr.fgColor}
          role="img"
          aria-label="Scan this QR code with your phone camera to get the YID app"
        />
      </div>
      <p className="mt-3 text-sm font-semibold text-brand-dark">Scan with your phone camera</p>
      <p className="mt-1 text-xs leading-5 text-slate-500">
        It installs the YID app if you need it, then registers your Yanez identity.
      </p>
      <p className="mt-2 text-xs text-slate-500">
        Can&apos;t scan?{" "}
        <a className="text-brand-blue underline" href={PULSE_SITE_URL} target="_blank" rel="noreferrer noopener">
          Open pulse.yanez.ai
        </a>
      </p>
    </div>
  );
}

const STEP_CHIP = "flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-brand-blue/10 text-xs font-semibold text-brand-blue";

/** Step 2: scan, create a key in the YID app, paste it. Face scan and cooldown wait in a collapsed row. */
export function PulseConnectStep(props: {
  agentKey: string;
  onAgentKeyChange: (value: string) => void;
  minTier: PulseMinTier;
  onMinTierChange: (value: PulseMinTier) => void;
  cooldown: PulseCooldown;
  onCooldownChange: (value: PulseCooldown) => void;
  error: string | null;
  pending: boolean;
  ready: boolean;
  onSubmit: () => void;
  onBack: () => void;
}) {
  const keyHint = pulseAgentKeyHint(props.agentKey);
  return (
    <div className="grid gap-6 p-6 lg:grid-cols-[240px_minmax(0,1fr)]">
      <PulseQrPanel />
      <div className="space-y-5">
        <ol className="space-y-3 text-sm leading-6 text-slate-600">
          <li className="flex gap-3">
            <span className={STEP_CHIP}>1</span>
            <span>Scan the code, or skip this if you already have the YID app.</span>
          </li>
          <li className="flex gap-3">
            <span className={STEP_CHIP}>2</span>
            <span>
              In the YID app, open <span className="font-medium text-brand-dark">Settings → Agent Keys</span> and create a key
              named HOL Guard.
            </span>
          </li>
          <li className="flex gap-3">
            <span className={STEP_CHIP}>3</span>
            <span>Paste the key here.</span>
          </li>
        </ol>
        <Field label="YID agent key" hint={keyHint ?? "Hidden as you type. Guard stores it in its secret store."}>
          <input
            type="password"
            autoComplete="off"
            spellCheck={false}
            autoFocus
            placeholder="yak_…"
            value={props.agentKey}
            onChange={(event) => props.onAgentKeyChange(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === "Enter" && props.ready && !props.pending) props.onSubmit();
            }}
            className={PULSE_INPUT_CLASS}
          />
        </Field>
        <details className="rounded-xl border border-slate-200 bg-slate-50/70 px-3 py-2">
          <summary className="cursor-pointer text-xs font-semibold text-brand-dark">
            Approval settings
            <span className="ml-2 font-normal text-slate-500">{pulseApprovalSettingsSummary(props.minTier, props.cooldown)}</span>
          </summary>
          <div className="mt-3 space-y-4 pb-1">
            <Field
              label="Face scan"
              hint="Strict needs a phone that supports the stronger face scan. To change this later, turn Pulse off and set it up again."
            >
              <select
                value={props.minTier}
                onChange={(event) => props.onMinTierChange(event.target.value === "high" ? "high" : "medium")}
                className={PULSE_INPUT_CLASS}
              >
                {PULSE_FACE_SCAN_OPTIONS.map((option) => (
                  <option key={option.value} value={option.value}>{option.label}</option>
                ))}
              </select>
            </Field>
            <Field label="Cooldown" hint="A cooldown only covers the same kind of action and scope from the same session. Guard changes always ask again.">
              <select
                value={String(props.cooldown)}
                onChange={(event) => {
                  const seconds = Number(event.target.value);
                  props.onCooldownChange(seconds === 900 ? 900 : seconds === 3600 ? 3600 : 0);
                }}
                className={PULSE_INPUT_CLASS}
              >
                {([0, 900, 3600] as const).map((seconds) => (
                  <option key={seconds} value={seconds}>{pulseCooldownLabel(seconds)}</option>
                ))}
              </select>
            </Field>
          </div>
        </details>
        <ErrorNote message={props.error} />
        <div className="flex flex-wrap gap-2">
          <ActionButton onClick={props.onSubmit} disabled={props.pending || !props.ready}>
            {props.pending ? "Contacting Pulse..." : "Continue"}
          </ActionButton>
          <ActionButton variant="outline" disabled={props.pending} onClick={props.onBack}>
            Back
          </ActionButton>
        </div>
      </div>
    </div>
  );
}

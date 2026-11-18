import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import QRCode from "react-qr-code";

import {
  PulseConnectStep,
  PulseQrPanel,
  focusWithoutScrolling,
  pulseAgentKeyHint,
  pulseApprovalSettingsSummary,
  pulseCooldownFromSeconds,
} from "./pulse-connect-step";
import { PULSE_SITE_URL } from "./pulse-setup-modal";
import { buildTotpQrImageOptions } from "./totp-enrollment-qr-panel";

function assert(condition: boolean, message: string): void {
  if (!condition) throw new Error(`Assertion failed: ${message}`);
}

function stepMarkup(agentKey: string): string {
  return renderToStaticMarkup(
    createElement(PulseConnectStep, {
      agentKey,
      onAgentKeyChange: () => {},
      minTier: "medium",
      onMinTierChange: () => {},
      cooldown: 0,
      onCooldownChange: () => {},
      error: null,
      pending: false,
      ready: agentKey.length > 0,
      onSubmit: () => {},
      onBack: () => {},
    }),
  );
}

/** The QR drawing's path data: two codes match only when they encode the same text. */
function qrShapes(markup: string): string {
  return [...markup.matchAll(/<path[^>]*\sd="([^"]+)"/g)].map((match) => match[1]).join("|");
}

function qrFor(value: string): string {
  const options = buildTotpQrImageOptions();
  return renderToStaticMarkup(
    createElement(QRCode, {
      value,
      size: options.size,
      level: options.level,
      bgColor: options.bgColor,
      fgColor: options.fgColor,
    }),
  );
}

function theQrCodeEncodesOnlyTheYidAppPage(): void {
  const panel = renderToStaticMarkup(createElement(PulseQrPanel));
  const shapes = qrShapes(panel);
  assert(shapes.length > 0, "PULSE-QR-1: the setup window draws a QR code itself");
  assert(shapes === qrShapes(qrFor(PULSE_SITE_URL)), "PULSE-QR-1: the QR code encodes the YID app page link");
  assert(shapes !== qrShapes(qrFor("https://example.invalid/")), "PULSE-QR-1: the comparison tells different links apart");
  assert(/role="img"/.test(panel) && /aria-label="Scan this QR code/.test(panel), "PULSE-QR-1: the QR code has a text label");
  assert(panel.includes(`href="${PULSE_SITE_URL}"`) && /rel="noreferrer noopener"/.test(panel),
    "PULSE-QR-1: users who cannot scan still get the link, opened without a referrer");
}

function stepTwoKeepsTheKeyFieldFirstAndTheSettingsCollapsed(): void {
  const markup = stepMarkup("");
  assert(markup.indexOf('type="password"') > -1 && markup.indexOf("YID agent key") > -1,
    "PULSE-QR-2: the agent key field stays on the step");
  assert(!/autofocus/i.test(markup),
    "PULSE-QR-2: focus comes from an effect that does not scroll, never from the autofocus attribute that would");
  const details = markup.slice(markup.indexOf("<details"), markup.indexOf("</details>"));
  assert(details.includes("Approval settings") && details.includes("Face scan") && details.includes("Cooldown"),
    "PULSE-QR-2: face scan and cooldown sit in the collapsed settings row");
  assert(!/<details[^>]*\sopen/.test(markup), "PULSE-QR-2: the settings row starts closed");
  assert(markup.indexOf("YID agent key") < markup.indexOf("<details"), "PULSE-QR-2: the key field comes before the settings row");
  assert(markup.indexOf("<details") < markup.indexOf("Continue"), "PULSE-QR-2: Continue sits below every field");
  assert(details.includes("Standard face scan (recommended)") && details.includes("Strict face scan"),
    "PULSE-QR-2: both face scan choices are still offered");
  assert(details.includes("Every action (recommended)") && details.includes("15 minutes") && details.includes("1 hour"),
    "PULSE-QR-2: every cooldown is still offered");
  assert(markup.includes("Back"), "PULSE-QR-2: the step still has Back");
}

function theAgentKeyHintOnlyAppearsForAKeyThatDoesNotLookRight(): void {
  assert(pulseAgentKeyHint("") === null, "PULSE-QR-3: nothing typed, no hint");
  assert(pulseAgentKeyHint("   ") === null, "PULSE-QR-3: only spaces, no hint");
  assert(pulseAgentKeyHint("yak_abc123") === null, "PULSE-QR-3: a yak_ key gets no hint");
  assert(pulseAgentKeyHint("  yak_abc123  ") === null, "PULSE-QR-3: pasted spaces around a yak_ key are fine");
  assert(pulseAgentKeyHint("abc123") !== null, "PULSE-QR-3: another start gets a hint");
  assert(/yak_/.test(pulseAgentKeyHint("483 921") ?? ""), "PULSE-QR-3: the hint names the prefix");
  assert(stepMarkup("abc123").includes("Agent keys start with yak_"), "PULSE-QR-3: the hint shows under the field");
  assert(!stepMarkup("yak_abc123").includes("Agent keys start with yak_"), "PULSE-QR-3: a good key shows the usual hint");
  assert(stepMarkup("yak_abc123").includes("Guard stores it in its secret store"),
    "PULSE-QR-3: the usual hint says where the key goes");
  const continueDisabled = (markup: string): boolean => /<button[^>]*\sdisabled=""[^>]*>Continue<\/button>/.test(markup);
  assert(continueDisabled(stepMarkup("")), "PULSE-QR-3: Continue waits for a key");
  assert(!continueDisabled(stepMarkup("abc123")), "PULSE-QR-3: the hint does not block Continue; Guard's own refusal is the check");
}

function theCollapsedRowShowsTheCurrentChoices(): void {
  assert(pulseApprovalSettingsSummary("medium", 0) === "Standard face scan · Every action",
    "PULSE-QR-4: defaults read without the 'recommended' tags");
  assert(pulseApprovalSettingsSummary("high", 900) === "Strict face scan · 15 minutes, same kind of action",
    "PULSE-QR-4: changed choices show on the closed row");
  assert(pulseApprovalSettingsSummary("medium", 3600) === "Standard face scan · 1 hour, same kind of action",
    "PULSE-QR-4: the one hour choice shows on the closed row");
}

function focusingTheKeyFieldNeverScrollsTheQrCodeOutOfView(): void {
  const calls: Array<FocusOptions | undefined> = [];
  focusWithoutScrolling({ focus: (options) => calls.push(options) });
  assert(calls.length === 1 && calls[0]?.preventScroll === true, "PULSE-QR-5: the key field is focused with preventScroll");
  focusWithoutScrolling(null);
  assert(calls.length === 1, "PULSE-QR-5: no field yet, nothing to focus");
}

function theCooldownSelectMapsBackToTheThreeChoices(): void {
  assert(pulseCooldownFromSeconds(0) === 0, "PULSE-QR-6: 0 means every action");
  assert(pulseCooldownFromSeconds(900) === 900, "PULSE-QR-6: 900 means 15 minutes");
  assert(pulseCooldownFromSeconds(3600) === 3600, "PULSE-QR-6: 3600 means 1 hour");
  assert(pulseCooldownFromSeconds(42) === 0 && pulseCooldownFromSeconds(Number.NaN) === 0,
    "PULSE-QR-6: an unknown value falls back to no cooldown");
}

theQrCodeEncodesOnlyTheYidAppPage();
stepTwoKeepsTheKeyFieldFirstAndTheSettingsCollapsed();
theAgentKeyHintOnlyAppearsForAKeyThatDoesNotLookRight();
theCollapsedRowShowsTheCurrentChoices();
focusingTheKeyFieldNeverScrollsTheQrCodeOutOfView();
theCooldownSelectMapsBackToTheThreeChoices();
console.log("pulse-connect-step tests passed");

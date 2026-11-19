import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import QRCode from "react-qr-code";

import {
  PulseConnectStep,
  PulseQrPanel,
  pulseAgentKeyHint,
  pulseApprovalSettingsSummary,
  pulseCooldownFromSeconds,
} from "./pulse-connect-step";
import {
  type PulseMeasurable,
  boxWithin,
  focusForPlan,
  isFullyVisible,
  pulseInitialFocusPlan,
} from "./pulse-initial-focus";
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
  assert(/<div[^>]*class="[^"]*\sp-5\s[^"]*"[^>]*><svg/.test(panel),
    "PULSE-QR-1: the white wrapper leaves about four modules of clear space around the code");
  assert(panel.includes("Tap its app link") && !panel.includes("It installs the YID app"),
    "PULSE-QR-1: the copy says what to tap after scanning instead of promising an install");
  assert(panel.includes('tabindex="-1"'), "PULSE-QR-1: the panel can take focus when the key field is out of view");
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

function focusingFollowsWhatTheUserCanSee(): void {
  const calls: Array<FocusOptions | undefined> = [];
  const element = { focus: (options?: FocusOptions) => { calls.push(options); } };
  focusForPlan(element, false);
  assert(calls.length === 1 && calls[0]?.preventScroll === true, "PULSE-QR-5: a visible target is focused with preventScroll");
  focusForPlan(element, true);
  assert(calls.length === 2 && calls[1]?.preventScroll === false, "PULSE-QR-5: a target out of view is focused with scrolling");
  focusForPlan(null, true);
  assert(calls.length === 2, "PULSE-QR-5: no element yet, nothing to focus");
  const keyVisible = pulseInitialFocusPlan(true, true);
  assert(keyVisible.target === "key" && !keyVisible.scroll, "PULSE-QR-5: a visible key field takes focus, no scroll");
  const keyOnly = pulseInitialFocusPlan(true, false);
  assert(keyOnly.target === "key" && !keyOnly.scroll, "PULSE-QR-5: a visible key field never scrolls, even with the panel out of view");
  const qrVisible = pulseInitialFocusPlan(false, true);
  assert(qrVisible.target === "qr" && !qrVisible.scroll,
    "PULSE-QR-5: a key field out of view never takes focus; the visible QR panel does, without scrolling");
  const nothingVisible = pulseInitialFocusPlan(false, false);
  assert(nothingVisible.target === "qr" && nothingVisible.scroll,
    "PULSE-QR-5: with neither in view the QR panel takes focus and is scrolled into view");
}

function stand(top: number, bottom: number, parent: PulseMeasurable | null, overflowY = "visible"):
  PulseMeasurable & { overflowY: string } {
  return { getBoundingClientRect: () => ({ top, bottom }), parentElement: parent, overflowY };
}

function theKeyFieldOnlyTakesFocusWhenTheUserCanSeeIt(): void {
  assert(boxWithin({ top: 10, bottom: 20 }, { top: 0, bottom: 20 }) && !boxWithin({ top: 10, bottom: 21 }, { top: 0, bottom: 20 }),
    "PULSE-QR-5: a box must sit wholly inside the span");
  const view = (innerHeight: number) => ({
    innerHeight,
    overflowY: (node: PulseMeasurable) => (node as PulseMeasurable & { overflowY: string }).overflowY,
  });
  const modalScroll = stand(100, 500, null, "auto");
  const inView = stand(300, 340, modalScroll);
  const belowTheFold = stand(520, 560, modalScroll);
  assert(isFullyVisible(inView, view(900)), "PULSE-QR-5: a field inside the modal's scroll area is visible");
  assert(!isFullyVisible(belowTheFold, view(900)),
    "PULSE-QR-5: a field below the modal's scroll area is not visible even in a tall window");
  assert(!isFullyVisible(inView, view(320)), "PULSE-QR-5: a field below the window is not visible");
  assert(!isFullyVisible(stand(90, 130, modalScroll), view(900)), "PULSE-QR-5: a field above the scroll area is not visible");
  const noScroller = stand(0, 5000, null);
  assert(isFullyVisible(stand(300, 340, noScroller), view(900)),
    "PULSE-QR-5: ancestors that do not clip never hide the field");
  assert(!isFullyVisible(stand(300, 340, stand(0, 5000, null, "hidden")), view(320)),
    "PULSE-QR-5: a clipping ancestor taller than the window still leaves the window as the limit");
}

function theFocusedQrPanelShowsAVisibleIndicator(): void {
  const panel = renderToStaticMarkup(createElement(PulseQrPanel));
  assert(panel.includes("focus:ring-2"), "PULSE-QR-5: the panel focus indicator is a ring, not removed");
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
focusingFollowsWhatTheUserCanSee();
theKeyFieldOnlyTakesFocusWhenTheUserCanSeeIt();
theFocusedQrPanelShowsAVisibleIndicator();
theCooldownSelectMapsBackToTheThreeChoices();
console.log("pulse-connect-step tests passed");

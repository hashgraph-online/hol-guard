import { r as reactExports, aK as fetchResolvedApprovalGate, j as jsxRuntimeExports, A as ActionButton, aL as ApprovalProofModal, T as Tag, aA as PROTECTION_POSTURE_COPY, aM as POSTURE_OUTCOME_COLUMNS, aN as getDefaultExportFromCjs, aO as React, V as HiMiniShieldCheck, aP as HiMiniSquares2X2, y as HiMiniLockClosed, aQ as HiMiniBellAlert, aR as HiMiniAdjustmentsHorizontal, aS as HiMiniCircleStack, aT as TabBar, H as HiMiniChevronRight, S as SectionLabel, a5 as useFocusTrap, aU as fetchCloudReviewSettings, a3 as HiMiniCloud, i as HiMiniArrowPath, a0 as HiMiniXMark, aV as ApprovalProofFieldInputs, aW as isApprovalProofSubmitDisabled, aX as buildApprovalProofCredentials, aY as changeCloudReviewSettings, aZ as shellHref, c as contextStatusCopy, a_ as listContextAgentSessions, h as harnessDisplayName, a$ as revokeContextAgentSession, b0 as authorizeContextAgentSession, b1 as ContextAssistanceApiError, b2 as ask, b3 as parseContextScope, b4 as validContextBrokerRevision, b5 as listContextWorkspaces, b6 as manageContextWorkspace, b7 as grantContextWorkspace, b8 as compileWorkspaceContext, w as HiMiniArrowRight, u as HiMiniDocumentText, v as HiMiniCheckCircle, b9 as HiMiniDocumentMagnifyingGlass, ba as HiMiniLink, s as HiMiniCommandLine, k as HiMiniCheck, bb as HiMiniClipboardDocument, bc as HiMiniArrowLeft, bd as HiMiniAcademicCap, be as subscribeDashboardLocation, bf as HiMiniCpuChip, bg as isGuardDemoMode, bh as fetchWithGuardAuth, bi as parseContextAssistanceStatus, bj as isCigarBuildIdentity, bk as isCigarProducerVersion, bl as isCigarCoreLabel, bm as fetchContextInstallations, f as fetchContextAssistance, bn as commitDashboardLocation, a as controlContextAssistance, bo as savedEvidenceCopy, bp as downloadBlob, bq as guardAwareHref, br as fetchContextData, bs as forgetContextHistory, bt as forgetSavedEvidence, bu as resolveProtectionLevelCopy, av as fetchSettings, bv as fetchRuntimeSnapshot, bw as clearHarnessWatchOverrides, bx as withHarnessPosturePatch, K as updateSettings, by as clearPolicy, bz as clearReviewQueue, bA as revokeApprovalGateCooldown, bB as disableApprovalGateTotp, bC as importSettings, bD as resetSettings, bE as enrollApprovalGateTotp, bF as verifyApprovalGateTotp, bG as clearEvidence, bH as exportDiagnostics, bI as repairApprovalCenter, bJ as exportSettings, bK as setupDesktopNotifications, a1 as EmptyState, bL as settingsWatchBannerModel, bM as WorkspacePageHeader, W as WatchProtectionBanner, t as HiMiniMagnifyingGlass, bN as navigateFromAnchor, g as HiMiniChevronDown, a7 as HiMiniExclamationTriangle, bO as humanizeList, bP as isProtectionPosture, bQ as deriveProtectionPosture, bR as normalizeHarnessPostures, bS as approvalGateCooldownLabel } from "../guard-dashboard.js";
import { p as planGuardHookRemoval, r as removeAllGuardHooks, a as GuardRepairRequestError, S as SettingsSaveProofModal, b as resolveSettingsSaveProofKind, c as requiresSettingsSaveProof, d as HarnessPostureSummaryCard, e as HarnessPostureManager, G as GuardRepairControl, f as resolveSettingsSaveProofModalCopy } from "./settings-save-proof-modal-D6WLu1uM.js";
import { f as filterSettingsBySearch, R as RISK_CONTROL_CONSEQUENCES } from "./app-catalog-Ca_M7GbC.js";
import { C as ConfirmDialog, u as useConfirmDialog } from "./confirm-dialog-CPN0cVtQ.js";
import { C as ConnectGuardCloudButton } from "./connect-guard-cloud-button-DtM-rmur.js";
function describeAffectedHarness(item) {
  const count2 = item.hook_count ?? item.swept_hook_count;
  if (typeof count2 === "number" && count2 > 0) {
    return `${item.harness} (${count2} hook${count2 === 1 ? "" : "s"})`;
  }
  return item.harness;
}
function removalOutcomeMessage(report) {
  if (report.status === "nothing_to_remove") return "No Guard hooks were found. Nothing was removed.";
  if (report.status === "partial") {
    return "Some Guard hooks could not be removed. Review the apps below, then try again or run `hol-guard hooks remove --all` in a terminal.";
  }
  return "Guard hooks were removed. Your coding apps now run without Guard protection.";
}
function AffectedList({ items, label }) {
  if (items.length === 0) return null;
  return /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "flex flex-wrap gap-1.5", "aria-label": label, children: items.map((item) => /* @__PURE__ */ jsxRuntimeExports.jsx("li", { children: /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: "slate", children: describeAffectedHarness(item) }) }, item.harness)) });
}
function remainingHooksMessage(report) {
  const remaining = report.post_state?.remaining_harnesses ?? [];
  if (remaining.length === 0) return "Check: no Guard hooks remain in any app.";
  return `Still has Guard hooks: ${remaining.map((item) => item.harness).join(", ")}.`;
}
function RemovalResult({ report }) {
  const outcome = /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-medium text-brand-dark", children: removalOutcomeMessage(report) });
  if (report.status === "nothing_to_remove") {
    return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "space-y-2", children: outcome });
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-2", children: [
    outcome,
    /* @__PURE__ */ jsxRuntimeExports.jsx(AffectedList, { items: report.harnesses, label: "Apps changed" }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-500", children: remainingHooksMessage(report) }),
    report.backup_dir ? /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "break-all text-xs text-slate-500", children: [
      "Backups: ",
      report.backup_dir
    ] }) : null,
    /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "text-xs text-slate-500", children: [
      "Reinstall with ",
      /* @__PURE__ */ jsxRuntimeExports.jsx("code", { className: "font-mono", children: report.reinstall_command }),
      "."
    ] })
  ] });
}
function GuardHookRemovalPanel() {
  const [phase, setPhase] = reactExports.useState({ kind: "idle" });
  const handleReview = reactExports.useCallback(async () => {
    setPhase({ kind: "loading" });
    try {
      const [plan, gate] = await Promise.all([planGuardHookRemoval(), fetchResolvedApprovalGate()]);
      setPhase(
        plan.status === "nothing_to_remove" ? { kind: "done", report: plan } : { kind: "review", plan, gate }
      );
    } catch (error) {
      setPhase({ kind: "error", message: error instanceof Error ? error.message : "Guard could not list its hooks." });
    }
  }, []);
  const handleReviewClick = reactExports.useCallback(() => {
    void handleReview();
  }, [handleReview]);
  const handleContinue = reactExports.useCallback(() => {
    setPhase(
      (current) => current.kind === "review" ? { kind: "proof", plan: current.plan, gate: current.gate, error: null } : current
    );
  }, []);
  const handleCancel = reactExports.useCallback(() => setPhase({ kind: "idle" }), []);
  const handleConfirm = reactExports.useCallback(
    async (credentials) => {
      if (phase.kind !== "proof") return;
      const { plan, gate } = phase;
      setPhase({ kind: "removing", plan, gate });
      try {
        setPhase({ kind: "done", report: await removeAllGuardHooks(credentials) });
      } catch (error) {
        const message2 = error instanceof Error ? error.message : "Guard could not remove its hooks.";
        const retryable = error instanceof GuardRepairRequestError && error.status >= 400 && error.status < 500;
        setPhase(retryable ? { kind: "proof", plan, gate, error: message2 } : { kind: "error", message: message2 });
      }
    },
    [phase]
  );
  const handleConfirmClick = reactExports.useCallback(
    (credentials) => {
      void handleConfirm(credentials);
    },
    [handleConfirm]
  );
  const gateMissing = (phase.kind === "review" || phase.kind === "proof" || phase.kind === "removing") && !phase.gate?.enabled;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-3", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-brand-dark", children: "Remove Guard from all apps" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-500", children: "Removes every Guard hook from every connected app, including ones Guard no longer tracks. Other hooks are left alone and each changed file is backed up. Needs your approval password or authenticator code." })
    ] }),
    phase.kind === "idle" || phase.kind === "loading" || phase.kind === "error" ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { children: /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { onClick: handleReviewClick, disabled: phase.kind === "loading", variant: "outline", children: phase.kind === "loading" ? "Checking apps…" : "Review and remove" }) }) : null,
    phase.kind === "review" || phase.kind === "proof" || phase.kind === "removing" ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-2 rounded-xl border border-brand-attention/20 bg-brand-attention/[0.04] p-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "text-sm font-medium text-brand-dark", children: [
        "Guard hooks will be removed from ",
        phase.plan.harnesses.length,
        " app",
        phase.plan.harnesses.length === 1 ? "" : "s",
        ". They stop being protected until you reinstall."
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(AffectedList, { items: phase.plan.harnesses, label: "Apps affected" }),
      gateMissing ? /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "text-xs text-slate-600", children: [
        "Removal from the dashboard needs the local approval gate. Enable it in Settings, Approval gate, or run",
        " ",
        /* @__PURE__ */ jsxRuntimeExports.jsx("code", { className: "font-mono", children: "hol-guard hooks remove --all" }),
        " in a terminal."
      ] }) : /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex gap-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { variant: "danger", onClick: handleContinue, disabled: phase.kind !== "review", children: "Remove Guard from all apps" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { variant: "outline", onClick: handleCancel, disabled: phase.kind === "removing", children: "Cancel" })
      ] }),
      gateMissing ? /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { variant: "outline", onClick: handleCancel, children: "Close" }) : null
    ] }) : null,
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { "aria-live": "polite", children: [
      phase.kind === "done" ? /* @__PURE__ */ jsxRuntimeExports.jsx(RemovalResult, { report: phase.report }) : null,
      phase.kind === "error" ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "alert", className: "text-sm text-brand-attention", children: phase.message }) : null
    ] }),
    phase.kind === "proof" || phase.kind === "removing" ? /* @__PURE__ */ jsxRuntimeExports.jsx(
      ApprovalProofModal,
      {
        title: "Remove Guard from all apps",
        detail: `Enter local approval proof. Guard hooks will be removed from: ${phase.plan.harnesses.map((item) => item.harness).join(", ")}.`,
        confirmLabel: "Remove Guard",
        busy: phase.kind === "removing",
        busyLabel: "Removing…",
        approvalGate: phase.gate,
        error: phase.kind === "proof" ? phase.error : null,
        onCancel: handleCancel,
        onConfirm: handleConfirmClick
      }
    ) : null
  ] });
}
const POSTURE_ORDER = ["protected", "extra_careful", "watch"];
function ProtectionPosturePanel(props) {
  const copy = PROTECTION_POSTURE_COPY[props.posture];
  const outcomes = POSTURE_OUTCOME_COLUMNS[props.posture];
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-6", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("fieldset", { className: "border-0 p-0", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("legend", { className: "sr-only", children: "Protection" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "flex flex-col gap-2 rounded-xl bg-slate-50 p-1 sm:flex-row", children: POSTURE_ORDER.map((value) => /* @__PURE__ */ jsxRuntimeExports.jsx(
        PostureChoice,
        {
          value,
          selected: props.posture === value,
          disabled: props.disabledPostures?.includes(value) === true,
          onSelect: props.onPostureChange
        },
        value
      )) })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm leading-relaxed text-slate-600", children: copy.help }),
    props.customRules ? /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "text-sm font-medium text-brand-dark", children: [
      "Using custom rules on top of ",
      copy.label
    ] }) : null,
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid gap-3 md:grid-cols-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(OutcomeColumn, { title: "Stops automatically", body: outcomes.stops }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(OutcomeColumn, { title: "Asks once, then remembers", body: outcomes.asks }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(OutcomeColumn, { title: "Runs quietly", body: outcomes.runs })
    ] }),
    props.capabilities.length > 0 ? /* @__PURE__ */ jsxRuntimeExports.jsxs("details", { className: "rounded-xl border border-slate-200 bg-white", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("summary", { className: "flex min-h-11 cursor-pointer list-none items-center px-4 py-3 text-sm font-semibold text-brand-dark [&::-webkit-details-marker]:hidden", children: "What this looks like in each app" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "space-y-3 border-t border-slate-100 px-4 py-3", children: props.capabilities.map((capability) => /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-medium text-brand-dark", children: capability.display_name }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-0.5 text-sm text-slate-500", children: capability.honesty_sentence })
      ] }, capability.harness)) })
    ] }) : null
  ] });
}
function PostureChoice(props) {
  const handleChange = reactExports.useCallback(() => {
    if (props.disabled) return;
    props.onSelect(props.value);
  }, [props.disabled, props.onSelect, props.value]);
  let choiceClass = "cursor-pointer text-slate-600 hover:text-brand-dark";
  if (props.disabled) {
    choiceClass = "cursor-not-allowed text-slate-400";
  } else if (props.selected) {
    choiceClass = "cursor-pointer bg-white text-brand-dark shadow-sm";
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(
    "label",
    {
      className: `flex min-h-11 flex-1 items-center justify-center rounded-lg px-3 py-2 text-sm font-semibold transition-colors ${choiceClass}`,
      children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "input",
          {
            type: "radio",
            name: "protection-posture",
            value: props.value,
            checked: props.selected,
            disabled: props.disabled,
            onChange: handleChange,
            className: "sr-only"
          }
        ),
        PROTECTION_POSTURE_COPY[props.value].label
      ]
    }
  );
}
function OutcomeColumn(props) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-xl border border-slate-200 bg-white p-4", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-semibold uppercase tracking-[0.16em] text-slate-400", children: props.title }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm leading-relaxed text-slate-600", children: props.body })
  ] });
}
var propTypes$2 = { exports: {} };
var ReactPropTypesSecret_1;
var hasRequiredReactPropTypesSecret;
function requireReactPropTypesSecret() {
  if (hasRequiredReactPropTypesSecret) return ReactPropTypesSecret_1;
  hasRequiredReactPropTypesSecret = 1;
  var ReactPropTypesSecret = "SECRET_DO_NOT_PASS_THIS_OR_YOU_WILL_BE_FIRED";
  ReactPropTypesSecret_1 = ReactPropTypesSecret;
  return ReactPropTypesSecret_1;
}
var factoryWithThrowingShims;
var hasRequiredFactoryWithThrowingShims;
function requireFactoryWithThrowingShims() {
  if (hasRequiredFactoryWithThrowingShims) return factoryWithThrowingShims;
  hasRequiredFactoryWithThrowingShims = 1;
  var ReactPropTypesSecret = /* @__PURE__ */ requireReactPropTypesSecret();
  function emptyFunction() {
  }
  function emptyFunctionWithReset() {
  }
  emptyFunctionWithReset.resetWarningCache = emptyFunction;
  factoryWithThrowingShims = function() {
    function shim(props, propName, componentName, location, propFullName, secret) {
      if (secret === ReactPropTypesSecret) {
        return;
      }
      var err = new Error(
        "Calling PropTypes validators directly is not supported by the `prop-types` package. Use PropTypes.checkPropTypes() to call them. Read more at http://fb.me/use-check-prop-types"
      );
      err.name = "Invariant Violation";
      throw err;
    }
    shim.isRequired = shim;
    function getShim() {
      return shim;
    }
    var ReactPropTypes = {
      array: shim,
      bigint: shim,
      bool: shim,
      func: shim,
      number: shim,
      object: shim,
      string: shim,
      symbol: shim,
      any: shim,
      arrayOf: getShim,
      element: shim,
      elementType: shim,
      instanceOf: getShim,
      node: shim,
      objectOf: getShim,
      oneOf: getShim,
      oneOfType: getShim,
      shape: getShim,
      exact: getShim,
      checkPropTypes: emptyFunctionWithReset,
      resetWarningCache: emptyFunction
    };
    ReactPropTypes.PropTypes = ReactPropTypes;
    return ReactPropTypes;
  };
  return factoryWithThrowingShims;
}
var hasRequiredPropTypes;
function requirePropTypes() {
  if (hasRequiredPropTypes) return propTypes$2.exports;
  hasRequiredPropTypes = 1;
  {
    propTypes$2.exports = /* @__PURE__ */ requireFactoryWithThrowingShims()();
  }
  return propTypes$2.exports;
}
var propTypesExports = /* @__PURE__ */ requirePropTypes();
const PropTypes = /* @__PURE__ */ getDefaultExportFromCjs(propTypesExports);
const qrcode = function(typeNumber, errorCorrectionLevel) {
  const PAD0 = 236;
  const PAD1 = 17;
  let _typeNumber = typeNumber;
  const _errorCorrectionLevel = QRErrorCorrectionLevel[errorCorrectionLevel];
  let _modules = null;
  let _moduleCount = 0;
  let _dataCache = null;
  const _dataList = [];
  const _this = {};
  const makeImpl = function(test, maskPattern) {
    _moduleCount = _typeNumber * 4 + 17;
    _modules = (function(moduleCount) {
      const modules = new Array(moduleCount);
      for (let row = 0; row < moduleCount; row += 1) {
        modules[row] = new Array(moduleCount);
        for (let col = 0; col < moduleCount; col += 1) {
          modules[row][col] = null;
        }
      }
      return modules;
    })(_moduleCount);
    setupPositionProbePattern(0, 0);
    setupPositionProbePattern(_moduleCount - 7, 0);
    setupPositionProbePattern(0, _moduleCount - 7);
    setupPositionAdjustPattern();
    setupTimingPattern();
    setupTypeInfo(test, maskPattern);
    if (_typeNumber >= 7) {
      setupTypeNumber(test);
    }
    if (_dataCache == null) {
      _dataCache = createData(_typeNumber, _errorCorrectionLevel, _dataList);
    }
    mapData(_dataCache, maskPattern);
  };
  const setupPositionProbePattern = function(row, col) {
    for (let r = -1; r <= 7; r += 1) {
      if (row + r <= -1 || _moduleCount <= row + r) continue;
      for (let c = -1; c <= 7; c += 1) {
        if (col + c <= -1 || _moduleCount <= col + c) continue;
        if (0 <= r && r <= 6 && (c == 0 || c == 6) || 0 <= c && c <= 6 && (r == 0 || r == 6) || 2 <= r && r <= 4 && 2 <= c && c <= 4) {
          _modules[row + r][col + c] = true;
        } else {
          _modules[row + r][col + c] = false;
        }
      }
    }
  };
  const getBestMaskPattern = function() {
    let minLostPoint = 0;
    let pattern = 0;
    for (let i = 0; i < 8; i += 1) {
      makeImpl(true, i);
      const lostPoint = QRUtil.getLostPoint(_this);
      if (i == 0 || minLostPoint > lostPoint) {
        minLostPoint = lostPoint;
        pattern = i;
      }
    }
    return pattern;
  };
  const setupTimingPattern = function() {
    for (let r = 8; r < _moduleCount - 8; r += 1) {
      if (_modules[r][6] != null) {
        continue;
      }
      _modules[r][6] = r % 2 == 0;
    }
    for (let c = 8; c < _moduleCount - 8; c += 1) {
      if (_modules[6][c] != null) {
        continue;
      }
      _modules[6][c] = c % 2 == 0;
    }
  };
  const setupPositionAdjustPattern = function() {
    const pos = QRUtil.getPatternPosition(_typeNumber);
    for (let i = 0; i < pos.length; i += 1) {
      for (let j = 0; j < pos.length; j += 1) {
        const row = pos[i];
        const col = pos[j];
        if (_modules[row][col] != null) {
          continue;
        }
        for (let r = -2; r <= 2; r += 1) {
          for (let c = -2; c <= 2; c += 1) {
            if (r == -2 || r == 2 || c == -2 || c == 2 || r == 0 && c == 0) {
              _modules[row + r][col + c] = true;
            } else {
              _modules[row + r][col + c] = false;
            }
          }
        }
      }
    }
  };
  const setupTypeNumber = function(test) {
    const bits = QRUtil.getBCHTypeNumber(_typeNumber);
    for (let i = 0; i < 18; i += 1) {
      const mod = !test && (bits >> i & 1) == 1;
      _modules[Math.floor(i / 3)][i % 3 + _moduleCount - 8 - 3] = mod;
    }
    for (let i = 0; i < 18; i += 1) {
      const mod = !test && (bits >> i & 1) == 1;
      _modules[i % 3 + _moduleCount - 8 - 3][Math.floor(i / 3)] = mod;
    }
  };
  const setupTypeInfo = function(test, maskPattern) {
    const data = _errorCorrectionLevel << 3 | maskPattern;
    const bits = QRUtil.getBCHTypeInfo(data);
    for (let i = 0; i < 15; i += 1) {
      const mod = !test && (bits >> i & 1) == 1;
      if (i < 6) {
        _modules[i][8] = mod;
      } else if (i < 8) {
        _modules[i + 1][8] = mod;
      } else {
        _modules[_moduleCount - 15 + i][8] = mod;
      }
    }
    for (let i = 0; i < 15; i += 1) {
      const mod = !test && (bits >> i & 1) == 1;
      if (i < 8) {
        _modules[8][_moduleCount - i - 1] = mod;
      } else if (i < 9) {
        _modules[8][15 - i - 1 + 1] = mod;
      } else {
        _modules[8][15 - i - 1] = mod;
      }
    }
    _modules[_moduleCount - 8][8] = !test;
  };
  const mapData = function(data, maskPattern) {
    let inc = -1;
    let row = _moduleCount - 1;
    let bitIndex = 7;
    let byteIndex = 0;
    const maskFunc = QRUtil.getMaskFunction(maskPattern);
    for (let col = _moduleCount - 1; col > 0; col -= 2) {
      if (col == 6) col -= 1;
      while (true) {
        for (let c = 0; c < 2; c += 1) {
          if (_modules[row][col - c] == null) {
            let dark = false;
            if (byteIndex < data.length) {
              dark = (data[byteIndex] >>> bitIndex & 1) == 1;
            }
            const mask = maskFunc(row, col - c);
            if (mask) {
              dark = !dark;
            }
            _modules[row][col - c] = dark;
            bitIndex -= 1;
            if (bitIndex == -1) {
              byteIndex += 1;
              bitIndex = 7;
            }
          }
        }
        row += inc;
        if (row < 0 || _moduleCount <= row) {
          row -= inc;
          inc = -inc;
          break;
        }
      }
    }
  };
  const createBytes = function(buffer, rsBlocks) {
    let offset = 0;
    let maxDcCount = 0;
    let maxEcCount = 0;
    const dcdata = new Array(rsBlocks.length);
    const ecdata = new Array(rsBlocks.length);
    for (let r = 0; r < rsBlocks.length; r += 1) {
      const dcCount = rsBlocks[r].dataCount;
      const ecCount = rsBlocks[r].totalCount - dcCount;
      maxDcCount = Math.max(maxDcCount, dcCount);
      maxEcCount = Math.max(maxEcCount, ecCount);
      dcdata[r] = new Array(dcCount);
      for (let i = 0; i < dcdata[r].length; i += 1) {
        dcdata[r][i] = 255 & buffer.getBuffer()[i + offset];
      }
      offset += dcCount;
      const rsPoly = QRUtil.getErrorCorrectPolynomial(ecCount);
      const rawPoly = qrPolynomial(dcdata[r], rsPoly.getLength() - 1);
      const modPoly = rawPoly.mod(rsPoly);
      ecdata[r] = new Array(rsPoly.getLength() - 1);
      for (let i = 0; i < ecdata[r].length; i += 1) {
        const modIndex = i + modPoly.getLength() - ecdata[r].length;
        ecdata[r][i] = modIndex >= 0 ? modPoly.getAt(modIndex) : 0;
      }
    }
    let totalCodeCount = 0;
    for (let i = 0; i < rsBlocks.length; i += 1) {
      totalCodeCount += rsBlocks[i].totalCount;
    }
    const data = new Array(totalCodeCount);
    let index = 0;
    for (let i = 0; i < maxDcCount; i += 1) {
      for (let r = 0; r < rsBlocks.length; r += 1) {
        if (i < dcdata[r].length) {
          data[index] = dcdata[r][i];
          index += 1;
        }
      }
    }
    for (let i = 0; i < maxEcCount; i += 1) {
      for (let r = 0; r < rsBlocks.length; r += 1) {
        if (i < ecdata[r].length) {
          data[index] = ecdata[r][i];
          index += 1;
        }
      }
    }
    return data;
  };
  const createData = function(typeNumber2, errorCorrectionLevel2, dataList) {
    const rsBlocks = QRRSBlock.getRSBlocks(typeNumber2, errorCorrectionLevel2);
    const buffer = qrBitBuffer();
    for (let i = 0; i < dataList.length; i += 1) {
      const data = dataList[i];
      buffer.put(data.getMode(), 4);
      buffer.put(data.getLength(), QRUtil.getLengthInBits(data.getMode(), typeNumber2));
      data.write(buffer);
    }
    let totalDataCount = 0;
    for (let i = 0; i < rsBlocks.length; i += 1) {
      totalDataCount += rsBlocks[i].dataCount;
    }
    if (buffer.getLengthInBits() > totalDataCount * 8) {
      throw "code length overflow. (" + buffer.getLengthInBits() + ">" + totalDataCount * 8 + ")";
    }
    if (buffer.getLengthInBits() + 4 <= totalDataCount * 8) {
      buffer.put(0, 4);
    }
    while (buffer.getLengthInBits() % 8 != 0) {
      buffer.putBit(false);
    }
    while (true) {
      if (buffer.getLengthInBits() >= totalDataCount * 8) {
        break;
      }
      buffer.put(PAD0, 8);
      if (buffer.getLengthInBits() >= totalDataCount * 8) {
        break;
      }
      buffer.put(PAD1, 8);
    }
    return createBytes(buffer, rsBlocks);
  };
  _this.addData = function(data, mode2) {
    mode2 = mode2 || "Byte";
    let newData = null;
    switch (mode2) {
      case "Numeric":
        newData = qrNumber(data);
        break;
      case "Alphanumeric":
        newData = qrAlphaNum(data);
        break;
      case "Byte":
        newData = qr8BitByte(data);
        break;
      case "Kanji":
        newData = qrKanji(data);
        break;
      default:
        throw "mode:" + mode2;
    }
    _dataList.push(newData);
    _dataCache = null;
  };
  _this.isDark = function(row, col) {
    if (row < 0 || _moduleCount <= row || col < 0 || _moduleCount <= col) {
      throw row + "," + col;
    }
    return _modules[row][col];
  };
  _this.getModuleCount = function() {
    return _moduleCount;
  };
  _this.make = function() {
    if (_typeNumber < 1) {
      let typeNumber2 = 1;
      for (; typeNumber2 < 40; typeNumber2++) {
        const rsBlocks = QRRSBlock.getRSBlocks(typeNumber2, _errorCorrectionLevel);
        const buffer = qrBitBuffer();
        for (let i = 0; i < _dataList.length; i++) {
          const data = _dataList[i];
          buffer.put(data.getMode(), 4);
          buffer.put(data.getLength(), QRUtil.getLengthInBits(data.getMode(), typeNumber2));
          data.write(buffer);
        }
        let totalDataCount = 0;
        for (let i = 0; i < rsBlocks.length; i++) {
          totalDataCount += rsBlocks[i].dataCount;
        }
        if (buffer.getLengthInBits() <= totalDataCount * 8) {
          break;
        }
      }
      _typeNumber = typeNumber2;
    }
    makeImpl(false, getBestMaskPattern());
  };
  _this.createTableTag = function(cellSize, margin) {
    cellSize = cellSize || 2;
    margin = typeof margin == "undefined" ? cellSize * 4 : margin;
    let qrHtml = "";
    qrHtml += '<table style="';
    qrHtml += " border-width: 0px; border-style: none;";
    qrHtml += " border-collapse: collapse;";
    qrHtml += " padding: 0px; margin: " + margin + "px;";
    qrHtml += '">';
    qrHtml += "<tbody>";
    for (let r = 0; r < _this.getModuleCount(); r += 1) {
      qrHtml += "<tr>";
      for (let c = 0; c < _this.getModuleCount(); c += 1) {
        qrHtml += '<td style="';
        qrHtml += " border-width: 0px; border-style: none;";
        qrHtml += " border-collapse: collapse;";
        qrHtml += " padding: 0px; margin: 0px;";
        qrHtml += " width: " + cellSize + "px;";
        qrHtml += " height: " + cellSize + "px;";
        qrHtml += " background-color: ";
        qrHtml += _this.isDark(r, c) ? "#000000" : "#ffffff";
        qrHtml += ";";
        qrHtml += '"/>';
      }
      qrHtml += "</tr>";
    }
    qrHtml += "</tbody>";
    qrHtml += "</table>";
    return qrHtml;
  };
  _this.createSvgTag = function(cellSize, margin, alt, title) {
    let opts = {};
    if (typeof arguments[0] == "object") {
      opts = arguments[0];
      cellSize = opts.cellSize;
      margin = opts.margin;
      alt = opts.alt;
      title = opts.title;
    }
    cellSize = cellSize || 2;
    margin = typeof margin == "undefined" ? cellSize * 4 : margin;
    alt = typeof alt === "string" ? { text: alt } : alt || {};
    alt.text = alt.text || null;
    alt.id = alt.text ? alt.id || "qrcode-description" : null;
    title = typeof title === "string" ? { text: title } : title || {};
    title.text = title.text || null;
    title.id = title.text ? title.id || "qrcode-title" : null;
    const size = _this.getModuleCount() * cellSize + margin * 2;
    let c, mc, r, mr, qrSvg = "", rect;
    rect = "l" + cellSize + ",0 0," + cellSize + " -" + cellSize + ",0 0,-" + cellSize + "z ";
    qrSvg += '<svg version="1.1" xmlns="http://www.w3.org/2000/svg"';
    qrSvg += !opts.scalable ? ' width="' + size + 'px" height="' + size + 'px"' : "";
    qrSvg += ' viewBox="0 0 ' + size + " " + size + '" ';
    qrSvg += ' preserveAspectRatio="xMinYMin meet"';
    qrSvg += title.text || alt.text ? ' role="img" aria-labelledby="' + escapeXml([title.id, alt.id].join(" ").trim()) + '"' : "";
    qrSvg += ">";
    qrSvg += title.text ? '<title id="' + escapeXml(title.id) + '">' + escapeXml(title.text) + "</title>" : "";
    qrSvg += alt.text ? '<description id="' + escapeXml(alt.id) + '">' + escapeXml(alt.text) + "</description>" : "";
    qrSvg += '<rect width="100%" height="100%" fill="white" cx="0" cy="0"/>';
    qrSvg += '<path d="';
    for (r = 0; r < _this.getModuleCount(); r += 1) {
      mr = r * cellSize + margin;
      for (c = 0; c < _this.getModuleCount(); c += 1) {
        if (_this.isDark(r, c)) {
          mc = c * cellSize + margin;
          qrSvg += "M" + mc + "," + mr + rect;
        }
      }
    }
    qrSvg += '" stroke="transparent" fill="black"/>';
    qrSvg += "</svg>";
    return qrSvg;
  };
  _this.createDataURL = function(cellSize, margin) {
    cellSize = cellSize || 2;
    margin = typeof margin == "undefined" ? cellSize * 4 : margin;
    const size = _this.getModuleCount() * cellSize + margin * 2;
    const min = margin;
    const max = size - margin;
    return createDataURL(size, size, function(x, y) {
      if (min <= x && x < max && min <= y && y < max) {
        const c = Math.floor((x - min) / cellSize);
        const r = Math.floor((y - min) / cellSize);
        return _this.isDark(r, c) ? 0 : 1;
      } else {
        return 1;
      }
    });
  };
  _this.createImgTag = function(cellSize, margin, alt) {
    cellSize = cellSize || 2;
    margin = typeof margin == "undefined" ? cellSize * 4 : margin;
    const size = _this.getModuleCount() * cellSize + margin * 2;
    let img = "";
    img += "<img";
    img += ' src="';
    img += _this.createDataURL(cellSize, margin);
    img += '"';
    img += ' width="';
    img += size;
    img += '"';
    img += ' height="';
    img += size;
    img += '"';
    if (alt) {
      img += ' alt="';
      img += escapeXml(alt);
      img += '"';
    }
    img += "/>";
    return img;
  };
  const escapeXml = function(s) {
    let escaped = "";
    for (let i = 0; i < s.length; i += 1) {
      const c = s.charAt(i);
      switch (c) {
        case "<":
          escaped += "&lt;";
          break;
        case ">":
          escaped += "&gt;";
          break;
        case "&":
          escaped += "&amp;";
          break;
        case '"':
          escaped += "&quot;";
          break;
        default:
          escaped += c;
          break;
      }
    }
    return escaped;
  };
  const _createHalfASCII = function(margin) {
    const cellSize = 1;
    margin = typeof margin == "undefined" ? cellSize * 2 : margin;
    const size = _this.getModuleCount() * cellSize + margin * 2;
    const min = margin;
    const max = size - margin;
    let y, x, r1, r2, p;
    const blocks = {
      "██": "█",
      "█ ": "▀",
      " █": "▄",
      "  ": " "
    };
    const blocksLastLineNoMargin = {
      "██": "▀",
      "█ ": "▀",
      " █": " ",
      "  ": " "
    };
    let ascii = "";
    for (y = 0; y < size; y += 2) {
      r1 = Math.floor((y - min) / cellSize);
      r2 = Math.floor((y + 1 - min) / cellSize);
      for (x = 0; x < size; x += 1) {
        p = "█";
        if (min <= x && x < max && min <= y && y < max && _this.isDark(r1, Math.floor((x - min) / cellSize))) {
          p = " ";
        }
        if (min <= x && x < max && min <= y + 1 && y + 1 < max && _this.isDark(r2, Math.floor((x - min) / cellSize))) {
          p += " ";
        } else {
          p += "█";
        }
        ascii += margin < 1 && y + 1 >= max ? blocksLastLineNoMargin[p] : blocks[p];
      }
      ascii += "\n";
    }
    if (size % 2 && margin > 0) {
      return ascii.substring(0, ascii.length - size - 1) + Array(size + 1).join("▀");
    }
    return ascii.substring(0, ascii.length - 1);
  };
  _this.createASCII = function(cellSize, margin) {
    cellSize = cellSize || 1;
    if (cellSize < 2) {
      return _createHalfASCII(margin);
    }
    cellSize -= 1;
    margin = typeof margin == "undefined" ? cellSize * 2 : margin;
    const size = _this.getModuleCount() * cellSize + margin * 2;
    const min = margin;
    const max = size - margin;
    let y, x, r, p;
    const white = Array(cellSize + 1).join("██");
    const black = Array(cellSize + 1).join("  ");
    let ascii = "";
    let line = "";
    for (y = 0; y < size; y += 1) {
      r = Math.floor((y - min) / cellSize);
      line = "";
      for (x = 0; x < size; x += 1) {
        p = 1;
        if (min <= x && x < max && min <= y && y < max && _this.isDark(r, Math.floor((x - min) / cellSize))) {
          p = 0;
        }
        line += p ? white : black;
      }
      for (r = 0; r < cellSize; r += 1) {
        ascii += line + "\n";
      }
    }
    return ascii.substring(0, ascii.length - 1);
  };
  _this.renderTo2dContext = function(context, cellSize) {
    cellSize = cellSize || 2;
    const length = _this.getModuleCount();
    for (let row = 0; row < length; row++) {
      for (let col = 0; col < length; col++) {
        context.fillStyle = _this.isDark(row, col) ? "black" : "white";
        context.fillRect(col * cellSize, row * cellSize, cellSize, cellSize);
      }
    }
  };
  return _this;
};
qrcode.stringToBytes = function(s) {
  const bytes = [];
  for (let i = 0; i < s.length; i += 1) {
    const c = s.charCodeAt(i);
    bytes.push(c & 255);
  }
  return bytes;
};
qrcode.createStringToBytes = function(unicodeData, numChars) {
  const unicodeMap = (function() {
    const bin = base64DecodeInputStream(unicodeData);
    const read = function() {
      const b = bin.read();
      if (b == -1) throw "eof";
      return b;
    };
    let count2 = 0;
    const unicodeMap2 = {};
    while (true) {
      const b0 = bin.read();
      if (b0 == -1) break;
      const b1 = read();
      const b2 = read();
      const b3 = read();
      const k = String.fromCharCode(b0 << 8 | b1);
      const v = b2 << 8 | b3;
      unicodeMap2[k] = v;
      count2 += 1;
    }
    if (count2 != numChars) {
      throw count2 + " != " + numChars;
    }
    return unicodeMap2;
  })();
  const unknownChar = "?".charCodeAt(0);
  return function(s) {
    const bytes = [];
    for (let i = 0; i < s.length; i += 1) {
      const c = s.charCodeAt(i);
      if (c < 128) {
        bytes.push(c);
      } else {
        const b = unicodeMap[s.charAt(i)];
        if (typeof b == "number") {
          if ((b & 255) == b) {
            bytes.push(b);
          } else {
            bytes.push(b >>> 8);
            bytes.push(b & 255);
          }
        } else {
          bytes.push(unknownChar);
        }
      }
    }
    return bytes;
  };
};
const QRMode = {
  MODE_NUMBER: 1 << 0,
  MODE_ALPHA_NUM: 1 << 1,
  MODE_8BIT_BYTE: 1 << 2,
  MODE_KANJI: 1 << 3
};
const QRErrorCorrectionLevel = {
  L: 1,
  M: 0,
  Q: 3,
  H: 2
};
const QRMaskPattern = {
  PATTERN000: 0,
  PATTERN001: 1,
  PATTERN010: 2,
  PATTERN011: 3,
  PATTERN100: 4,
  PATTERN101: 5,
  PATTERN110: 6,
  PATTERN111: 7
};
const QRUtil = (function() {
  const PATTERN_POSITION_TABLE = [
    [],
    [6, 18],
    [6, 22],
    [6, 26],
    [6, 30],
    [6, 34],
    [6, 22, 38],
    [6, 24, 42],
    [6, 26, 46],
    [6, 28, 50],
    [6, 30, 54],
    [6, 32, 58],
    [6, 34, 62],
    [6, 26, 46, 66],
    [6, 26, 48, 70],
    [6, 26, 50, 74],
    [6, 30, 54, 78],
    [6, 30, 56, 82],
    [6, 30, 58, 86],
    [6, 34, 62, 90],
    [6, 28, 50, 72, 94],
    [6, 26, 50, 74, 98],
    [6, 30, 54, 78, 102],
    [6, 28, 54, 80, 106],
    [6, 32, 58, 84, 110],
    [6, 30, 58, 86, 114],
    [6, 34, 62, 90, 118],
    [6, 26, 50, 74, 98, 122],
    [6, 30, 54, 78, 102, 126],
    [6, 26, 52, 78, 104, 130],
    [6, 30, 56, 82, 108, 134],
    [6, 34, 60, 86, 112, 138],
    [6, 30, 58, 86, 114, 142],
    [6, 34, 62, 90, 118, 146],
    [6, 30, 54, 78, 102, 126, 150],
    [6, 24, 50, 76, 102, 128, 154],
    [6, 28, 54, 80, 106, 132, 158],
    [6, 32, 58, 84, 110, 136, 162],
    [6, 26, 54, 82, 110, 138, 166],
    [6, 30, 58, 86, 114, 142, 170]
  ];
  const G15 = 1 << 10 | 1 << 8 | 1 << 5 | 1 << 4 | 1 << 2 | 1 << 1 | 1 << 0;
  const G18 = 1 << 12 | 1 << 11 | 1 << 10 | 1 << 9 | 1 << 8 | 1 << 5 | 1 << 2 | 1 << 0;
  const G15_MASK = 1 << 14 | 1 << 12 | 1 << 10 | 1 << 4 | 1 << 1;
  const _this = {};
  const getBCHDigit = function(data) {
    let digit = 0;
    while (data != 0) {
      digit += 1;
      data >>>= 1;
    }
    return digit;
  };
  _this.getBCHTypeInfo = function(data) {
    let d = data << 10;
    while (getBCHDigit(d) - getBCHDigit(G15) >= 0) {
      d ^= G15 << getBCHDigit(d) - getBCHDigit(G15);
    }
    return (data << 10 | d) ^ G15_MASK;
  };
  _this.getBCHTypeNumber = function(data) {
    let d = data << 12;
    while (getBCHDigit(d) - getBCHDigit(G18) >= 0) {
      d ^= G18 << getBCHDigit(d) - getBCHDigit(G18);
    }
    return data << 12 | d;
  };
  _this.getPatternPosition = function(typeNumber) {
    return PATTERN_POSITION_TABLE[typeNumber - 1];
  };
  _this.getMaskFunction = function(maskPattern) {
    switch (maskPattern) {
      case QRMaskPattern.PATTERN000:
        return function(i, j) {
          return (i + j) % 2 == 0;
        };
      case QRMaskPattern.PATTERN001:
        return function(i, j) {
          return i % 2 == 0;
        };
      case QRMaskPattern.PATTERN010:
        return function(i, j) {
          return j % 3 == 0;
        };
      case QRMaskPattern.PATTERN011:
        return function(i, j) {
          return (i + j) % 3 == 0;
        };
      case QRMaskPattern.PATTERN100:
        return function(i, j) {
          return (Math.floor(i / 2) + Math.floor(j / 3)) % 2 == 0;
        };
      case QRMaskPattern.PATTERN101:
        return function(i, j) {
          return i * j % 2 + i * j % 3 == 0;
        };
      case QRMaskPattern.PATTERN110:
        return function(i, j) {
          return (i * j % 2 + i * j % 3) % 2 == 0;
        };
      case QRMaskPattern.PATTERN111:
        return function(i, j) {
          return (i * j % 3 + (i + j) % 2) % 2 == 0;
        };
      default:
        throw "bad maskPattern:" + maskPattern;
    }
  };
  _this.getErrorCorrectPolynomial = function(errorCorrectLength) {
    let a = qrPolynomial([1], 0);
    for (let i = 0; i < errorCorrectLength; i += 1) {
      a = a.multiply(qrPolynomial([1, QRMath.gexp(i)], 0));
    }
    return a;
  };
  _this.getLengthInBits = function(mode2, type) {
    if (1 <= type && type < 10) {
      switch (mode2) {
        case QRMode.MODE_NUMBER:
          return 10;
        case QRMode.MODE_ALPHA_NUM:
          return 9;
        case QRMode.MODE_8BIT_BYTE:
          return 8;
        case QRMode.MODE_KANJI:
          return 8;
        default:
          throw "mode:" + mode2;
      }
    } else if (type < 27) {
      switch (mode2) {
        case QRMode.MODE_NUMBER:
          return 12;
        case QRMode.MODE_ALPHA_NUM:
          return 11;
        case QRMode.MODE_8BIT_BYTE:
          return 16;
        case QRMode.MODE_KANJI:
          return 10;
        default:
          throw "mode:" + mode2;
      }
    } else if (type < 41) {
      switch (mode2) {
        case QRMode.MODE_NUMBER:
          return 14;
        case QRMode.MODE_ALPHA_NUM:
          return 13;
        case QRMode.MODE_8BIT_BYTE:
          return 16;
        case QRMode.MODE_KANJI:
          return 12;
        default:
          throw "mode:" + mode2;
      }
    } else {
      throw "type:" + type;
    }
  };
  _this.getLostPoint = function(qrcode2) {
    const moduleCount = qrcode2.getModuleCount();
    let lostPoint = 0;
    for (let row = 0; row < moduleCount; row += 1) {
      for (let col = 0; col < moduleCount; col += 1) {
        let sameCount = 0;
        const dark = qrcode2.isDark(row, col);
        for (let r = -1; r <= 1; r += 1) {
          if (row + r < 0 || moduleCount <= row + r) {
            continue;
          }
          for (let c = -1; c <= 1; c += 1) {
            if (col + c < 0 || moduleCount <= col + c) {
              continue;
            }
            if (r == 0 && c == 0) {
              continue;
            }
            if (dark == qrcode2.isDark(row + r, col + c)) {
              sameCount += 1;
            }
          }
        }
        if (sameCount > 5) {
          lostPoint += 3 + sameCount - 5;
        }
      }
    }
    for (let row = 0; row < moduleCount - 1; row += 1) {
      for (let col = 0; col < moduleCount - 1; col += 1) {
        let count2 = 0;
        if (qrcode2.isDark(row, col)) count2 += 1;
        if (qrcode2.isDark(row + 1, col)) count2 += 1;
        if (qrcode2.isDark(row, col + 1)) count2 += 1;
        if (qrcode2.isDark(row + 1, col + 1)) count2 += 1;
        if (count2 == 0 || count2 == 4) {
          lostPoint += 3;
        }
      }
    }
    for (let row = 0; row < moduleCount; row += 1) {
      for (let col = 0; col < moduleCount - 6; col += 1) {
        if (qrcode2.isDark(row, col) && !qrcode2.isDark(row, col + 1) && qrcode2.isDark(row, col + 2) && qrcode2.isDark(row, col + 3) && qrcode2.isDark(row, col + 4) && !qrcode2.isDark(row, col + 5) && qrcode2.isDark(row, col + 6)) {
          lostPoint += 40;
        }
      }
    }
    for (let col = 0; col < moduleCount; col += 1) {
      for (let row = 0; row < moduleCount - 6; row += 1) {
        if (qrcode2.isDark(row, col) && !qrcode2.isDark(row + 1, col) && qrcode2.isDark(row + 2, col) && qrcode2.isDark(row + 3, col) && qrcode2.isDark(row + 4, col) && !qrcode2.isDark(row + 5, col) && qrcode2.isDark(row + 6, col)) {
          lostPoint += 40;
        }
      }
    }
    let darkCount = 0;
    for (let col = 0; col < moduleCount; col += 1) {
      for (let row = 0; row < moduleCount; row += 1) {
        if (qrcode2.isDark(row, col)) {
          darkCount += 1;
        }
      }
    }
    const ratio = Math.abs(100 * darkCount / moduleCount / moduleCount - 50) / 5;
    lostPoint += ratio * 10;
    return lostPoint;
  };
  return _this;
})();
const QRMath = (function() {
  const EXP_TABLE = new Array(256);
  const LOG_TABLE = new Array(256);
  for (let i = 0; i < 8; i += 1) {
    EXP_TABLE[i] = 1 << i;
  }
  for (let i = 8; i < 256; i += 1) {
    EXP_TABLE[i] = EXP_TABLE[i - 4] ^ EXP_TABLE[i - 5] ^ EXP_TABLE[i - 6] ^ EXP_TABLE[i - 8];
  }
  for (let i = 0; i < 255; i += 1) {
    LOG_TABLE[EXP_TABLE[i]] = i;
  }
  const _this = {};
  _this.glog = function(n) {
    if (n < 1) {
      throw "glog(" + n + ")";
    }
    return LOG_TABLE[n];
  };
  _this.gexp = function(n) {
    while (n < 0) {
      n += 255;
    }
    while (n >= 256) {
      n -= 255;
    }
    return EXP_TABLE[n];
  };
  return _this;
})();
const qrPolynomial = function(num, shift) {
  if (typeof num.length == "undefined") {
    throw num.length + "/" + shift;
  }
  const _num = (function() {
    let offset = 0;
    while (offset < num.length && num[offset] == 0) {
      offset += 1;
    }
    const _num2 = new Array(num.length - offset + shift);
    for (let i = 0; i < num.length - offset; i += 1) {
      _num2[i] = num[i + offset];
    }
    return _num2;
  })();
  const _this = {};
  _this.getAt = function(index) {
    return _num[index];
  };
  _this.getLength = function() {
    return _num.length;
  };
  _this.multiply = function(e) {
    const num2 = new Array(_this.getLength() + e.getLength() - 1);
    for (let i = 0; i < _this.getLength(); i += 1) {
      for (let j = 0; j < e.getLength(); j += 1) {
        num2[i + j] ^= QRMath.gexp(QRMath.glog(_this.getAt(i)) + QRMath.glog(e.getAt(j)));
      }
    }
    return qrPolynomial(num2, 0);
  };
  _this.mod = function(e) {
    if (_this.getLength() - e.getLength() < 0) {
      return _this;
    }
    const ratio = QRMath.glog(_this.getAt(0)) - QRMath.glog(e.getAt(0));
    const num2 = new Array(_this.getLength());
    for (let i = 0; i < _this.getLength(); i += 1) {
      num2[i] = _this.getAt(i);
    }
    for (let i = 0; i < e.getLength(); i += 1) {
      num2[i] ^= QRMath.gexp(QRMath.glog(e.getAt(i)) + ratio);
    }
    return qrPolynomial(num2, 0).mod(e);
  };
  return _this;
};
const QRRSBlock = (function() {
  const RS_BLOCK_TABLE = [
    // L
    // M
    // Q
    // H
    // 1
    [1, 26, 19],
    [1, 26, 16],
    [1, 26, 13],
    [1, 26, 9],
    // 2
    [1, 44, 34],
    [1, 44, 28],
    [1, 44, 22],
    [1, 44, 16],
    // 3
    [1, 70, 55],
    [1, 70, 44],
    [2, 35, 17],
    [2, 35, 13],
    // 4
    [1, 100, 80],
    [2, 50, 32],
    [2, 50, 24],
    [4, 25, 9],
    // 5
    [1, 134, 108],
    [2, 67, 43],
    [2, 33, 15, 2, 34, 16],
    [2, 33, 11, 2, 34, 12],
    // 6
    [2, 86, 68],
    [4, 43, 27],
    [4, 43, 19],
    [4, 43, 15],
    // 7
    [2, 98, 78],
    [4, 49, 31],
    [2, 32, 14, 4, 33, 15],
    [4, 39, 13, 1, 40, 14],
    // 8
    [2, 121, 97],
    [2, 60, 38, 2, 61, 39],
    [4, 40, 18, 2, 41, 19],
    [4, 40, 14, 2, 41, 15],
    // 9
    [2, 146, 116],
    [3, 58, 36, 2, 59, 37],
    [4, 36, 16, 4, 37, 17],
    [4, 36, 12, 4, 37, 13],
    // 10
    [2, 86, 68, 2, 87, 69],
    [4, 69, 43, 1, 70, 44],
    [6, 43, 19, 2, 44, 20],
    [6, 43, 15, 2, 44, 16],
    // 11
    [4, 101, 81],
    [1, 80, 50, 4, 81, 51],
    [4, 50, 22, 4, 51, 23],
    [3, 36, 12, 8, 37, 13],
    // 12
    [2, 116, 92, 2, 117, 93],
    [6, 58, 36, 2, 59, 37],
    [4, 46, 20, 6, 47, 21],
    [7, 42, 14, 4, 43, 15],
    // 13
    [4, 133, 107],
    [8, 59, 37, 1, 60, 38],
    [8, 44, 20, 4, 45, 21],
    [12, 33, 11, 4, 34, 12],
    // 14
    [3, 145, 115, 1, 146, 116],
    [4, 64, 40, 5, 65, 41],
    [11, 36, 16, 5, 37, 17],
    [11, 36, 12, 5, 37, 13],
    // 15
    [5, 109, 87, 1, 110, 88],
    [5, 65, 41, 5, 66, 42],
    [5, 54, 24, 7, 55, 25],
    [11, 36, 12, 7, 37, 13],
    // 16
    [5, 122, 98, 1, 123, 99],
    [7, 73, 45, 3, 74, 46],
    [15, 43, 19, 2, 44, 20],
    [3, 45, 15, 13, 46, 16],
    // 17
    [1, 135, 107, 5, 136, 108],
    [10, 74, 46, 1, 75, 47],
    [1, 50, 22, 15, 51, 23],
    [2, 42, 14, 17, 43, 15],
    // 18
    [5, 150, 120, 1, 151, 121],
    [9, 69, 43, 4, 70, 44],
    [17, 50, 22, 1, 51, 23],
    [2, 42, 14, 19, 43, 15],
    // 19
    [3, 141, 113, 4, 142, 114],
    [3, 70, 44, 11, 71, 45],
    [17, 47, 21, 4, 48, 22],
    [9, 39, 13, 16, 40, 14],
    // 20
    [3, 135, 107, 5, 136, 108],
    [3, 67, 41, 13, 68, 42],
    [15, 54, 24, 5, 55, 25],
    [15, 43, 15, 10, 44, 16],
    // 21
    [4, 144, 116, 4, 145, 117],
    [17, 68, 42],
    [17, 50, 22, 6, 51, 23],
    [19, 46, 16, 6, 47, 17],
    // 22
    [2, 139, 111, 7, 140, 112],
    [17, 74, 46],
    [7, 54, 24, 16, 55, 25],
    [34, 37, 13],
    // 23
    [4, 151, 121, 5, 152, 122],
    [4, 75, 47, 14, 76, 48],
    [11, 54, 24, 14, 55, 25],
    [16, 45, 15, 14, 46, 16],
    // 24
    [6, 147, 117, 4, 148, 118],
    [6, 73, 45, 14, 74, 46],
    [11, 54, 24, 16, 55, 25],
    [30, 46, 16, 2, 47, 17],
    // 25
    [8, 132, 106, 4, 133, 107],
    [8, 75, 47, 13, 76, 48],
    [7, 54, 24, 22, 55, 25],
    [22, 45, 15, 13, 46, 16],
    // 26
    [10, 142, 114, 2, 143, 115],
    [19, 74, 46, 4, 75, 47],
    [28, 50, 22, 6, 51, 23],
    [33, 46, 16, 4, 47, 17],
    // 27
    [8, 152, 122, 4, 153, 123],
    [22, 73, 45, 3, 74, 46],
    [8, 53, 23, 26, 54, 24],
    [12, 45, 15, 28, 46, 16],
    // 28
    [3, 147, 117, 10, 148, 118],
    [3, 73, 45, 23, 74, 46],
    [4, 54, 24, 31, 55, 25],
    [11, 45, 15, 31, 46, 16],
    // 29
    [7, 146, 116, 7, 147, 117],
    [21, 73, 45, 7, 74, 46],
    [1, 53, 23, 37, 54, 24],
    [19, 45, 15, 26, 46, 16],
    // 30
    [5, 145, 115, 10, 146, 116],
    [19, 75, 47, 10, 76, 48],
    [15, 54, 24, 25, 55, 25],
    [23, 45, 15, 25, 46, 16],
    // 31
    [13, 145, 115, 3, 146, 116],
    [2, 74, 46, 29, 75, 47],
    [42, 54, 24, 1, 55, 25],
    [23, 45, 15, 28, 46, 16],
    // 32
    [17, 145, 115],
    [10, 74, 46, 23, 75, 47],
    [10, 54, 24, 35, 55, 25],
    [19, 45, 15, 35, 46, 16],
    // 33
    [17, 145, 115, 1, 146, 116],
    [14, 74, 46, 21, 75, 47],
    [29, 54, 24, 19, 55, 25],
    [11, 45, 15, 46, 46, 16],
    // 34
    [13, 145, 115, 6, 146, 116],
    [14, 74, 46, 23, 75, 47],
    [44, 54, 24, 7, 55, 25],
    [59, 46, 16, 1, 47, 17],
    // 35
    [12, 151, 121, 7, 152, 122],
    [12, 75, 47, 26, 76, 48],
    [39, 54, 24, 14, 55, 25],
    [22, 45, 15, 41, 46, 16],
    // 36
    [6, 151, 121, 14, 152, 122],
    [6, 75, 47, 34, 76, 48],
    [46, 54, 24, 10, 55, 25],
    [2, 45, 15, 64, 46, 16],
    // 37
    [17, 152, 122, 4, 153, 123],
    [29, 74, 46, 14, 75, 47],
    [49, 54, 24, 10, 55, 25],
    [24, 45, 15, 46, 46, 16],
    // 38
    [4, 152, 122, 18, 153, 123],
    [13, 74, 46, 32, 75, 47],
    [48, 54, 24, 14, 55, 25],
    [42, 45, 15, 32, 46, 16],
    // 39
    [20, 147, 117, 4, 148, 118],
    [40, 75, 47, 7, 76, 48],
    [43, 54, 24, 22, 55, 25],
    [10, 45, 15, 67, 46, 16],
    // 40
    [19, 148, 118, 6, 149, 119],
    [18, 75, 47, 31, 76, 48],
    [34, 54, 24, 34, 55, 25],
    [20, 45, 15, 61, 46, 16]
  ];
  const qrRSBlock = function(totalCount, dataCount) {
    const _this2 = {};
    _this2.totalCount = totalCount;
    _this2.dataCount = dataCount;
    return _this2;
  };
  const _this = {};
  const getRsBlockTable = function(typeNumber, errorCorrectionLevel) {
    switch (errorCorrectionLevel) {
      case QRErrorCorrectionLevel.L:
        return RS_BLOCK_TABLE[(typeNumber - 1) * 4 + 0];
      case QRErrorCorrectionLevel.M:
        return RS_BLOCK_TABLE[(typeNumber - 1) * 4 + 1];
      case QRErrorCorrectionLevel.Q:
        return RS_BLOCK_TABLE[(typeNumber - 1) * 4 + 2];
      case QRErrorCorrectionLevel.H:
        return RS_BLOCK_TABLE[(typeNumber - 1) * 4 + 3];
      default:
        return void 0;
    }
  };
  _this.getRSBlocks = function(typeNumber, errorCorrectionLevel) {
    const rsBlock = getRsBlockTable(typeNumber, errorCorrectionLevel);
    if (typeof rsBlock == "undefined") {
      throw "bad rs block @ typeNumber:" + typeNumber + "/errorCorrectionLevel:" + errorCorrectionLevel;
    }
    const length = rsBlock.length / 3;
    const list = [];
    for (let i = 0; i < length; i += 1) {
      const count2 = rsBlock[i * 3 + 0];
      const totalCount = rsBlock[i * 3 + 1];
      const dataCount = rsBlock[i * 3 + 2];
      for (let j = 0; j < count2; j += 1) {
        list.push(qrRSBlock(totalCount, dataCount));
      }
    }
    return list;
  };
  return _this;
})();
const qrBitBuffer = function() {
  const _buffer = [];
  let _length = 0;
  const _this = {};
  _this.getBuffer = function() {
    return _buffer;
  };
  _this.getAt = function(index) {
    const bufIndex = Math.floor(index / 8);
    return (_buffer[bufIndex] >>> 7 - index % 8 & 1) == 1;
  };
  _this.put = function(num, length) {
    for (let i = 0; i < length; i += 1) {
      _this.putBit((num >>> length - i - 1 & 1) == 1);
    }
  };
  _this.getLengthInBits = function() {
    return _length;
  };
  _this.putBit = function(bit) {
    const bufIndex = Math.floor(_length / 8);
    if (_buffer.length <= bufIndex) {
      _buffer.push(0);
    }
    if (bit) {
      _buffer[bufIndex] |= 128 >>> _length % 8;
    }
    _length += 1;
  };
  return _this;
};
const qrNumber = function(data) {
  const _mode = QRMode.MODE_NUMBER;
  const _data = data;
  const _this = {};
  _this.getMode = function() {
    return _mode;
  };
  _this.getLength = function(buffer) {
    return _data.length;
  };
  _this.write = function(buffer) {
    const data2 = _data;
    let i = 0;
    while (i + 2 < data2.length) {
      buffer.put(strToNum(data2.substring(i, i + 3)), 10);
      i += 3;
    }
    if (i < data2.length) {
      if (data2.length - i == 1) {
        buffer.put(strToNum(data2.substring(i, i + 1)), 4);
      } else if (data2.length - i == 2) {
        buffer.put(strToNum(data2.substring(i, i + 2)), 7);
      }
    }
  };
  const strToNum = function(s) {
    let num = 0;
    for (let i = 0; i < s.length; i += 1) {
      num = num * 10 + chatToNum(s.charAt(i));
    }
    return num;
  };
  const chatToNum = function(c) {
    if ("0" <= c && c <= "9") {
      return c.charCodeAt(0) - "0".charCodeAt(0);
    }
    throw "illegal char :" + c;
  };
  return _this;
};
const qrAlphaNum = function(data) {
  const _mode = QRMode.MODE_ALPHA_NUM;
  const _data = data;
  const _this = {};
  _this.getMode = function() {
    return _mode;
  };
  _this.getLength = function(buffer) {
    return _data.length;
  };
  _this.write = function(buffer) {
    const s = _data;
    let i = 0;
    while (i + 1 < s.length) {
      buffer.put(
        getCode(s.charAt(i)) * 45 + getCode(s.charAt(i + 1)),
        11
      );
      i += 2;
    }
    if (i < s.length) {
      buffer.put(getCode(s.charAt(i)), 6);
    }
  };
  const getCode = function(c) {
    if ("0" <= c && c <= "9") {
      return c.charCodeAt(0) - "0".charCodeAt(0);
    } else if ("A" <= c && c <= "Z") {
      return c.charCodeAt(0) - "A".charCodeAt(0) + 10;
    } else {
      switch (c) {
        case " ":
          return 36;
        case "$":
          return 37;
        case "%":
          return 38;
        case "*":
          return 39;
        case "+":
          return 40;
        case "-":
          return 41;
        case ".":
          return 42;
        case "/":
          return 43;
        case ":":
          return 44;
        default:
          throw "illegal char :" + c;
      }
    }
  };
  return _this;
};
const qr8BitByte = function(data) {
  const _mode = QRMode.MODE_8BIT_BYTE;
  const _bytes = qrcode.stringToBytes(data);
  const _this = {};
  _this.getMode = function() {
    return _mode;
  };
  _this.getLength = function(buffer) {
    return _bytes.length;
  };
  _this.write = function(buffer) {
    for (let i = 0; i < _bytes.length; i += 1) {
      buffer.put(_bytes[i], 8);
    }
  };
  return _this;
};
const qrKanji = function(data) {
  const _mode = QRMode.MODE_KANJI;
  const stringToBytes = qrcode.stringToBytes;
  !(function(c, code) {
    const test = stringToBytes(c);
    if (test.length != 2 || (test[0] << 8 | test[1]) != code) {
      throw "sjis not supported.";
    }
  })("友", 38726);
  const _bytes = stringToBytes(data);
  const _this = {};
  _this.getMode = function() {
    return _mode;
  };
  _this.getLength = function(buffer) {
    return ~~(_bytes.length / 2);
  };
  _this.write = function(buffer) {
    const data2 = _bytes;
    let i = 0;
    while (i + 1 < data2.length) {
      let c = (255 & data2[i]) << 8 | 255 & data2[i + 1];
      if (33088 <= c && c <= 40956) {
        c -= 33088;
      } else if (57408 <= c && c <= 60351) {
        c -= 49472;
      } else {
        throw "illegal char at " + (i + 1) + "/" + c;
      }
      c = (c >>> 8 & 255) * 192 + (c & 255);
      buffer.put(c, 13);
      i += 2;
    }
    if (i < data2.length) {
      throw "illegal char at " + (i + 1);
    }
  };
  return _this;
};
const byteArrayOutputStream = function() {
  const _bytes = [];
  const _this = {};
  _this.writeByte = function(b) {
    _bytes.push(b & 255);
  };
  _this.writeShort = function(i) {
    _this.writeByte(i);
    _this.writeByte(i >>> 8);
  };
  _this.writeBytes = function(b, off, len) {
    off = off || 0;
    len = len || b.length;
    for (let i = 0; i < len; i += 1) {
      _this.writeByte(b[i + off]);
    }
  };
  _this.writeString = function(s) {
    for (let i = 0; i < s.length; i += 1) {
      _this.writeByte(s.charCodeAt(i));
    }
  };
  _this.toByteArray = function() {
    return _bytes;
  };
  _this.toString = function() {
    let s = "";
    s += "[";
    for (let i = 0; i < _bytes.length; i += 1) {
      if (i > 0) {
        s += ",";
      }
      s += _bytes[i];
    }
    s += "]";
    return s;
  };
  return _this;
};
const base64EncodeOutputStream = function() {
  let _buffer = 0;
  let _buflen = 0;
  let _length = 0;
  let _base64 = "";
  const _this = {};
  const writeEncoded = function(b) {
    _base64 += String.fromCharCode(encode(b & 63));
  };
  const encode = function(n) {
    if (n < 0) {
      throw "n:" + n;
    } else if (n < 26) {
      return 65 + n;
    } else if (n < 52) {
      return 97 + (n - 26);
    } else if (n < 62) {
      return 48 + (n - 52);
    } else if (n == 62) {
      return 43;
    } else if (n == 63) {
      return 47;
    } else {
      throw "n:" + n;
    }
  };
  _this.writeByte = function(n) {
    _buffer = _buffer << 8 | n & 255;
    _buflen += 8;
    _length += 1;
    while (_buflen >= 6) {
      writeEncoded(_buffer >>> _buflen - 6);
      _buflen -= 6;
    }
  };
  _this.flush = function() {
    if (_buflen > 0) {
      writeEncoded(_buffer << 6 - _buflen);
      _buffer = 0;
      _buflen = 0;
    }
    if (_length % 3 != 0) {
      const padlen = 3 - _length % 3;
      for (let i = 0; i < padlen; i += 1) {
        _base64 += "=";
      }
    }
  };
  _this.toString = function() {
    return _base64;
  };
  return _this;
};
const base64DecodeInputStream = function(str) {
  const _str = str;
  let _pos = 0;
  let _buffer = 0;
  let _buflen = 0;
  const _this = {};
  _this.read = function() {
    while (_buflen < 8) {
      if (_pos >= _str.length) {
        if (_buflen == 0) {
          return -1;
        }
        throw "unexpected end of file./" + _buflen;
      }
      const c = _str.charAt(_pos);
      _pos += 1;
      if (c == "=") {
        _buflen = 0;
        return -1;
      } else if (c.match(/^\s$/)) {
        continue;
      }
      _buffer = _buffer << 6 | decode(c.charCodeAt(0));
      _buflen += 6;
    }
    const n = _buffer >>> _buflen - 8 & 255;
    _buflen -= 8;
    return n;
  };
  const decode = function(c) {
    if (65 <= c && c <= 90) {
      return c - 65;
    } else if (97 <= c && c <= 122) {
      return c - 97 + 26;
    } else if (48 <= c && c <= 57) {
      return c - 48 + 52;
    } else if (c == 43) {
      return 62;
    } else if (c == 47) {
      return 63;
    } else {
      throw "c:" + c;
    }
  };
  return _this;
};
const gifImage = function(width, height) {
  const _width = width;
  const _height = height;
  const _data = new Array(width * height);
  const _this = {};
  _this.setPixel = function(x, y, pixel) {
    _data[y * _width + x] = pixel;
  };
  _this.write = function(out) {
    out.writeString("GIF87a");
    out.writeShort(_width);
    out.writeShort(_height);
    out.writeByte(128);
    out.writeByte(0);
    out.writeByte(0);
    out.writeByte(0);
    out.writeByte(0);
    out.writeByte(0);
    out.writeByte(255);
    out.writeByte(255);
    out.writeByte(255);
    out.writeString(",");
    out.writeShort(0);
    out.writeShort(0);
    out.writeShort(_width);
    out.writeShort(_height);
    out.writeByte(0);
    const lzwMinCodeSize = 2;
    const raster = getLZWRaster(lzwMinCodeSize);
    out.writeByte(lzwMinCodeSize);
    let offset = 0;
    while (raster.length - offset > 255) {
      out.writeByte(255);
      out.writeBytes(raster, offset, 255);
      offset += 255;
    }
    out.writeByte(raster.length - offset);
    out.writeBytes(raster, offset, raster.length - offset);
    out.writeByte(0);
    out.writeString(";");
  };
  const bitOutputStream = function(out) {
    const _out = out;
    let _bitLength = 0;
    let _bitBuffer = 0;
    const _this2 = {};
    _this2.write = function(data, length) {
      if (data >>> length != 0) {
        throw "length over";
      }
      while (_bitLength + length >= 8) {
        _out.writeByte(255 & (data << _bitLength | _bitBuffer));
        length -= 8 - _bitLength;
        data >>>= 8 - _bitLength;
        _bitBuffer = 0;
        _bitLength = 0;
      }
      _bitBuffer = data << _bitLength | _bitBuffer;
      _bitLength = _bitLength + length;
    };
    _this2.flush = function() {
      if (_bitLength > 0) {
        _out.writeByte(_bitBuffer);
      }
    };
    return _this2;
  };
  const getLZWRaster = function(lzwMinCodeSize) {
    const clearCode = 1 << lzwMinCodeSize;
    const endCode = (1 << lzwMinCodeSize) + 1;
    let bitLength = lzwMinCodeSize + 1;
    const table = lzwTable();
    for (let i = 0; i < clearCode; i += 1) {
      table.add(String.fromCharCode(i));
    }
    table.add(String.fromCharCode(clearCode));
    table.add(String.fromCharCode(endCode));
    const byteOut = byteArrayOutputStream();
    const bitOut = bitOutputStream(byteOut);
    bitOut.write(clearCode, bitLength);
    let dataIndex = 0;
    let s = String.fromCharCode(_data[dataIndex]);
    dataIndex += 1;
    while (dataIndex < _data.length) {
      const c = String.fromCharCode(_data[dataIndex]);
      dataIndex += 1;
      if (table.contains(s + c)) {
        s = s + c;
      } else {
        bitOut.write(table.indexOf(s), bitLength);
        if (table.size() < 4095) {
          if (table.size() == 1 << bitLength) {
            bitLength += 1;
          }
          table.add(s + c);
        }
        s = c;
      }
    }
    bitOut.write(table.indexOf(s), bitLength);
    bitOut.write(endCode, bitLength);
    bitOut.flush();
    return byteOut.toByteArray();
  };
  const lzwTable = function() {
    const _map = {};
    let _size = 0;
    const _this2 = {};
    _this2.add = function(key2) {
      if (_this2.contains(key2)) {
        throw "dup key:" + key2;
      }
      _map[key2] = _size;
      _size += 1;
    };
    _this2.size = function() {
      return _size;
    };
    _this2.indexOf = function(key2) {
      return _map[key2];
    };
    _this2.contains = function(key2) {
      return typeof _map[key2] != "undefined";
    };
    return _this2;
  };
  return _this;
};
const createDataURL = function(width, height, getPixel) {
  const gif = gifImage(width, height);
  for (let y = 0; y < height; y += 1) {
    for (let x = 0; x < width; x += 1) {
      gif.setPixel(x, y, getPixel(x, y));
    }
  }
  const b = byteArrayOutputStream();
  gif.write(b);
  const base64 = base64EncodeOutputStream();
  const bytes = b.toByteArray();
  for (let i = 0; i < bytes.length; i += 1) {
    base64.writeByte(bytes[i]);
  }
  base64.flush();
  return "data:image/gif;base64," + base64;
};
qrcode.stringToBytes;
function _extends() {
  return _extends = Object.assign ? Object.assign.bind() : function(n) {
    for (var e = 1; e < arguments.length; e++) {
      var t = arguments[e];
      for (var r in t) ({}).hasOwnProperty.call(t, r) && (n[r] = t[r]);
    }
    return n;
  }, _extends.apply(null, arguments);
}
function _objectWithoutProperties(e, t) {
  if (null == e) return {};
  var o, r, i = _objectWithoutPropertiesLoose(e, t);
  if (Object.getOwnPropertySymbols) {
    var n = Object.getOwnPropertySymbols(e);
    for (r = 0; r < n.length; r++) o = n[r], -1 === t.indexOf(o) && {}.propertyIsEnumerable.call(e, o) && (i[o] = e[o]);
  }
  return i;
}
function _objectWithoutPropertiesLoose(r, e) {
  if (null == r) return {};
  var t = {};
  for (var n in r) if ({}.hasOwnProperty.call(r, n)) {
    if (-1 !== e.indexOf(n)) continue;
    t[n] = r[n];
  }
  return t;
}
var _excluded$1 = ["bgColor", "bgD", "fgD", "fgColor", "size", "title", "viewBoxSize", "xmlns"];
var propTypes$1 = {
  bgColor: PropTypes.oneOfType([PropTypes.object, PropTypes.string]).isRequired,
  bgD: PropTypes.string.isRequired,
  fgColor: PropTypes.oneOfType([PropTypes.object, PropTypes.string]).isRequired,
  fgD: PropTypes.string.isRequired,
  size: PropTypes.number.isRequired,
  title: PropTypes.string,
  viewBoxSize: PropTypes.number.isRequired,
  xmlns: PropTypes.string
};
var QRCodeSvg = /* @__PURE__ */ reactExports.forwardRef(function(_ref, ref) {
  var bgColor = _ref.bgColor, bgD = _ref.bgD, fgD = _ref.fgD, fgColor = _ref.fgColor, size = _ref.size, title = _ref.title, viewBoxSize = _ref.viewBoxSize, _ref$xmlns = _ref.xmlns, xmlns = _ref$xmlns === void 0 ? "http://www.w3.org/2000/svg" : _ref$xmlns, props = _objectWithoutProperties(_ref, _excluded$1);
  return /* @__PURE__ */ React.createElement("svg", _extends({}, props, {
    height: size,
    ref,
    viewBox: "0 0 ".concat(viewBoxSize, " ").concat(viewBoxSize),
    width: size,
    xmlns
  }), title ? /* @__PURE__ */ React.createElement("title", null, title) : null, /* @__PURE__ */ React.createElement("path", {
    d: bgD,
    fill: bgColor
  }), /* @__PURE__ */ React.createElement("path", {
    d: fgD,
    fill: fgColor
  }));
});
QRCodeSvg.displayName = "QRCodeSvg";
QRCodeSvg.propTypes = propTypes$1;
var _excluded = ["bgColor", "fgColor", "level", "size", "value"];
qrcode.stringToBytes = function(s) {
  return Array.from(new TextEncoder().encode(s));
};
var propTypes = {
  bgColor: PropTypes.oneOfType([PropTypes.object, PropTypes.string]),
  fgColor: PropTypes.oneOfType([PropTypes.object, PropTypes.string]),
  level: PropTypes.string,
  size: PropTypes.number,
  value: PropTypes.string.isRequired
};
var QRCode = /* @__PURE__ */ reactExports.forwardRef(function(_ref, ref) {
  var _ref$bgColor = _ref.bgColor, bgColor = _ref$bgColor === void 0 ? "#FFFFFF" : _ref$bgColor, _ref$fgColor = _ref.fgColor, fgColor = _ref$fgColor === void 0 ? "#000000" : _ref$fgColor, _ref$level = _ref.level, level = _ref$level === void 0 ? "L" : _ref$level, _ref$size = _ref.size, size = _ref$size === void 0 ? 256 : _ref$size, value = _ref.value, props = _objectWithoutProperties(_ref, _excluded);
  var qr = qrcode(0, level);
  qr.addData(value);
  qr.make();
  var moduleCount = qr.getModuleCount();
  var cells = Array.from({
    length: moduleCount
  }, function(_, rowIndex) {
    return Array.from({
      length: moduleCount
    }, function(_2, colIndex) {
      return qr.isDark(rowIndex, colIndex);
    });
  });
  return /* @__PURE__ */ React.createElement(QRCodeSvg, _extends({}, props, {
    bgColor,
    bgD: cells.map(function(row, rowIndex) {
      return row.map(function(cell, cellIndex) {
        return !cell ? "M ".concat(cellIndex, " ").concat(rowIndex, " l 1 0 0 1 -1 0 Z") : "";
      }).join(" ");
    }).join(" "),
    fgColor,
    fgD: cells.map(function(row, rowIndex) {
      return row.map(function(cell, cellIndex) {
        return cell ? "M ".concat(cellIndex, " ").concat(rowIndex, " l 1 0 0 1 -1 0 Z") : "";
      }).join(" ");
    }).join(" "),
    ref,
    size,
    viewBoxSize: moduleCount
  }));
});
QRCode.displayName = "QRCode";
QRCode.propTypes = propTypes;
function buildTotpQrImageOptions() {
  return {
    bgColor: "#ffffff",
    fgColor: "#121a3a",
    level: "M",
    size: 160
  };
}
function formatTotpManualKey(value) {
  return (value ?? "").replace(/[\s-]+/g, "").replace(/(.{4})/g, "$1 ").trim();
}
function formatTotpEnrollmentExpiry(value) {
  if (!value) return "Enrollment expiration unknown.";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "Enrollment expiration unknown.";
  return `Enrollment expires at ${date.toLocaleString()}.`;
}
function TotpEnrollmentQrPanel({ enrollment }) {
  const qrOptions = buildTotpQrImageOptions();
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "rounded-xl border border-brand-blue/15 bg-gradient-to-br from-brand-blue/[0.08] via-white to-white p-4", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid gap-4 md:grid-cols-[180px_minmax(0,1fr)] md:items-center", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      "div",
      {
        className: "flex min-h-[180px] items-center justify-center rounded-2xl border border-white bg-white p-3 shadow-sm",
        "aria-label": "Scan this QR code in Google Authenticator or another TOTP app",
        children: /* @__PURE__ */ jsxRuntimeExports.jsx(
          QRCode,
          {
            value: enrollment.otpauth_uri,
            size: qrOptions.size,
            level: qrOptions.level,
            bgColor: qrOptions.bgColor,
            fgColor: qrOptions.fgColor,
            role: "img",
            "aria-label": "Scan this QR code in Google Authenticator or another TOTP app"
          }
        )
      }
    ),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-brand-dark", children: "Scan with your authenticator app" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-xs leading-5 text-slate-500", children: "Open Google Authenticator, 1Password, Authy, or iCloud Passwords. Choose add account, scan this code, then enter the six-digit code below to finish setup." })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("ol", { className: "grid gap-2 text-xs text-slate-600", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { className: "flex gap-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-semibold text-brand-blue", children: "1." }),
          " Scan QR code."
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { className: "flex gap-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-semibold text-brand-blue", children: "2." }),
          " Confirm account says HOL Guard."
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { className: "flex gap-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-semibold text-brand-blue", children: "3." }),
          " Type current six-digit code and verify."
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("details", { className: "rounded-lg border border-slate-200 bg-white px-3 py-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("summary", { className: "cursor-pointer text-xs font-semibold text-brand-dark", children: "Cannot scan? Use manual key" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 select-all break-all font-mono text-xs tracking-wide text-brand-dark", children: formatTotpManualKey(enrollment.manual_key) })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-[11px] text-slate-500", children: formatTotpEnrollmentExpiry(enrollment.expires_at) })
    ] })
  ] }) });
}
const localSettingsNavGroups = [
  {
    key: "local",
    label: "This machine",
    summary: "Protection, approval checks, alerts, tuning, and local upkeep."
  }
];
const ICON_PROTECTION = /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniShieldCheck, { className: "h-4 w-4", "aria-hidden": "true" });
const ICON_APPS = /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniSquares2X2, { className: "h-4 w-4", "aria-hidden": "true" });
const ICON_APPROVAL = /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniLockClosed, { className: "h-4 w-4", "aria-hidden": "true" });
const ICON_NOTIFICATIONS = /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniBellAlert, { className: "h-4 w-4", "aria-hidden": "true" });
const ICON_RISK = /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniAdjustmentsHorizontal, { className: "h-4 w-4", "aria-hidden": "true" });
const ICON_MAINTENANCE = /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCircleStack, { className: "h-4 w-4", "aria-hidden": "true" });
const localSettingsNavItems = [
  {
    key: "protection",
    label: "Protection",
    mobileLabel: "Protect",
    summary: "Security level, mode, sync, and what Guard pauses.",
    group: "local",
    icon: ICON_PROTECTION
  },
  {
    key: "apps",
    label: "Apps",
    mobileLabel: "Apps",
    summary: "Choose protection or Watch for each app on this machine.",
    group: "local",
    icon: ICON_APPS
  },
  {
    key: "approval",
    label: "Approval gate",
    mobileLabel: "Gate",
    summary: "Password, app code, cooldown, and extra checks.",
    group: "local",
    icon: ICON_APPROVAL
  },
  {
    key: "notifications",
    label: "Notifications",
    mobileLabel: "Alerts",
    summary: "Desktop alerts when Guard needs your attention.",
    group: "local",
    icon: ICON_NOTIFICATIONS
  },
  {
    key: "rules",
    label: "Protection rules",
    mobileLabel: "Rules",
    summary: "Tune risky actions and advanced fallback behavior.",
    group: "local",
    icon: ICON_RISK
  },
  {
    key: "maintenance",
    label: "Data & repair",
    mobileLabel: "Data",
    summary: "Export, reset, clear logs, and fix connection issues.",
    group: "local",
    icon: ICON_MAINTENANCE
  }
];
const localSettingsMobileTabLabels = Object.fromEntries(
  localSettingsNavItems.map((item) => [item.key, item.mobileLabel ?? item.label])
);
function isLocalSettingsTabKey(value) {
  return value === "protection" || value === "apps" || value === "approval" || value === "notifications" || value === "rules" || value === "maintenance";
}
function SettingsSectionNavItem({ active, item, onSelect }) {
  const handleClick = reactExports.useCallback(() => {
    onSelect(item);
  }, [item, onSelect]);
  return /* @__PURE__ */ jsxRuntimeExports.jsx("li", { children: /* @__PURE__ */ jsxRuntimeExports.jsxs(
    "button",
    {
      type: "button",
      onClick: handleClick,
      "aria-current": active ? "page" : void 0,
      "data-testid": `settings-section-nav-${item.key}`,
      className: `flex min-h-11 w-full flex-col gap-0.5 rounded-lg px-3 py-2 text-left text-sm font-semibold transition-[color,background-color] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/50 ${active ? "bg-brand-blue/10 text-brand-blue" : "text-slate-600 hover:bg-slate-100 hover:text-brand-dark"}`,
      children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "flex min-w-0 items-center gap-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: active ? "text-brand-blue" : "text-slate-400", "aria-hidden": "true", children: item.icon }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "truncate", children: item.label }),
          active ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniChevronRight, { className: "ml-auto h-4 w-4 shrink-0", "aria-hidden": "true" }) : null
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "span",
          {
            className: `truncate text-[11px] font-normal leading-snug ${active ? "text-brand-blue/70" : "text-slate-400"}`,
            children: item.summary
          }
        )
      ]
    }
  ) });
}
function SettingsSectionShell({
  activeTab,
  onTabChange,
  intro,
  children
}) {
  const handleNavSelect = reactExports.useCallback(
    (item) => {
      onTabChange(item.key);
    },
    [onTabChange]
  );
  const mobileTabs = localSettingsNavItems.map((item) => ({
    value: item.key,
    label: localSettingsMobileTabLabels[item.key],
    id: `settings-tab-${item.key}`
  }));
  const activeItem = localSettingsNavItems.find((item) => item.key === activeTab);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "guard-settings-shell flex min-h-0 flex-1 flex-col gap-6", children: [
    intro,
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "guard-settings-layout flex min-h-0 flex-1 flex-col gap-6 lg:flex-row lg:items-stretch", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        "nav",
        {
          "aria-label": "Settings section navigation",
          "data-testid": "settings-section-nav",
          className: "guard-settings-side-nav hidden w-full shrink-0 lg:block lg:w-60",
          children: /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "flex flex-col gap-0.5 p-0", children: localSettingsNavGroups.map((group) => /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { className: "flex flex-col", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "px-3 pb-1 pt-2 text-[10px] font-semibold uppercase tracking-[0.2em] text-slate-400", children: group.label }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "flex flex-col gap-0.5", children: localSettingsNavItems.filter((item) => item.group === group.key).map((item) => /* @__PURE__ */ jsxRuntimeExports.jsx(
              SettingsSectionNavItem,
              {
                active: activeTab === item.key,
                item,
                onSelect: handleNavSelect
              },
              item.key
            )) })
          ] }, group.key)) })
        }
      ),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex min-h-0 min-w-0 flex-1 flex-col gap-4", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "guard-settings-mobile-tabs -mx-1 overflow-x-auto px-1 lg:hidden", children: /* @__PURE__ */ jsxRuntimeExports.jsx(TabBar, { tabs: mobileTabs, active: activeTab, onChange: onTabChange }) }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs(
          "div",
          {
            role: "tabpanel",
            id: `settings-panel-${activeTab}`,
            "aria-label": activeItem ? `${activeItem.label} settings` : void 0,
            className: "guard-settings-panel guard-tab-enter flex min-h-[min(28rem,calc(100dvh-18rem))] flex-1 flex-col rounded-2xl border border-slate-100 bg-white p-4 sm:p-6",
            children: [
              activeItem ? /* @__PURE__ */ jsxRuntimeExports.jsxs("header", { className: "guard-settings-mobile-heading mb-5 shrink-0 border-b border-slate-100 pb-4 lg:hidden", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-semibold uppercase tracking-[0.18em] text-slate-400", children: activeItem.label }),
                /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm text-slate-500", children: activeItem.summary })
              ] }) : null,
              /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "flex min-h-0 flex-1 flex-col", children })
            ]
          }
        )
      ] })
    ] })
  ] });
}
function SettingsFormSection({ title, description, children }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "guard-settings-section space-y-4", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "guard-settings-section-title", children: title }),
      description ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "guard-settings-body mt-1 text-slate-500", children: description }) : null
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "divide-y divide-slate-100 rounded-xl border border-slate-100 bg-white px-4", children })
  ] });
}
function SettingsToggleRow({
  label,
  description,
  checked,
  onChange,
  disabled = false
}) {
  const labelId = reactExports.useId();
  const descriptionId = reactExports.useId();
  const handleToggle = reactExports.useCallback(() => {
    if (!disabled) {
      onChange(!checked);
    }
  }, [checked, disabled, onChange]);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center justify-between gap-4 py-3", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0 flex-1", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { id: labelId, className: "guard-settings-body font-medium text-brand-dark", children: label }),
      description ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { id: descriptionId, className: "guard-settings-caption mt-0.5 text-slate-500", children: description }) : null
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      "button",
      {
        type: "button",
        role: "switch",
        "aria-checked": checked,
        "aria-labelledby": labelId,
        "aria-describedby": description ? descriptionId : void 0,
        disabled,
        onClick: handleToggle,
        className: `relative h-7 w-12 shrink-0 rounded-full transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/60 ${checked ? "bg-brand-blue" : "bg-slate-200"} ${disabled ? "cursor-not-allowed opacity-50" : "cursor-pointer"}`,
        children: /* @__PURE__ */ jsxRuntimeExports.jsx(
          "span",
          {
            className: `absolute top-0.5 left-0.5 h-6 w-6 rounded-full bg-white shadow-sm transition-transform ${checked ? "translate-x-5" : "translate-x-0"}`
          }
        )
      }
    )
  ] });
}
function SettingsSelectRow({
  label,
  description,
  value,
  options,
  onChange,
  disabled = false
}) {
  const selectId = reactExports.useId();
  const descriptionId = reactExports.useId();
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid gap-2 py-3 md:grid-cols-[minmax(0,1fr)_200px] md:items-center", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("label", { htmlFor: selectId, className: "guard-settings-body font-medium text-brand-dark", children: label }),
      description ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { id: descriptionId, className: "guard-settings-caption mt-0.5 text-slate-500", children: description }) : null
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      "select",
      {
        id: selectId,
        value,
        onChange,
        disabled,
        "aria-describedby": description ? descriptionId : void 0,
        className: "min-h-11 w-full rounded-lg border border-slate-200 bg-white px-2.5 py-1.5 text-sm text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-1 focus:ring-brand-blue/20 disabled:cursor-not-allowed disabled:opacity-60",
        children: options.map((option) => /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: option.value, children: option.label }, option.value))
      }
    )
  ] });
}
function resolveApprovalPasswordSectionCopy(wasConfigured, enabled = true) {
  if (wasConfigured) {
    if (!enabled) {
      return "Local approval is off. Choose a password to enable it again. Your authenticator stays connected.";
    }
    return "Guard asks for this password before allow or trust changes stick. Save settings to confirm changes, or change the password when needed.";
  }
  if (!enabled) {
    return "Choose a password to protect approvals and permission changes on this device. Setup turns on password checks.";
  }
  return "Set an approval password before allow or trust changes stick. Use the setup action below to choose it.";
}
function ApprovalPasswordSetupAction(props) {
  return /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { onClick: props.onClick, variant: "outline", children: "Set up approval password" });
}
function ApprovalPasswordSection(props) {
  const copyEnabled = props.wasConfigured ? props.gateActive : props.enabled;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-xl border border-slate-100 bg-white p-4", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Approval password" }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-xs text-slate-500", children: resolveApprovalPasswordSectionCopy(props.wasConfigured, copyEnabled) }),
    props.wasConfigured && props.gateActive ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-3", children: /* @__PURE__ */ jsxRuntimeExports.jsx(
      "button",
      {
        type: "button",
        onClick: () => props.onOpenPasswordChangeModal(),
        className: "text-xs font-medium text-brand-blue transition-colors hover:text-brand-blue/80",
        children: "Change password"
      }
    ) }) : null,
    !props.wasConfigured || !props.gateActive ? /* @__PURE__ */ jsxRuntimeExports.jsx(ApprovalPasswordSetupAction, { onClick: () => props.onOpenPasswordChangeModal("setup-gate") }) : null
  ] });
}
function cloudReviewProofIncomplete(gate, password, totp, requireFreshTotp) {
  if (!gate?.enabled) return false;
  if (isApprovalProofSubmitDisabled(
    gate,
    { approvalPassword: password, approvalTotpCode: totp },
    false,
    requireFreshTotp
  )) return true;
  return requireFreshTotp && totp.trim().length !== 6;
}
function cloudReviewConfirmationError(message2) {
  if (message2 === "TOTP code is required.") {
    return "Enter the current six-digit code from your authenticator.";
  }
  if (message2 === "Approval password is required.") {
    return "Enter your approval password to continue.";
  }
  return message2;
}
function cloudReviewStatusCopy(status) {
  if (!status.connected) return "Connect Guard Cloud on this device to review its requests in the cloud.";
  if (status.reconnect_required) return "Guard Cloud sign-in needs repair. Reconnect to resume uploads and cloud decisions; local review is still available.";
  if (!status.enabled) return "Cloud sync is connected. Cloud decisions still need this device's authorization. Confirm it here to update pending requests; you do not need to reconnect.";
  if (status.activation_error) return "Authorization is saved. Request delivery needs another attempt.";
  if (status.held_events > 0) return "Cloud Review is enabled. Some earlier requests need your confirmation before upload.";
  if (status.isolated_events > 0) return "Cloud Review is enabled. Requests tied to another identity stay in local Review.";
  if (status.delivery_state === "error") return "Cloud Review is enabled. Uploads are retrying; local review is still available.";
  if (status.pending_uploads > 0) return "Cloud Review is enabled. Pending requests are being uploaded.";
  return "Cloud Review is enabled for this device. Each cloud decision applies only to its exact request.";
}
function cloudReviewConnectionLabel(status) {
  if (status.reconnect_required) return "Reconnect needed";
  return status.connected ? "Connected" : "Not connected";
}
function cloudReviewDecisionLabel(status) {
  if (status.reconnect_required) return "Paused until sign-in";
  return status.enabled ? "Enabled" : "Confirmation needed";
}
function cloudReviewRecoveryAction(status) {
  if (!status.connected || status.reconnect_required) return "connect";
  if (!status.enabled) return "authorize";
  if (status.activation_error || status.held_events > 0) return "restore";
  return "none";
}
function CloudReviewSettings() {
  const [status, setStatus] = reactExports.useState(null);
  const [error, setError] = reactExports.useState(null);
  const [loading, setLoading] = reactExports.useState(true);
  const [action, setAction] = reactExports.useState(null);
  const [pending, setPending] = reactExports.useState(false);
  const [includeHeld, setIncludeHeld] = reactExports.useState(false);
  const [password, setPassword] = reactExports.useState("");
  const [totp, setTotp] = reactExports.useState("");
  const dialog = reactExports.useRef(null);
  const revision = reactExports.useRef(0);
  useFocusTrap(action !== null, dialog);
  const refresh = reactExports.useCallback(async (showLoading = true) => {
    const current = ++revision.current;
    if (showLoading) setLoading(true);
    try {
      const result = await fetchCloudReviewSettings();
      if (current !== revision.current) return;
      setStatus(result);
      setError(null);
    } catch {
      if (current !== revision.current) return;
      setStatus(null);
      setError("Cloud Review status is unavailable. Refresh to check again; local review remains available.");
    } finally {
      if (current === revision.current) setLoading(false);
    }
  }, []);
  reactExports.useEffect(() => {
    void refresh();
    return () => {
      revision.current += 1;
    };
  }, [refresh]);
  reactExports.useEffect(() => {
    const onFocus = () => {
      if (action === null && !document.hidden) void refresh(false);
    };
    window.addEventListener("focus", onFocus);
    document.addEventListener("visibilitychange", onFocus);
    const timer = window.setInterval(onFocus, 15e3);
    return () => {
      window.removeEventListener("focus", onFocus);
      document.removeEventListener("visibilitychange", onFocus);
      window.clearInterval(timer);
    };
  }, [refresh, action]);
  function openConfirmation(nextAction) {
    revision.current += 1;
    setAction(nextAction);
    setError(null);
  }
  function close() {
    if (pending) return;
    setAction(null);
    setPassword("");
    setTotp("");
    setIncludeHeld(false);
  }
  async function confirm() {
    if (!status || !action || pending) return;
    const requireFreshTotp2 = status.approval_gate.totp_enabled === true;
    if (cloudReviewProofIncomplete(status.approval_gate, password, totp, requireFreshTotp2)) return;
    const proof = status.approval_gate.enabled ? buildApprovalProofCredentials(
      status.approval_gate,
      { approvalPassword: password, approvalTotpCode: totp },
      requireFreshTotp2
    ) : {};
    revision.current += 1;
    setPending(true);
    setError(null);
    try {
      const result = await changeCloudReviewSettings({
        action,
        workspace_id: status.workspace_id,
        source: status.source,
        include_held_requests: action === "enable" && includeHeld,
        ...proof
      });
      setStatus(result);
      setAction(null);
      setIncludeHeld(false);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "The change was not saved. Try again.");
    } finally {
      setPassword("");
      setTotp("");
      setPending(false);
    }
  }
  const recoveryAction = status ? cloudReviewRecoveryAction(status) : "none";
  const requireFreshTotp = status?.approval_gate.totp_enabled === true;
  const disabled = pending || cloudReviewProofIncomplete(status?.approval_gate, password, totp, requireFreshTotp);
  let confirmLabel = "Turn off Cloud Review";
  if (action === "enable") confirmLabel = "Authorize this device";
  if (pending) confirmLabel = "Saving...";
  let statusCopy = error;
  if (status) statusCopy = cloudReviewStatusCopy(status);
  if (loading) statusCopy = "Checking device authorization...";
  const deliveredAt = status?.last_synced_at && Number.isFinite(Date.parse(status.last_synced_at)) ? new Date(status.last_synced_at) : null;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { "aria-labelledby": "cloud-review-heading", className: "border-t border-slate-200 pt-4", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start justify-between gap-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("h3", { id: "cloud-review-heading", className: "flex items-center gap-2 text-sm font-semibold text-brand-dark", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCloud, { "aria-hidden": "true", className: "h-5 w-5 shrink-0" }),
          " Cloud Review"
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm text-slate-600", role: "status", children: statusCopy }),
        status?.enabled && status.expires_at ? /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-1 text-xs text-slate-600", children: [
          "Authorized until ",
          new Date(status.expires_at).toLocaleDateString(),
          "."
        ] }) : null
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        "button",
        {
          type: "button",
          disabled: loading || pending,
          onClick: () => void refresh(),
          title: "Refresh Cloud Review status",
          "aria-label": "Refresh Cloud Review status",
          className: "inline-flex h-10 w-10 shrink-0 items-center justify-center rounded-md text-brand-dark hover:bg-slate-100 disabled:opacity-50",
          children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowPath, { "aria-hidden": "true", className: "h-4 w-4" })
        }
      )
    ] }),
    status ? /* @__PURE__ */ jsxRuntimeExports.jsxs("dl", { className: "mt-3 grid grid-cols-1 gap-x-6 gap-y-2 text-sm sm:grid-cols-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-xs text-slate-600", children: "Cloud connection" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "mt-1 font-medium text-brand-dark", children: cloudReviewConnectionLabel(status) })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-xs text-slate-600", children: "Cloud decisions" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "mt-1 font-medium text-brand-dark", children: cloudReviewDecisionLabel(status) })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-xs text-slate-600", children: "Last activity delivered" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "mt-1 font-medium text-brand-dark", children: deliveredAt ? /* @__PURE__ */ jsxRuntimeExports.jsx("time", { dateTime: deliveredAt.toISOString(), children: deliveredAt.toLocaleString(void 0, {
          month: "short",
          day: "numeric",
          hour: "numeric",
          minute: "2-digit"
        }) }) : "Not recorded yet" })
      ] })
    ] }) : null,
    status ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-3 flex flex-wrap items-start gap-2", children: [
      recoveryAction === "connect" ? /* @__PURE__ */ jsxRuntimeExports.jsx(
        ConnectGuardCloudButton,
        {
          label: status.reconnect_required ? "Reconnect Guard Cloud" : "Connect Guard Cloud",
          variant: status.reconnect_required ? "primary" : "secondary",
          onConnected: () => {
            void refresh(false);
          }
        }
      ) : null,
      recoveryAction === "authorize" || recoveryAction === "restore" ? /* @__PURE__ */ jsxRuntimeExports.jsx(
        "button",
        {
          type: "button",
          disabled: loading || pending,
          onClick: () => openConfirmation("enable"),
          className: "min-h-10 rounded-md bg-brand-blue px-3 py-2 text-sm font-semibold text-white disabled:opacity-50",
          children: recoveryAction === "restore" ? "Restore Cloud Review" : "Enable Cloud Review"
        }
      ) : null,
      status.enabled ? /* @__PURE__ */ jsxRuntimeExports.jsx(
        "button",
        {
          type: "button",
          disabled: loading || pending,
          onClick: () => openConfirmation("disable"),
          className: "min-h-10 rounded-md border border-slate-200 px-3 py-2 text-sm font-semibold text-brand-dark hover:bg-slate-50 disabled:opacity-50",
          children: "Turn off Cloud Review"
        }
      ) : null
    ] }) : null,
    action && status ? /* @__PURE__ */ jsxRuntimeExports.jsx(
      "div",
      {
        className: "fixed inset-0 z-50 flex items-center justify-center overflow-y-auto bg-black/30 p-4",
        onKeyDown: (event) => {
          if (event.key === "Escape") close();
        },
        children: /* @__PURE__ */ jsxRuntimeExports.jsxs(
          "form",
          {
            ref: dialog,
            role: "dialog",
            "aria-modal": "true",
            "aria-labelledby": "cloud-review-confirm-title",
            noValidate: true,
            onSubmit: (event) => {
              event.preventDefault();
              void confirm();
            },
            className: "max-h-[90dvh] w-full max-w-lg overflow-y-auto rounded-lg bg-white p-5 shadow-xl",
            children: [
              /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start justify-between gap-3", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "cloud-review-confirm-title", className: "text-base font-semibold text-brand-dark", children: action === "enable" ? "Authorize Cloud Review" : "Turn off Cloud Review?" }),
                /* @__PURE__ */ jsxRuntimeExports.jsx(
                  "button",
                  {
                    type: "button",
                    onClick: close,
                    disabled: pending,
                    "aria-label": "Close Cloud Review dialog",
                    className: "inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-md hover:bg-slate-100",
                    children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniXMark, { "aria-hidden": "true", className: "h-5 w-5" })
                  }
                )
              ] }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-3 text-sm text-slate-600", children: action === "enable" ? "Allow signed cloud decisions for exact requests from this device for 30 days. Existing pending requests will be refreshed automatically. Local protection stays on." : "Cloud decisions will stop on this device. You can still review requests locally; Cloud sync stays connected." }),
              action === "enable" && status.held_events > 0 ? /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "mt-4 flex items-start gap-3 text-sm text-brand-dark", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx("input", { type: "checkbox", checked: includeHeld, onChange: (event) => setIncludeHeld(event.target.checked), disabled: pending, className: "mt-1" }),
                /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { children: [
                  "Also send ",
                  status.held_events.toLocaleString(),
                  " previously unassigned events to the connected workspace.",
                  /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "mt-1 block text-xs text-slate-600", children: "Requests tied to another account or workspace stay isolated." }),
                  /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "mt-1 block break-all text-xs text-slate-600", children: [
                    "Workspace: ",
                    status.workspace_id ?? "Not connected"
                  ] })
                ] })
              ] }) : null,
              status.approval_gate.enabled ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4", children: /* @__PURE__ */ jsxRuntimeExports.jsx(
                ApprovalProofFieldInputs,
                {
                  approvalGate: status.approval_gate,
                  approvalPassword: password,
                  approvalTotpCode: totp,
                  requireFreshTotp,
                  onApprovalPasswordChange: (event) => setPassword(event.target.value),
                  onApprovalTotpCodeChange: (event) => setTotp(event.target.value)
                }
              ) }) : null,
              error ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "alert", className: "mt-3 text-sm text-red-700", children: cloudReviewConfirmationError(error) }) : null,
              /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-5 flex flex-wrap justify-end gap-2", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", onClick: close, disabled: pending, className: "min-h-10 rounded-md border border-slate-200 px-4 py-2 text-sm text-brand-dark", children: "Cancel" }),
                /* @__PURE__ */ jsxRuntimeExports.jsx(
                  "button",
                  {
                    type: "submit",
                    disabled,
                    className: "min-h-10 rounded-md bg-brand-blue px-4 py-2 text-sm font-semibold text-white disabled:opacity-50",
                    children: confirmLabel
                  }
                )
              ] })
            ]
          }
        )
      }
    ) : null
  ] });
}
function withContextProfile(config, profile) {
  const limits = profile === "low_memory" ? { context_tokens: 768, reserve_tokens: 128, max_active_workspaces: 1, idle_shutdown_seconds: 120 } : profile === "balanced" ? { context_tokens: 2048, reserve_tokens: 256, max_active_workspaces: 2, idle_shutdown_seconds: 600 } : config.limits;
  return { ...config, resource_profile: profile, limits: { ...limits } };
}
function settingsWithContextOff(settings, fallback) {
  return {
    ...settings,
    context_assistance: { ...settings.context_assistance ?? fallback, enabled: false },
    ...settings.context_assistance_requested !== void 0 ? { context_assistance_requested: { ...fallback, enabled: false } } : {}
  };
}
const phases = {
  prepared: "Context checked before launch",
  not_dispatched: "No new dispatch acknowledged",
  dispatch_acknowledged: "Native dispatch acknowledged",
  completed: "Native execution record completed",
  outcome_unknown: "Native outcome needs reconciliation"
};
function ContextExecutionPanel({ status }) {
  if (!status?.preferences.features.execution_context) return null;
  const observations = status.execution_observations;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { "aria-label": "Native execution context observations", className: "space-y-3 rounded-lg border border-slate-200 p-3 text-sm", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("h4", { className: "font-semibold text-brand-dark", children: "Native execution context" }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-slate-600", children: status.execution_ready ? "Preparation is ready for Pi and Oh My Pi workspace grants using Guard's native captured-Bash executor." : "Preparation is unavailable. Commands keep their native authorization and can proceed without this association." }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-slate-600", children: "Execution checks use fixed native capture and policy facts. Selected files and shared notes remain separate review context. End-to-end app delivery has not been qualified in this candidate." }),
    observations === null ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "status", children: "Recent observations are busy. Refresh status to check again." }) : !observations?.length ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "No recent execution-context observations." }) : /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "space-y-3", children: observations.slice(0, 6).map((item) => /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { className: "rounded-md bg-slate-50 p-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "font-medium text-brand-dark", children: phases[item.phase] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: item.association_applied ? "Checked context was associated at native dispatch." : item.phase === "prepared" ? "Association awaits native dispatch." : "No CIGAR association is confirmed for this attempt." }),
      item.phase === "outcome_unknown" ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-amber-800", children: "Consult Guard's native execution record before retrying." }) : null,
      /* @__PURE__ */ jsxRuntimeExports.jsxs("details", { className: "mt-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("summary", { className: "cursor-pointer font-medium", children: "Observation details" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("dl", { className: "mt-2 space-y-1 break-all text-xs text-slate-600", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { children: "Execution reference" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { children: item.execution_reference ?? "Not associated" })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { children: "Context snapshot" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { children: item.snapshot_id })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { children: "Native launch check" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { children: item.native_barrier_checked_at_ms === null ? "No launch check recorded" : new Date(item.native_barrier_checked_at_ms).toLocaleString() })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { children: "Scope" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { children: item.scope_id })
          ] }),
          item.reason ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { children: "Association detail" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { children: item.reason.replaceAll("_", " ") })
          ] }) : null
        ] })
      ] })
    ] }, item.effect_id)) }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-500", children: "Up to 32 metadata observations remain in memory for five minutes. Entries can be omitted; this is a context check record. Guard's native journal owns execution, approvals and uncertain outcomes." })
  ] });
}
const versionButton = "min-h-11 rounded-lg border border-slate-200 px-3 py-2 text-sm font-semibold text-brand-dark disabled:cursor-not-allowed disabled:opacity-50";
const versionField = "mt-1 min-h-11 w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm text-brand-dark";
const versionCard = "space-y-3 rounded-xl border border-slate-200 bg-white p-4";
const versionBytes = (bytes) => (bytes / 1048576).toFixed(1) + " MiB";
function CigarRuntimeSelection(props) {
  const id2 = props.status?.preferences.runtime_id ?? props.value.runtime_id;
  const selected = props.installations?.find((item) => item.runtime_id === id2);
  const pending = props.status !== null && props.value.runtime_id !== id2;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-2", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-brand-dark", children: "Selected runtime" }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "break-all text-sm text-slate-600", children: id2 || "No runtime selected" }),
    selected ? /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "text-sm text-slate-600", children: [
      selected.sdk_version ? "CIGAR " + selected.sdk_version + " · " : "",
      "Python ",
      selected.python_version.join("."),
      " · ",
      selected.platform,
      " · ",
      selected.qualification.replaceAll("_", " ")
    ] }) : null,
    props.installations?.length === 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-slate-600", children: "No registered CIGAR runtime is available in this profile. Python 3.14 may already be installed; use Versions & updates to inspect approved builds and registration options." }) : null,
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-slate-600", children: "Choose, prepare and switch runtimes in Versions & updates. A separate selection job protects your current runtime and data." }),
    props.onManage ? /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", className: versionButton, disabled: props.disabled, onClick: props.onManage, children: "Choose or switch runtime" }) : /* @__PURE__ */ jsxRuntimeExports.jsx("a", { className: versionButton + " inline-flex items-center", href: shellHref("/cigar?section=versions"), children: "Choose or switch runtime" }),
    props.installations !== null ? /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", className: versionButton, disabled: props.disabled, onClick: props.onRefresh, children: "Refresh runtime list" }) : null,
    pending ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { role: "status", className: "text-sm text-amber-800", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "A pending runtime choice is in this form. Use the current selection before preparing a different runtime in Versions & updates." }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", className: versionButton, disabled: props.disabled, onClick: props.onRestore, children: "Use current selection" })
    ] }) : null
  ] });
}
const buttonClass = "min-h-11 rounded-lg border border-slate-200 px-3 py-2 text-sm font-semibold text-brand-dark hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-50";
function ContextSettingsControls(props) {
  const { value, status, installations } = props;
  const titleId = reactExports.useId();
  const statusCopy = status ? contextStatusCopy(status) : null;
  const selected = installations?.some((item) => item.runtime_id === value?.runtime_id) === true;
  const disabled = props.disabled || props.busy;
  const editingDisabled = disabled || props.locked || value === null || status === null;
  const checkDisabled = disabled || props.dirty || !status?.verification_permitted || Boolean(status?.job) || !value?.runtime_id;
  const stopped = !value?.enabled && !status?.requested_enabled && !status?.job && !status?.effective_enabled;
  const runtime = status?.runtime ?? status?.last_check;
  return /* @__PURE__ */ jsxRuntimeExports.jsx(SettingsFormSection, { title: "Context assistance", description: "Optional local context from CIGAR helps explain work using the sources you authorize.", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-4 py-4", "aria-labelledby": titleId, children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-start justify-between gap-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h4", { id: titleId, className: "text-sm font-semibold text-brand-dark", children: runtime ? "CIGAR " + runtime.package_version : "CIGAR runtime" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm text-slate-600", role: "status", "aria-live": "polite", children: props.loading ? "Checking availability…" : statusCopy ? `${statusCopy.label}. ${statusCopy.detail}` : "Availability has not been verified." })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", className: buttonClass, disabled: disabled || props.loading, onClick: props.onRefresh, children: "Refresh status" })
    ] }),
    props.error ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "alert", className: "text-sm text-red-700", children: props.error }) : null,
    props.dirty ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "status", className: "text-sm text-slate-600", children: "Save settings before checking or starting this runtime." }) : null,
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-2", children: [
      status?.requested_enabled && !status.effective_enabled ? /* @__PURE__ */ jsxRuntimeExports.jsx(
        "button",
        {
          type: "button",
          className: buttonClass + " border-brand-blue bg-brand-blue/10",
          disabled: checkDisabled || !status.effective_preferences.enabled,
          onClick: () => props.onControl("activate"),
          children: "Start context assistance"
        }
      ) : null,
      /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", className: buttonClass, disabled: checkDisabled, onClick: () => props.onControl("recheck"), children: "Check selected runtime" }),
      !stopped ? /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", className: buttonClass, disabled, onClick: () => props.onControl("stop"), children: "Turn off now" }) : null
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-slate-600", children: "Requires a verified final CPython 3.14 runtime on this machine. A separate Python 3.14 environment works even when Guard uses an older supported Python." }),
    props.locked ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-slate-600", children: "Your organization manages these preferences. You can still turn context assistance off." }) : null,
    status?.restriction ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-slate-600", children: "Policy restrictions apply. Your saved choices are retained; effective limits are shown below." }) : null,
    value ? /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        SettingsToggleRow,
        {
          label: "Use CIGAR on this machine",
          checked: value.enabled,
          description: "Save your preferences, then click Start CIGAR at the top of this page to verify and run the runtime.",
          disabled: editingDisabled || !value.enabled && !selected,
          onChange: (enabled) => props.onChange({ ...value, enabled })
        }
      ),
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        CigarRuntimeSelection,
        {
          value,
          status,
          installations,
          disabled,
          onManage: props.onManageVersions,
          onRefresh: props.onChooseRuntime,
          onRestore: () => {
            if (status) props.onChange({
              ...value,
              runtime_id: status.preferences.runtime_id,
              enabled: value.enabled && Boolean(status.preferences.runtime_id)
            });
          }
        }
      ),
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        SettingsSelectRow,
        {
          label: "Context size",
          value: value.resource_profile,
          disabled: editingDisabled,
          description: "Smaller context uses one workspace and stops after two idle minutes. Balanced allows two workspaces and ten idle minutes.",
          options: [{ value: "low_memory", label: "Smaller context" }, { value: "balanced", label: "Balanced" }, { value: "custom", label: "Custom limits" }],
          onChange: (event) => props.onChange(withContextProfile(value, event.target.value))
        }
      ),
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        SettingsToggleRow,
        {
          label: "Review briefs",
          description: "Prepare cited context to help you understand a request. Guard's approval choices stay available.",
          checked: value.features.review_briefs,
          disabled: editingDisabled,
          onChange: (review_briefs) => props.onChange({ ...value, features: { ...value.features, review_briefs } })
        }
      ),
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        SettingsToggleRow,
        {
          label: "Context for AI apps",
          description: "Allow scoped context tools for apps you authorize. Sharing between agents requires a separate choice.",
          checked: value.features.agent_context,
          disabled: editingDisabled,
          onChange: (agent_context) => props.onChange({ ...value, features: { ...value.features, agent_context, shared_agents: agent_context && value.features.shared_agents } })
        }
      ),
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        SettingsToggleRow,
        {
          label: "Share context between paired AI connections",
          description: "Separate connections for the same app and workspace can use shared context. Notes require explicit access and your review before sharing. Saving this change ends existing context grants; pair connections again after starting the runtime.",
          checked: value.features.shared_agents,
          disabled: editingDisabled || !value.features.agent_context || status?.capabilities?.shared_agents !== true,
          onChange: (shared_agents) => props.onChange({ ...value, features: { ...value.features, shared_agents } })
        }
      ),
      !value.features.agent_context ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-slate-600", children: "Enable Context for AI apps before choosing sharing." }) : null,
      /* @__PURE__ */ jsxRuntimeExports.jsxs("details", { className: "rounded-lg border border-slate-100 p-3 text-sm", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("summary", { className: "cursor-pointer font-medium text-brand-dark", children: "Sources, limits and runtime details" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          SettingsToggleRow,
          {
            label: "Associate native context with execution",
            description: "Add a short context check to supported native captured-Bash commands. Requires native facts and fresh app/workspace access. Guard proceeds under its existing authorization when the association is unavailable.",
            checked: value.features.execution_context === true,
            disabled: editingDisabled || value.features.execution_context !== true && (status?.capabilities?.execution_context !== true || !value.sources.native_policy_facts),
            onChange: (execution_context) => props.onChange({ ...value, features: { ...value.features, execution_context } })
          }
        ),
        status?.capabilities?.execution_context !== true ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-500", children: "This native execution route is unavailable in the current build. Review briefs and scoped context tools have their own controls." }) : null,
        !value.sources.native_policy_facts ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-500", children: "Enable native policy and decision facts to choose execution associations." }) : null,
        value.resource_profile === "custom" ? /* @__PURE__ */ jsxRuntimeExports.jsxs("fieldset", { className: "mt-3 grid gap-3 sm:grid-cols-2", disabled: editingDisabled, children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("legend", { className: "mb-2 font-medium text-brand-dark", children: "Custom limits" }),
          [
            ["context_tokens", "Context token budget", 64, 16384],
            ["reserve_tokens", "Reserved tokens", 0, value.limits.context_tokens - 1],
            ["max_active_workspaces", "Active workspaces", 1, 8],
            ["idle_shutdown_seconds", "Idle shutdown in seconds", 30, 3600]
          ].map(([key2, label, min, max]) => /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "text-sm text-slate-600", children: [
            label,
            /* @__PURE__ */ jsxRuntimeExports.jsx(
              "input",
              {
                type: "number",
                min,
                max,
                step: 1,
                value: value.limits[key2],
                className: "mt-1 min-h-11 w-full rounded-lg border border-slate-200 px-3 py-2 text-brand-dark",
                onChange: (event) => {
                  const next = event.target.valueAsNumber;
                  if (Number.isSafeInteger(next)) props.onChange({ ...value, limits: { ...value.limits, [key2]: next } });
                }
              }
            )
          ] }, key2))
        ] }) : null,
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          SettingsToggleRow,
          {
            label: "Native policy and decision facts",
            description: "Use admitted policy facts and native evaluation metadata. Up to 64 recent native decisions stay in local memory for five minutes.",
            checked: value.sources.native_policy_facts,
            disabled: editingDisabled,
            onChange: (native_policy_facts) => props.onChange({
              ...value,
              features: { ...value.features, execution_context: native_policy_facts && value.features.execution_context === true },
              sources: { ...value.sources, native_policy_facts }
            })
          }
        ),
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          SettingsToggleRow,
          {
            label: "Sanitized receipt facts",
            description: "Use sanitized facts from Guard's local history.",
            checked: value.sources.sanitized_receipt_facts,
            disabled: editingDisabled,
            onChange: (sanitized_receipt_facts) => props.onChange({ ...value, sources: { ...value.sources, sanitized_receipt_facts } })
          }
        ),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-slate-600", children: "Workspace documents require explicit source access. Runtime activation grants no document access." }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          SettingsToggleRow,
          {
            label: "Allow selected workspace documents",
            description: "After saving, choose each folder and file in Workspace context access. Files are read only with an explicit grant.",
            checked: value.sources.workspace_documents,
            disabled: editingDisabled,
            onChange: (workspace_documents) => props.onChange({ ...value, sources: {
              ...value.sources,
              workspace_documents,
              source_set_id: workspace_documents ? value.sources.source_set_id || "selected-workspaces" : value.sources.source_set_id
            } })
          }
        ),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block text-sm text-slate-600", children: [
          "Evidence storage",
          /* @__PURE__ */ jsxRuntimeExports.jsxs(
            "select",
            {
              value: value.storage.mode,
              disabled: editingDisabled,
              className: "mt-1 min-h-11 w-full rounded-lg border border-slate-200 px-3 py-2 text-brand-dark",
              onChange: (event) => props.onChange({ ...value, storage: { ...value.storage, mode: event.target.value === "sqlite" ? "sqlite" : "memory" } }),
              children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "memory", children: "Memory only (recommended)" }),
                /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "sqlite", disabled: status?.capabilities?.private_persistence !== true, children: "Save evidence locally" })
              ]
            }
          )
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-500", children: "Memory data ends when the runtime stops. Saved evidence uses private local files, with no Guard encryption; it can outlive the runtime until retention or removal. Restoring it never restores app access or approvals. Saving a storage change ends current context access." }),
        status?.capabilities?.private_persistence !== true ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-500", children: "Saved evidence activation is unavailable in this build. Existing saved data can be removed in Data & repair." }) : null,
        /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block text-sm text-slate-600", children: [
          "Context history, saved evidence and shared-note retention in hours",
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            "input",
            {
              type: "number",
              min: 1,
              max: 720,
              step: 1,
              value: value.storage.retention_hours,
              disabled: editingDisabled,
              className: "mt-1 min-h-11 w-full rounded-lg border border-slate-200 px-3 py-2 text-brand-dark",
              onChange: (event) => {
                const retention_hours = event.target.valueAsNumber;
                if (Number.isSafeInteger(retention_hours)) props.onChange({ ...value, storage: { ...value.storage, retention_hours } });
              }
            }
          )
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-500", children: "Memory data also ends when access is revoked, the runtime stops, or Guard restarts. Changing preferences requires fresh grants." }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("dl", { className: "mt-3 grid gap-2 sm:grid-cols-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { children: "Effective context budget" }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("dd", { children: [
              (status?.effective_preferences ?? value).limits.context_tokens,
              " tokens, including ",
              (status?.effective_preferences ?? value).limits.reserve_tokens,
              " reserved"
            ] })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { children: "Effective workspace limit" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { children: (status?.effective_preferences ?? value).limits.max_active_workspaces })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { children: "Effective idle shutdown" }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("dd", { children: [
              (status?.effective_preferences ?? value).limits.idle_shutdown_seconds,
              " seconds"
            ] })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { children: "Storage" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { children: value.storage.mode === "memory" ? "Memory only" : "Private persistence requested" })
          ] }),
          runtime ? /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { children: "Last verified Python" }),
              /* @__PURE__ */ jsxRuntimeExports.jsxs("dd", { children: [
                runtime.interpreter.version.join("."),
                " · ",
                runtime.interpreter.platform
              ] })
            ] }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { children: "Qualification" }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { children: "Local development candidate" })
            ] }),
            value.features.shared_agents ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { children: "Shared context check" }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { children: runtime.shared_compile_verified ? "Verified with an independent local client" : "Check and start the selected runtime" })
            ] }) : null,
            value.storage.mode === "sqlite" ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { children: "Saved evidence check" }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { children: runtime.persistence_compile_verified ? "Verified write, restart and fresh-grant recovery" : "Check and start the selected runtime" })
            ] }) : null,
            value.features.execution_context ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { children: "Execution SDK check" }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { children: runtime.execution_handoff_verified ? "Verified submission, host review, binding and one-time context take" : "Check and start the selected runtime" })
            ] }) : null
          ] }) : null
        ] }),
        status?.diagnostic ? /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-3 break-words text-xs text-slate-500", children: [
          "Diagnostic: ",
          status.diagnostic
        ] }) : null
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(ContextExecutionPanel, { status })
    ] }) : /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-slate-600", children: "Update Guard to a native core with context assistance support before choosing these settings." }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-500", children: "Context is supporting information. Guard keeps command protection and approval decisions in its native execution flow." })
  ] }) });
}
const button$3 = "min-h-11 rounded-lg border border-slate-200 px-3 py-2 text-sm font-semibold text-brand-dark disabled:cursor-not-allowed disabled:opacity-50";
function ContextAgentsPanel({ ready, enabled, dirty, generation, scopes, gate }) {
  const [sessions, setSessions] = reactExports.useState([]);
  const [selected, setSelected] = reactExports.useState({});
  const [confirm, setConfirm] = reactExports.useState(null);
  const [error, setError] = reactExports.useState(null);
  const [statusError, setStatusError] = reactExports.useState(null);
  const [busy, setBusy] = reactExports.useState(false);
  const revision = reactExports.useRef(0);
  const request = reactExports.useRef(null);
  const pending = reactExports.useRef(false);
  const allowed = ready && enabled;
  const confirmationScope = scopes.find((scope) => scope.scope_id === selected[confirm?.session_id ?? ""]);
  const refresh = reactExports.useCallback(async () => {
    if (!allowed || pending.current) return;
    const id2 = ++revision.current;
    request.current?.abort();
    const controller = new AbortController();
    request.current = controller;
    try {
      const values = await listContextAgentSessions(controller.signal);
      if (revision.current === id2) {
        setSessions(values);
        setStatusError(null);
      }
    } catch {
      if (revision.current === id2) {
        setSessions([]);
        setStatusError("Connection status is unavailable. Refresh before granting access.");
      }
    }
  }, [allowed]);
  reactExports.useEffect(() => {
    setSessions([]);
    setSelected({});
    setConfirm(null);
    setError(null);
    setStatusError(null);
    setBusy(false);
    void refresh();
    const timer = allowed ? window.setInterval(() => {
      if (!document.hidden) void refresh();
    }, 3e3) : null;
    return () => {
      revision.current += 1;
      request.current?.abort();
      if (timer !== null) window.clearInterval(timer);
    };
  }, [allowed, generation, refresh]);
  async function perform(session, credentials, revoke = false) {
    if (pending.current) return;
    const scope = scopes.find((scope2) => scope2.scope_id === selected[session.session_id] && !scope2.revoked && scope2.app !== "dashboard");
    if (!revoke && (dirty || !scope)) return;
    pending.current = true;
    const id2 = ++revision.current;
    request.current?.abort();
    const controller = new AbortController();
    request.current = controller;
    setBusy(true);
    setError(null);
    try {
      if (revoke) await revokeContextAgentSession(session.session_id, controller.signal);
      else await authorizeContextAgentSession(session.session_id, scope.scope_id, credentials, controller.signal);
      if (revision.current === id2) setConfirm(null);
    } catch (failure) {
      if (revision.current === id2) setError(failure instanceof ContextAssistanceApiError ? failure.message : "The connection change did not return a verified result. Refresh its status before trying again.");
    } finally {
      pending.current = false;
      if (revision.current === id2) {
        setBusy(false);
        void refresh();
      }
    }
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { "aria-label": "AI app context connections", className: "space-y-3 rounded-lg border border-slate-200 p-3", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("h4", { className: "text-sm font-semibold text-brand-dark", children: "AI app context connections" }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-slate-600", children: "Use Guard's MCP server in your app, then match the connection code from get_context_status before granting access. Pairing authenticates that MCP process; the app label is your permission choice. A running runtime alone grants no app access." }),
    !allowed ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-slate-600", children: "Enable Context for AI apps, save settings and start a verified runtime to pair a connection." }) : /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
      error || statusError ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "alert", className: "text-sm text-red-700", children: error ?? statusError }) : null,
      /* @__PURE__ */ jsxRuntimeExports.jsx("button", { className: button$3, type: "button", disabled: busy, onClick: () => {
        setError(null);
        void refresh();
      }, children: "Refresh app connections" }),
      sessions.length === 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-slate-600", children: "No context connection is waiting or paired." }) : sessions.map((session) => /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "space-y-2 border-t border-slate-100 pt-3", "aria-label": `Context connection ${session.session_id}`, children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "break-all font-mono text-xs text-slate-600", children: [
          "Connection code: ",
          session.session_id
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "text-sm text-slate-600", children: [
          session.phase === "pending" ? "Waiting for your permission" : "Grant assigned",
          " · expires in ",
          Math.ceil(session.expires_in_seconds / 60),
          " minutes."
        ] }),
        session.phase === "pending" ? /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block text-sm text-slate-600", children: [
            "Workspace and app grant",
            /* @__PURE__ */ jsxRuntimeExports.jsxs(
              "select",
              {
                className: "mt-1 min-h-11 w-full rounded-lg border border-slate-200 bg-white px-3 text-sm",
                disabled: busy || dirty,
                value: selected[session.session_id] ?? "",
                onChange: (event) => setSelected((values) => ({ ...values, [session.session_id]: event.target.value })),
                children: [
                  /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "", children: "Choose a grant" }),
                  scopes.filter((scope) => !scope.revoked && scope.app !== "dashboard").map((scope) => /* @__PURE__ */ jsxRuntimeExports.jsxs("option", { value: scope.scope_id, children: [
                    harnessDisplayName(scope.app),
                    " · ",
                    scope.workspace
                  ] }, scope.scope_id))
                ]
              }
            )
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("button", { className: button$3, type: "button", disabled: busy || dirty || !selected[session.session_id], onClick: () => {
            if (gate?.enabled) setConfirm(session);
            else void perform(session);
          }, children: "Authorize context connection" })
        ] }) : /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-slate-600", children: scopes.find((scope) => scope.scope_id === session.scope_id)?.workspace ?? "This grant is unavailable. Revoke it and pair again." }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("button", { className: button$3, type: "button", disabled: busy, onClick: () => void perform(session, void 0, true), children: "Revoke context connection" })
      ] }, session.session_id))
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      SettingsSaveProofModal,
      {
        open: confirm !== null,
        mode: "verify-save",
        gate,
        title: "Authorize AI app context",
        detail: `Grant connection ${confirm?.session_id ?? ""} access to ${confirmationScope ? `${harnessDisplayName(confirmationScope.app)} sources in ${confirmationScope.workspace}` : "the selected sources"} for this runtime session.${confirmationScope?.sharing?.mode === "shared_broker" ? ` Five-minute lease. Reviewed shared notes: ${confirmationScope.sharing.notes.read ? "allowed" : "not granted"}. Note proposals: ${confirmationScope.sharing.notes.propose ? "allowed, subject to your separate review" : "not granted"}.` : ""} This grants no command approval.`,
        confirmLabel: "Authorize connection",
        pending: busy,
        error,
        onCancel: () => {
          if (!busy) setConfirm(null);
        },
        onConfirm: (credentials) => {
          if (confirm) void perform(confirm, credentials);
        }
      }
    )
  ] });
}
const record = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
const id$4 = (value) => typeof value === "string" && /^[A-Za-z0-9_.:-]{1,128}$/.test(value);
const digest$1 = (value) => typeof value === "string" && /^[a-f0-9]{64}$/.test(value);
const count$2 = (value, max) => Number.isSafeInteger(value) && value >= 0 && value <= max;
const documents = (value) => Array.isArray(value) && value.length <= 32 && value.every((item) => record(item) && id$4(item.id) && item.id.startsWith("note:") && item.start_line === 1 && typeof item.text === "string" && item.text.length <= 16384) && value.reduce((total, item) => total + item.text.length, 0) <= 16384;
function invalid$4() {
  throw new ContextAssistanceApiError("proposal_payload_invalid", "Guard returned incompatible shared-note data. Refresh the proposal list.");
}
function common(value) {
  return record(value) && id$4(value.proposal_id) && (value.connection_id === null || id$4(value.connection_id) && value.connection_id.startsWith("agent:")) && ["pending", "admitted", "rejected"].includes(String(value.state)) && digest$1(value.basis_snapshot) && validContextBrokerRevision(value.expected) && record(value.basis) && Object.keys(value.basis).length <= 32 && Object.entries(value.basis).every(([source, revision]) => id$4(source) && validContextBrokerRevision(revision)) && value.data_role === true;
}
async function listContextProposals(scopeId, signal) {
  const result = await ask("workspace", { action: "proposals", scope_id: scopeId }, void 0, signal);
  const scope = parseContextScope(result.scope);
  const permitted = ["guard:policy", "guard:receipts", ...scope.sources.map((source) => source.source_id)];
  if (scope.scope_id !== scopeId || scope.sharing?.notes.read !== true || !Array.isArray(result.proposals) || result.proposals.length > 32 || !result.proposals.every((item) => common(item) && count$2(item.documents, 32) && count$2(item.bytes, 16384) && Object.keys(item.basis).every((source) => permitted.includes(source)))) invalid$4();
  return result.proposals;
}
async function loadContextProposal(scopeId, proposalId, signal) {
  const result = await ask("workspace", { action: "proposal", scope_id: scopeId, proposal_id: proposalId }, void 0, signal);
  const scope = parseContextScope(result.scope);
  const value = result.proposal;
  const permitted = ["guard:policy", "guard:receipts", ...scope.sources.map((source) => source.source_id)];
  if (scope.scope_id !== scopeId || scope.sharing?.notes.read !== true || !common(value) || value.proposal_id !== proposalId || !Object.keys(value.basis).every((source) => permitted.includes(source)) || value.approval_grant !== false || !["available", "unavailable"].includes(String(value.source_access)) || !(value.documents === null || documents(value.documents)) || !(value.current_documents === null || documents(value.current_documents)) || !(value.current_revision === null || validContextBrokerRevision(value.current_revision)) || value.source_access === "unavailable" && (value.documents !== null || value.current_documents !== null) || !Array.isArray(value.source_states) || value.source_states.length > 32 || !value.source_states.every((state) => record(state) && id$4(state.source_id) && typeof state.path === "string" && state.path.length <= 4096 && ["unchanged", "changed", "unavailable"].includes(String(state.state)) && (state.current_sha256 === null || digest$1(state.current_sha256)) && scope.sources.some((source) => source.source_id === state.source_id && source.path === state.path)) || new Set(value.source_states.map((state) => state.source_id)).size !== value.source_states.length || value.source_states.length !== scope.sources.filter((source) => Object.hasOwn(value.basis, source.source_id)).length) invalid$4();
  return value;
}
async function decideContextProposal(scopeId, proposalId, admit, proof, signal) {
  const result = await ask(admit ? "workspace-grant" : "workspace-access", {
    action: admit ? "admit_proposal" : "reject_proposal",
    scope_id: scopeId,
    proposal_id: proposalId
  }, proof, signal);
  if (result.proposal_id !== proposalId || result.state !== (admit ? "admitted" : "rejected") || result.data_role !== true || admit && (result.approval_grant !== false || !validContextBrokerRevision(result.revision))) invalid$4();
  return result;
}
async function clearContextNotes(scopeId, signal) {
  return ask("workspace-access", { action: "clear_notes", scope_id: scopeId }, void 0, signal);
}
const button$2 = "min-h-11 rounded-lg border border-slate-200 px-3 py-2 text-sm font-semibold text-brand-dark disabled:cursor-not-allowed disabled:opacity-50";
function ContextNotesPanel({ scope, disabled, gate, onChanged }) {
  const [proposals, setProposals] = reactExports.useState([]);
  const [detail, setDetail] = reactExports.useState(null);
  const [busy, setBusy] = reactExports.useState(false);
  const [error, setError] = reactExports.useState(null);
  const [proofOpen, setProofOpen] = reactExports.useState(false);
  const request = reactExports.useRef(null);
  const revision = reactExports.useRef(0);
  const identity = JSON.stringify([scope.scope_id, scope.policy_revision, scope.sources, scope.sharing?.notes.revision]);
  reactExports.useEffect(() => {
    const current = ++revision.current;
    request.current?.abort();
    const controller = new AbortController();
    request.current = controller;
    setProposals([]);
    setDetail(null);
    setError(null);
    setBusy(false);
    setProofOpen(false);
    void listContextProposals(scope.scope_id, controller.signal).then((values) => {
      if (current === revision.current) setProposals(values);
    }).catch((cause) => {
      if (current === revision.current && !controller.signal.aborted) setError(cause instanceof Error ? cause.message : "Shared notes are unavailable.");
    });
    return () => {
      revision.current += 1;
      controller.abort();
    };
  }, [identity, scope.scope_id]);
  async function perform(operation2) {
    if (busy || disabled) return;
    const current = ++revision.current;
    request.current?.abort();
    const controller = new AbortController();
    request.current = controller;
    setBusy(true);
    setError(null);
    try {
      await operation2(controller.signal);
    } catch (cause) {
      if (current === revision.current && !controller.signal.aborted) {
        setDetail(null);
        setProofOpen(false);
        setError(`${cause instanceof Error ? cause.message : "No confirmed result was returned."} Refresh proposals to check the recorded outcome before taking another action.`);
      }
    } finally {
      if (current === revision.current) setBusy(false);
    }
  }
  function refresh() {
    setDetail(null);
    setProofOpen(false);
    void perform(async (signal) => {
      const values = await listContextProposals(scope.scope_id, signal);
      if (!signal.aborted) setProposals(values);
    });
  }
  async function decide(admit, credentials) {
    if (!detail || detail.state !== "pending" || admit && !admittable) return;
    const id2 = detail.proposal_id;
    await perform(async (signal) => {
      await decideContextProposal(scope.scope_id, id2, admit, credentials, signal);
      if (signal.aborted) return;
      setProofOpen(false);
      setDetail(null);
      const values = await listContextProposals(scope.scope_id, signal);
      if (!signal.aborted) {
        setProposals(values);
        onChanged();
      }
    });
  }
  const admittable = detail?.source_access === "available" && detail.current_documents !== null && detail.source_states.every((source) => source.state === "unchanged");
  const previous = new Map(detail?.current_documents?.map((document2) => [document2.id, document2.text]));
  const changed = detail?.documents?.filter((document2) => previous.get(document2.id) !== document2.text) ?? [];
  const removed = detail?.current_documents?.filter((document2) => !detail.documents?.some((item) => item.id === document2.id)) ?? [];
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { "aria-label": "Reviewed shared notes", className: "space-y-3 rounded-lg border border-slate-200 p-3", "aria-busy": busy, children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("h5", { className: "text-sm font-semibold text-brand-dark", children: "Reviewed shared notes" }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "text-sm text-slate-600", children: [
      scope.sharing?.notes.documents ?? 0,
      " admitted notes. AI proposals remain quarantined until you admit them here. Shared notes are supporting data and grant no command approval."
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-500", children: "Connections expire after five minutes. Notes stay in memory for the configured retention period and are cleared when their source basis changes, access ends, or assistance stops." }),
    error ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "alert", className: "text-sm text-red-700", children: error }) : null,
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-2", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", className: button$2, disabled: busy || disabled, onClick: refresh, children: "Refresh proposals" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", className: button$2, disabled: busy || disabled, onClick: () => void perform(async (signal) => {
        await clearContextNotes(scope.scope_id, signal);
        if (!signal.aborted) {
          setDetail(null);
          setProposals([]);
          onChanged();
        }
      }), children: "Clear shared notes and proposals" })
    ] }),
    proposals.length === 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-slate-600", children: "No retained proposals. Text loads only when you open a proposal." }) : /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "space-y-2", children: proposals.map((proposal) => /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { className: "space-y-1 text-sm", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "break-all", children: [
        proposal.connection_id ?? "Expired connection",
        " · ",
        proposal.state,
        " · ",
        proposal.documents,
        " documents · ",
        proposal.bytes,
        " bytes"
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", className: button$2, disabled: busy || disabled, onClick: () => void perform(async (signal) => {
        const value = await loadContextProposal(scope.scope_id, proposal.proposal_id, signal);
        if (!signal.aborted) setDetail(value);
      }), children: [
        "Review ",
        proposal.proposal_id
      ] })
    ] }, proposal.proposal_id)) }),
    detail ? /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { "aria-label": "Shared note proposal", className: "space-y-3 border-t border-slate-200 pt-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("h6", { className: "break-all text-sm font-semibold", children: [
        "Proposal ",
        detail.proposal_id,
        " · ",
        detail.state
      ] }),
      detail.source_access === "unavailable" ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "status", className: "text-sm text-amber-800", children: "A required source cannot be read safely. Proposal text is withheld." }) : /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
        detail.current_documents === null ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "status", className: "text-sm text-amber-800", children: "Shared notes changed since this proposal was prepared. Inspect its text, then reject it or ask the connection to prepare a new proposal." }) : null,
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold", children: "Proposed changes" }),
        changed.length === 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-slate-600", children: "No added or changed note text." }) : changed.map((document2) => /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-2 text-sm", children: [
          previous.has(document2.id) ? /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "whitespace-pre-wrap break-words text-slate-500", children: [
            "Earlier: ",
            previous.get(document2.id)
          ] }) : null,
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "whitespace-pre-wrap break-words text-slate-700", children: document2.text })
        ] }, document2.id)),
        removed.map((document2) => /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "whitespace-pre-wrap break-words text-sm text-slate-500", children: [
          "Removed: ",
          document2.text
        ] }, document2.id)),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("details", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("summary", { className: "cursor-pointer text-sm font-semibold", children: "All proposed note text" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "max-h-64 space-y-3 overflow-auto text-sm", children: detail.documents?.map((document2) => /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "whitespace-pre-wrap break-words", children: document2.text }, document2.id)) })
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "space-y-1 text-sm text-slate-600", children: detail.source_states.map((source) => /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { className: "break-all", children: [
        source.path,
        ": ",
        source.state
      ] }, source.source_id)) }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "break-all text-xs text-slate-500", children: [
        "Basis snapshot: ",
        detail.basis_snapshot,
        ". Expected notes revision: ",
        detail.expected.version,
        "."
      ] }),
      detail.state === "pending" ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", className: button$2, disabled: busy || disabled || !admittable, onClick: () => {
          if (gate?.enabled) setProofOpen(true);
          else void decide(true);
        }, children: "Admit shared note" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", className: button$2, disabled: busy || disabled, onClick: () => void decide(false), children: "Reject proposal" }),
        !admittable ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-amber-800", children: "Admission needs unchanged, safely readable sources and the current notes revision." }) : null
      ] }) : null
    ] }) : null,
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      SettingsSaveProofModal,
      {
        open: proofOpen,
        mode: "verify-save",
        gate,
        title: "Confirm shared note admission",
        detail: "Admit the displayed proposal as supporting evidence for this app and workspace. This grants no command approval.",
        confirmLabel: "Admit shared note",
        pending: busy,
        error,
        onCancel: () => {
          if (!busy) setProofOpen(false);
        },
        onConfirm: (credentials) => void decide(true, credentials)
      }
    )
  ] });
}
const button$1 = "min-h-11 rounded-lg border border-slate-200 px-3 py-2 text-sm font-semibold text-brand-dark disabled:cursor-not-allowed disabled:opacity-50";
const field = "mt-1 min-h-11 w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm text-brand-dark";
function ContextWorkspacesPanel({ ready, generation, dirty, documentsAllowed, agentsAllowed, sharingAllowed = false, executionAllowed = false, gate }) {
  const [scopes, setScopes] = reactExports.useState([]);
  const [workspace, setWorkspace] = reactExports.useState("");
  const [paths, setPaths] = reactExports.useState("");
  const [app, setApp] = reactExports.useState("dashboard");
  const [notesRead, setNotesRead] = reactExports.useState(false);
  const [notesPropose, setNotesPropose] = reactExports.useState(false);
  const [query, setQuery] = reactExports.useState("");
  const [brief, setBrief] = reactExports.useState(null);
  const [previous, setPrevious] = reactExports.useState(null);
  const [busy, setBusy] = reactExports.useState(false);
  const [error, setError] = reactExports.useState(null);
  const [proofOpen, setProofOpen] = reactExports.useState(false);
  const request = reactExports.useRef(null);
  const revision = reactExports.useRef(0);
  const id2 = reactExports.useId();
  reactExports.useEffect(() => {
    if (!agentsAllowed && !executionAllowed) setApp("dashboard");
  }, [agentsAllowed, executionAllowed]);
  reactExports.useEffect(() => {
    const generation2 = ++revision.current;
    request.current?.abort();
    setScopes([]);
    setBrief(null);
    setPrevious(null);
    setProofOpen(false);
    setBusy(false);
    setError(null);
    if (!ready) return;
    const controller = new AbortController();
    request.current = controller;
    void listContextWorkspaces(controller.signal).then((values) => {
      if (revision.current === generation2) setScopes(values);
    }).catch((cause) => {
      if (revision.current === generation2 && !controller.signal.aborted) setError(cause instanceof Error ? cause.message : "Context access is unavailable.");
    });
    return () => {
      revision.current += 1;
      controller.abort();
    };
  }, [ready, generation]);
  async function perform(operation2) {
    if (busy || !ready) return;
    const generation2 = ++revision.current;
    request.current?.abort();
    const controller = new AbortController();
    request.current = controller;
    setBusy(true);
    setError(null);
    try {
      await operation2(controller.signal);
    } catch (cause) {
      if (revision.current === generation2 && !controller.signal.aborted) {
        if (brief) setPrevious(brief.value);
        setBrief(null);
        setError(cause instanceof Error ? cause.message : "Context did not return a verified result.");
      }
    } finally {
      if (revision.current === generation2) setBusy(false);
    }
  }
  async function grant(credentials) {
    await perform(async (signal) => {
      const selected = paths.split(/\r?\n/).map((path) => path.trim()).filter(Boolean);
      const scope = await grantContextWorkspace(
        workspace.trim(),
        selected,
        credentials,
        signal,
        app,
        sharingAllowed && app !== "dashboard" ? { read: notesRead, propose: notesPropose } : void 0
      );
      if (signal.aborted) return;
      setScopes((values) => [...values, scope]);
      setProofOpen(false);
      setPaths("");
    });
  }
  function manage(action, scopeId, sourceId) {
    void perform(async (signal) => {
      if (action === "refresh") {
        if (brief) setPrevious(brief.value);
      } else setPrevious(null);
      setBrief(null);
      await manageContextWorkspace(action, scopeId, sourceId, signal);
      const values = await listContextWorkspaces(signal);
      if (!signal.aborted) setScopes(values);
      if (action === "revoke" || action === "clear" || action === "withdraw") setPrevious(null);
    });
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(SettingsFormSection, { title: "Workspace context access", description: "Choose each workspace and file used for local review context. Source access ends when you turn assistance off.", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "space-y-4 py-4", "aria-busy": busy, children: !ready ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-slate-600", children: "Start a verified context runtime to manage sources. Existing Guard approvals remain available." }) : /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
      error ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "alert", className: "text-sm text-red-700", children: error }) : null,
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-slate-600", children: "Context uses the native Guard facts you enable and files you select. Environment files, credential stores, detected secrets and unsafe paths are excluded. Guard stores context locally using your Evidence storage preference." }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("fieldset", { disabled: busy || dirty, className: "grid gap-3", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("legend", { className: "text-sm font-semibold text-brand-dark", children: "Add review sources" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { htmlFor: `${id2}-app`, className: "text-sm text-slate-600", children: [
          "Context consumer",
          /* @__PURE__ */ jsxRuntimeExports.jsxs("select", { id: `${id2}-app`, className: field, value: app, onChange: (event) => setApp(event.target.value), children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "dashboard", children: "Guard dashboard" }),
            agentsAllowed ? ["codex", "claude-code", "cursor"].map((name) => /* @__PURE__ */ jsxRuntimeExports.jsxs("option", { value: name, children: [
              harnessDisplayName(name),
              " · paired MCP connection"
            ] }, name)) : null,
            executionAllowed ? ["pi", "omp"].map((name) => /* @__PURE__ */ jsxRuntimeExports.jsxs("option", { value: name, children: [
              harnessDisplayName(name),
              " · native captured-Bash executor"
            ] }, name)) : null
          ] })
        ] }),
        executionAllowed ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-slate-600", children: "Execution associations apply to Pi and Oh My Pi through Guard's native captured-Bash executor on macOS. Granting access does not install an app adapter." }) : null,
        sharingAllowed && app !== "dashboard" ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-2 text-sm text-slate-600", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "flex min-h-11 items-center gap-3", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(
              "input",
              {
                type: "checkbox",
                checked: notesRead,
                onChange: (event) => {
                  setNotesRead(event.target.checked);
                  if (!event.target.checked) setNotesPropose(false);
                }
              }
            ),
            "Allow reviewed shared notes in this app's context"
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "flex min-h-11 items-center gap-3", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(
              "input",
              {
                type: "checkbox",
                checked: notesPropose,
                disabled: !notesRead,
                onChange: (event) => setNotesPropose(event.target.checked)
              }
            ),
            "Allow paired connections to propose shared notes"
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "Proposals require a current context snapshot and your separate review. Pair each connection after granting access. Connections expire after five minutes." })
        ] }) : null,
        /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { htmlFor: `${id2}-workspace`, className: "text-sm text-slate-600", children: [
          "Workspace folder",
          /* @__PURE__ */ jsxRuntimeExports.jsx("input", { id: `${id2}-workspace`, className: field, value: workspace, onChange: (event) => setWorkspace(event.target.value), placeholder: "Absolute workspace path", autoComplete: "off" })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { htmlFor: `${id2}-sources`, className: "text-sm text-slate-600", children: [
          "Files relative to the workspace, one per line",
          /* @__PURE__ */ jsxRuntimeExports.jsx("textarea", { id: `${id2}-sources`, className: field, rows: 3, value: paths, onChange: (event) => setPaths(event.target.value), placeholder: "README.md\ndocs/design.md", disabled: !documentsAllowed })
        ] }),
        !documentsAllowed ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-slate-600", children: "Enable selected workspace documents in Context assistance and save settings to add files. You can still use native Guard facts." }) : null,
        dirty ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "status", className: "text-sm text-slate-600", children: "Save your context preferences before granting access." }) : null,
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "button",
          {
            className: button$1,
            type: "button",
            disabled: !workspace.trim() || paths.split(/\r?\n/).filter((path) => path.trim()).length > 32,
            onClick: () => {
              if (gate?.enabled) setProofOpen(true);
              else void grant();
            },
            children: "Grant review source access"
          }
        )
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("button", { className: button$1, type: "button", disabled: busy, onClick: () => void perform(async (signal) => {
          const values = await listContextWorkspaces(signal);
          if (!signal.aborted) setScopes(values);
        }), children: "Refresh context access" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("button", { className: button$1, type: "button", disabled: busy || scopes.length === 0, onClick: () => manage("clear"), children: "Clear all context data" })
      ] }),
      scopes.length === 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-slate-600", children: "No workspace has context access." }) : /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { htmlFor: `${id2}-query`, className: "block text-sm text-slate-600", children: [
          "What would you like context about?",
          /* @__PURE__ */ jsxRuntimeExports.jsx("input", { id: `${id2}-query`, className: field, maxLength: 4096, value: query, onChange: (event) => setQuery(event.target.value) })
        ] }),
        scopes.map((scope) => /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "space-y-3 rounded-lg border border-slate-200 p-3", "aria-label": `Context access for ${scope.workspace}`, children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "break-all text-sm font-semibold text-brand-dark", children: scope.workspace }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-slate-600", children: scope.revoked ? "Access revoked by policy. Grant access again to continue." : `${scope.app === "dashboard" ? "Review context" : harnessDisplayName(scope.app)} · local memory` }),
          scope.native_policy_facts ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-slate-600", children: "Includes native Guard policy and decision facts." }) : null,
          scope.sharing?.mode === "shared_broker" ? /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "text-sm text-slate-600", children: [
            "Shared context · ",
            scope.sharing.notes.read ? "reviewed notes allowed" : "shared notes not granted",
            scope.sharing.notes.propose ? " · connection proposals allowed" : "",
            ". Each paired connection has a five-minute lease."
          ] }) : null,
          scope.receipt_window?.enabled ? /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "text-sm text-slate-600", children: [
            "Recent native receipt facts: ",
            scope.receipt_window.retained,
            " of at most 16 retained. This window covers recorded decisions in this exact workspace, not execution confirmation or a complete activity history."
          ] }) : null,
          scope.receipt_window?.enabled && scope.receipt_window.dropped !== "0" ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "status", className: "text-sm text-amber-800", children: "Some optional receipt updates were missed. Earlier context was invalidated; durable Guard evidence is unchanged." }) : null,
          /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "space-y-2", children: scope.sources.map((source) => /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { className: "flex flex-wrap items-center justify-between gap-2 text-sm", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "break-all", children: source.path }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { className: button$1, type: "button", disabled: busy, onClick: () => manage("withdraw", scope.scope_id, source.source_id), children: [
              "Withdraw ",
              source.path
            ] })
          ] }, source.source_id)) }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-2", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("button", { className: button$1, type: "button", disabled: busy || dirty || scope.revoked, onClick: () => void perform(async (signal) => {
              const value = await compileWorkspaceContext(scope.scope_id, query, signal);
              if (!signal.aborted) {
                if (brief) setPrevious(brief.value);
                const current = value.scope ?? scope;
                setBrief({ scope: current, value: value.brief });
                setScopes((values) => values.map((item) => item.scope_id === current.scope_id ? current : item));
              }
            }), children: "Prepare cited context" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("button", { className: button$1, type: "button", disabled: busy || scope.revoked, onClick: () => manage("refresh", scope.scope_id), children: "Refresh selected files" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("button", { className: button$1, type: "button", disabled: busy, onClick: () => manage("revoke", scope.scope_id), children: "Revoke workspace access" })
          ] }),
          !scope.revoked && scope.sharing?.mode === "shared_broker" && scope.sharing.notes.read ? /* @__PURE__ */ jsxRuntimeExports.jsx(
            ContextNotesPanel,
            {
              scope,
              disabled: busy || dirty,
              gate,
              onChanged: () => {
                setBrief(null);
                setPrevious(null);
                void perform(async (signal) => {
                  const values = await listContextWorkspaces(signal);
                  if (!signal.aborted) setScopes(values);
                });
              }
            }
          ) : null
        ] }, scope.scope_id))
      ] }),
      brief ? /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { "aria-label": "Prepared context", className: "space-y-3 rounded-lg border border-slate-200 p-3", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h4", { className: "text-sm font-semibold text-brand-dark", children: "Cited context" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "text-sm text-slate-600", children: [
          "Supporting data verified when prepared. Use a fresh context after files or access change. ",
          brief.value.rendered_tokens,
          " tokens."
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "max-h-96 space-y-3 overflow-auto text-sm text-slate-700", children: brief.value.excerpts.map((excerpt, index) => /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "whitespace-pre-wrap break-words", children: excerpt.text }, index)) }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("details", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("summary", { className: "cursor-pointer text-sm font-semibold", children: "Sources and revisions" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "mt-2 space-y-2 text-sm", children: brief.value.citations.map((citation, index) => /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { children: [
            brief.scope.sources.find((source) => source.source_id === citation.source)?.path ?? (citation.source === "guard:notes" ? "Reviewed shared notes" : citation.source === "guard:receipts" ? "Native Guard receipt facts" : "Native Guard policy facts"),
            ", lines ",
            citation.start_line,
            "–",
            citation.end_line,
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "block break-all text-xs text-slate-500", children: citation.document_digest })
          ] }, `${citation.node_id}-${index}`)) })
        ] }),
        previous ? /* @__PURE__ */ jsxRuntimeExports.jsxs("details", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("summary", { className: "cursor-pointer text-sm font-semibold", children: "Compare with earlier context" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "my-2 text-sm text-slate-600", children: "Earlier context is historical and may no longer apply." }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "max-h-64 space-y-3 overflow-auto text-sm", children: previous.excerpts.map((excerpt, index) => /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "whitespace-pre-wrap break-words", children: excerpt.text }, index)) })
        ] }) : null
      ] }) : null
    ] }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(ContextAgentsPanel, { ready, enabled: agentsAllowed, dirty, generation, scopes, gate }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      SettingsSaveProofModal,
      {
        open: proofOpen,
        mode: "verify-save",
        gate,
        title: "Confirm source access",
        detail: `Grant ${app === "dashboard" ? "Guard dashboard" : harnessDisplayName(app)} context access for ${workspace.trim()}. Allow the enabled native Guard facts and ${paths.split(/\r?\n/).filter((path) => path.trim()).length} selected workspace files.${executionAllowed && (app === "pi" || app === "omp") ? " Execution associations use native capture facts. This does not approve commands or install an app adapter." : ""}${sharingAllowed && app !== "dashboard" ? ` Reviewed shared notes: ${notesRead ? "allowed" : "not granted"}. Connection note proposals: ${notesPropose ? "allowed, subject to your separate review" : "not granted"}.` : ""}`,
        confirmLabel: "Grant source access",
        error,
        pending: busy,
        onCancel: () => {
          if (!busy) setProofOpen(false);
        },
        onConfirm: (credentials) => void grant(credentials)
      }
    )
  ] });
}
const CIGAR_UPDATE_TUTORIAL = {
  id: "cigar-updates",
  title: "Update CIGAR with less interruption",
  level: "Runtime maintenance",
  description: "Prepare a replacement beside the current build and choose when to switch.",
  outcome: "A verified selection, an understood reconnect boundary, and a path to the last good build.",
  steps: [
    {
      title: "Read the available builds",
      description: "Opening Versions & updates reads metadata without starting Python or CIGAR.",
      instructions: ["Check the Guard host, catalog freshness and build ID. Different builds can have the same version label.", "A withdrawn, expired or upstream-only artifact is unavailable for preparation. A new Guard release does not qualify an SDK automatically.", "Use Check for catalog updates only when a trusted feed is configured, or import a catalog signed by an already trusted key."],
      expect: "You can identify the exact build and whether this Guard host has a qualified artifact.",
      target: "versions",
      action: "Inspect versions & updates"
    },
    {
      title: "Prepare beside your current runtime",
      description: "Downloading and verifying a replacement does not select or enable it.",
      instructions: ["Choose a registered Python interpreter for an available SDK build, or explicitly prepare an eligible private Python build first.", "Click Prepare this build and watch its native job. The current runtime remains selected while preparation runs.", "Cancel the job if you change your mind. For an uncertain response, refresh jobs and inspect the recorded job ID before another action."],
      expect: "The prepared installation appears in Registered installations, with your current selection intact.",
      target: "versions",
      action: "Prepare an eligible build"
    },
    {
      title: "Prepare the selection",
      description: "Guard checks the target and compatible data before offering a commit.",
      instructions: ["Save any pending CIGAR preference edits, then click Prepare selection beside the target installation.", "Wait for that selection job to become ready. Its preparation can be cancelled without choosing the target.", "If Guard requires a saved-data choice or recovery, follow the diagnostic. Do not clear data just to bypass a refusal."],
      expect: "A current native selection job offers Switch now, or Select & keep CIGAR off.",
      target: "versions",
      action: "Review selection readiness"
    },
    {
      title: "Choose the switch boundary",
      description: "A live switch briefly pauses CIGAR and ends existing context authority.",
      instructions: ["For a live runtime, finish current context work and acknowledge that sources and app connections will need fresh access.", "Click Switch now and provide Guard's settings proof when required. Refresh jobs if the response is uncertain; the browser never retries the change automatically.", "If CIGAR is off, Select & keep CIGAR off commits only the selection. It does not turn CIGAR on."],
      expect: "The selected runtime changes only after your explicit commit. Your Guard command approvals remain available.",
      target: "versions",
      action: "Review the explicit switch"
    },
    {
      title: "Reconnect the scopes you need",
      description: "Saved evidence does not restore source or app permission.",
      instructions: ["If you selected while off, return to Runtime & preferences, choose your enabled preference, save and explicitly start CIGAR.", "Use the live runtime status to confirm readiness before granting workspace access.", "Grant only the intended workspace sources and pair the current app connection again when needed."],
      expect: "Your intended sources and apps have fresh access to the selected runtime.",
      target: "access",
      action: "Review sources & AI apps"
    },
    {
      title: "Use the last good build deliberately",
      description: "Rollback prepares current compatible data for the previous verified installation.",
      instructions: ["In Versions & updates, choose Prepare last good build when you need to return to the retained installation.", "Wait for the rollback selection job, then commit it explicitly with the same reconnect acknowledgement when live.", "Use Recover job for interrupted work. Recovery does not re-grant context access. Your Guard approvals remain in place."],
      expect: "You know where to inspect a rollback or interrupted job before taking another action.",
      target: "versions",
      action: "Inspect rollback & recovery"
    }
  ]
};
const CIGAR_FULL_NAME = "Context Intelligence Graph Agentic Runtime";
const CIGAR_TUTORIALS = [
  {
    id: "first-brief",
    title: "Prepare your first cited brief",
    level: "Start here",
    description: "Go from a running runtime to useful evidence for one workspace.",
    outcome: "A context brief whose sources and revisions you can inspect.",
    steps: [
      {
        title: "Start your saved runtime",
        description: "Ready means the selected Python, CIGAR package, and worker passed Guard's checks.",
        instructions: ["If no runtime is selected, use Versions & updates to prepare and select a registered installation while CIGAR stays off. Then return to Runtime & preferences and turn on Use CIGAR on this machine.", "Keep Review briefs on. Smaller context and Memory only are useful starting choices for a single workspace.", "Save CIGAR preferences, then click Start CIGAR at the top. Wait for the live status to say Ready."],
        expect: "The live status says Ready. Saving alone shows Not started.",
        target: "runtime",
        action: "Open runtime & preferences",
        tip: "Final CPython 3.14 is required for CIGAR. Guard itself can use another supported Python version."
      },
      {
        title: "Choose a small evidence set",
        description: "Pick the sources that can answer your question before granting workspace access.",
        instructions: ["Open Sources, limits and runtime details in Runtime & preferences. Native policy and decision facts can be used without adding project files.", "For project documentation, turn on Allow selected workspace documents. Plan to start with one or two relevant files, such as README.md and a release guide that exists in your project.", "Save changes and start CIGAR again if its status returns to Not started. Changing preferences can end existing context access."],
        expect: "Your intended source preferences are saved and the runtime is Ready.",
        target: "runtime",
        action: "Choose source preferences",
        tip: "A document preference allows you to choose files later. It does not grant access to the whole workspace."
      },
      {
        title: "Grant one workspace access",
        description: "A grant connects a workspace and a consumer to the evidence you explicitly select.",
        instructions: ["In Sources & AI apps, choose Guard dashboard as the Context consumer.", "Enter the absolute Workspace folder. Add individual files relative to that folder, one per line, if document context is enabled. Leave the file list empty for native facts only.", "Click Grant review source access. Confirm the exact workspace, consumer, and sources when Guard asks for approval proof."],
        expect: "A Context access section appears for your chosen workspace.",
        target: "access",
        action: "Open sources & AI apps",
        tip: "Choose only relevant sources. Environment files and credential stores are not valid context sources."
      },
      {
        title: "Ask one concrete question",
        description: "Tell CIGAR what evidence you need for the task in front of you.",
        instructions: ["Fill What would you like context about? with one focused question.", "For native facts only, try the example below. If you granted project docs, ask about a specific documented workflow, file, or rule.", "Click Prepare cited context in the section for the workspace you want to use."],
        expect: "Prepared context contains excerpts and citations. If relevant evidence is missing, refine the question or select better sources.",
        target: "access",
        action: "Prepare context in your workspace",
        question: "Which native Guard policy and decision facts apply to this workspace?",
        tip: "The brief is evidence prepared for your question. Your review or authorized AI app can use that evidence to reason about the task."
      },
      {
        title: "Read the evidence behind it",
        description: "Use the citations to decide whether the brief supports your task.",
        instructions: ["Read the excerpts in Prepared context, then open Sources and revisions.", "Check the source names, line ranges, and document revisions. A citation identifies the evidence checked when the brief was prepared.", "For a pending command in Inbox, request its context brief when available, inspect the evidence, and make your Guard approval decision separately."],
        expect: "You can trace a useful statement back to its admitted source. A brief never grants command permission.",
        target: "access",
        action: "Inspect your prepared context"
      },
      {
        title: "Keep context current",
        description: "Fresh sources make the next brief useful as your work changes.",
        instructions: ["After editing a selected document, click Refresh selected files, then Prepare cited context again.", "Use Withdraw beside a file or Revoke workspace access when it is no longer needed.", "Stopping or restarting the runtime ends active access. Grant the workspace again when needed; saved evidence never restores permission."],
        expect: "You know how to prepare a fresh brief and remove its source access.",
        target: "access",
        action: "Review workspace access",
        tip: "Use Data & privacy to inspect or remove saved evidence. Memory is the default and ends with the runtime."
      }
    ]
  },
  {
    id: "ai-apps",
    title: "Give an AI app scoped context",
    level: "After your first brief",
    description: "Choose sources for an app, match its real connection code, and pair it explicitly.",
    outcome: "One authorized Guard MCP connection with access to a chosen workspace.",
    steps: [
      {
        title: "Enable app context deliberately",
        description: "App access is a separate feature choice from review briefs.",
        instructions: ["In Runtime & preferences, enable Context for AI apps. Choose source preferences before granting access.", "Keep Share context between paired AI connections off while you try a single connection.", "Save preferences and click Start CIGAR if needed. Confirm the live status is Ready."],
        expect: "Context for AI apps is saved and the runtime is Ready.",
        target: "runtime",
        action: "Choose AI app preferences"
      },
      {
        title: "Grant sources for that app",
        description: "A dashboard grant and an app grant have different consumers.",
        instructions: ["In Sources & AI apps, choose your app in Context consumer: Codex, Claude Code, or Cursor.", "Choose the workspace and individual source files it needs. Enable document context first if you want to add files.", "Click Grant review source access and review the app and workspace in the confirmation."],
        expect: "A workspace grant names the app you chose.",
        target: "access",
        action: "Choose the app's sources"
      },
      {
        title: "Identify the real connection",
        description: "Use the local Guard MCP server configured in your app.",
        instructions: ["In the app's Guard MCP connection, request get_context_status to obtain its pending connection code.", "Return to AI app context connections and click Refresh app connections.", "Match the displayed Connection code to the one from that app's actual process."],
        expect: "The same code appears in your app and the pending connection shown here.",
        target: "access",
        action: "Find the pending connection",
        tip: "This screen does not install an app connection. Choosing an app label is a permission choice; matching the real code identifies the connection you are authorizing."
      },
      {
        title: "Authorize one connection",
        description: "Pair the verified connection with the workspace grant you intended.",
        instructions: ["Under the matched connection, choose its Workspace and app grant.", "Click Authorize context connection and confirm the connection code, app, and workspace when prompted.", "Look for Grant assigned. A running runtime alone does not grant app access."],
        expect: "The intended connection shows Grant assigned for the chosen workspace.",
        target: "access",
        action: "Authorize the matched connection",
        tip: "Connections have short leases. If one expires or the runtime restarts, reconnect and pair its current code."
      },
      {
        title: "Ask the app to use its context",
        description: "Make evidence use part of a focused task request.",
        instructions: ["Ask the authorized app to request Guard context for a specific workspace task, using the example below as a starting point.", "Check the app's cited sources and ask it to identify missing evidence rather than assume an answer.", "Use Revoke context connection when you are finished. Add sharing only when you need it, with separate reviewed-note permissions."],
        expect: "The app can request context within its grant. Missing access or evidence is reported explicitly.",
        target: "access",
        action: "Review app access",
        question: "Use your Guard context tools for this workspace to explain the relevant project rules. Cite the evidence you receive and identify anything the available context does not establish."
      }
    ]
  },
  {
    id: "execution",
    title: "Understand execution context",
    level: "Advanced · supported routes only",
    description: "Learn the optional native preparation path for Pi and Oh My Pi captured-Bash actions.",
    outcome: "An understanding of the route requirements and how to inspect an execution-context observation.",
    steps: [
      {
        title: "Check the route first",
        description: "Execution context has a narrower scope than general review briefs.",
        instructions: ["Use an existing supported native captured-Bash route for Pi or Oh My Pi on macOS.", "Check the execution capability and Native execution context panel in Runtime & preferences.", "This candidate has local native preparation checks. Full delivery from external apps has not yet been qualified."],
        expect: "You know whether the preparation route is available in this build.",
        target: "runtime",
        action: "Inspect execution availability",
        tip: "You can read this walkthrough even when the route is unavailable. Review briefs and paired app context have their own controls."
      },
      {
        title: "Choose the execution preference",
        description: "Execution associations use native capture and policy facts.",
        instructions: ["Open Sources, limits and runtime details. Enable Native policy and decision facts.", "If the build offers it, enable Associate native context with execution.", "Save and start CIGAR. Inspect the Native execution context panel for preparation readiness."],
        expect: "The panel reports the current native preparation state.",
        target: "runtime",
        action: "Review execution preferences"
      },
      {
        title: "Scope the executor's workspace",
        description: "Choose the app and workspace for the native route you use.",
        instructions: ["In Sources & AI apps, choose Pi or Oh My Pi as Context consumer when offered.", "Enter the workspace, review its native facts and any separately selected documents, and grant only that scope.", "A workspace grant does not install an app adapter or approve a command."],
        expect: "The workspace grant names the intended executor consumer.",
        target: "access",
        action: "Inspect executor workspace access"
      },
      {
        title: "Inspect the native observation",
        description: "Keep the command decision in Guard's normal approval flow.",
        instructions: ["Use your existing supported app route. Inspect its Guard review and choose the approval scope you intend, such as Run once or Always allow this version in this project.", "Return to Native execution context observations to inspect whether preparation or association was recorded.", "For an uncertain outcome, consult Guard's native execution record before retrying."],
        expect: "You can distinguish context preparation, a dispatch acknowledgement, and a native execution record.",
        target: "runtime",
        action: "Open execution observations",
        tip: "Context is supporting information. Guard owns command authorization and the execution record."
      }
    ]
  },
  CIGAR_UPDATE_TUTORIAL
];
function cigarTutorial(id2) {
  return CIGAR_TUTORIALS.find((tutorial) => tutorial.id === id2) ?? CIGAR_TUTORIALS[0];
}
const flow = [
  {
    icon: HiMiniDocumentText,
    title: "Choose the sources",
    detail: "Start with evidence you have deliberately admitted.",
    explanation: "Guard admits the enabled native facts, sanitized receipt facts, and individual workspace documents you authorize before they reach CIGAR.",
    points: ["A workspace grant names its consumer and selected sources.", "Document preferences and source grants are separate choices.", "Starting a runtime grants no files, app connections, or command permissions."]
  },
  {
    icon: HiMiniCircleStack,
    title: "Build a scoped graph",
    detail: "Keep reusable context bounded to a workspace and its access.",
    explanation: "CIGAR's graph holds admitted source material and facts. Guard gives each workspace and consumer a bounded view of the evidence it may use, and the running runtime can reuse that graph for later questions.",
    points: ["A graph is an organized context store; it is not permission to read more files.", "Different workspaces and app grants retain their own scope.", "Source or policy changes can invalidate an earlier view or prepared brief."]
  },
  {
    icon: HiMiniSquares2X2,
    title: "Compile a cited brief",
    detail: "Prepare evidence for a concrete question within your budget.",
    explanation: "Your question and allowed sources guide context preparation. The result contains selected excerpts and citations, bounded by the context limits you choose.",
    points: ["Sources and revisions identifies source names, line ranges, and document revisions.", "A smaller budget limits the context prepared here; it does not change an AI model's own context window.", "Missing evidence calls for a better source or question. Increasing a budget cannot add facts that were never admitted."]
  },
  {
    icon: HiMiniShieldCheck,
    title: "Use it with Guard and apps",
    detail: "Bring the evidence to a review, an authorized app, or a supported native route.",
    explanation: "Read a cited brief in the dashboard, let a paired Guard MCP connection request scoped context, or use optional execution associations on a supported native route.",
    points: ["Guard makes and enforces command decisions and approvals.", "Each app connection needs its own explicit workspace access.", "Shared notes and saved evidence are separate opt-ins. Neither restores an expired permission."]
  }
];
function CigarGuide({ onSelect }) {
  const [active, setActive] = reactExports.useState(0);
  const id2 = reactExports.useId();
  const stage = flow[active];
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "cigar-guide", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "cigar-card", "aria-labelledby": "cigar-explained-heading", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "cigar-eyebrow", children: "Meet CIGAR" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "cigar-explained-heading", children: CIGAR_FULL_NAME }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { children: "CIGAR" }),
        " prepares reusable, scoped evidence for Guard and the AI apps you authorize. Think of it as the context layer behind a task: you choose what it can use, ask a focused question, and inspect the sources behind the prepared brief."
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", className: "cigar-text-button", onClick: () => onSelect("tutorials"), children: [
        "Try a guided walkthrough",
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowRight, { "aria-hidden": "true" })
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "cigar-card", "aria-labelledby": "cigar-flow-heading", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "cigar-section-heading", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "cigar-eyebrow", children: "How it works" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "cigar-flow-heading", children: "From your sources to a better informed action" })
      ] }) }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "cigar-section-description", children: "Select a stage to explore this conceptual flow. These examples explain the process; they do not represent a graph or source grant from your workspace." }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("ol", { className: "cigar-concept-flow", children: flow.map(({ icon: Icon, title, detail }, index) => /* @__PURE__ */ jsxRuntimeExports.jsx("li", { children: /* @__PURE__ */ jsxRuntimeExports.jsxs(
        "button",
        {
          type: "button",
          id: id2 + "-stage-" + index,
          "aria-expanded": active === index,
          "aria-controls": id2 + "-detail",
          onClick: () => setActive(index),
          title: detail,
          children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "cigar-icon", children: /* @__PURE__ */ jsxRuntimeExports.jsx(Icon, { "aria-hidden": "true" }) }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "cigar-eyebrow", children: [
              "Stage ",
              index + 1
            ] }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { children: title })
          ]
        }
      ) }, title)) }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "cigar-concept-detail", id: id2 + "-detail", role: "region", "aria-labelledby": id2 + "-stage-" + active, children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { children: stage.title }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: stage.explanation }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "cigar-simple-list", children: stage.points.map((point) => /* @__PURE__ */ jsxRuntimeExports.jsx("li", { children: point }, point)) })
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "cigar-overview-grid", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "cigar-card", "aria-labelledby": "cigar-runtime-guide-heading", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "cigar-eyebrow", children: "Runtime setup" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "cigar-runtime-guide-heading", children: "Python installed? Here is what comes next." }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "Final CPython 3.14 is required for the selected CIGAR runtime. Python 3.14.7 qualifies. Guard itself can use another supported Python version." }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "A registered runtime includes the CIGAR package and its matching worker as well as Python. Guard checks their identities and runs a compilation check before activation." }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "cigar-note", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { children: "An empty list means no bundle is registered." }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "It does not establish which Python versions are installed. Refreshing the list reads registrations; it does not scan your machine or install packages." })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "Use Versions & updates to inspect registered installations and catalog builds. Preparation requires a qualified artifact for this Guard host; a listed upstream release alone does not authorize installation." }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", className: "cigar-text-button", onClick: () => onSelect("versions"), children: [
          "Choose a runtime in Versions & updates",
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowRight, { "aria-hidden": "true" })
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "cigar-card", "aria-labelledby": "cigar-first-use-heading", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "cigar-eyebrow", children: "Try it first" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "cigar-first-use-heading", children: "Start with one workspace." }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("ol", { className: "cigar-simple-list", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("li", { children: "Prepare and select a runtime in Versions & updates. Then enable review briefs in Runtime & preferences, save, and start CIGAR." }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("li", { children: "Open Sources & AI apps and grant context access for one workspace. Add individual files only if you want document context." }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("li", { children: "For an available Guard review, request its context brief and inspect the cited evidence." }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("li", { children: "When you want app context, enable that feature, save, and explicitly authorize a paired connection." })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "cigar-caption", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCheckCircle, { "aria-hidden": "true" }),
          "You can keep app sharing and saved evidence off while trying review briefs."
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", className: "cigar-text-button", onClick: () => onSelect("access"), children: [
          "Open sources & AI apps",
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowRight, { "aria-hidden": "true" })
        ] })
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "cigar-card", "aria-labelledby": "cigar-tuning-heading", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "cigar-eyebrow", children: "Build a useful habit" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "cigar-tuning-heading", children: "Start focused, then adjust what you need" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "cigar-effective-grid", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("article", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { children: "Use a small source set" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "Choose documents that describe the task, such as the project's release guide. Keep unrelated files out of the grant and add sources when evidence is missing." })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("article", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { children: "Tune the context size" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "Smaller context is a useful starting point for one workspace. Balanced allows more workspace capacity and a longer idle interval. These are resource preferences, not measured savings." })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("article", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { children: "Choose storage deliberately" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "Memory ends with the runtime. Optional saved evidence can outlive it, has retention controls, and uses private local files without Guard encryption. Restored evidence still needs fresh access grants." })
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", className: "cigar-text-button", onClick: () => onSelect("runtime"), children: [
        "Review context preferences",
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowRight, { "aria-hidden": "true" })
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "cigar-card cigar-faq", "aria-labelledby": "cigar-faq-heading", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "cigar-eyebrow", children: "Good to know" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "cigar-faq-heading", children: "Common questions" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("details", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("summary", { children: "Does turning on CIGAR give it access to all my files?" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "No. Workspace documents require the document preference and explicit access to selected sources. Starting a runtime grants no document access." })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("details", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("summary", { children: "What is the difference between saving and starting?" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "Saving records your preferences. Starting verifies and activates the selected runtime. A saved on preference can still be unavailable; use the live status to confirm Ready." })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("details", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("summary", { children: "Why did I get an empty or unhelpful brief?" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "Check that the intended workspace and consumer have a current grant, that the right files are selected, and that the question is specific. Native facts alone do not contain your project's release guide. Refresh selected files after edits and prepare context again." })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("details", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("summary", { children: "What should I do after a source or connection changes?" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "Refresh changed files and prepare a new brief. For a runtime restart, revoked workspace, or expired connection, grant or pair access again as appropriate. An earlier citation describes the evidence checked at preparation time." })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("details", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("summary", { children: "What happens when CIGAR is stopped or unavailable?" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "Guard continues protecting commands under its existing policy and approvals. Turn off CIGAR to cancel context work. Memory context and active access end when the runtime stops." })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("details", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("summary", { children: "Can two AI apps share context?" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "Sharing is a separate opt-in for supported paired connections in the same app and workspace. Each connection requires access, and shared notes require your review." })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("details", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("summary", { children: "What is saved on disk?" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "Memory is the default. Optional saved evidence uses private local SQLite files without Guard encryption and can outlive a runtime. Data & privacy provides retention, diagnostics, and removal controls. Restoring evidence never restores app access or approvals." })
      ] })
    ] })
  ] });
}
const CIGAR_TABS = [
  { value: "overview", label: "Overview" },
  { value: "runtime", label: "Runtime & preferences" },
  { value: "versions", label: "Versions & updates" },
  { value: "access", label: "Sources & AI apps" },
  { value: "data", label: "Data & privacy" },
  { value: "tutorials", label: "Tutorials" },
  { value: "guide", label: "How it works" }
];
function canStartCigar(status, dirty) {
  return !dirty && status !== null && status.requested_enabled && status.preferences.enabled && status.effective_preferences.enabled && status.verification_permitted && Boolean(status.preferences.runtime_id) && !status.effective_enabled && status.job === null;
}
function cigarTabFromSearch(search) {
  const value = new URLSearchParams(search).get("section");
  return CIGAR_TABS.find((tab) => tab.value === value)?.value ?? "overview";
}
function cigarSetupSteps(status, installations) {
  const registered = (installations?.length ?? 0) > 0 || status?.runtime !== null && status?.runtime !== void 0;
  const selected = Boolean(status?.preferences.runtime_id) && (installations?.some((item) => item.runtime_id === status?.preferences.runtime_id) === true || status?.runtime !== null && status?.runtime !== void 0);
  return [
    {
      title: "Connect a local runtime",
      description: registered ? "A registered CIGAR bundle with Python 3.14 is available on this machine." : "Register an approved CIGAR bundle that uses final CPython 3.14, then refresh the runtime list.",
      complete: registered,
      action: registered ? "View runtimes" : "Set up runtime",
      tab: "runtime"
    },
    {
      title: "Choose your preferences",
      description: "Select the runtime, turn on CIGAR, choose the features you want, and save your preferences.",
      complete: selected && status?.requested_enabled === true,
      action: "Choose preferences",
      tab: "runtime"
    },
    {
      title: "Start context assistance",
      description: "Start the saved runtime. Guard verifies Python, the CIGAR package, and its worker before reporting Ready.",
      complete: status?.effective_enabled === true,
      action: status?.effective_enabled ? "Manage runtime" : "Check & start",
      tab: "runtime"
    }
  ];
}
function cigarRuntimeSummary(status, installations) {
  if (status?.runtime && status.effective_enabled) return {
    label: "Python " + status.runtime.interpreter.version.join("."),
    detail: "CIGAR " + status.runtime.package_version + " · running locally"
  };
  const selected = installations?.find((item) => item.runtime_id === status?.preferences.runtime_id);
  if (selected) return {
    label: "Python " + selected.python_version.join("."),
    detail: "Selected · activation verifies this bundle again"
  };
  if (installations?.length) return {
    label: "Python " + installations[0].python_version.join("."),
    detail: installations.length === 1 ? "Registered · choose it to get started" : String(installations.length) + " registered runtimes · choose one"
  };
  return {
    label: installations === null ? "Runtime status pending" : "Runtime setup needed",
    detail: "Requires a registered CIGAR bundle with CPython 3.14"
  };
}
function CigarOverview({ status, installations, loading, onSelect }) {
  const steps = cigarSetupSteps(status, installations);
  const completed = steps.filter((step) => step.complete).length;
  const current = steps.findIndex((step) => !step.complete);
  const features = [
    { icon: HiMiniDocumentMagnifyingGlass, title: "Understand a review", description: "Read a cited brief from the context you allow before deciding what a command can do.", preference: status?.preferences.features.review_briefs },
    { icon: HiMiniLink, title: "Give AI apps useful context", description: "Pair an app with a workspace so it can request scoped context. You choose each connection's access.", preference: status?.preferences.features.agent_context },
    { icon: HiMiniCommandLine, title: "Connect context to execution", description: "Add native facts to supported captured-Bash actions. Availability and access checks still apply.", preference: status?.preferences.features.execution_context }
  ];
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "cigar-overview", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "cigar-benefits", children: features.map(({ icon: Icon, title, description, preference }) => /* @__PURE__ */ jsxRuntimeExports.jsxs("article", { className: "cigar-card cigar-benefit", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "cigar-icon", children: /* @__PURE__ */ jsxRuntimeExports.jsx(Icon, { "aria-hidden": "true" }) }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { children: title }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: description }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", className: "cigar-text-button", onClick: () => onSelect("runtime"), children: [
        preference ? "Preference on" : "Choose this feature",
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowRight, { "aria-hidden": "true" })
      ] })
    ] }, title)) }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "cigar-overview-grid", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "cigar-card cigar-setup", "aria-labelledby": "cigar-setup-heading", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "cigar-section-heading", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "cigar-eyebrow", children: "Get started" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "cigar-setup-heading", children: "Your path to useful context" })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "cigar-count", children: loading || !status ? "Checking setup" : String(completed) + " of 3 complete" })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("ol", { className: "cigar-steps", children: steps.map((step, index) => /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { "data-complete": step.complete, "aria-current": index === current && status ? "step" : void 0, children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "cigar-step-number", children: step.complete ? /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCheck, { "aria-hidden": "true" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "sr-only", children: "Complete: " })
          ] }) : index + 1 }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { children: step.title }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: step.description }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", className: "cigar-text-button", onClick: () => onSelect(step.tab), children: [
              step.action,
              /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowRight, { "aria-hidden": "true" })
            ] })
          ] })
        ] }, step.title)) }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "cigar-next-step", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniLink, { "aria-hidden": "true" }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { children: "Next, choose sources and app access" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "Workspace files, AI app connections, and sharing each need your permission." }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", className: "cigar-text-button", onClick: () => onSelect("access"), children: [
              "Manage sources & AI apps",
              /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowRight, { "aria-hidden": "true" })
            ] })
          ] })
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("aside", { className: "cigar-card cigar-boundaries", "aria-labelledby": "cigar-boundaries-heading", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "cigar-icon", children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniLockClosed, { "aria-hidden": "true" }) }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "cigar-boundaries-heading", children: "You choose the context." }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "Start with native Guard facts. Add workspace files and app access when they help your work." }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("ul", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCheckCircle, { "aria-hidden": "true" }),
            "Optional, with a visible off switch"
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCheckCircle, { "aria-hidden": "true" }),
            "Memory storage by default"
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCheckCircle, { "aria-hidden": "true" }),
            "Separate choices for app sharing and saved evidence"
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCheckCircle, { "aria-hidden": "true" }),
            "Guard keeps authority over approvals and execution"
          ] })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", className: "cigar-text-button", onClick: () => onSelect("guide"), children: [
          "See how CIGAR works",
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowRight, { "aria-hidden": "true" })
        ] })
      ] })
    ] })
  ] });
}
const key = "hol-guard:cigar-tutorial:v1";
const initial = { schema: 1, tutorial: "first-brief", step: 0 };
function parseTutorialProgress(value) {
  if (!value || typeof value !== "object") return initial;
  const item = value;
  const tutorial = CIGAR_TUTORIALS.find((entry) => entry.id === item.tutorial);
  if (item.schema !== 1 || !tutorial || !Number.isSafeInteger(item.step) || Number(item.step) < 0 || Number(item.step) >= tutorial.steps.length) return initial;
  return { schema: 1, tutorial: tutorial.id, step: Number(item.step) };
}
function readProgress() {
  try {
    return typeof window === "undefined" ? initial : parseTutorialProgress(JSON.parse(window.sessionStorage.getItem(key) ?? "null"));
  } catch {
    return initial;
  }
}
function useCigarTutorial() {
  const [progress, setProgress] = reactExports.useState(readProgress);
  const [active, setActive] = reactExports.useState(false);
  function save(value) {
    setProgress(value);
    try {
      window.sessionStorage.setItem(key, JSON.stringify(value));
    } catch {
    }
    return value;
  }
  function begin(id2, resume = false) {
    const next = save({ schema: 1, tutorial: id2, step: resume && progress.tutorial === id2 ? progress.step : 0 });
    setActive(true);
    return next;
  }
  function move(step) {
    return save(parseTutorialProgress({ ...progress, step }));
  }
  return { active, progress, tutorial: cigarTutorial(progress.tutorial), begin, move, exit: () => setActive(false) };
}
function CigarTutorials(props) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "cigar-guide", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "cigar-card cigar-learning-intro", "aria-labelledby": "cigar-tutorials-heading", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "cigar-icon", children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniAcademicCap, { "aria-hidden": "true" }) }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "cigar-eyebrow", children: "Learn by doing" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "cigar-tutorials-heading", children: "Make CIGAR useful for your next task" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { children: "CIGAR" }),
          " stands for ",
          /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { children: CIGAR_FULL_NAME }),
          ". Start with one question and one workspace, then add app access or execution context when you need it."
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "cigar-learning-caption", children: "Guidance stays with your chosen step as you move between sections. It explains the steps; you choose every setting, start, and access grant." })
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "cigar-benefits", children: CIGAR_TUTORIALS.map((tutorial) => /* @__PURE__ */ jsxRuntimeExports.jsxs("article", { className: "cigar-card cigar-benefit", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "cigar-eyebrow", children: tutorial.level }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { children: tutorial.title }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: tutorial.description }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "cigar-learning-caption", children: [
        tutorial.steps.length,
        " guided steps"
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "cigar-lesson-outcome", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { children: "What you will learn" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: tutorial.outcome })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", className: "cigar-text-button", onClick: () => props.onBegin(tutorial.id, props.progress.tutorial === tutorial.id && props.progress.step > 0), children: [
        props.progress.tutorial === tutorial.id && props.progress.step > 0 ? "Resume walkthrough" : "Start walkthrough",
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowRight, { "aria-hidden": "true" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "sr-only", children: [
          ": ",
          tutorial.title
        ] })
      ] })
    ] }, tutorial.id)) }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "cigar-card", "aria-labelledby": "cigar-effective-heading", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "cigar-eyebrow", children: "Use context effectively" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "cigar-effective-heading", children: "A useful brief starts with a focused question" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "cigar-effective-grid", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("article", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { children: "Name the decision" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "Ask which release rules apply to a change, which documented steps to follow, or which native policy facts affect a workspace." })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("article", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { children: "Choose evidence that can answer it" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "Start with one or two relevant documents and the native facts you need. Add sources when a specific gap appears." })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("article", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { children: "Use citations as your check" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "Inspect source names, line ranges, and revisions. Refresh after edits and ask the app to identify missing evidence." })
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "cigar-note", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { children: "Try a specific task instead of a broad request" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "For selected release docs: “Which release steps and approval rules are documented for this project?” For native facts only: “Which Guard policy facts apply to this workspace?”" })
      ] })
    ] })
  ] });
}
function CigarWalkthrough(props) {
  const id2 = reactExports.useId();
  const [copyMessage, setCopyMessage] = reactExports.useState("");
  const step = props.tutorial.steps[props.step];
  const last = props.step === props.tutorial.steps.length - 1;
  const liveStatus = props.status ? contextStatusCopy(props.status).label : "Status unavailable";
  reactExports.useEffect(() => {
    setCopyMessage("");
  }, [props.step, props.tutorial.id]);
  async function copyQuestion() {
    if (!step.question) return;
    try {
      if (!navigator.clipboard) throw new Error("clipboard_unavailable");
      await navigator.clipboard.writeText(step.question);
      setCopyMessage("Question copied. Paste it into the context question field or your authorized app.");
    } catch {
      setCopyMessage("Select the example text and copy it with your usual keyboard or touch controls.");
    }
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("aside", { className: "cigar-card cigar-walkthrough", "aria-labelledby": id2 + "-title", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "cigar-section-heading", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "cigar-eyebrow", children: "Guided walkthrough" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", className: "cigar-walkthrough-close", onClick: props.onExit, "aria-label": "Exit walkthrough", children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniXMark, { "aria-hidden": "true" }) })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: id2 + "-title", children: props.tutorial.title }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "cigar-learning-caption", children: [
      "Step ",
      props.step + 1,
      " of ",
      props.tutorial.steps.length,
      " · learning progress"
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("details", { className: "cigar-lesson-index", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("summary", { children: [
        "All ",
        props.tutorial.steps.length,
        " steps"
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("ol", { className: "cigar-lesson-steps", "aria-label": "Walkthrough steps", children: props.tutorial.steps.map((item, index) => /* @__PURE__ */ jsxRuntimeExports.jsx("li", { children: /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", "aria-current": props.step === index ? "step" : void 0, onClick: () => props.onMove(index), children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: index + 1 }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: item.title })
      ] }) }, item.title)) })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "cigar-lesson-body", "aria-live": "polite", "aria-atomic": "false", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { children: step.title }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: step.description }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("ol", { className: "cigar-simple-list", children: step.instructions.map((instruction) => /* @__PURE__ */ jsxRuntimeExports.jsx("li", { children: instruction }, instruction)) }),
      step.question ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "cigar-example-question", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { children: "Example question" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: step.question }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", className: "cigar-text-button", onClick: () => void copyQuestion(), children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniClipboardDocument, { "aria-hidden": "true" }),
          "Copy question"
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { role: "status", className: "cigar-learning-caption", children: copyMessage })
      ] }) : null,
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "cigar-lesson-outcome", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { children: "What to look for" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: step.expect })
      ] }),
      step.tip ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "cigar-learning-tip", children: step.tip }) : null,
      /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", className: "cigar-text-button", onClick: props.onOpen, children: [
        step.action,
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowRight, { "aria-hidden": "true" })
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "cigar-lesson-navigation", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", className: "cigar-button", disabled: props.step === 0, onClick: () => props.onMove(props.step - 1), children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowLeft, { "aria-hidden": "true" }),
        "Back"
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", className: "cigar-button", onClick: () => last ? props.onExit() : props.onMove(props.step + 1), children: [
        last ? "Finish walkthrough" : "Next step",
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowRight, { "aria-hidden": "true" })
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "cigar-learning-caption", children: [
      "Live runtime: ",
      /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { children: liveStatus }),
      props.dirty ? " · unsaved preferences" : "",
      ". Reading ahead does not complete setup or grant access."
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", className: "cigar-text-button", onClick: () => props.onMove(0), children: "Restart this walkthrough" })
  ] });
}
function CigarWorkspace(props) {
  const [tab, setTab] = reactExports.useState(() => cigarTabFromSearch(typeof window === "undefined" ? "" : window.location.search));
  const id2 = reactExports.useId();
  const panel = reactExports.useRef(null);
  const walkthroughAnchor = reactExports.useRef(null);
  const lesson = useCigarTutorial();
  const status = props.status;
  const copy = props.loading ? { label: "Checking status", detail: "Reading the local runtime registration and availability." } : status ? contextStatusCopy(status) : { label: "Status unavailable", detail: "Reconnect to the local Guard service, then refresh. Your Python version has not been checked here." };
  const runtime = cigarRuntimeSummary(status, props.installations);
  const canStop = props.stopAvailable ?? Boolean(status?.requested_enabled || status?.effective_enabled || status?.job);
  const startRequested = status?.requested_enabled === true && !status.effective_enabled;
  const primaryLabel = status?.job ? status.job.phase === "cancelling" ? "Stopping…" : "Checking runtime…" : props.dirty ? "Save preferences first" : status?.effective_enabled ? "Use CIGAR" : startRequested ? "Start CIGAR" : "Get started";
  const primaryDisabled = props.disabled || props.busy || props.loading || Boolean(status?.job) || !props.dirty && startRequested && !canStartCigar(status, props.dirty);
  reactExports.useEffect(() => {
    const sync = () => setTab(cigarTabFromSearch(window.location.search));
    return subscribeDashboardLocation(sync);
  }, []);
  function select(next, focusPanel = true) {
    setTab(next);
    const url = new URL(window.location.href);
    url.searchParams.set("section", next);
    window.history.replaceState({}, "", url.pathname + url.search + url.hash);
    if (focusPanel) window.requestAnimationFrame(() => panel.current?.focus());
  }
  function moveTab(event, index) {
    let next;
    if (event.key === "ArrowRight") next = (index + 1) % CIGAR_TABS.length;
    else if (event.key === "ArrowLeft") next = (index + CIGAR_TABS.length - 1) % CIGAR_TABS.length;
    else if (event.key === "Home") next = 0;
    else if (event.key === "End") next = CIGAR_TABS.length - 1;
    else return;
    event.preventDefault();
    select(CIGAR_TABS[next].value, false);
    document.getElementById(id2 + "-tab-" + CIGAR_TABS[next].value)?.focus();
  }
  function focusWalkthrough() {
    window.requestAnimationFrame(() => {
      walkthroughAnchor.current?.focus({ preventScroll: true });
      walkthroughAnchor.current?.scrollIntoView({ block: "start" });
    });
  }
  function beginTutorial(tutorial, resume = false) {
    const progress = lesson.begin(tutorial, resume);
    select(cigarTutorial(progress.tutorial).steps[progress.step].target, false);
    focusWalkthrough();
  }
  function moveTutorial(step) {
    const progress = lesson.move(step);
    select(cigarTutorial(progress.tutorial).steps[progress.step].target, false);
    focusWalkthrough();
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "cigar-workspace", "data-testid": "cigar-workspace", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("header", { className: "cigar-heading", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "cigar-eyebrow", children: "Local context assistance" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("h1", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCircleStack, { "aria-hidden": "true" }),
          "CIGAR"
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: CIGAR_FULL_NAME })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "cigar-heading-actions", children: [
        canStop ? /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", className: "cigar-button", disabled: props.disabled || props.busy, onClick: props.onStop, children: "Turn off CIGAR" }) : null,
        /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", className: "cigar-button", disabled: props.disabled || props.busy || props.loading, onClick: props.onRefresh, children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowPath, { "aria-hidden": "true" }),
          "Refresh status"
        ] })
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "cigar-hero", "aria-labelledby": "cigar-hero-heading", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "cigar-hero-copy", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "cigar-hero-kicker", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { "aria-hidden": "true" }),
          "Optional. Local. Yours to control."
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("h2", { id: "cigar-hero-heading", children: [
          "Bring the right context",
          /* @__PURE__ */ jsxRuntimeExports.jsx("br", { className: "hidden sm:block" }),
          " to your next action."
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "Turn the sources you trust into useful context for command reviews, connected AI apps, and supported execution flows." }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "cigar-hero-actions", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs(
            "button",
            {
              type: "button",
              className: "cigar-button cigar-button-primary",
              disabled: primaryDisabled,
              onClick: () => {
                if (canStartCigar(status, props.dirty)) props.onStart();
                else select(!props.dirty && status?.effective_enabled ? "access" : "runtime");
              },
              children: [
                primaryLabel,
                /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowRight, { "aria-hidden": "true" })
              ]
            }
          ),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", className: "cigar-hero-link", onClick: () => select("guide"), children: [
            "How it works",
            /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowRight, { "aria-hidden": "true" })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", className: "cigar-hero-link", onClick: () => select("tutorials"), children: [
            "Take a walkthrough",
            /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowRight, { "aria-hidden": "true" })
          ] })
        ] }),
        props.dirty ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-3 text-xs text-slate-200", children: "Save your changes before starting CIGAR or granting context access." }) : null
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "cigar-runtime-card", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "cigar-runtime-top", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "cigar-eyebrow", children: "On this machine" }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "cigar-status", "data-ready": status?.effective_enabled === true, role: "status", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { "aria-hidden": "true" }),
            copy.label
          ] })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCpuChip, { className: "cigar-runtime-symbol", "aria-hidden": "true" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { children: props.loading ? "Reading runtime…" : runtime.label }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: props.loading ? "No runtime is started by opening this page." : runtime.detail }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "cigar-runtime-note", children: copy.detail })
      ] })
    ] }),
    props.error ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "cigar-note", role: "alert", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { children: "CIGAR needs attention" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: props.error })
    ] }) : null,
    /* @__PURE__ */ jsxRuntimeExports.jsx("nav", { className: "cigar-tabs", role: "tablist", "aria-label": "CIGAR sections", children: CIGAR_TABS.map((item, index) => /* @__PURE__ */ jsxRuntimeExports.jsx(
      "button",
      {
        id: id2 + "-tab-" + item.value,
        type: "button",
        role: "tab",
        "aria-selected": tab === item.value,
        "aria-controls": id2 + "-panel",
        tabIndex: tab === item.value ? 0 : -1,
        onKeyDown: (event) => moveTab(event, index),
        onClick: () => select(item.value, false),
        children: item.label
      },
      item.value
    )) }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "cigar-learning-layout" + (lesson.active ? " has-walkthrough" : ""), children: [
      lesson.active ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { ref: walkthroughAnchor, tabIndex: -1, className: "cigar-walkthrough-anchor", children: /* @__PURE__ */ jsxRuntimeExports.jsx(
        CigarWalkthrough,
        {
          tutorial: lesson.tutorial,
          step: lesson.progress.step,
          status,
          dirty: props.dirty,
          onMove: moveTutorial,
          onOpen: () => select(lesson.tutorial.steps[lesson.progress.step].target),
          onExit: () => {
            lesson.exit();
            select("tutorials");
          }
        }
      ) }) : null,
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { ref: panel, id: id2 + "-panel", role: "tabpanel", "aria-labelledby": id2 + "-tab-" + tab, tabIndex: -1, className: "cigar-panel", children: [
        tab === "overview" ? /* @__PURE__ */ jsxRuntimeExports.jsx(CigarOverview, { status, installations: props.installations, loading: props.loading, onSelect: select }) : null,
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { hidden: tab !== "runtime", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "cigar-section-intro", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "cigar-eyebrow", children: "Make it yours" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { children: "Runtime & preferences" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "Manage runtime selection in Versions & updates, choose the features you want here, and save. Start the runtime when you are ready to use context." })
          ] }),
          props.installations?.length === 0 ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "cigar-note", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { children: "No CIGAR bundle is registered in this Guard profile." }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "Python 3.14 may already be installed. Guard also needs the approved CIGAR package and worker registered together; an empty list does not mean your Python is incompatible." }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", className: "cigar-text-button", onClick: () => select("guide"), children: [
              "Read the runtime setup guide",
              /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowRight, { "aria-hidden": "true" })
            ] })
          ] }) : null,
          props.controls
        ] }),
        tab === "versions" ? props.versions : null,
        tab === "access" ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "cigar-section-intro", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "cigar-eyebrow", children: "Give context a scope" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { children: "Sources & AI apps" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "Grant access to one workspace at a time. Choose documents and app connections explicitly; sharing requires its own preference." })
          ] }),
          !status?.effective_enabled ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "cigar-note", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { children: "Start CIGAR before granting context access." }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "Save your runtime and feature preferences, then start context assistance. Sources and app access become available when the runtime is Ready." }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", className: "cigar-text-button", onClick: () => select("runtime"), children: [
              "Open runtime & preferences",
              /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowRight, { "aria-hidden": "true" })
            ] })
          ] }) : null,
          props.access
        ] }) : null,
        tab === "data" ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "cigar-section-intro", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "cigar-eyebrow", children: "Stay in control" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { children: "Data & privacy" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "Review context storage, revoke access, clear saved evidence, or stop the runtime. Storage and retention preferences live in Runtime & preferences." })
          ] }),
          props.data
        ] }) : null,
        tab === "tutorials" ? /* @__PURE__ */ jsxRuntimeExports.jsx(CigarTutorials, { progress: lesson.progress, onBegin: beginTutorial }) : null,
        tab === "guide" ? /* @__PURE__ */ jsxRuntimeExports.jsx(CigarGuide, { onSelect: select }) : null
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("footer", { className: "cigar-footer", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniShieldCheck, { "aria-hidden": "true" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: "Guard makes and enforces security decisions. CIGAR supplies context from the sources you authorize." }),
      props.dirty ? /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { children: "Unsaved preferences" }) : null
    ] })
  ] });
}
const cigarVersionJobId = () => "dashboard:" + crypto.randomUUID();
function canCommitCigarJob(job, status) {
  return status !== null && job.can_commit && !job.cleanup_pending && job.expected_generation === status.generation && (job.initial_selection ? status.preferences.runtime_id === "" : job.source_runtime_id === status.preferences.runtime_id);
}
function cigarJobPending(job) {
  return job.worker_live === true || !job.recovery_available && !["ready", "completed", "cancelled", "failed", "recovery_required"].includes(job.phase);
}
function cigarBuildBlock(catalog, build, updates) {
  if (build.withdrawn) return "This build has been withdrawn.";
  if (!catalog.catalog.fresh_for_preparation) return "Refresh the catalog before preparing a build.";
  const host = build.platforms.find((p) => p.platform === catalog.host_platform);
  if (!host) return "No artifact is available for this Guard host.";
  if (host.qualification !== "guard_qualified") return "This artifact still needs Guard qualification.";
  if (!host.has_wheel) return "This entry has no installable SDK package.";
  if (build.channel !== "stable") return "Preview and local candidate installation is unavailable in this Guard build.";
  if (updates.effective.pinned_build && updates.effective.pinned_build !== build.identity.build_id) return "Update preferences pin another build.";
  return null;
}
function cigarPythonBlock(catalog, build) {
  if (build.withdrawn) return "This Python build has been withdrawn.";
  if (!catalog.catalog.fresh_for_preparation) return "Refresh the catalog before preparing Python.";
  if (build.platform !== catalog.host_platform) return "This Python build is for another Guard host.";
  if (build.qualification !== "guard_qualified") return "This Python build still needs Guard qualification.";
  return null;
}
function CigarVersionBuildsPanel({ data, status, disabled, selectionDisabled, onAction }) {
  const [python, setPython] = reactExports.useState("");
  const id2 = reactExports.useId(), catalog = data.catalog;
  const registered = data.interpreters.filter((p) => p.platform === catalog.host_platform);
  const interpreter = registered.find((p) => p.interpreter_id === python) ?? registered[0];
  const activeSelection = data.jobs.some((job) => job.family === "selection" && (cigarJobPending(job) || job.recovery_available));
  const selectionBlocked = selectionDisabled || !status || activeSelection;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-6", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "space-y-3", "aria-labelledby": id2 + "-installed", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { id: id2 + "-installed", className: "font-semibold text-brand-dark", children: "Registered installations" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-slate-600", children: "Prepare a selection alongside your current runtime. Guard verifies the target and saved data before it offers a switch." }),
      !data.installations.length ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-slate-600", children: "Prepare an available SDK build below, or register an approved bundle with the Guard CLI." }) : null,
      data.installations.map((item) => /* @__PURE__ */ jsxRuntimeExports.jsxs("article", { className: versionCard, "aria-labelledby": id2 + "-installed-" + item.runtime_id, children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("h4", { id: id2 + "-installed-" + item.runtime_id, className: "font-semibold text-brand-dark", children: [
          "CIGAR ",
          item.sdk_version ?? "registered bundle",
          item.runtime_id === status?.preferences.runtime_id ? status.runtime?.active ? " · selected · running" : " · selected" : ""
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "text-sm text-slate-600", children: [
          "Core ",
          item.core_version ?? "not reported",
          " · Python ",
          item.python_version.join("."),
          " · ",
          item.platform,
          " · ",
          item.managed ? "Guard managed" : "externally registered",
          " · ",
          item.qualification.replaceAll("_", " ")
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "break-all text-xs text-slate-600", children: [
          "Build: ",
          item.build_id ?? "legacy registration"
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "button",
          {
            type: "button",
            className: versionButton,
            disabled: selectionBlocked || item.runtime_id === status?.preferences.runtime_id,
            onClick: () => {
              if (status) onAction({
                input: { action: "prepare_switch", job_id: cigarVersionJobId(), target_runtime_id: item.runtime_id, expected_generation: status.generation },
                title: "Prepare CIGAR selection",
                detail: "Verify this target and its data without committing a runtime switch. CIGAR stays off if it is off now."
              });
            },
            children: "Prepare selection"
          }
        )
      ] }, item.runtime_id)),
      status?.preferences.runtime_id ? /* @__PURE__ */ jsxRuntimeExports.jsx(
        "button",
        {
          type: "button",
          className: versionButton,
          disabled: selectionBlocked,
          onClick: () => {
            if (status) onAction({
              input: { action: "prepare_rollback", job_id: cigarVersionJobId(), expected_generation: status.generation },
              title: "Prepare last good CIGAR build",
              detail: "Verify the last good installation and current data. Guard will offer a separate explicit rollback switch when it is ready."
            });
          },
          children: "Prepare last good build"
        }
      ) : null,
      activeSelection ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "status", className: "text-sm text-slate-600", children: "Finish, cancel or recover the current selection job before preparing another." }) : null
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "space-y-3", "aria-labelledby": id2 + "-builds", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { id: id2 + "-builds", className: "font-semibold text-brand-dark", children: "Available SDK builds" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-slate-600", children: "Preparing downloads a separate, verified installation. It keeps your current runtime selected." }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block text-sm text-slate-600", children: [
        "Python for SDK preparation",
        /* @__PURE__ */ jsxRuntimeExports.jsxs("select", { className: versionField, disabled: disabled || !registered.length, value: interpreter?.interpreter_id ?? "", onChange: (event) => setPython(event.target.value), children: [
          !registered.length ? /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "", children: "No Python interpreter registered for this host" }) : null,
          registered.map((p) => /* @__PURE__ */ jsxRuntimeExports.jsxs("option", { value: p.interpreter_id, children: [
            "Python ",
            p.python_version.join("."),
            " · ",
            p.managed ? "Guard managed" : "registered",
            " · ",
            p.interpreter_id
          ] }, p.interpreter_id))
        ] })
      ] }),
      !catalog.builds.length ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-slate-600", children: "No SDK builds are available in this catalog." }) : null,
      catalog.builds.map((build) => {
        const reason = cigarBuildBlock(catalog, build, data.updates), host = build.platforms.find((p) => p.platform === catalog.host_platform);
        return /* @__PURE__ */ jsxRuntimeExports.jsxs("article", { className: versionCard, "aria-labelledby": id2 + "-build-" + build.identity.build_id + " " + id2 + "-build-id-" + build.identity.build_id, children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("h4", { id: id2 + "-build-" + build.identity.build_id, className: "font-semibold text-brand-dark", children: [
            "CIGAR ",
            build.identity.sdk_version,
            " · ",
            build.channel.replaceAll("_", " "),
            build.withdrawn ? " · withdrawn" : ""
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { id: id2 + "-build-id-" + build.identity.build_id, className: "break-all text-sm text-slate-600", children: [
            "Build: ",
            build.identity.build_id
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "text-sm text-slate-600", children: [
            "Core ",
            build.identity.core_version,
            " · ",
            host?.qualification.replaceAll("_", " ") ?? "no artifact for this host",
            host ? " · download " + versionBytes(host.download_bytes) : ""
          ] }),
          reason ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { id: id2 + "-build-reason-" + build.identity.build_id, className: "text-sm text-amber-800", children: reason }) : null,
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            "button",
            {
              type: "button",
              className: versionButton,
              "aria-describedby": reason ? id2 + "-build-reason-" + build.identity.build_id : void 0,
              disabled: disabled || reason !== null || !interpreter,
              onClick: () => {
                if (interpreter) onAction({
                  input: { action: "install", job_id: cigarVersionJobId(), build_id: build.identity.build_id, interpreter_id: interpreter.interpreter_id },
                  title: "Prepare CIGAR build",
                  detail: "Download and verify this SDK in a separate managed installation. Keep the selected runtime in place."
                });
              },
              children: "Prepare this build"
            }
          ),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("details", { className: "text-xs text-slate-600", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("summary", { className: "cursor-pointer", children: "Build identity" }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "break-all", children: [
              "Source: ",
              build.identity.source_revision
            ] }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "break-all", children: [
              "Manifest: ",
              build.identity.manifest_sha256
            ] }),
            host ? /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "break-all", children: [
              "Worker: ",
              host.worker_sha256
            ] }) : null
          ] })
        ] }, build.identity.build_id);
      })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "space-y-3", "aria-labelledby": id2 + "-python", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { id: id2 + "-python", className: "font-semibold text-brand-dark", children: "Private Python builds" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-slate-600", children: "Guard can prepare its own Python alongside your existing interpreters. Your system Python is unchanged." }),
      !catalog.interpreter_builds.length ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-slate-600", children: "No private Python builds are listed." }) : null,
      catalog.interpreter_builds.map((build) => {
        const reason = cigarPythonBlock(catalog, build), present = data.interpreters.some((p) => p.build_id === build.build_id);
        return /* @__PURE__ */ jsxRuntimeExports.jsxs("article", { className: versionCard, "aria-labelledby": id2 + "-python-" + build.build_id + " " + id2 + "-python-id-" + build.build_id, children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("h4", { id: id2 + "-python-" + build.build_id, className: "font-semibold text-brand-dark", children: [
            "Python ",
            build.python_version.join("."),
            " · ",
            build.platform
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { id: id2 + "-python-id-" + build.build_id, className: "break-all text-xs text-slate-600", children: [
            build.build_id,
            " · download ",
            versionBytes(build.archive_bytes)
          ] }),
          reason ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { id: id2 + "-python-reason-" + build.build_id, className: "text-sm text-amber-800", children: reason }) : null,
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            "button",
            {
              type: "button",
              className: versionButton,
              "aria-describedby": reason ? id2 + "-python-reason-" + build.build_id : void 0,
              disabled: disabled || present || reason !== null,
              onClick: () => onAction({
                input: { action: "setup_interpreter", job_id: cigarVersionJobId(), build_id: build.build_id },
                title: "Prepare private Python",
                detail: "Download and verify the catalog's immutable Python build. Leave your system Python and current CIGAR selection unchanged."
              }),
              children: present ? "Python registered" : "Prepare private Python"
            }
          )
        ] }, build.build_id);
      })
    ] })
  ] });
}
const operation = {
  install: "Prepare SDK",
  verify: "Verify installation",
  setup_interpreter: "Prepare Python",
  refresh_catalog: "Refresh catalog",
  switch: "Switch runtime",
  rollback: "Roll back runtime",
  select: "Select first runtime",
  recover: "Recover selection"
};
function CigarVersionJobsPanel(props) {
  const [acknowledged, setAcknowledged] = reactExports.useState(null);
  const id2 = reactExports.useId();
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "space-y-3", "aria-labelledby": id2 + "-heading", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { id: id2 + "-heading", className: "font-semibold text-brand-dark", children: "Preparation & selection jobs" }),
    !props.jobs.length ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-slate-600", children: "No CIGAR update jobs have been recorded." }) : null,
    props.jobs.map((job) => /* @__PURE__ */ jsxRuntimeExports.jsxs("article", { className: versionCard, "aria-label": operation[job.operation] + " " + job.job_id, children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h4", { className: "font-semibold text-brand-dark", children: operation[job.operation] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "text-sm text-slate-600", role: "status", children: [
        job.phase.replaceAll("_", " "),
        job.cancel_requested ? " · cancellation requested" : ""
      ] }),
      job.family === "selection" ? /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "break-all text-sm text-slate-600", children: [
          "Target: ",
          job.target_runtime_id
        ] }),
        job.keeps_disabled ? /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "text-sm text-slate-600", children: [
          job.operation === "recover" ? "Recovery keeps CIGAR off." : "Selecting this runtime keeps CIGAR off.",
          " Start it separately when you are ready."
        ] }) : /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-slate-600", children: "Switching briefly pauses CIGAR. Context access and app connections require fresh grants afterward. Your Guard approvals remain in place." }),
        job.can_commit ? /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
          job.reconnect_required ? /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "flex min-h-11 items-center gap-3 text-sm text-slate-600", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(
              "input",
              {
                type: "checkbox",
                checked: acknowledged === job.job_id + ":" + job.expected_generation,
                disabled: props.selectionDisabled,
                onChange: (event) => setAcknowledged(event.target.checked ? job.job_id + ":" + job.expected_generation : null)
              }
            ),
            "I am ready to reconnect context sources and apps."
          ] }) : null,
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            "button",
            {
              type: "button",
              className: versionButton,
              disabled: props.selectionDisabled || !canCommitCigarJob(job, props.status) || job.reconnect_required && acknowledged !== job.job_id + ":" + job.expected_generation,
              onClick: () => props.onAction({
                input: { action: "commit", job_id: job.job_id, expected_generation: job.expected_generation, reconnect: job.reconnect_required },
                title: job.keeps_disabled ? "Select CIGAR runtime" : "Switch CIGAR now",
                detail: job.keeps_disabled ? "Commit the verified selection and keep CIGAR off." : "Switch to the verified runtime now. Reconnect context sources and apps after the switch."
              }),
              children: job.keeps_disabled ? "Select & keep CIGAR off" : "Switch now"
            }
          ),
          !canCommitCigarJob(job, props.status) ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-amber-800", children: "The live selection changed. Refresh status and jobs before continuing." }) : null
        ] }) : null
      ] }) : null,
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-2", children: [
        cigarJobPending(job) && !job.cancel_requested ? /* @__PURE__ */ jsxRuntimeExports.jsx(
          "button",
          {
            type: "button",
            className: versionButton,
            disabled: props.disabled,
            onClick: () => props.onAction({ input: { action: "cancel", job_id: job.job_id }, title: "Cancel CIGAR job", detail: "Ask Guard to cancel this job and finish its cleanup." }),
            children: "Cancel job"
          }
        ) : null,
        job.recovery_available ? /* @__PURE__ */ jsxRuntimeExports.jsx(
          "button",
          {
            type: "button",
            className: versionButton,
            disabled: props.disabled || !props.status,
            onClick: () => props.onAction({
              input: {
                action: "recover",
                job_id: job.job_id,
                ...job.family === "selection" && props.status ? { expected_generation: props.status.generation } : {}
              },
              title: "Recover interrupted CIGAR work",
              detail: "Ask Guard to reconcile the interrupted operation. Recovery never restores old context grants or approvals."
            }),
            children: "Recover job"
          }
        ) : null
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("details", { className: "text-xs text-slate-600", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("summary", { className: "cursor-pointer", children: "Job details" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "break-all", children: [
          "Job: ",
          job.job_id
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "break-all", children: [
          "Diagnostic: ",
          job.code
        ] }),
        job.family === "selection" ? /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { children: [
          "Expected generation: ",
          job.expected_generation
        ] }) : null,
        job.family === "selection" && job.recovery_attempt ? /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { children: [
            "Recovery deadline: ",
            /* @__PURE__ */ jsxRuntimeExports.jsx("time", { dateTime: new Date(job.recovery_attempt.deadline_at_ms).toISOString(), children: new Date(job.recovery_attempt.deadline_at_ms).toLocaleString() })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { children: [
            "Original preparation deadline: ",
            /* @__PURE__ */ jsxRuntimeExports.jsx("time", { dateTime: new Date(job.deadline_at_ms).toISOString(), children: new Date(job.deadline_at_ms).toLocaleString() })
          ] })
        ] }) : /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { children: [
          "Deadline: ",
          /* @__PURE__ */ jsxRuntimeExports.jsx("time", { dateTime: new Date(job.deadline_at_ms).toISOString(), children: new Date(job.deadline_at_ms).toLocaleString() })
        ] }),
        job.family === "selection" && job.cleanup_pending ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "Cleanup is still pending. Wait before another switch." }) : null
      ] })
    ] }, job.job_id))
  ] });
}
function CigarUpdatePreferencesPanel({ value, builds, disabled, onAction }) {
  const [draft, setDraft] = reactExports.useState(value.requested);
  const id2 = reactExports.useId();
  reactExports.useEffect(() => {
    setDraft(value.requested);
  }, [value.revision]);
  const locked = (key2) => disabled || value.locked_settings.some((k) => k === "context_assistance_updates" || k === "context_assistance_updates." + key2);
  const changed = JSON.stringify(draft) !== JSON.stringify(value.requested);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: versionCard, "aria-labelledby": id2 + "-heading", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { id: id2 + "-heading", className: "font-semibold text-brand-dark", children: "Update preferences" }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-slate-600", children: "Preparing a build leaves your current selection in place. This Guard build requires an explicit switch and keeps the last good build." }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block text-sm text-slate-600", children: [
      "Update mode",
      /* @__PURE__ */ jsxRuntimeExports.jsxs(
        "select",
        {
          className: versionField,
          value: draft.mode,
          disabled: locked("mode"),
          onChange: (event) => setDraft({ ...draft, mode: event.target.value }),
          children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "manual", children: "Manual" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "notify", disabled: true, children: "Notify · delivery unavailable" }),
            draft.mode === "prepare" ? /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "prepare", disabled: true, children: "Automatic preparation · unavailable" }) : null
          ]
        }
      )
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-slate-600", children: "Update notifications and automatic preparation are not available in this Guard build." }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "flex min-h-11 items-center gap-3 text-sm text-slate-600", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        "input",
        {
          type: "checkbox",
          checked: draft.allow_preview,
          disabled: locked("allow_preview"),
          onChange: (event) => setDraft({ ...draft, allow_preview: event.target.checked })
        }
      ),
      "Allow preview selections"
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-slate-600", children: "Preview installation still needs release qualification and support in Guard." }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block text-sm text-slate-600", children: [
      "Pin to a build",
      /* @__PURE__ */ jsxRuntimeExports.jsxs(
        "select",
        {
          className: versionField,
          value: draft.pinned_build ?? "",
          disabled: locked("pinned_build"),
          onChange: (event) => {
            const { pinned_build: _pin, ...rest } = draft;
            setDraft(event.target.value ? { ...rest, pinned_build: event.target.value } : rest);
          },
          children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "", children: "No pin" }),
            draft.pinned_build && !builds.some((b) => b.identity.build_id === draft.pinned_build) ? /* @__PURE__ */ jsxRuntimeExports.jsxs("option", { value: draft.pinned_build, children: [
              draft.pinned_build,
              " · unavailable in catalog"
            ] }) : null,
            builds.map((b) => /* @__PURE__ */ jsxRuntimeExports.jsxs("option", { value: b.identity.build_id, children: [
              b.identity.sdk_version,
              " · ",
              b.identity.build_id,
              b.withdrawn ? " · withdrawn" : ""
            ] }, b.identity.build_id))
          ]
        }
      )
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "break-all text-sm text-slate-600", children: [
      "Effective pin: ",
      value.effective.pinned_build ?? "none",
      ". Last good build: ",
      value.effective.retain_last_good ? "retained" : "retention disabled by saved policy",
      "."
    ] }),
    value.locked_settings.length ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-slate-600", children: "Your organization manages some update preferences. Effective values may differ from your saved choices." }) : null,
    value.diagnostic ? /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { role: "status", className: "break-all text-sm text-amber-800", children: [
      "Update preference diagnostic: ",
      value.diagnostic
    ] }) : null,
    /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", className: versionButton, disabled: disabled || !changed, onClick: () => onAction({
      input: { action: "set_preferences", expected_revision: value.revision, preferences: draft },
      title: "Save CIGAR update preferences",
      detail: "Save these update choices without changing or starting the selected runtime."
    }), children: "Save update preferences" })
  ] });
}
const object$4 = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
const readRoutes = {
  releases: "/v1/context-assistance/versions",
  catalog: "/v1/context-assistance/catalog",
  interpreters: "/v1/context-assistance/interpreters",
  jobs: "/v1/context-assistance/jobs"
};
const noProof = /* @__PURE__ */ new Set(["releases", "catalog", "interpreters", "jobs", "job", "cancel", "preferences"]);
function parseCigarVersionsReply(value) {
  if (!object$4(value) || value.schema !== "guard-cigar-versions-result.v1" || !object$4(value.result)) {
    throw new ContextAssistanceApiError("versions_payload_invalid", "Guard returned incompatible CIGAR update data. Refresh status.");
  }
  return { state: parseContextAssistanceStatus(value.state), result: value.result };
}
function errorMessage(code, status) {
  if (status === 404) return "Update Guard to use CIGAR version controls.";
  if (status === 401) return "Reconnect to the local Guard session, then refresh CIGAR updates.";
  if (status === 403) return "Guard needs your approval before this change.";
  if (code.endsWith("outcome_unknown")) return "Guard may have accepted this operation. Refresh jobs before retrying.";
  if (code.endsWith("preferences_conflict") || code.endsWith("selection_conflict") || code.endsWith("context_stale")) {
    return "CIGAR settings changed. Refresh the current selection and jobs before trying again.";
  }
  if (code.endsWith("_busy") || code.endsWith("cleanup_pending")) return "Another CIGAR operation is finishing. Refresh jobs after it completes.";
  if (code.endsWith("recovery_required")) return "This CIGAR operation needs recovery. Refresh its job before choosing the next action.";
  if (code.endsWith("data_choice_required")) return "Saved CIGAR data needs an explicit choice before this selection can proceed.";
  return "CIGAR did not return a confirmed result. Refresh status and jobs before trying again.";
}
async function requestCigarVersions(input, proof, signal) {
  if (isGuardDemoMode()) throw new ContextAssistanceApiError("demo_unavailable", "CIGAR updates require a local Guard installation.");
  const route = Object.hasOwn(readRoutes, input.action) ? readRoutes[input.action] : void 0;
  const timeout = AbortSignal.timeout(12e3);
  const credentials = noProof.has(input.action) ? void 0 : proof;
  const response = await fetchWithGuardAuth(route ?? "/v1/context-assistance/versions", {
    cache: "no-store",
    signal: signal ? AbortSignal.any([signal, timeout]) : timeout,
    ...route ? {} : {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        input,
        ...credentials?.currentPassword ? { approval_password: credentials.currentPassword } : {},
        ...credentials?.totpCode ? { approval_totp_code: credentials.totpCode } : {}
      })
    }
  });
  const body = await response.json().catch(() => null);
  if (!response.ok) {
    const code = object$4(body) && typeof body.code === "string" && /^[a-z0-9_]{1,160}$/.test(body.code) ? body.code : "context_assistance_unavailable";
    throw new ContextAssistanceApiError(code, errorMessage(code, response.status));
  }
  return parseCigarVersionsReply(body);
}
const object$3 = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const id$3 = (v) => typeof v === "string" && /^[a-z0-9_:-]{1,128}$/i.test(v);
const digest = (v) => typeof v === "string" && /^[a-f0-9]{64}$/.test(v);
const count$1 = (v) => typeof v === "number" && Number.isSafeInteger(v) && v >= 0;
const platform = (v) => typeof v === "string" && ["darwin-arm64", "darwin-x64", "linux-x64-gnu", "linux-arm64-gnu", "linux-x64-musl", "linux-arm64-musl", "win32-x64"].includes(v);
const qualification = (v) => typeof v === "string" && ["local_candidate", "upstream_only", "guard_qualified"].includes(v);
const diagnostic = (v) => v === null || typeof v === "string" && /^[a-z0-9_]{1,160}$/.test(v);
function invalid$3() {
  throw new ContextAssistanceApiError("versions_catalog_invalid", "Guard returned incompatible CIGAR catalog data. Refresh the catalog.");
}
function pythonVersion(v) {
  return Array.isArray(v) && v.length === 3 && v.every((n) => count$1(n) && n <= 65535);
}
function wheelBytes(v) {
  if (!object$3(v) || !count$1(v.bytes) || v.bytes === 0 || !digest(v.sha256)) invalid$3();
  return v.bytes;
}
function parsePlatform(v) {
  if (!object$3(v) || !platform(v.platform) || !qualification(v.qualification) || !digest(v.worker_sha256) || !(v.package_tree_sha256 === null || digest(v.package_tree_sha256)) || !(v.qualification_receipt_sha256 === null || digest(v.qualification_receipt_sha256)) || v.qualification === "guard_qualified" && v.qualification_receipt_sha256 === null || !Array.isArray(v.features) || v.features.length > 16 || !v.features.every((f) => typeof f === "string" && /^[a-z0-9_]{1,128}$/.test(f)) || new Set(v.features).size !== v.features.length || !Array.isArray(v.dependencies) || v.dependencies.length > 32) invalid$3();
  const hasWheel = v.wheel !== null;
  const bytes = (hasWheel ? wheelBytes(v.wheel) : 0) + v.dependencies.reduce((n, w) => n + wheelBytes(w), 0);
  if (!count$1(bytes)) invalid$3();
  return {
    platform: v.platform,
    qualification: v.qualification,
    features: v.features,
    worker_sha256: v.worker_sha256,
    package_tree_sha256: v.package_tree_sha256,
    qualification_receipt_sha256: v.qualification_receipt_sha256,
    has_wheel: hasWheel,
    download_bytes: bytes
  };
}
function parseBuild(v) {
  if (!object$3(v) || !isCigarBuildIdentity(v.identity) || !id$3(v.profile_id) || !["stable", "preview", "local_candidate"].includes(String(v.channel)) || typeof v.withdrawn !== "boolean" || !Array.isArray(v.platforms) || v.platforms.length === 0 || v.platforms.length > 7) invalid$3();
  const platforms = v.platforms.map(parsePlatform);
  if (new Set(platforms.map((p) => p.platform)).size !== platforms.length) invalid$3();
  return { identity: {
    build_id: v.identity.build_id,
    sdk_version: v.identity.sdk_version,
    core_version: v.identity.core_version,
    source_revision: v.identity.source_revision,
    manifest_sha256: v.identity.manifest_sha256
  }, profile_id: v.profile_id, channel: v.channel, withdrawn: v.withdrawn, platforms };
}
function parseInterpreter(v) {
  if (!object$3(v) || !id$3(v.build_id) || !pythonVersion(v.python_version) || !platform(v.platform) || !qualification(v.qualification) || typeof v.withdrawn !== "boolean" || !count$1(v.archive_bytes) || v.archive_bytes === 0) invalid$3();
  return {
    build_id: v.build_id,
    python_version: [...v.python_version],
    platform: v.platform,
    qualification: v.qualification,
    withdrawn: v.withdrawn,
    archive_bytes: v.archive_bytes
  };
}
function parseCigarCatalogMetadata(v) {
  if (!object$3(v) || !["bundled", "cached"].includes(String(v.source)) || typeof v.fresh_for_preparation !== "boolean" || !diagnostic(v.diagnostic) || !diagnostic(v.trust_diagnostic) || !diagnostic(v.feed_diagnostic) || typeof v.trust_configured !== "boolean" || typeof v.remote_feed_configured !== "boolean" || v.activation_granted !== false || v.fresh_for_preparation && v.diagnostic !== null) invalid$3();
  return {
    source: v.source,
    fresh_for_preparation: v.fresh_for_preparation,
    diagnostic: v.diagnostic,
    trust_configured: v.trust_configured,
    trust_diagnostic: v.trust_diagnostic,
    remote_feed_configured: v.remote_feed_configured,
    feed_diagnostic: v.feed_diagnostic
  };
}
function parseCigarCatalog(v) {
  if (!object$3(v) || v.schema !== "guard-cigar-releases.v1" || !(v.host_platform === void 0 || v.host_platform === null || platform(v.host_platform)) || !Array.isArray(v.builds) || v.builds.length > 128 || !Array.isArray(v.interpreter_builds) || v.interpreter_builds.length > 128) invalid$3();
  const builds = v.builds.map(parseBuild), interpreters = v.interpreter_builds.map(parseInterpreter);
  if (new Set(builds.map((b) => b.identity.build_id)).size !== builds.length || new Set(interpreters.map((b) => b.build_id)).size !== interpreters.length) invalid$3();
  return { host_platform: v.host_platform ?? null, builds, interpreter_builds: interpreters, catalog: parseCigarCatalogMetadata(v.catalog) };
}
const object$2 = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const id$2 = (v) => typeof v === "string" && /^[a-z0-9_:-]{1,128}$/i.test(v);
function invalid$2() {
  throw new ContextAssistanceApiError("versions_interpreters_invalid", "Guard returned incompatible Python registration data. Refresh updates.");
}
function parseCigarInterpreters(value) {
  if (!object$2(value) || !Array.isArray(value.interpreters) || value.interpreters.length > 16) invalid$2();
  const values = value.interpreters.map((v) => {
    if (!object$2(v) || !id$2(v.interpreter_id) || !Array.isArray(v.python_version) || v.python_version.length !== 3 || !v.python_version.every((n) => Number.isSafeInteger(n) && n >= 0 && n <= 65535) || !id$2(v.platform) || !id$2(v.implementation) || !id$2(v.abi) || typeof v.managed !== "boolean" || !(v.build_id === null || id$2(v.build_id)) || v.managed !== (v.build_id !== null)) invalid$2();
    return {
      interpreter_id: v.interpreter_id,
      python_version: [...v.python_version],
      platform: v.platform,
      implementation: v.implementation,
      abi: v.abi,
      managed: v.managed,
      build_id: v.build_id
    };
  });
  if (new Set(values.map((v) => v.interpreter_id)).size !== values.length) invalid$2();
  return values;
}
const object$1 = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const id$1 = (v) => typeof v === "string" && /^[a-z0-9_:-]{1,128}$/i.test(v);
const word = (v) => typeof v === "string" && /^[a-z0-9_]{1,128}$/.test(v);
const count = (v) => typeof v === "number" && Number.isSafeInteger(v) && v >= 0;
const isCigarGeneration = (v) => typeof v === "string" && /^[1-9][0-9]{0,19}$/.test(v) && (v.length < 20 || v <= "18446744073709551615");
function invalid$1() {
  throw new ContextAssistanceApiError("versions_job_invalid", "Guard returned incompatible CIGAR job data. Refresh jobs.");
}
function recovery(v) {
  if (v === void 0 || v === null) return null;
  if (!object$1(v) || typeof v.id !== "string" || !/^[a-f0-9]{32}$/.test(v.id) || !isCigarGeneration(v.expected_generation) || !count(v.started_at_ms) || !count(v.deadline_at_ms) || v.deadline_at_ms < v.started_at_ms) invalid$1();
  return { id: v.id, expected_generation: v.expected_generation, started_at_ms: v.started_at_ms, deadline_at_ms: v.deadline_at_ms };
}
function parseCigarVersionJob(value) {
  if (!object$1(value) || !id$1(value.job_id) || !word(value.phase) || !word(value.code) || !count(value.created_at_ms) || !count(value.updated_at_ms) || value.updated_at_ms < value.created_at_ms || !count(value.deadline_at_ms) || value.deadline_at_ms < value.created_at_ms || !(value.worker_live === null || typeof value.worker_live === "boolean") || typeof value.cancel_requested !== "boolean" || typeof value.recovery_available !== "boolean" || value.worker_live === true && value.recovery_available) invalid$1();
  const base = {
    schema: String(value.schema),
    job_id: value.job_id,
    phase: value.phase,
    code: value.code,
    created_at_ms: value.created_at_ms,
    updated_at_ms: value.updated_at_ms,
    deadline_at_ms: value.deadline_at_ms,
    worker_live: value.worker_live,
    cancel_requested: value.cancel_requested,
    recovery_available: value.recovery_available
  };
  if (value.schema === "guard-cigar-switch-job.v1") {
    if (!["switch", "rollback", "select", "recover"].includes(String(value.operation)) || !id$1(value.target_runtime_id) || !(value.source_runtime_id === null || id$1(value.source_runtime_id)) || !isCigarGeneration(value.expected_generation) || value.authority_restored !== false || ["can_commit", "keeps_disabled", "reconnect_required", "initial_selection", "cleanup_pending"].some((key2) => typeof value[key2] !== "boolean") || value.keeps_disabled === value.reconnect_required || (value.initial_selection ? value.source_runtime_id !== null || !value.keeps_disabled : !id$1(value.source_runtime_id) || value.source_runtime_id === value.target_runtime_id) || value.operation === "select" && !value.initial_selection || ["switch", "rollback"].includes(String(value.operation)) && value.initial_selection || value.can_commit && (value.phase !== "ready" || value.worker_live !== true || value.cancel_requested)) invalid$1();
    const attempt = recovery(value.recovery_attempt);
    if (value.operation === "recover" ? !attempt || attempt.expected_generation !== value.expected_generation || value.can_commit : attempt !== null) invalid$1();
    return {
      ...base,
      family: "selection",
      operation: value.operation,
      target_runtime_id: value.target_runtime_id,
      source_runtime_id: value.source_runtime_id,
      expected_generation: value.expected_generation,
      can_commit: value.can_commit,
      keeps_disabled: value.keeps_disabled,
      reconnect_required: value.reconnect_required,
      initial_selection: value.initial_selection,
      cleanup_pending: value.cleanup_pending,
      recovery_attempt: attempt
    };
  }
  const schemas = {
    "guard-cigar-install-job.v1": ["install", "verify"],
    "guard-cigar-python-setup-job.v1": ["setup_interpreter"],
    "guard-cigar-catalog-refresh-job.v1": ["refresh_catalog"]
  };
  if (!Object.hasOwn(schemas, String(value.schema)) || !schemas[String(value.schema)].includes(String(value.operation)) || value.activation_granted !== false) invalid$1();
  if (value.operation === "refresh_catalog") return { ...base, family: "preparation", operation: "refresh_catalog", can_commit: false };
  if (!id$1(value.build_id)) invalid$1();
  if (value.operation === "setup_interpreter") {
    if (!(value.interpreter_id === null || id$1(value.interpreter_id)) || value.phase === "ready" && value.interpreter_id === null) invalid$1();
    return {
      ...base,
      family: "preparation",
      operation: "setup_interpreter",
      build_id: value.build_id,
      interpreter_id: value.interpreter_id,
      can_commit: false
    };
  }
  if (!id$1(value.interpreter_id)) invalid$1();
  if (!id$1(value.runtime_id) || !isCigarProducerVersion(value.sdk_version) || !isCigarCoreLabel(value.core_version)) invalid$1();
  return {
    ...base,
    family: "preparation",
    operation: value.operation,
    build_id: value.build_id,
    interpreter_id: value.interpreter_id,
    runtime_id: value.runtime_id,
    sdk_version: value.sdk_version,
    core_version: value.core_version,
    can_commit: false
  };
}
function parseCigarVersionJobs(value) {
  if (!object$1(value) || !Array.isArray(value.jobs) || value.jobs.length > 32) invalid$1();
  const jobs = value.jobs.map(parseCigarVersionJob);
  if (new Set(jobs.map((job) => job.job_id)).size !== jobs.length) invalid$1();
  return jobs;
}
const object = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const id = (v) => typeof v === "string" && /^[a-z0-9_:-]{1,128}$/i.test(v);
const mode = (v) => typeof v === "string" && ["manual", "notify", "prepare"].includes(v);
function invalid() {
  throw new ContextAssistanceApiError("versions_preferences_invalid", "Guard returned incompatible CIGAR update preferences. Refresh preferences.");
}
function preferences(v) {
  if (!object(v) || !mode(v.mode) || typeof v.allow_preview !== "boolean" || typeof v.retain_last_good !== "boolean" || !(v.pinned_build === void 0 || v.pinned_build === null || id(v.pinned_build))) invalid();
  return {
    mode: v.mode,
    allow_preview: v.allow_preview,
    retain_last_good: v.retain_last_good,
    ...typeof v.pinned_build === "string" ? { pinned_build: v.pinned_build } : {}
  };
}
function parseCigarUpdateSettings(v) {
  if (!object(v) || v.schema !== "guard-cigar-update-preferences.v1" || typeof v.revision !== "string" || !/^sha256:[a-f0-9]{64}$/.test(v.revision) || !(v.diagnostic === null || typeof v.diagnostic === "string" && /^[a-z0-9_]{1,160}$/.test(v.diagnostic)) || !Array.isArray(v.locked_settings) || v.locked_settings.length > 64 || !v.locked_settings.every((k) => typeof k === "string" && k.length <= 256 && /^context_assistance_updates(?:\.[a-z_]+)?$/.test(k)) || !object(v.capabilities) || !Array.isArray(v.capabilities.modes) || v.capabilities.modes.length > 3 || !v.capabilities.modes.every(mode) || new Set(v.capabilities.modes).size !== v.capabilities.modes.length || typeof v.capabilities.automatic_preparation !== "boolean" || typeof v.capabilities.automatic_selection !== "boolean" || typeof v.capabilities.retention_reduction !== "boolean") invalid();
  return {
    requested: preferences(v.requested),
    effective: preferences(v.effective),
    revision: v.revision,
    diagnostic: v.diagnostic,
    locked_settings: [...v.locked_settings],
    capabilities: {
      modes: [...v.capabilities.modes],
      automatic_preparation: v.capabilities.automatic_preparation,
      automatic_selection: v.capabilities.automatic_selection,
      retention_reduction: v.capabilities.retention_reduction
    }
  };
}
async function loadCigarVersionsData(signal) {
  const [releases, interpreters, jobs, updates] = await Promise.all([
    requestCigarVersions({ action: "releases" }, void 0, signal),
    requestCigarVersions({ action: "interpreters" }, void 0, signal),
    requestCigarVersions({ action: "jobs" }, void 0, signal),
    requestCigarVersions({ action: "preferences" }, void 0, signal)
  ]);
  const catalog = parseCigarCatalog(releases.result), python = parseCigarInterpreters(interpreters.result);
  const progress = parseCigarVersionJobs(jobs.result), preferences2 = parseCigarUpdateSettings(updates.result);
  const state = await fetchContextInstallations(signal);
  if (state.installation_options === null) throw new Error("Refresh CIGAR updates to read registered installations.");
  return { catalog, interpreters: python, jobs: progress, updates: preferences2, installations: state.installation_options, state };
}
const message = (cause) => cause instanceof Error ? cause.message : "Refresh CIGAR status and jobs before trying again.";
function useCigarVersions(capture) {
  const [data, setData] = reactExports.useState(null);
  const [loading, setLoading] = reactExports.useState(true);
  const [busy, setBusy] = reactExports.useState(false);
  const [error, setError] = reactExports.useState(null);
  const [uncertain, setUncertain] = reactExports.useState(false);
  const [tracking, setTracking] = reactExports.useState(null);
  const revision = reactExports.useRef(0), pending = reactExports.useRef(false), mounted = reactExports.useRef(false);
  const request = reactExports.useRef(null);
  const captureRef = reactExports.useRef(capture);
  captureRef.current = capture;
  const refresh = reactExports.useCallback(async () => {
    if (pending.current) return;
    const current = ++revision.current;
    request.current?.abort();
    const controller = new AbortController();
    request.current = controller;
    const publish = captureRef.current();
    setLoading(true);
    try {
      const value = await loadCigarVersionsData(controller.signal);
      if (current !== revision.current || !mounted.current) return;
      setData(value);
      publish(value.state);
      setError(null);
      setUncertain(false);
    } catch (cause) {
      if (current === revision.current && mounted.current && !controller.signal.aborted) {
        setError(message(cause));
        setUncertain(true);
      }
    } finally {
      if (current === revision.current && mounted.current) setLoading(false);
    }
  }, []);
  reactExports.useEffect(() => {
    mounted.current = true;
    void refresh();
    return () => {
      mounted.current = false;
      ++revision.current;
      request.current?.abort();
    };
  }, [refresh]);
  reactExports.useEffect(() => {
    const focus = () => {
      if (!document.hidden) void refresh();
    };
    window.addEventListener("focus", focus);
    document.addEventListener("visibilitychange", focus);
    return () => {
      window.removeEventListener("focus", focus);
      document.removeEventListener("visibilitychange", focus);
    };
  }, [refresh]);
  reactExports.useEffect(() => {
    if (busy || loading || !data?.jobs.some(cigarJobPending)) return;
    const timer = window.setTimeout(() => {
      if (!document.hidden) void refresh();
    }, 1500);
    return () => window.clearTimeout(timer);
  }, [data, busy, loading, refresh]);
  async function perform(input, proof) {
    if (pending.current) return;
    pending.current = true;
    const current = ++revision.current;
    request.current?.abort();
    const controller = new AbortController();
    request.current = controller;
    const publish = captureRef.current();
    setBusy(true);
    setLoading(false);
    setError(null);
    if ("job_id" in input) setTracking(input.job_id);
    try {
      const reply = await requestCigarVersions(input, proof, controller.signal);
      if (current !== revision.current || !mounted.current) return;
      publish(reply.state);
      const value = await loadCigarVersionsData(controller.signal);
      if (current !== revision.current || !mounted.current) return;
      setData(value);
      publish(value.state);
      setUncertain(false);
    } catch (cause) {
      if (current === revision.current && mounted.current && !controller.signal.aborted) {
        setError(message(cause));
        setUncertain(true);
      }
    } finally {
      pending.current = false;
      if (current === revision.current && mounted.current) setBusy(false);
    }
  }
  return { data, loading, busy, error, uncertain, tracking, refresh, perform };
}
function CigarVersionsPanel(props) {
  const versions = useCigarVersions(props.captureStatus);
  const [approval, setApproval] = reactExports.useState(null);
  const [signedCatalog, setSignedCatalog] = reactExports.useState("");
  const { data } = versions;
  const disabled = props.disabled || versions.busy || versions.loading;
  const changesDisabled = disabled || versions.uncertain;
  const selectionDisabled = changesDisabled || props.locked || props.dirty || !props.status || Boolean(props.status.job);
  function choose(action) {
    if (disabled || action.input.action !== "cancel" && versions.uncertain) return;
    if (action.input.action !== "cancel" && props.gate?.enabled) setApproval(action);
    else void versions.perform(action.input);
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-6", "data-testid": "cigar-versions", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "cigar-section-intro", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "cigar-eyebrow", children: "Keep your workflow moving" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { children: "Versions & updates" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "Prepare CIGAR beside your current runtime, then choose when to switch. Opening this page only reads registration and update metadata." })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-2", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", className: versionButton, disabled: props.disabled || versions.busy || versions.loading, onClick: () => void versions.refresh(), children: "Refresh versions & jobs" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        "button",
        {
          type: "button",
          className: versionButton,
          disabled: changesDisabled || !data?.catalog.catalog.remote_feed_configured || !data.catalog.catalog.trust_configured || Boolean(data.catalog.catalog.feed_diagnostic),
          onClick: () => choose({
            input: { action: "refresh_catalog", job_id: cigarVersionJobId() },
            title: "Check for CIGAR catalog updates",
            detail: "Fetch the configured signed release catalog. This does not prepare or switch an SDK."
          }),
          children: "Check for catalog updates"
        }
      )
    ] }),
    versions.loading ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "status", className: "text-sm text-slate-600", children: "Reading CIGAR versions and job metadata…" }) : null,
    versions.busy ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "status", className: "text-sm text-slate-600", children: "Submitting the selected action. Preparation continues as a native job." }) : null,
    versions.error ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { role: "alert", className: "cigar-note", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { children: "CIGAR updates need attention" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: versions.error }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "Refresh versions and jobs before submitting another change." })
    ] }) : null,
    versions.tracking ? /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "break-all text-xs text-slate-600", children: [
      "Last submitted job: ",
      versions.tracking,
      ". Refresh jobs to confirm its outcome."
    ] }) : null,
    props.dirty ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "status", className: "text-sm text-slate-600", children: "You can prepare builds now. Save your CIGAR preference edits before preparing or committing a selection." }) : null,
    data ? /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: versionCard, "aria-label": "CIGAR release catalog", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "text-sm text-slate-600", children: [
          "Catalog: ",
          data.catalog.catalog.source,
          " · ",
          data.catalog.catalog.fresh_for_preparation ? "current for preparation" : "refresh required",
          " · Guard host: ",
          data.catalog.host_platform ?? "not reported by this Guard build"
        ] }),
        !data.catalog.catalog.remote_feed_configured ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-slate-600", children: "A remote release feed is not configured. Guard can still use eligible bundled entries." }) : null,
        data.catalog.catalog.diagnostic ? /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "break-all text-sm text-amber-800", children: [
          "Catalog diagnostic: ",
          data.catalog.catalog.diagnostic
        ] }) : null,
        data.catalog.catalog.trust_diagnostic || data.catalog.catalog.feed_diagnostic ? /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "break-all text-sm text-amber-800", children: [
          "Catalog update configuration: ",
          data.catalog.catalog.trust_diagnostic ?? data.catalog.catalog.feed_diagnostic
        ] }) : null,
        /* @__PURE__ */ jsxRuntimeExports.jsxs("details", { className: "text-sm text-slate-600", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("summary", { className: "cursor-pointer", children: "Import a signed catalog" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2", children: "Use a catalog signed by an already trusted release key. Importing metadata never selects or starts a runtime." }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "mt-2 block", children: [
            "Signed catalog JSON",
            /* @__PURE__ */ jsxRuntimeExports.jsx(
              "textarea",
              {
                className: versionField,
                rows: 4,
                maxLength: 2e6,
                value: signedCatalog,
                disabled: changesDisabled,
                onChange: (event) => setSignedCatalog(event.target.value),
                spellCheck: false
              }
            )
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            "button",
            {
              type: "button",
              className: versionButton,
              disabled: changesDisabled || !signedCatalog.trim() || !data.catalog.catalog.trust_configured,
              onClick: () => choose({
                input: { action: "import_catalog", signed_catalog: signedCatalog },
                title: "Import signed CIGAR catalog",
                detail: "Verify and publish this release metadata using Guard's existing trusted keys. Leave the selected runtime unchanged."
              }),
              children: "Verify & import catalog"
            }
          )
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(CigarVersionJobsPanel, { jobs: data.jobs, status: props.status, disabled, selectionDisabled, onAction: choose }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(CigarVersionBuildsPanel, { data, status: props.status, disabled: changesDisabled, selectionDisabled, onAction: choose }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(CigarUpdatePreferencesPanel, { value: data.updates, builds: data.catalog.builds, disabled: changesDisabled, onAction: choose })
    ] }) : null,
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      SettingsSaveProofModal,
      {
        open: approval !== null,
        mode: "verify-save",
        gate: props.gate,
        title: approval?.title ?? "Confirm CIGAR change",
        detail: approval?.detail ?? "",
        confirmLabel: "Confirm change",
        error: null,
        pending: versions.busy,
        onCancel: () => setApproval(null),
        onConfirm: (proof) => {
          if (approval) {
            const action = approval;
            setApproval(null);
            void versions.perform(action.input, proof);
          }
        }
      }
    )
  ] });
}
function ordered(value) {
  if (Array.isArray(value)) return value.map(ordered);
  if (value !== null && typeof value === "object") {
    const fields = value;
    return Object.fromEntries(Object.keys(fields).sort().map((key2) => [key2, ordered(fields[key2])]));
  }
  return value;
}
const defaults = (value) => ({
  ...value,
  features: { ...value.features, execution_context: value.features.execution_context === true }
});
const sameCigarPreferences = (a, b) => JSON.stringify(ordered(defaults(a))) === JSON.stringify(ordered(defaults(b)));
const same = sameCigarPreferences;
function withCigarSelection(settings, native, previous, draft = false) {
  if (same(native, previous)) return settings;
  const current = settings.context_assistance;
  if (!current) return settings;
  if (!draft && !same(current, previous)) return settings;
  if (draft && current.runtime_id !== previous.runtime_id) return settings;
  const config = !draft || same(current, previous) ? native : { ...current, runtime_id: native.runtime_id, enabled: current.enabled && native.enabled };
  return {
    ...settings,
    context_assistance: config,
    ...settings.context_assistance_requested !== void 0 ? { context_assistance_requested: native } : {}
  };
}
function ContextAssistanceSettings(props) {
  const workspace = props.workspace === true;
  const [status, setStatus] = reactExports.useState(null);
  const [installations, setInstallations] = reactExports.useState(null);
  const [error, setError] = reactExports.useState(null);
  const [loading, setLoading] = reactExports.useState(true);
  const [busy, setBusy] = reactExports.useState(false);
  const request = reactExports.useRef(null);
  const revision = reactExports.useRef(0);
  const pending = reactExports.useRef(false);
  const mounted = reactExports.useRef(false);
  const savedRevision = JSON.stringify(props.savedValue);
  const versionInputs = reactExports.useRef({ saved: props.savedValue, changed: props.onSelectionChanged });
  versionInputs.current = { saved: props.savedValue, changed: props.onSelectionChanged };
  const captureVersionStatus = reactExports.useCallback(() => {
    if (pending.current) return (_result) => {
    };
    const current = ++revision.current;
    request.current?.abort();
    const previous = versionInputs.current.saved;
    return (result) => {
      if (!mounted.current || current !== revision.current || pending.current) return;
      setStatus(result);
      setLoading(false);
      if (result.installation_options !== null) setInstallations(result.installation_options);
      if (previous && !sameCigarPreferences(previous, result.preferences)) {
        versionInputs.current.changed?.(result.preferences, previous);
      }
    };
  }, []);
  const refresh = reactExports.useCallback(async () => {
    if (pending.current) return;
    const current = ++revision.current;
    request.current?.abort();
    const controller = new AbortController();
    request.current = controller;
    try {
      const result = await (workspace ? fetchContextInstallations(controller.signal) : fetchContextAssistance(controller.signal));
      if (current !== revision.current) return;
      setStatus(result);
      if (workspace) setInstallations(result.installation_options ?? []);
      setError(null);
    } catch (cause) {
      if (current !== revision.current) return;
      setStatus(null);
      if (workspace) setInstallations(null);
      setError(cause instanceof Error ? cause.message : "Context assistance status is unavailable.");
    } finally {
      if (current === revision.current) setLoading(false);
    }
  }, [workspace]);
  reactExports.useEffect(() => {
    void refresh();
  }, [refresh, savedRevision]);
  reactExports.useEffect(() => {
    const onFocus = () => {
      if (!document.hidden) void refresh();
    };
    window.addEventListener("focus", onFocus);
    document.addEventListener("visibilitychange", onFocus);
    return () => {
      window.removeEventListener("focus", onFocus);
      document.removeEventListener("visibilitychange", onFocus);
    };
  }, [refresh]);
  reactExports.useEffect(() => {
    if (!status?.job && !status?.effective_enabled) return;
    const timer = window.setTimeout(() => {
      if (!document.hidden) void refresh();
    }, status.job ? 500 : 1e4);
    return () => window.clearTimeout(timer);
  }, [status, refresh]);
  const onBusyChange = props.onBusyChange;
  reactExports.useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      revision.current += 1;
      request.current?.abort();
      onBusyChange(false);
    };
  }, [onBusyChange]);
  async function perform(action) {
    if (pending.current || props.disabled) return;
    pending.current = true;
    const current = ++revision.current;
    request.current?.abort();
    const controller = new AbortController();
    request.current = controller;
    setBusy(true);
    props.onBusyChange(true);
    setError(null);
    const value2 = props.value ?? status?.preferences;
    if (action === "stop" && value2) props.onChange({ ...value2, enabled: false });
    try {
      const result = action === "installations" ? await fetchContextInstallations(controller.signal) : await controlContextAssistance(action, controller.signal);
      if (current !== revision.current) return;
      setStatus(result);
      if (action === "installations") setInstallations(result.installation_options ?? []);
      if (action === "stop") props.onStopped(result.preferences);
    } catch (cause) {
      if (current !== revision.current) return;
      setStatus(null);
      setError(cause instanceof Error ? cause.message : "The context assistance operation did not return a verified result. Refresh its status.");
    } finally {
      pending.current = false;
      if (mounted.current && current === revision.current) {
        setBusy(false);
        setLoading(false);
        props.onBusyChange(false);
      }
    }
  }
  const value = props.value ?? status?.preferences ?? null;
  const saved = props.savedValue ?? status?.preferences ?? null;
  const dirty = value && saved ? !sameCigarPreferences(value, saved) : value !== saved;
  const controls = /* @__PURE__ */ jsxRuntimeExports.jsx(
    ContextSettingsControls,
    {
      value,
      status,
      installations,
      loading,
      busy,
      disabled: props.disabled,
      locked: props.locked,
      dirty,
      error: workspace ? null : error,
      onChange: props.onChange,
      onRefresh: () => void refresh(),
      onChooseRuntime: () => void perform("installations"),
      onControl: (action) => void perform(action),
      onManageVersions: workspace ? () => {
        const url = new URL(window.location.href);
        url.searchParams.set("section", "versions");
        commitDashboardLocation(url.pathname + url.search + url.hash);
      } : void 0
    }
  );
  const access = /* @__PURE__ */ jsxRuntimeExports.jsx(
    ContextWorkspacesPanel,
    {
      ready: status?.effective_enabled === true,
      generation: status?.generation ?? null,
      dirty,
      documentsAllowed: status?.effective_preferences.sources.workspace_documents === true,
      agentsAllowed: status?.effective_preferences.features.agent_context === true,
      executionAllowed: status?.effective_preferences.features.execution_context === true && status?.capabilities?.execution_context === true,
      sharingAllowed: status?.effective_preferences.features.shared_agents === true && status?.runtime?.shared_compile_verified === true,
      gate: props.gate ?? null
    }
  );
  return workspace ? /* @__PURE__ */ jsxRuntimeExports.jsx(
    CigarWorkspace,
    {
      status,
      installations,
      loading,
      busy,
      disabled: props.disabled,
      dirty,
      error,
      stopAvailable: Boolean(value?.enabled || saved?.enabled || status?.job || status?.effective_enabled || error),
      controls,
      access,
      data: props.data,
      versions: /* @__PURE__ */ jsxRuntimeExports.jsx(
        CigarVersionsPanel,
        {
          status,
          disabled: props.disabled || busy,
          locked: props.locked,
          dirty,
          gate: props.gate ?? null,
          captureStatus: captureVersionStatus
        }
      ),
      onRefresh: () => void refresh(),
      onStart: () => void perform("activate"),
      onStop: () => void perform("stop")
    }
  ) : /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
    controls,
    access
  ] });
}
const button = "min-h-11 rounded-lg border border-slate-200 px-3 py-2 text-sm font-semibold text-brand-dark disabled:cursor-not-allowed disabled:opacity-50";
function contextDiagnostics(status, data) {
  const runtime = status.runtime ?? status.last_check;
  const code = (value) => value === null ? null : /^[a-z0-9_]{1,160}$/.test(value) ? value : "redacted_diagnostic";
  return {
    schema: "guard-context-diagnostics.v1",
    exported_at: (/* @__PURE__ */ new Date()).toISOString(),
    data_role: true,
    availability: status.availability,
    requested_enabled: status.requested_enabled,
    effective_enabled: status.effective_enabled,
    qualification: status.qualification,
    diagnostic: code(status.diagnostic),
    restriction: code(status.restriction),
    status_observation: "last_successful_refresh",
    verification_permitted: status.verification_permitted,
    generation: status.generation,
    job: status.job ? { operation: status.job.operation, phase: status.job.phase } : null,
    runtime: runtime ? {
      python_version: runtime.interpreter.version,
      python_implementation: runtime.interpreter.implementation,
      sdk_version: runtime.package_version,
      protocol: runtime.protocol,
      worker_fingerprint: runtime.worker_fingerprint,
      package_fingerprint: runtime.package_fingerprint,
      compile_verified: runtime.compile_verified,
      persistence_compile_verified: runtime.persistence_compile_verified ?? false,
      active: runtime.active
    } : null,
    storage: { mode: status.effective_preferences.storage.mode, retention_hours: status.effective_preferences.storage.retention_hours },
    counts: data ? {
      active_scopes: data.active_scopes,
      selected_files: data.selected_files,
      current_contexts: data.current_contexts,
      history_entries: data.history_entries,
      history_encoded_bytes: data.history_encoded_bytes,
      agent_sessions: data.agent_sessions,
      saved_evidence: data.saved_evidence ? {
        status: data.saved_evidence.status,
        slots: data.saved_evidence.slots,
        bytes: data.saved_evidence.bytes,
        unresolved_writes: data.saved_evidence.unresolved_writes,
        invalid_records: data.saved_evidence.invalid_records,
        diagnostic: code(data.saved_evidence.diagnostic)
      } : null
    } : null,
    redaction: "No source text, queries, workspace paths, executable paths, credentials or approval tokens."
  };
}
function ContextDataRepairPanel({ savedEnabled, disabled, onStopped, onBusyChange }) {
  const [status, setStatus] = reactExports.useState(null);
  const [data, setData] = reactExports.useState(null);
  const [busy, setBusy] = reactExports.useState(false);
  const [message2, setMessage] = reactExports.useState(null);
  const [confirm, setConfirm] = reactExports.useState(null);
  const request = reactExports.useRef(null);
  const revision = reactExports.useRef(0);
  async function refresh(signal) {
    const value = await fetchContextAssistance(signal);
    if (signal.aborted) return;
    setStatus(value);
    setData(null);
    const summary = await fetchContextData(signal);
    if (!signal.aborted) setData(summary);
  }
  async function perform(operation2, changes = false) {
    if (busy || disabled) return;
    const current = ++revision.current;
    request.current?.abort();
    const controller = new AbortController();
    request.current = controller;
    setBusy(true);
    setMessage(null);
    if (changes) onBusyChange(true);
    try {
      await operation2(controller.signal);
    } catch (cause) {
      if (revision.current === current && !controller.signal.aborted) {
        setStatus(null);
        setData(null);
        setMessage(cause instanceof Error ? cause.message : "Context data is unavailable. Refresh its status.");
      }
    } finally {
      if (changes) onBusyChange(false);
      if (revision.current === current) setBusy(false);
    }
  }
  reactExports.useEffect(() => {
    const controller = new AbortController();
    request.current = controller;
    void refresh(controller.signal).catch(() => {
      if (!controller.signal.aborted) setMessage("Context status is unavailable. Refresh or turn off the feature to check it.");
    });
    return () => {
      revision.current += 1;
      controller.abort();
      request.current?.abort();
      onBusyChange(false);
    };
  }, []);
  function execute(action) {
    setConfirm(null);
    void perform(async (signal) => {
      if (action === "history") {
        const value = await forgetContextHistory(signal);
        if (!signal.aborted) {
          setData(value);
          setMessage("Prepared context history cleared. Current context and source access remain available.");
        }
      } else if (action === "saved") {
        await forgetSavedEvidence(signal);
        await refresh(signal);
        if (!signal.aborted) setMessage("Saved evidence removed and current context access ended. Check and start the runtime, then grant sources again to continue.");
      } else if (action === "data") {
        await manageContextWorkspace("clear", void 0, void 0, signal);
        await refresh(signal);
        if (!signal.aborted) setMessage("Context data cleared. Grant workspace and app access again before preparing more context.");
      } else {
        const value = await controlContextAssistance("recheck", signal);
        if (!signal.aborted) {
          setStatus(value);
          setData(null);
          setMessage("Runtime check scheduled. Refresh status to see the result; earlier context access has ended.");
        }
      }
    }, true);
  }
  function stop() {
    void perform(async (signal) => {
      const value = await controlContextAssistance("stop", signal);
      if (!signal.aborted) {
        setStatus(value);
        setData(null);
        onStopped(value.preferences);
        setMessage("Context assistance is off. Guard approvals and evidence remain available.");
      }
    }, true);
  }
  const ready = Boolean(status?.effective_enabled);
  const copy = status ? contextStatusCopy(status) : { label: "Status unavailable", detail: "Refresh context status to inspect this optional feature." };
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(SettingsFormSection, { title: "Context data and repair", description: "Inspect or clear optional context separately from Guard approvals and evidence.", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { role: "region", "aria-label": "Context data and repair controls", className: "space-y-3 py-4", "aria-busy": busy, children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "status", className: "text-sm font-semibold text-brand-dark", children: copy.label }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-slate-600", children: copy.detail }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "text-sm text-slate-600", children: [
        "Prepared contexts and history use local memory. ",
        status?.capabilities?.private_persistence ? "Optional saved evidence uses private local files, with no Guard encryption. It remains after the runtime stops until expiry cleanup or removal. Guard removes expired evidence while running or before reuse after launch. Permissions must be granted again after restart." : "This build cannot activate saved evidence. Existing saved evidence can still be inspected and removed below."
      ] }),
      data ? /* @__PURE__ */ jsxRuntimeExports.jsxs("dl", { className: "grid grid-cols-2 gap-2 text-sm text-slate-600", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { children: "Active workspace/app grants" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { children: data.active_scopes }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { children: "Selected files" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { children: data.selected_files }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { children: "Current contexts" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { children: data.current_contexts }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { children: "Prepared history entries" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { children: data.history_entries }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { children: "Encoded history payload" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("dd", { children: [
          data.history_encoded_bytes.toLocaleString(),
          " bytes"
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { children: "App connections" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { children: data.agent_sessions })
      ] }) : /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-slate-600", children: "Live context counts are available while a verified runtime is ready." }),
      data?.saved_evidence ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-2 text-sm text-slate-600", role: "region", "aria-label": "Saved context evidence", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "status", children: savedEvidenceCopy(data.saved_evidence) }),
        data.saved_evidence.slots !== null ? /* @__PURE__ */ jsxRuntimeExports.jsxs("dl", { className: "grid grid-cols-2 gap-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { children: "Saved workspace/app stores" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { children: data.saved_evidence.slots }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { children: "Saved file bytes" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { children: data.saved_evidence.bytes?.toLocaleString() ?? "Unavailable" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { children: "Note writes to reconcile" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { children: data.saved_evidence.unresolved_writes ?? "Unavailable" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { children: "Expired stores awaiting cleanup" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { children: data.saved_evidence.expired_slots ?? "Unavailable" })
        ] }) : null,
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "Saved evidence is limited to eight stores and 528 MiB of logical file bytes, including database journals. This does not measure process memory." })
      ] }) : null,
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-slate-600", children: "History is limited to eight entries and 512 KiB of encoded payload per workspace/app grant, with the configured retention period. These counts do not measure process memory or execution safety." }),
      message2 ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "status", className: "text-sm text-slate-600", children: message2 }) : null,
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("button", { className: button, type: "button", disabled: busy || disabled, onClick: () => void perform(refresh), children: "Refresh context data" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("button", { className: button, type: "button", disabled: busy || disabled || !ready || !data?.history_entries, onClick: () => setConfirm("history"), children: "Clear context history" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("button", { className: button, type: "button", disabled: busy || disabled || !ready && !data?.saved_evidence, onClick: () => setConfirm("data"), children: "Clear all context data" }),
        data?.saved_evidence && data.saved_evidence.status !== "empty" && data.saved_evidence.status !== "unsupported" ? /* @__PURE__ */ jsxRuntimeExports.jsx("button", { className: button, type: "button", disabled: busy || disabled, onClick: () => setConfirm("saved"), children: "Remove saved evidence" }) : null,
        /* @__PURE__ */ jsxRuntimeExports.jsx("button", { className: button, type: "button", disabled: busy || disabled || !status?.verification_permitted || !status?.preferences.runtime_id || Boolean(status.job), onClick: () => setConfirm("recheck"), children: "Recheck context runtime" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("button", { className: button, type: "button", disabled: busy || !status, onClick: () => {
          if (status) downloadBlob(new Blob([JSON.stringify(contextDiagnostics(status, data), null, 2)], { type: "application/json" }), "guard-context-diagnostics.json");
        }, children: "Export context diagnostics" }),
        savedEnabled || status?.requested_enabled || status?.effective_enabled || status?.job ? /* @__PURE__ */ jsxRuntimeExports.jsx("button", { className: button, type: "button", disabled: busy || disabled, onClick: stop, children: "Turn off context assistance" }) : null,
        /* @__PURE__ */ jsxRuntimeExports.jsx("a", { className: `${button} inline-flex items-center`, href: guardAwareHref("/cigar?section=runtime"), children: "Manage context setup" })
      ] }),
      !ready ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-slate-600", children: "If a runtime is unavailable, turn off assistance to release its context. Rechecking requires an enrolled Python 3.14 runtime." }) : null
    ] }),
    confirm ? /* @__PURE__ */ jsxRuntimeExports.jsx(
      ConfirmDialog,
      {
        title: confirm === "history" ? "Clear prepared context history?" : confirm === "saved" ? "Remove saved evidence?" : confirm === "data" ? "Clear all context data?" : "Recheck context runtime?",
        description: confirm === "history" ? "Deletes retained historical briefs. Current contexts and source permissions stay available. Guard approvals and evidence are unchanged." : confirm === "saved" ? "Ends current context access and removes saved source evidence and reviewed notes, including inactive stores. Check and start the runtime and grant access again to continue. Guard approvals and evidence are unchanged." : confirm === "data" ? "Closes context graphs and deletes retained briefs, saved evidence, native context origins, source grants and app connections. Grant access again to continue. Guard approvals and evidence are unchanged." : "Ends current context access and checks the selected runtime again. An enabled preference may start a fresh runtime. Grant source and app access again afterward.",
        confirmLabel: confirm === "history" ? "Clear history" : confirm === "saved" ? "Remove saved evidence" : confirm === "data" ? "Clear context data" : "Recheck runtime",
        tone: confirm === "recheck" ? "default" : "destructive",
        onCancel: () => setConfirm(null),
        onConfirm: () => execute(confirm)
      }
    ) : null
  ] });
}
const PRESENTATION_SCHEMA_VERSION = 1;
const LEGACY = {
  simple: "everyday",
  advanced: "technical",
  developer: "technical"
};
function resolvePresentationMode(input) {
  const revision = typeof input.revision === "number" && Number.isSafeInteger(input.revision) && input.revision >= 0 ? input.revision : 0;
  const writable = input.writable !== false;
  const resolved = (value, source, explicit, diagnostic22 = null) => ({
    value,
    source,
    explicit,
    writable,
    schemaVersion: PRESENTATION_SCHEMA_VERSION,
    revision,
    diagnostic: diagnostic22
  });
  if (input.readError) return resolved("everyday", "read-error", false, "presentation_settings_unavailable");
  if (input.sessionPreview === "everyday" || input.sessionPreview === "technical") {
    return resolved(input.sessionPreview, "session-preview", true);
  }
  const unsupportedSchema = input.schemaVersion !== void 0 && input.schemaVersion !== PRESENTATION_SCHEMA_VERSION;
  const persistedMode = !unsupportedSchema && (input.value === "everyday" || input.value === "technical") ? input.value : null;
  if (persistedMode !== null && input.explicit === true) {
    return resolved(persistedMode, "local-explicit", true);
  }
  if (!unsupportedSchema && typeof input.value === "string" && LEGACY[input.value]) {
    return resolved(LEGACY[input.value], "migrated", true, `migrated_legacy_${input.value}_presentation_mode`);
  }
  if (input.cloudProfile === "everyday" || input.cloudProfile === "technical") {
    return resolved(input.cloudProfile, "cloud-profile", false);
  }
  if (persistedMode !== null) {
    return resolved(persistedMode, "default", false);
  }
  let diagnostic2 = null;
  if (unsupportedSchema) {
    diagnostic2 = "unsupported_presentation_schema_fell_back_to_everyday";
  } else if (input.value !== void 0 && input.value !== null && input.value !== "") {
    diagnostic2 = "unknown_presentation_mode_fell_back_to_everyday";
  }
  return resolved("everyday", "default", false, diagnostic2);
}
const presentationModeOptions = [
  { value: "everyday", label: "Everyday Mode - clear summaries" },
  { value: "technical", label: "Technical Mode - show more detail" }
];
function resolveSettingsPresentation(settings) {
  const resolved = resolvePresentationMode({
    value: settings.presentation_mode,
    explicit: settings.presentation_mode_explicit,
    schemaVersion: settings.presentation_schema_version,
    revision: settings.presentation_revision,
    writable: settings.presentation?.writable ?? true
  });
  const authoritative = settings.presentation;
  if (isAuthoritativePresentation(authoritative, resolved)) {
    return {
      ...resolved,
      source: authoritative.source,
      writable: authoritative.writable,
      diagnostic: authoritative.diagnostic
    };
  }
  return resolved;
}
function isAuthoritativePresentation(presentation, resolved) {
  return presentation !== void 0 && presentation.value === resolved.value && presentation.explicit === resolved.explicit && presentation.schema_version === resolved.schemaVersion && presentation.revision === resolved.revision;
}
function buildSettingsUpdatePayload(draft, saved) {
  const previous = saved ?? draft;
  const presentationChanged = draft.presentation_mode !== previous.presentation_mode || draft.presentation_mode_explicit !== previous.presentation_mode_explicit;
  const payload = { ...draft };
  delete payload.presentation;
  delete payload.presentation_diagnostic;
  delete payload.context_assistance_diagnostic;
  delete payload.context_assistance_requested;
  if (draft.context_assistance_requested === void 0 || settingsValueEquals(draft.context_assistance, previous.context_assistance)) {
    delete payload.context_assistance;
  }
  delete payload.presentation_mode;
  delete payload.presentation_mode_explicit;
  delete payload.presentation_schema_version;
  delete payload.presentation_revision;
  if (presentationChanged) {
    payload.presentation_mode = draft.presentation_mode;
    payload.presentation_mode_explicit = true;
    payload.presentation_schema_version = PRESENTATION_SCHEMA_VERSION;
    payload.presentation_revision = previous.presentation_revision;
  }
  return payload;
}
function normalizePresentationSettings(settings) {
  const presentation = resolveSettingsPresentation(settings);
  return {
    ...settings,
    presentation_mode: presentation.value,
    presentation_mode_explicit: presentation.explicit,
    presentation_schema_version: presentation.schemaVersion,
    presentation_revision: presentation.revision,
    presentation: {
      value: presentation.value,
      source: presentation.source,
      explicit: presentation.explicit,
      writable: presentation.writable,
      schema_version: presentation.schemaVersion,
      revision: presentation.revision,
      diagnostic: presentation.diagnostic
    },
    presentation_diagnostic: presentation.diagnostic
  };
}
function parsePresentationMode(value) {
  if (value === "everyday" || value === "technical") {
    return value;
  }
  return null;
}
function applyPresentationMode(settings, mode2) {
  return {
    ...settings,
    presentation_mode: mode2,
    presentation_mode_explicit: true,
    presentation_schema_version: PRESENTATION_SCHEMA_VERSION
  };
}
function presentationModeStatus(presentation) {
  if (presentation.source === "migrated") {
    return presentation.explicit ? "Chosen on this device. Your previous display preference was migrated." : "Recommended default. Your previous display preference was migrated.";
  }
  return presentation.explicit ? "Chosen on this device." : "Recommended default.";
}
const PRESENTATION_PAYLOAD_KEYS = /* @__PURE__ */ new Set([
  "presentation_mode",
  "presentation_mode_explicit",
  "presentation_schema_version",
  "presentation_revision"
]);
function settingsValueEquals(a, b) {
  if (a === b) {
    return true;
  }
  if (Array.isArray(a) && Array.isArray(b)) {
    return a.length === b.length && a.every((item, index) => settingsValueEquals(item, b[index]));
  }
  if (a !== null && b !== null && typeof a === "object" && typeof b === "object") {
    const aRecord = a;
    const bRecord = b;
    const aKeys = Object.keys(aRecord);
    const bKeys = Object.keys(bRecord);
    if (aKeys.length !== bKeys.length) {
      return false;
    }
    return aKeys.every((key2) => settingsValueEquals(aRecord[key2], bRecord[key2]));
  }
  return false;
}
function isPresentationOnlyChange(draft, saved) {
  const previous = saved ?? draft;
  const presentationChanged = draft.presentation_mode !== previous.presentation_mode || draft.presentation_mode_explicit !== previous.presentation_mode_explicit;
  if (!presentationChanged) {
    return false;
  }
  for (const key2 of Object.keys(draft)) {
    if (key2 === "presentation" || key2 === "presentation_diagnostic") {
      continue;
    }
    if (PRESENTATION_PAYLOAD_KEYS.has(key2)) {
      continue;
    }
    if (!settingsValueEquals(draft[key2], previous[key2])) {
      return false;
    }
  }
  return true;
}
function presentationOnlySavePayload(draft, saved) {
  if (!isPresentationOnlyChange(draft, saved)) {
    return null;
  }
  const base = buildSettingsUpdatePayload(draft, saved);
  return {
    presentation_mode: base.presentation_mode,
    presentation_mode_explicit: base.presentation_mode_explicit,
    presentation_schema_version: base.presentation_schema_version,
    presentation_revision: base.presentation_revision
  };
}
const resolveSecurityLevelDescription = resolveProtectionLevelCopy;
function resolveInitialSettingsTab(search) {
  const section = new URLSearchParams(search).get("section");
  return section !== null && isLocalSettingsTabKey(section) ? section : "protection";
}
function resolveSecurityLevelCardDescription(level) {
  if (level === "relaxed") return "Warn on dangerous actions. Most safe actions run without a prompt.";
  if (level === "balanced") return "Ask before secret access, hidden execution, exfiltration, and destructive actions.";
  if (level === "strict") return "Ask more often, including new network destinations.";
  return "Use the exact choices below for this machine and connected apps.";
}
function resolveFineTuningSectionDescription(securityLevel) {
  if (securityLevel === "custom") {
    return "Using custom rules on top of this machine's protection posture.";
  }
  const postureLabel = securityLevel === "strict" ? "Extra careful" : "Protected";
  return `These rules follow ${postureLabel}. Switch to Custom to change how Guard handles each action type.`;
}
function isFineTuningEditable(securityLevel) {
  return securityLevel === "custom";
}
const REPAIR_APPROVAL_CENTER_LABELS = {
  locator: "stale approval link",
  daemon_state: "stale service record",
  daemon_process: "unresponsive background service",
  daemon_discovery_key: "invalid discovery key"
};
function resolveRepairApprovalCenterMessage(cleared) {
  if (cleared.length === 0) {
    return "Nothing needed repair. The approval center is already reachable from this dashboard.";
  }
  const labels = cleared.map((code) => REPAIR_APPROVAL_CENTER_LABELS[code] ?? code);
  return `Approval center repaired: cleared ${humanizeList(labels)}. Approval links reconnect the next time a hook reaches Guard.`;
}
function buildClearPolicyPayload(all) {
  return { all };
}
function buildClearReviewQueuePayload(input) {
  return {
    status: "pending",
    ...input.approvalPassword ? { approval_password: input.approvalPassword } : {},
    ...input.approvalTotpCode ? { approval_totp_code: input.approvalTotpCode } : {}
  };
}
function buildApprovalGateWriteProof(credentials) {
  const approvalPassword = credentials?.currentPassword?.trim() ?? "";
  const approvalTotpCode = credentials?.totpCode?.trim() ?? "";
  return {
    ...approvalPassword.length > 0 ? { approval_password: approvalPassword } : {},
    ...approvalTotpCode.length > 0 ? { approval_totp_code: approvalTotpCode } : {}
  };
}
function resolveTotpSetupStep(enrollment) {
  return enrollment !== null ? "scan" : "confirm";
}
function hasApprovalGateSettingsChanged(gateConfig, enabled, cooldownSeconds, strictAllDecisions) {
  if (gateConfig === null) {
    return false;
  }
  return enabled !== gateConfig.enabled || cooldownSeconds !== gateConfig.cooldown_seconds || strictAllDecisions !== gateConfig.strict_all_decisions;
}
function effectiveApprovalGateCooldownSeconds(cooldownSeconds, totpEnabled) {
  return totpEnabled ? 0 : cooldownSeconds;
}
function resolveTotpSetupModalTitle(isConfirmStep) {
  if (isConfirmStep) {
    return "Confirm your approval password";
  }
  return "Scan and verify";
}
function resolveTotpSetupModalDescription(isConfirmStep) {
  if (isConfirmStep) {
    return "Guard needs your approval password before it can generate a QR code for your authenticator app.";
  }
  return "Open your authenticator app, add an account, scan the code, then enter the live six-digit code.";
}
const actionOptions = [
  { value: "allow", label: "Allow" },
  { value: "warn", label: "Allow and record" },
  { value: "review", label: "Ask once" },
  { value: "require-reapproval", label: "Ask every time" },
  { value: "sandbox-required", label: "Run in sandbox" },
  { value: "block", label: "Stop" }
];
const surfacePolicyOptions = [
  { value: "attention-aware", label: "In the app when possible" },
  { value: "approval-center", label: "Always in Guard" },
  { value: "native-only", label: "Never open a browser" }
];
const riskControls = [
  { key: "local_secret_read", label: "Local secrets", description: "Files such as .env, .npmrc, .netrc, SSH keys, and cloud credentials.", consequence: RISK_CONTROL_CONSEQUENCES["local_secret_read"] },
  { key: "credential_exfiltration", label: "Credential sharing", description: "Commands or scripts that appear to send keys, tokens, or credentials away.", consequence: RISK_CONTROL_CONSEQUENCES["credential_exfiltration"] },
  { key: "data_flow_exfiltration", label: "Secret data flow", description: "Detected source-to-sink route where a local secret is read and its value reaches a network or external sink.", consequence: RISK_CONTROL_CONSEQUENCES["data_flow_exfiltration"] },
  { key: "destructive_shell", label: "Destructive commands", description: "Shell actions that delete, overwrite, or rewrite local files.", consequence: RISK_CONTROL_CONSEQUENCES["destructive_shell"] },
  { key: "encoded_execution", label: "Hidden scripts", description: "Encoded, encrypted, or decoded-and-run command payloads.", consequence: RISK_CONTROL_CONSEQUENCES["encoded_execution"] },
  { key: "network_egress", label: "New network destinations", description: "Outbound connections Guard has not seen in this context.", consequence: RISK_CONTROL_CONSEQUENCES["network_egress"] },
  { key: "prompt_injection", label: "Prompt injection", description: "Prompts that try to override Guard, leak secrets, or weaken review.", consequence: RISK_CONTROL_CONSEQUENCES["prompt_injection"] },
  { key: "mcp_dangerous_tool", label: "Connected tools", description: "Tool calls that can read files, run commands, or reach the network.", consequence: RISK_CONTROL_CONSEQUENCES["mcp_dangerous_tool"] },
  { key: "malicious_skill", label: "Skills", description: "Agent skills from unknown or risky sources.", consequence: RISK_CONTROL_CONSEQUENCES["malicious_skill"] },
  { key: "package_script", label: "Package scripts", description: "Lifecycle scripts such as postinstall, prepare, and prepublish.", consequence: RISK_CONTROL_CONSEQUENCES["package_script"] },
  { key: "persistence", label: "Persistence", description: "Startup files, launch agents, scheduled jobs, and recurring hooks.", consequence: RISK_CONTROL_CONSEQUENCES["persistence"] },
  { key: "guard_bypass", label: "Guard bypass", description: "Attempts to disable Guard hooks, policies, or approval flow.", consequence: RISK_CONTROL_CONSEQUENCES["guard_bypass"] },
  { key: "cloud_advisory", label: "Cloud advisories", description: "Team and Cloud guidance for known risky patterns.", consequence: RISK_CONTROL_CONSEQUENCES["cloud_advisory"] },
  { key: "encoded_exfiltration", label: "Encoded exfiltration", description: "Encoded payloads that hide secret extraction and network transfer.", consequence: RISK_CONTROL_CONSEQUENCES["encoded_exfiltration"] },
  { key: "package_unknown", label: "Unrecognized packages", description: "Packages Guard cannot identify or find reputation for.", consequence: RISK_CONTROL_CONSEQUENCES["package_unknown"] },
  { key: "package_lockfile_drift", label: "Lockfile bumps", description: "Manifest dependencies the lockfile does not pin yet.", consequence: RISK_CONTROL_CONSEQUENCES["package_lockfile_drift"] },
  { key: "package_direct_source", label: "Direct package sources", description: "Git, URL, archive, local-path and replaced sources instead of the registry.", consequence: RISK_CONTROL_CONSEQUENCES["package_direct_source"] },
  { key: "package_custom_registry", label: "Custom registries", description: "Installs that use a non-default package index or registry.", consequence: RISK_CONTROL_CONSEQUENCES["package_custom_registry"] },
  { key: "package_install", label: "Every package install", description: "Every package install or update, even with no risk signal.", consequence: RISK_CONTROL_CONSEQUENCES["package_install"] },
  { key: "low_trust_artifact", label: "Low trust scores", description: "Skills, MCP servers, and plugins scoring below 80 in the HOL Registry.", consequence: RISK_CONTROL_CONSEQUENCES["low_trust_artifact"] },
  { key: "runtime_known_vulnerable", label: "Vulnerable runtimes", description: "Node.js builds with a known high or critical advisory, checked before launch.", consequence: RISK_CONTROL_CONSEQUENCES["runtime_known_vulnerable"] }
];
const riskProfileActions = {
  relaxed: {
    local_secret_read: "warn",
    credential_exfiltration: "warn",
    data_flow_exfiltration: "warn",
    destructive_shell: "warn",
    encoded_execution: "warn",
    network_egress: "allow",
    prompt_injection: "warn",
    mcp_dangerous_tool: "warn",
    malicious_skill: "warn",
    package_script: "warn",
    persistence: "warn",
    guard_bypass: "warn",
    cloud_advisory: "allow",
    encoded_exfiltration: "warn",
    package_unknown: "allow",
    package_lockfile_drift: "allow",
    package_direct_source: "allow",
    package_custom_registry: "allow",
    package_install: "allow",
    low_trust_artifact: "warn",
    runtime_known_vulnerable: "warn"
  },
  balanced: {
    local_secret_read: "require-reapproval",
    credential_exfiltration: "require-reapproval",
    data_flow_exfiltration: "require-reapproval",
    destructive_shell: "require-reapproval",
    encoded_execution: "require-reapproval",
    network_egress: "warn",
    prompt_injection: "require-reapproval",
    mcp_dangerous_tool: "require-reapproval",
    malicious_skill: "require-reapproval",
    package_script: "warn",
    persistence: "require-reapproval",
    guard_bypass: "block",
    cloud_advisory: "warn",
    encoded_exfiltration: "require-reapproval",
    package_unknown: "allow",
    package_lockfile_drift: "allow",
    package_direct_source: "allow",
    package_custom_registry: "allow",
    package_install: "allow",
    low_trust_artifact: "require-reapproval",
    runtime_known_vulnerable: "require-reapproval"
  },
  strict: {
    local_secret_read: "require-reapproval",
    credential_exfiltration: "require-reapproval",
    data_flow_exfiltration: "block",
    destructive_shell: "require-reapproval",
    encoded_execution: "require-reapproval",
    network_egress: "require-reapproval",
    prompt_injection: "block",
    mcp_dangerous_tool: "block",
    malicious_skill: "block",
    package_script: "require-reapproval",
    persistence: "block",
    guard_bypass: "block",
    cloud_advisory: "require-reapproval",
    encoded_exfiltration: "block",
    package_unknown: "block",
    package_lockfile_drift: "require-reapproval",
    package_direct_source: "require-reapproval",
    package_custom_registry: "allow",
    package_install: "allow",
    low_trust_artifact: "require-reapproval",
    runtime_known_vulnerable: "block"
  },
  custom: {
    local_secret_read: "require-reapproval",
    credential_exfiltration: "require-reapproval",
    data_flow_exfiltration: "require-reapproval",
    destructive_shell: "require-reapproval",
    encoded_execution: "require-reapproval",
    network_egress: "warn",
    prompt_injection: "require-reapproval",
    mcp_dangerous_tool: "require-reapproval",
    malicious_skill: "require-reapproval",
    package_script: "warn",
    persistence: "require-reapproval",
    guard_bypass: "block",
    cloud_advisory: "warn",
    encoded_exfiltration: "require-reapproval",
    package_unknown: "allow",
    package_lockfile_drift: "allow",
    package_direct_source: "allow",
    package_custom_registry: "allow",
    package_install: "allow",
    low_trust_artifact: "require-reapproval",
    runtime_known_vulnerable: "require-reapproval"
  }
};
function normalizeSettingsPayload(payload) {
  return { ...payload, settings: normalizeGuardSettings(payload.settings) };
}
function normalizeGuardSettings(settings) {
  const securityLevel = settings.security_level === "gentle" ? "relaxed" : settings.security_level;
  const defaults2 = riskProfileActions[securityLevel];
  const explicitOverrides = settings.risk_action_overrides ?? {};
  const effectiveRiskActions = riskControls.reduce((actions, risk) => {
    actions[risk.key] = settings.risk_actions?.[risk.key] ?? explicitOverrides[risk.key] ?? defaults2[risk.key];
    return actions;
  }, {});
  const posture = isProtectionPosture(settings.protection_posture) ? settings.protection_posture : deriveProtectionPosture(settings.mode, securityLevel);
  return {
    ...normalizePresentationSettings(settings),
    protection_posture: posture,
    watch_auto_revert_hours: settings.watch_auto_revert_hours ?? 24,
    security_level: securityLevel,
    risk_actions: effectiveRiskActions,
    risk_action_overrides: explicitOverrides,
    harness_risk_actions: settings.harness_risk_actions ?? {},
    harness_postures: normalizeHarnessPostures(settings.harness_postures)
  };
}
function applyProtectionPosture(settings, posture) {
  if (posture === "watch") {
    return {
      ...settings,
      protection_posture: "watch",
      protection_posture_explicit: true,
      mode: "observe"
    };
  }
  const securityLevel = posture === "extra_careful" ? "strict" : "balanced";
  return {
    ...settings,
    protection_posture: posture,
    protection_posture_explicit: true,
    mode: "enforce",
    security_level: securityLevel,
    risk_actions: riskProfileActions[securityLevel],
    risk_action_overrides: {}
  };
}
function currentProtectionPosture(settings) {
  if (isProtectionPosture(settings.protection_posture)) {
    return settings.protection_posture;
  }
  return deriveProtectionPosture(settings.mode, settings.security_level);
}
function lockedSetting(settings, key2) {
  return settings.managed_locked_settings?.includes(key2) === true;
}
function lockedProtectionPostures(settings) {
  const allPostures = ["protected", "extra_careful", "watch"];
  if (lockedSetting(settings, "protection_posture")) {
    const current = currentProtectionPosture(settings);
    return allPostures.filter((posture) => posture !== current);
  }
  if (lockedSetting(settings, "mode") && settings.mode !== "observe") {
    return ["watch"];
  }
  return [];
}
function buildConsequenceSummary(settings) {
  const posture = currentProtectionPosture(settings);
  if (posture === "watch") {
    return "Protection is off. Guard is only recording.";
  }
  if (posture === "extra_careful") {
    return "Guard will also ask the first time this project talks to a new site or installs a new tool.";
  }
  if (settings.security_level === "custom") {
    const postureLabel = PROTECTION_POSTURE_COPY[posture].label;
    return `Using custom rules on top of ${postureLabel}.`;
  }
  return "Guard stops dangerous actions automatically. Choose how blocked requests are handled in Approval gate.";
}
function hasUnsavedChanges(saved, draft) {
  if (saved === null || draft === null) return false;
  return JSON.stringify(saved) !== JSON.stringify(draft);
}
function applyApprovalGateDraft(settings, updates) {
  const gate = settings.approval_gate;
  if (gate !== void 0) {
    return {
      ...settings,
      approval_gate: {
        ...gate,
        enabled: updates.enabled,
        cooldown_seconds: updates.cooldown_seconds,
        strict_all_decisions: updates.strict_all_decisions ?? gate.strict_all_decisions
      }
    };
  }
  return {
    ...settings,
    approval_gate: {
      enabled: updates.enabled,
      configured: false,
      cooldown_seconds: updates.cooldown_seconds,
      cooldown_active: false,
      cooldown_expires_at: null,
      locked_until: null,
      fail_closed: false,
      strict_all_decisions: updates.strict_all_decisions ?? false,
      totp_enabled: false,
      totp_pending: false
    }
  };
}
function saveStatusText(saveSuccess, saveError) {
  if (saveSuccess) {
    return "Settings saved successfully.";
  }
  return saveError ?? "";
}
function SettingsWorkspace({ onApprovalGateChange, contextOnly = false, onNavigate }) {
  const [returnToExtensions] = reactExports.useState(() => new URLSearchParams(window.location.search).get("returnTo") === "extensions");
  const approvalSetupRef = reactExports.useRef(null);
  const [state, setState] = reactExports.useState({ kind: "loading" });
  const [draft, setDraft] = reactExports.useState(null);
  const [saving, setSaving] = reactExports.useState(false);
  const [contextAssistanceBusy, setContextAssistanceBusy] = reactExports.useState(false);
  const [saveSuccess, setSaveSuccess] = reactExports.useState(false);
  const [saveError, setSaveError] = reactExports.useState(null);
  const [clearingApprovals, setClearingApprovals] = reactExports.useState(false);
  const [clearingEvidence, setClearingEvidence] = reactExports.useState(false);
  const [clearingReviewQueue, setClearingReviewQueue] = reactExports.useState(false);
  const [exporting, setExporting] = reactExports.useState(false);
  const [repairing, setRepairing] = reactExports.useState(false);
  const [settingUpNotifications, setSettingUpNotifications] = reactExports.useState(false);
  const [notificationSetup, setNotificationSetup] = reactExports.useState(null);
  const [actionMessage, setActionMessage] = reactExports.useState(null);
  const [actionMessageKind, setActionMessageKind] = reactExports.useState("success");
  const [perfSnapshot, setPerfSnapshot] = reactExports.useState(null);
  const [pendingMode, setPendingMode] = reactExports.useState(null);
  const [pendingPosture, setPendingPosture] = reactExports.useState(null);
  const [activeTab, setActiveTab] = reactExports.useState(() => resolveInitialSettingsTab(window.location.search));
  const [searchQuery, setSearchQuery] = reactExports.useState("");
  reactExports.useEffect(() => {
    if (!returnToExtensions || activeTab !== "approval" || state.kind !== "ready") return;
    approvalSetupRef.current?.focus();
    approvalSetupRef.current?.scrollIntoView({ block: "start" });
  }, [returnToExtensions, activeTab, state.kind]);
  const [importingSettings, setImportingSettings] = reactExports.useState(false);
  const [resettingSettings, setResettingSettings] = reactExports.useState(false);
  const [exportingSettings, setExportingSettings] = reactExports.useState(false);
  const settingsImportInputRef = reactExports.useRef(null);
  const saveSuccessTimerRef = reactExports.useRef(null);
  const savedSettingsRef = reactExports.useRef(null);
  const setupGateRevertRef = reactExports.useRef(null);
  const [approvalGateEnabled, setApprovalGateEnabled] = reactExports.useState(false);
  const [approvalGateTotpCode, setApprovalGateTotpCode] = reactExports.useState("");
  const [approvalGateTotpDeviceLabel, setApprovalGateTotpDeviceLabel] = reactExports.useState("local-device");
  const [approvalGateStrictAllDecisions, setApprovalGateStrictAllDecisions] = reactExports.useState(false);
  const [approvalGateCooldown, setApprovalGateCooldown] = reactExports.useState(0);
  const { confirm: requestConfirmation, dialog: confirmDialog } = useConfirmDialog();
  const [totpEnrollment, setTotpEnrollment] = reactExports.useState(null);
  const [totpSetupOpen, setTotpSetupOpen] = reactExports.useState(false);
  const [totpSetupStep, setTotpSetupStep] = reactExports.useState("confirm");
  const [totpActionPassword, setTotpActionPassword] = reactExports.useState("");
  const [totpActionPending, setTotpActionPending] = reactExports.useState(null);
  const [totpActionError, setTotpActionError] = reactExports.useState(null);
  const [proofModalOpen, setProofModalOpen] = reactExports.useState(false);
  const [proofModalMode, setProofModalMode] = reactExports.useState("verify-save");
  const [proofModalError, setProofModalError] = reactExports.useState(null);
  const [proofModalPending, setProofModalPending] = reactExports.useState(false);
  const [pendingProofAction, setPendingProofAction] = reactExports.useState(null);
  reactExports.useEffect(() => {
    let cancelled = false;
    fetchSettings().then((payload) => {
      if (!cancelled) {
        const normalizedPayload = normalizeSettingsPayload(payload);
        setState({ kind: "ready", payload: normalizedPayload });
        setDraft(normalizedPayload.settings);
        savedSettingsRef.current = normalizedPayload.settings;
        const gate = normalizedPayload.settings.approval_gate;
        if (gate !== void 0) {
          setApprovalGateEnabled(gate.enabled);
          setApprovalGateCooldown(gate.cooldown_seconds);
          setApprovalGateStrictAllDecisions(gate.strict_all_decisions);
          onApprovalGateChange?.(gate);
        }
      }
    }).catch((error) => {
      if (!cancelled) {
        setState({ kind: "error", message: error instanceof Error ? error.message : "Unable to load Guard settings." });
      }
    });
    return () => {
      cancelled = true;
    };
  }, [onApprovalGateChange]);
  reactExports.useEffect(() => {
    let cancelled = false;
    fetchRuntimeSnapshot().then((snapshot) => {
      if (!cancelled) setPerfSnapshot(snapshot);
    }).catch((_err) => {
    });
    return () => {
      cancelled = true;
    };
  }, []);
  reactExports.useEffect(() => {
    return () => {
      if (saveSuccessTimerRef.current !== null) clearTimeout(saveSuccessTimerRef.current);
    };
  }, []);
  reactExports.useEffect(() => {
    const handlePopState = () => {
      setActiveTab(resolveInitialSettingsTab(window.location.search));
      setActionMessage(null);
    };
    window.addEventListener("popstate", handlePopState);
    return () => window.removeEventListener("popstate", handlePopState);
  }, []);
  reactExports.useEffect(() => {
    function handleBeforeUnload(event) {
      if (hasUnsavedChanges(savedSettingsRef.current, draft)) {
        event.preventDefault();
        event.returnValue = "";
      }
    }
    window.addEventListener("beforeunload", handleBeforeUnload);
    return () => window.removeEventListener("beforeunload", handleBeforeUnload);
  }, [draft]);
  const handleTabChange = reactExports.useCallback((tab) => {
    setActiveTab(tab);
    setActionMessage(null);
    const url = new URL(window.location.href);
    url.searchParams.set("section", tab);
    window.history.replaceState({}, "", `${url.pathname}${url.search}${url.hash}`);
  }, []);
  const handleSearchChange = reactExports.useCallback((event) => {
    setSearchQuery(event.target.value);
  }, []);
  const handleStringChange = reactExports.useCallback(
    (key2) => (event) => {
      setDraft((value) => value === null ? value : { ...value, [key2]: event.target.value });
      setSaveError(null);
    },
    []
  );
  const handlePresentationModeChange = reactExports.useCallback((event) => {
    const nextMode = parsePresentationMode(event.target.value);
    if (nextMode === null) return;
    setDraft((value) => value === null ? value : applyPresentationMode(value, nextMode));
    setSaveError(null);
  }, []);
  const handleSecurityLevelChange = reactExports.useCallback((securityLevel) => {
    setDraft((value) => {
      if (value === null) return value;
      if (securityLevel === "custom") return { ...value, security_level: securityLevel };
      const normalizedLevel = securityLevel === "gentle" ? "relaxed" : securityLevel;
      return {
        ...value,
        security_level: normalizedLevel,
        risk_actions: riskProfileActions[normalizedLevel],
        risk_action_overrides: {},
        harness_risk_actions: {}
      };
    });
    setSaveError(null);
  }, []);
  const handleSwitchToCustomFineTuning = reactExports.useCallback(() => {
    handleSecurityLevelChange("custom");
  }, [handleSecurityLevelChange]);
  const handleRiskActionChange = reactExports.useCallback(
    (riskKey) => (event) => {
      setDraft((value) => {
        if (value === null) return value;
        return { ...value, security_level: "custom", risk_actions: { ...value.risk_actions, [riskKey]: event.target.value }, risk_action_overrides: { ...value.risk_action_overrides, [riskKey]: event.target.value } };
      });
      setSaveError(null);
    },
    []
  );
  const handleCodexSecretReadChange = reactExports.useCallback((event) => {
    setDraft((value) => {
      if (value === null) return value;
      return { ...value, security_level: "custom", harness_risk_actions: { ...value.harness_risk_actions, codex: { ...value.harness_risk_actions.codex ?? {}, local_secret_read: event.target.value } } };
    });
    setSaveError(null);
  }, []);
  const handleTimeoutChange = reactExports.useCallback((event) => {
    const nextValue = Number.parseInt(event.target.value, 10);
    const nextTimeout = Number.isNaN(nextValue) ? 0 : nextValue;
    setDraft((value) => value === null ? value : { ...value, approval_wait_timeout_seconds: nextTimeout });
    setSaveError(null);
  }, []);
  const handleNumberChange = reactExports.useCallback(
    (key2) => (event) => {
      const parsed = Number.parseInt(event.target.value, 10);
      const value = Number.isNaN(parsed) ? 0 : parsed;
      setDraft((settings) => settings === null ? settings : { ...settings, [key2]: value });
      setSaveError(null);
    },
    []
  );
  reactExports.useCallback((event) => {
    const nextMode = event.target.value;
    if (nextMode === "observe") {
      setPendingMode(nextMode);
      return;
    }
    setDraft((value) => value === null ? value : { ...value, mode: nextMode });
    setSaveError(null);
  }, []);
  const applyDraftPosture = reactExports.useCallback((posture) => {
    setDraft((value) => value === null ? value : applyProtectionPosture(value, posture));
    setSaveError(null);
  }, []);
  const setDraftSettings = reactExports.useCallback((settings) => {
    setDraft(settings);
    setSaveError(null);
  }, []);
  const handleProtectionPostureChange = reactExports.useCallback((posture) => {
    if (posture === "watch") {
      setPendingPosture(posture);
      return;
    }
    applyDraftPosture(posture);
  }, [applyDraftPosture]);
  const handleTurnProtectionOn = reactExports.useCallback(() => {
    setDraft((value) => {
      if (value === null) return value;
      const cleared = clearHarnessWatchOverrides(value);
      return currentProtectionPosture(cleared) === "watch" ? applyProtectionPosture(cleared, "protected") : cleared;
    });
    setSaveError(null);
  }, []);
  const handleWatchAutoRevertToggle = reactExports.useCallback((checked) => {
    setDraft((value) => value === null ? value : { ...value, watch_auto_revert_hours: checked ? 24 : 0 });
    setSaveError(null);
  }, []);
  const confirmModeChange = reactExports.useCallback(() => {
    if (pendingPosture === "watch") {
      applyDraftPosture("watch");
      setPendingPosture(null);
      setPendingMode(null);
      return;
    }
    if (pendingMode === null) return;
    setDraft((value) => value === null ? value : { ...value, mode: pendingMode });
    setPendingMode(null);
    setSaveError(null);
  }, [applyDraftPosture, pendingMode, pendingPosture]);
  const cancelModeChange = reactExports.useCallback(() => {
    setPendingMode(null);
    setPendingPosture(null);
  }, []);
  reactExports.useCallback(
    (key2) => (event) => {
      setDraft((value) => value === null ? value : { ...value, [key2]: event.target.checked });
      setSaveError(null);
    },
    []
  );
  const handleTelemetryToggle = reactExports.useCallback((checked) => {
    setDraft((value) => value === null ? value : { ...value, telemetry: checked });
    setSaveError(null);
  }, []);
  const handleSyncToggle = reactExports.useCallback((checked) => {
    setDraft((value) => value === null ? value : { ...value, sync: checked });
    setSaveError(null);
  }, []);
  const handleBillingToggle = reactExports.useCallback((checked) => {
    setDraft((value) => value === null ? value : { ...value, billing: checked });
    setSaveError(null);
  }, []);
  const handleApprovalGateToggle = reactExports.useCallback((event) => {
    const checked = event.target.checked;
    setApprovalGateEnabled(checked);
    setDraft(
      (value) => value === null ? value : applyApprovalGateDraft(value, {
        enabled: checked,
        cooldown_seconds: approvalGateCooldown,
        strict_all_decisions: approvalGateStrictAllDecisions
      })
    );
    setSaveError(null);
  }, [approvalGateCooldown, approvalGateStrictAllDecisions]);
  const handleApprovalGateTotpCode = reactExports.useCallback((event) => {
    setApprovalGateTotpCode(event.target.value);
    setTotpActionError(null);
  }, []);
  const handleApprovalGateTotpDeviceLabel = reactExports.useCallback((event) => {
    setApprovalGateTotpDeviceLabel(event.target.value);
    setTotpActionError(null);
  }, []);
  const handleTotpActionPasswordChange = reactExports.useCallback((event) => {
    setTotpActionPassword(event.target.value);
    setTotpActionError(null);
  }, []);
  const handleOpenTotpSetup = reactExports.useCallback(() => {
    setTotpSetupStep(resolveTotpSetupStep(totpEnrollment));
    setTotpActionError(null);
    setTotpSetupOpen(true);
  }, [totpEnrollment]);
  const handleCloseTotpSetup = reactExports.useCallback(() => {
    setTotpSetupOpen(false);
    setTotpSetupStep("confirm");
    if (totpEnrollment === null) {
      setTotpActionPassword("");
    }
    setTotpActionError(null);
  }, [totpEnrollment]);
  const handleApprovalGateCooldownChange = reactExports.useCallback((event) => {
    const next = Number(event.target.value);
    setApprovalGateCooldown(next);
    setDraft(
      (value) => value === null ? value : applyApprovalGateDraft(value, {
        enabled: approvalGateEnabled,
        cooldown_seconds: next,
        strict_all_decisions: approvalGateStrictAllDecisions
      })
    );
    setSaveError(null);
  }, [approvalGateEnabled, approvalGateStrictAllDecisions]);
  const handleApprovalGateStrictAllDecisions = reactExports.useCallback((event) => {
    const strict = event.target.checked;
    setApprovalGateStrictAllDecisions(strict);
    setDraft(
      (value) => value === null ? value : applyApprovalGateDraft(value, {
        enabled: approvalGateEnabled,
        cooldown_seconds: approvalGateCooldown,
        strict_all_decisions: strict
      })
    );
    setSaveError(null);
  }, [approvalGateEnabled, approvalGateCooldown]);
  const applyLoadedSettingsPayload = reactExports.useCallback((normalizedPayload) => {
    setState({ kind: "ready", payload: normalizedPayload });
    setDraft(normalizedPayload.settings);
    savedSettingsRef.current = normalizedPayload.settings;
    const gate = normalizedPayload.settings.approval_gate;
    if (gate !== void 0) {
      setApprovalGateEnabled(gate.enabled);
      setApprovalGateCooldown(gate.cooldown_seconds);
      setApprovalGateStrictAllDecisions(gate.strict_all_decisions);
      onApprovalGateChange?.(gate);
    }
  }, [onApprovalGateChange]);
  const handleContextAssistanceChange = reactExports.useCallback((config) => {
    setDraft((current) => current ? { ...current, context_assistance: config } : current);
    setSaveSuccess(false);
  }, []);
  const handleCigarSelectionChanged = reactExports.useCallback((config, previous) => {
    const saved = savedSettingsRef.current;
    if (!saved) return;
    const next = withCigarSelection(saved, config, previous);
    if (next === saved) return;
    savedSettingsRef.current = next;
    setDraft((current) => current ? withCigarSelection(current, config, previous, true) : current);
    setState((current) => current.kind === "ready" ? {
      ...current,
      payload: { ...current.payload, settings: withCigarSelection(current.payload.settings, config, previous) }
    } : current);
  }, []);
  const handleContextAssistanceStopped = reactExports.useCallback((config) => {
    const saved = savedSettingsRef.current;
    if (saved) savedSettingsRef.current = settingsWithContextOff(saved, config);
    setDraft((current) => current ? settingsWithContextOff(current, config) : current);
    setState((current) => current.kind === "ready" ? {
      ...current,
      payload: { ...current.payload, settings: settingsWithContextOff(current.payload.settings, config) }
    } : current);
  }, []);
  const openProofModal = reactExports.useCallback((mode2, action) => {
    setProofModalMode(mode2);
    setPendingProofAction(action);
    setProofModalError(null);
    setProofModalOpen(true);
  }, []);
  const closeProofModal = reactExports.useCallback(() => {
    if (proofModalPending) {
      return;
    }
    const revertGate = setupGateRevertRef.current;
    if (proofModalMode === "setup-gate" && revertGate !== null) {
      setApprovalGateEnabled(revertGate.enabled);
      setDraft((value) => value === null ? value : { ...value, approval_gate: revertGate.gate });
    }
    setupGateRevertRef.current = null;
    setProofModalOpen(false);
    setPendingProofAction(null);
    setProofModalError(null);
  }, [proofModalPending, proofModalMode, approvalGateCooldown, approvalGateStrictAllDecisions]);
  const executeSave = reactExports.useCallback(async (proof, scope = "all") => {
    if (draft === null) {
      return;
    }
    const fromModal = proof !== void 0;
    if (!fromModal) {
      setSaving(true);
      setSaveError(null);
      setSaveSuccess(false);
    }
    try {
      const approvalGateUpdate = {
        enabled: approvalGateEnabled,
        configured: draft.approval_gate?.configured ?? false,
        cooldown_seconds: approvalGateCooldown,
        cooldown_active: draft.approval_gate?.cooldown_active ?? false,
        cooldown_expires_at: draft.approval_gate?.cooldown_expires_at ?? null,
        locked_until: draft.approval_gate?.locked_until ?? null,
        fail_closed: draft.approval_gate?.fail_closed ?? false,
        strict_all_decisions: approvalGateStrictAllDecisions,
        totp_enabled: draft.approval_gate?.totp_enabled ?? false,
        totp_pending: draft.approval_gate?.totp_pending ?? false,
        ...proof?.currentPassword ? { current_password: proof.currentPassword } : {},
        ...proof?.newPassword ? { new_password: proof.newPassword } : {},
        ...proof?.confirmPassword ? { confirm_password: proof.confirmPassword } : {},
        ...proof?.totpCode ? { totp_code: proof.totpCode } : {}
      };
      let settingsToSave;
      if (scope === "approval-gate") {
        settingsToSave = { approval_gate: approvalGateUpdate };
      } else {
        const presentationOnlyPayload = presentationOnlySavePayload(draft, savedSettingsRef.current);
        if (presentationOnlyPayload !== null) {
          settingsToSave = presentationOnlyPayload;
        } else {
          settingsToSave = {
            ...withHarnessPosturePatch(
              buildSettingsUpdatePayload(draft, savedSettingsRef.current),
              draft,
              savedSettingsRef.current
            ),
            risk_actions: draft.security_level === "custom" ? draft.risk_actions : draft.risk_action_overrides,
            approval_gate: approvalGateUpdate
          };
        }
      }
      const payload = await updateSettings(settingsToSave);
      const normalizedPayload = normalizeSettingsPayload(payload);
      setState({ kind: "ready", payload: normalizedPayload });
      setDraft(normalizedPayload.settings);
      savedSettingsRef.current = normalizedPayload.settings;
      if (normalizedPayload.settings.approval_gate !== void 0) {
        const gate = normalizedPayload.settings.approval_gate;
        setApprovalGateEnabled(gate.enabled);
        setApprovalGateCooldown(gate.cooldown_seconds);
        setApprovalGateStrictAllDecisions(gate.strict_all_decisions);
        onApprovalGateChange?.(gate);
      }
      if (!fromModal) {
        setSaveSuccess(true);
        if (saveSuccessTimerRef.current !== null) clearTimeout(saveSuccessTimerRef.current);
        saveSuccessTimerRef.current = setTimeout(() => setSaveSuccess(false), 2e3);
      } else {
        setSaveSuccess(true);
        setSaveError(null);
        if (saveSuccessTimerRef.current !== null) clearTimeout(saveSuccessTimerRef.current);
        saveSuccessTimerRef.current = setTimeout(() => setSaveSuccess(false), 2e3);
      }
    } catch (error) {
      if (fromModal) {
        throw error;
      }
      setSaveError(error instanceof Error ? error.message : "Unable to save settings.");
    } finally {
      if (!fromModal) {
        setSaving(false);
      }
    }
  }, [
    draft,
    approvalGateEnabled,
    approvalGateCooldown,
    approvalGateStrictAllDecisions,
    onApprovalGateChange
  ]);
  const executeMaintenanceWithProof = reactExports.useCallback(async (action, proof) => {
    const password = proof.currentPassword?.trim() ?? "";
    const totpCode = proof.totpCode?.trim() ?? "";
    if (action === "clear-approvals") {
      setClearingApprovals(true);
      setActionMessage(null);
      try {
        await clearPolicy({
          all: true,
          approval_password: password || void 0,
          approval_totp_code: totpCode || void 0
        });
        setActionMessage("Saved approvals cleared. Guard will ask again for future matching actions.");
        setActionMessageKind("success");
      } finally {
        setClearingApprovals(false);
      }
      return;
    }
    if (action === "clear-queue") {
      setClearingReviewQueue(true);
      setActionMessage(null);
      try {
        const result = await clearReviewQueue(buildClearReviewQueuePayload({
          approvalPassword: password,
          approvalTotpCode: totpCode
        }));
        setActionMessage(`Review queue cleared. Removed ${result.cleared} pending ${result.cleared === 1 ? "item" : "items"}.`);
        setActionMessageKind("success");
      } finally {
        setClearingReviewQueue(false);
      }
      return;
    }
    if (action === "revoke-cooldown") {
      try {
        const payload = await revokeApprovalGateCooldown(
          password,
          totpCode.length > 0 ? totpCode : void 0
        );
        const normalizedPayload = normalizeSettingsPayload(payload);
        const gate = normalizedPayload.settings.approval_gate;
        setState({ kind: "ready", payload: normalizedPayload });
        setDraft(normalizedPayload.settings);
        savedSettingsRef.current = normalizedPayload.settings;
        if (gate !== void 0) {
          setApprovalGateEnabled(gate.enabled);
          setApprovalGateCooldown(gate.cooldown_seconds);
          setApprovalGateStrictAllDecisions(gate.strict_all_decisions);
          onApprovalGateChange?.(gate);
        }
        setActionMessage("Cooldown revoked successfully.");
        setActionMessageKind("success");
      } catch (error) {
        throw error;
      }
      return;
    }
    setTotpActionPending("disable");
    setTotpActionError(null);
    try {
      const payload = await disableApprovalGateTotp(password, totpCode);
      const normalizedPayload = normalizeSettingsPayload(payload);
      const gate = normalizedPayload.settings.approval_gate;
      setState({ kind: "ready", payload: normalizedPayload });
      setDraft(normalizedPayload.settings);
      savedSettingsRef.current = normalizedPayload.settings;
      if (gate !== void 0) {
        setApprovalGateEnabled(gate.enabled);
        setApprovalGateCooldown(gate.cooldown_seconds);
        setApprovalGateStrictAllDecisions(gate.strict_all_decisions);
        onApprovalGateChange?.(gate);
      }
      setApprovalGateTotpCode("");
      setTotpActionPassword("");
      setTotpEnrollment(null);
      setTotpSetupOpen(false);
      setTotpSetupStep("confirm");
      setActionMessage("Authenticator app disconnected.");
      setActionMessageKind("success");
    } finally {
      setTotpActionPending(null);
    }
  }, [onApprovalGateChange]);
  const executeImportSettings = reactExports.useCallback(async (settingsExport, proof) => {
    setImportingSettings(true);
    setActionMessage(null);
    try {
      const payload = await importSettings(settingsExport, buildApprovalGateWriteProof(proof));
      const normalizedPayload = normalizeSettingsPayload(payload);
      applyLoadedSettingsPayload(normalizedPayload);
      setActionMessage("Settings imported.");
      setActionMessageKind("success");
    } catch (error) {
      setActionMessage(error instanceof Error ? error.message : "Unable to import settings.");
      setActionMessageKind("error");
      throw error;
    } finally {
      setImportingSettings(false);
    }
  }, [applyLoadedSettingsPayload]);
  const executeResetSettings = reactExports.useCallback(async (proof) => {
    setResettingSettings(true);
    setActionMessage(null);
    try {
      const payload = await resetSettings(buildApprovalGateWriteProof(proof));
      const normalizedPayload = normalizeSettingsPayload(payload);
      applyLoadedSettingsPayload(normalizedPayload);
      setActionMessage("Settings reset to defaults.");
      setActionMessageKind("success");
    } catch (error) {
      setActionMessage(error instanceof Error ? error.message : "Unable to reset settings.");
      setActionMessageKind("error");
      throw error;
    } finally {
      setResettingSettings(false);
    }
  }, [applyLoadedSettingsPayload]);
  const handleProofModalConfirm = reactExports.useCallback(async (proof) => {
    if (pendingProofAction === null) {
      return;
    }
    setProofModalPending(true);
    setProofModalError(null);
    try {
      if (pendingProofAction.kind === "save") {
        await executeSave(proof, pendingProofAction.scope);
      } else if (pendingProofAction.action === "import-settings") {
        if (pendingProofAction.importExport === void 0) {
          throw new Error("Missing settings import payload.");
        }
        await executeImportSettings(pendingProofAction.importExport, proof);
      } else if (pendingProofAction.action === "reset-settings") {
        await executeResetSettings(proof);
      } else {
        await executeMaintenanceWithProof(pendingProofAction.action, proof);
      }
      setupGateRevertRef.current = null;
      setProofModalOpen(false);
      setPendingProofAction(null);
    } catch (error) {
      setProofModalError(error instanceof Error ? error.message : "Unable to continue.");
    } finally {
      setProofModalPending(false);
    }
  }, [pendingProofAction, executeSave, executeImportSettings, executeResetSettings, executeMaintenanceWithProof]);
  const handleSave = reactExports.useCallback(() => {
    if (draft === null) {
      return;
    }
    const savedGateConfig = savedSettingsRef.current?.approval_gate ?? null;
    const proofKind = resolveSettingsSaveProofKind({
      savedGateEnabled: savedGateConfig?.enabled === true,
      wasConfigured: savedGateConfig?.configured === true,
      draftGateEnabled: approvalGateEnabled
    });
    if (requiresSettingsSaveProof(proofKind) && !isPresentationOnlyChange(draft, savedSettingsRef.current)) {
      openProofModal(proofKind, { kind: "save" });
      return;
    }
    void executeSave();
  }, [approvalGateEnabled, draft, executeSave, openProofModal]);
  const handleOpenPasswordChangeModal = reactExports.useCallback((mode2 = "change-password") => {
    if (mode2 === "setup-gate") {
      setupGateRevertRef.current = { enabled: approvalGateEnabled, gate: draft?.approval_gate };
      setApprovalGateEnabled(true);
      setDraft(
        (value) => value === null ? value : applyApprovalGateDraft(value, {
          enabled: true,
          cooldown_seconds: approvalGateCooldown,
          strict_all_decisions: approvalGateStrictAllDecisions
        })
      );
    }
    openProofModal(mode2, { kind: "save", scope: mode2 === "setup-gate" ? "approval-gate" : "all" });
  }, [openProofModal, approvalGateEnabled, approvalGateCooldown, approvalGateStrictAllDecisions, draft]);
  const handleRequestRevokeCooldown = reactExports.useCallback(() => {
    openProofModal("maintenance", { kind: "maintenance", action: "revoke-cooldown" });
  }, [openProofModal]);
  const handleRequestDisableTotp = reactExports.useCallback(() => {
    openProofModal("maintenance", { kind: "maintenance", action: "disable-totp" });
  }, [openProofModal]);
  const handleStartTotpEnrollment = reactExports.useCallback(async () => {
    if (!totpActionPassword.trim()) {
      setTotpActionError("Enter your approval password to continue.");
      return;
    }
    setTotpActionPending("enroll");
    setTotpActionError(null);
    try {
      const payload = await enrollApprovalGateTotp(
        totpActionPassword,
        approvalGateTotpDeviceLabel.trim() || "local-device"
      );
      const normalizedPayload = normalizeSettingsPayload(payload);
      const gate = normalizedPayload.settings.approval_gate;
      setState({ kind: "ready", payload: normalizedPayload });
      setDraft(normalizedPayload.settings);
      savedSettingsRef.current = normalizedPayload.settings;
      if (gate !== void 0) {
        setApprovalGateEnabled(gate.enabled);
        setApprovalGateCooldown(gate.cooldown_seconds);
        setApprovalGateStrictAllDecisions(gate.strict_all_decisions);
        onApprovalGateChange?.(gate);
      }
      setTotpEnrollment(payload.enrollment ?? null);
      setTotpSetupStep("scan");
      setTotpSetupOpen(payload.enrollment !== void 0 && payload.enrollment !== null);
      setActionMessage("Scan the QR code, then enter a live code from your app.");
      setActionMessageKind("success");
    } catch (error) {
      setTotpActionError(error instanceof Error ? error.message : "Unable to start TOTP enrollment.");
    } finally {
      setTotpActionPending(null);
    }
  }, [totpActionPassword, approvalGateTotpDeviceLabel, onApprovalGateChange]);
  const handleVerifyTotpEnrollment = reactExports.useCallback(async () => {
    if (!totpActionPassword.trim()) {
      setTotpActionError("Enter your approval password to continue.");
      return;
    }
    if (!approvalGateTotpCode.trim()) {
      setTotpActionError("Enter the six-digit code from your authenticator app.");
      return;
    }
    setTotpActionPending("verify");
    setTotpActionError(null);
    try {
      const payload = await verifyApprovalGateTotp(totpActionPassword, approvalGateTotpCode);
      const normalizedPayload = normalizeSettingsPayload(payload);
      const gate = normalizedPayload.settings.approval_gate;
      setState({ kind: "ready", payload: normalizedPayload });
      setDraft(normalizedPayload.settings);
      savedSettingsRef.current = normalizedPayload.settings;
      if (gate !== void 0) {
        setApprovalGateEnabled(gate.enabled);
        setApprovalGateCooldown(gate.cooldown_seconds);
        setApprovalGateStrictAllDecisions(gate.strict_all_decisions);
        onApprovalGateChange?.(gate);
      }
      setApprovalGateTotpCode("");
      setTotpActionPassword("");
      setTotpEnrollment(null);
      setTotpSetupOpen(false);
      setTotpSetupStep("confirm");
      setActionMessage("Authenticator app connected.");
      setActionMessageKind("success");
    } catch (error) {
      setTotpActionError(error instanceof Error ? error.message : "Unable to verify TOTP.");
    } finally {
      setTotpActionPending(null);
    }
  }, [totpActionPassword, approvalGateTotpCode, onApprovalGateChange]);
  const handleDisableTotp = reactExports.useCallback(async () => {
    handleRequestDisableTotp();
  }, [handleRequestDisableTotp]);
  const handleClearApprovals = reactExports.useCallback(async () => {
    if (!await requestConfirmation({
      title: "Clear all saved approvals?",
      description: "Guard will ask again for every action it previously approved. Pending reviews and evidence are kept.",
      confirmLabel: "Clear approvals",
      tone: "destructive"
    })) {
      return;
    }
    const savedGateEnabled = savedSettingsRef.current?.approval_gate?.enabled === true;
    if (savedGateEnabled) {
      openProofModal("maintenance", { kind: "maintenance", action: "clear-approvals" });
      return;
    }
    setClearingApprovals(true);
    setActionMessage(null);
    void clearPolicy({ all: true }).then(() => {
      setActionMessage("Saved approvals cleared. Guard will ask again for future matching actions.");
      setActionMessageKind("success");
    }).catch((error) => {
      setActionMessage(error instanceof Error ? error.message : "Unable to clear approvals.");
      setActionMessageKind("error");
    }).finally(() => {
      setClearingApprovals(false);
    });
  }, [openProofModal, requestConfirmation]);
  const handleClearReviewQueue = reactExports.useCallback(async () => {
    if (!await requestConfirmation({
      title: "Clear the pending review queue?",
      description: "Waiting items are removed without recording an allow or block decision.",
      confirmLabel: "Clear review queue",
      tone: "destructive"
    })) {
      return;
    }
    const savedGateEnabled = savedSettingsRef.current?.approval_gate?.enabled === true;
    if (savedGateEnabled) {
      openProofModal("maintenance", { kind: "maintenance", action: "clear-queue" });
      return;
    }
    setClearingReviewQueue(true);
    setActionMessage(null);
    void clearReviewQueue(buildClearReviewQueuePayload({})).then((result) => {
      setActionMessage(`Review queue cleared. Removed ${result.cleared} pending ${result.cleared === 1 ? "item" : "items"}.`);
      setActionMessageKind("success");
    }).catch((error) => {
      setActionMessage(error instanceof Error ? error.message : "Unable to clear review queue.");
      setActionMessageKind("error");
    }).finally(() => {
      setClearingReviewQueue(false);
    });
  }, [openProofModal, requestConfirmation]);
  const handleClearEvidence = reactExports.useCallback(async () => {
    if (!await requestConfirmation({
      title: "Clear the evidence log permanently?",
      description: "Local audit history on this machine is deleted. This cannot be undone.",
      confirmLabel: "Clear evidence",
      tone: "destructive"
    })) return;
    setClearingEvidence(true);
    setActionMessage(null);
    try {
      await clearEvidence();
      setActionMessage("Evidence log cleared.");
      setActionMessageKind("success");
    } catch (error) {
      setActionMessage(error instanceof Error ? error.message : "Unable to clear evidence.");
      setActionMessageKind("error");
    } finally {
      setClearingEvidence(false);
    }
  }, [requestConfirmation]);
  const handleExportDiagnostics = reactExports.useCallback(async () => {
    setExporting(true);
    setActionMessage(null);
    try {
      const blob = await exportDiagnostics();
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `guard-diagnostics-${Date.now()}.json`;
      document.body.appendChild(anchor);
      anchor.click();
      document.body.removeChild(anchor);
      URL.revokeObjectURL(url);
      setActionMessage("Diagnostics exported.");
      setActionMessageKind("success");
    } catch (error) {
      setActionMessage(error instanceof Error ? error.message : "Unable to export diagnostics.");
      setActionMessageKind("error");
    } finally {
      setExporting(false);
    }
  }, []);
  const handleRepairApprovalCenter = reactExports.useCallback(async () => {
    if (!await requestConfirmation({
      title: "Repair the approval center?",
      description: "Guard clears stale approval-center discovery state so approval links resolve again. A healthy background service and pending approvals are preserved.",
      confirmLabel: "Repair"
    })) return;
    setRepairing(true);
    setActionMessage(null);
    try {
      const result = await repairApprovalCenter();
      const cleared = Array.isArray(result?.cleared) ? result.cleared.filter((code) => typeof code === "string") : [];
      setActionMessage(resolveRepairApprovalCenterMessage(cleared));
      setActionMessageKind("success");
    } catch (error) {
      setActionMessage(error instanceof Error ? error.message : "Unable to repair approval center.");
      setActionMessageKind("error");
    } finally {
      setRepairing(false);
    }
  }, [requestConfirmation]);
  const handleExportSettings = reactExports.useCallback(async () => {
    setExportingSettings(true);
    setActionMessage(null);
    try {
      const exported = await exportSettings();
      const blob = new Blob([JSON.stringify(exported, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `guard-settings-${Date.now()}.json`;
      document.body.appendChild(anchor);
      anchor.click();
      document.body.removeChild(anchor);
      URL.revokeObjectURL(url);
      setActionMessage("Settings exported.");
      setActionMessageKind("success");
    } catch (error) {
      setActionMessage(error instanceof Error ? error.message : "Unable to export settings.");
      setActionMessageKind("error");
    } finally {
      setExportingSettings(false);
    }
  }, []);
  const handleImportSettingsClick = reactExports.useCallback(() => {
    settingsImportInputRef.current?.click();
  }, []);
  const handleImportSettingsFile = reactExports.useCallback(async (event) => {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file) return;
    setActionMessage(null);
    try {
      const text = await file.text();
      const parsed = JSON.parse(text);
      const savedGateEnabled = savedSettingsRef.current?.approval_gate?.enabled === true;
      if (savedGateEnabled) {
        openProofModal("maintenance", {
          kind: "maintenance",
          action: "import-settings",
          importExport: parsed
        });
        return;
      }
      await executeImportSettings(parsed);
    } catch (error) {
      setActionMessage(error instanceof Error ? error.message : "Unable to import settings.");
      setActionMessageKind("error");
    }
  }, [executeImportSettings, openProofModal]);
  const handleResetSettings = reactExports.useCallback(async () => {
    if (!await requestConfirmation({
      title: "Reset all local Guard settings to defaults?",
      description: "Protection rules, notifications, and approval-gate preferences return to factory values on this machine. This cannot be undone.",
      confirmLabel: "Reset settings",
      tone: "destructive"
    })) return;
    const savedGateEnabled = savedSettingsRef.current?.approval_gate?.enabled === true;
    if (savedGateEnabled) {
      openProofModal("maintenance", { kind: "maintenance", action: "reset-settings" });
      return;
    }
    try {
      await executeResetSettings();
    } catch {
    }
  }, [executeResetSettings, openProofModal, requestConfirmation]);
  const handleSetupNotifications = reactExports.useCallback(async () => {
    setSettingUpNotifications(true);
    setActionMessage(null);
    try {
      const result = await setupDesktopNotifications();
      setNotificationSetup(result);
      if (!result.supported) {
        setActionMessage("Desktop notification setup is not available on this OS.");
        setActionMessageKind("error");
      } else if (result.settings_opened) {
        setActionMessage("Notification settings opened. Turn on alerts and sounds for Guard.");
        setActionMessageKind("success");
      } else {
        setActionMessage(
          "We could not open Settings automatically. Open System Settings > Notifications and allow alerts for Guard."
        );
        setActionMessageKind("success");
      }
    } catch (error) {
      setActionMessage(error instanceof Error ? error.message : "Unable to set up notifications.");
      setActionMessageKind("error");
    } finally {
      setSettingUpNotifications(false);
    }
  }, []);
  if (state.kind === "loading") {
    return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-4", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "guard-skeleton h-10 w-64" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "guard-skeleton h-72 w-full" })
    ] });
  }
  if (state.kind === "error" || draft === null) {
    return /* @__PURE__ */ jsxRuntimeExports.jsx(EmptyState, { title: "Settings are unavailable", body: state.kind === "error" ? state.message : "Guard did not return editable settings.", tone: "teach" });
  }
  const consequenceSummary = buildConsequenceSummary(draft);
  const selectedPosture = currentProtectionPosture(draft);
  const resolvedPresentation = resolveSettingsPresentation(draft);
  const protectionCapabilities = state.kind === "ready" ? state.payload.protection_capabilities ?? [] : [];
  const watchBanner = settingsWatchBannerModel(draft, protectionCapabilities);
  const searchMatches = filterSettingsBySearch(searchQuery);
  const hasSearch = searchQuery.trim().length > 0;
  const riskSearchMatches = searchMatches.filter((m) => m.section === "risk");
  const visibleRiskControls = hasSearch ? riskControls.filter((rc) => riskSearchMatches.some((m) => m.key === rc.key)) : riskControls;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex min-h-[calc(100dvh-11rem)] flex-col gap-6", children: [
    contextOnly ? /* @__PURE__ */ jsxRuntimeExports.jsx(
      ContextAssistanceSettings,
      {
        workspace: true,
        value: draft.context_assistance,
        savedValue: state.payload.settings.context_assistance,
        gate: state.payload.settings.approval_gate ?? null,
        locked: (draft.managed_locked_settings ?? []).some((key2) => key2 === "context_assistance" || key2.startsWith("context_assistance.")),
        disabled: saving || proofModalOpen,
        onChange: handleContextAssistanceChange,
        onStopped: handleContextAssistanceStopped,
        onBusyChange: setContextAssistanceBusy,
        onSelectionChanged: handleCigarSelectionChanged,
        data: /* @__PURE__ */ jsxRuntimeExports.jsx(
          ContextDataRepairPanel,
          {
            savedEnabled: Boolean(state.payload.settings.context_assistance?.enabled),
            disabled: saving || proofModalOpen,
            onStopped: handleContextAssistanceStopped,
            onBusyChange: setContextAssistanceBusy
          }
        )
      }
    ) : /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        WorkspacePageHeader,
        {
          eyebrow: "This machine",
          title: "Protection",
          description: "Guard stops dangerous actions automatically. Choose how blocked requests are handled in Approval gate."
        }
      ),
      watchBanner !== null ? /* @__PURE__ */ jsxRuntimeExports.jsx(WatchProtectionBanner, { model: watchBanner, onTurnProtectionOn: handleTurnProtectionOn }) : null,
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "relative", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniMagnifyingGlass, { className: "pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400", "aria-hidden": "true" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "input",
          {
            id: "settings-search",
            name: "settings-search",
            type: "search",
            value: searchQuery,
            onChange: handleSearchChange,
            placeholder: "Search settings...",
            "aria-label": "Search settings",
            className: "w-full rounded-xl border border-slate-200 bg-white py-2.5 pl-9 pr-4 text-sm text-brand-dark placeholder:text-slate-400 focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
          }
        )
      ] }),
      hasSearch && searchMatches.length === 0 && /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-slate-500", children: "No settings match your search." }),
      hasSearch && searchMatches.some((match) => match.key === "harness_postures") ? /* @__PURE__ */ jsxRuntimeExports.jsxs(
        "button",
        {
          type: "button",
          onClick: () => {
            setSearchQuery("");
            handleTabChange("apps");
          },
          "data-testid": "settings-search-open-apps",
          className: "flex min-h-11 w-full items-center justify-between rounded-xl border border-slate-100 bg-white px-4 py-3 text-left text-sm font-medium text-brand-dark hover:border-brand-blue/30",
          children: [
            "Protection by app",
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-xs font-semibold text-brand-blue", children: "Open the Apps tab" })
          ]
        }
      ) : null,
      hasSearch && riskSearchMatches.length > 0 && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-xl border border-slate-100 p-4", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Matching fine-tuning rules" }),
        !isFineTuningEditable(draft.security_level) ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-3", children: /* @__PURE__ */ jsxRuntimeExports.jsx(
          FineTuningPresetBanner,
          {
            securityLevel: draft.security_level,
            posture: selectedPosture,
            onSwitchToCustom: handleSwitchToCustomFineTuning
          }
        ) }) : null,
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-3 divide-y divide-slate-100 border-t border-slate-100", children: visibleRiskControls.map((risk) => /* @__PURE__ */ jsxRuntimeExports.jsx(
          RiskControlRow,
          {
            risk,
            value: draft.risk_actions[risk.key] ?? "require-reapproval",
            disabled: !isFineTuningEditable(draft.security_level),
            onChange: handleRiskActionChange(risk.key),
            showConsequence: true
          },
          risk.key
        )) })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "flex min-h-0 flex-1 flex-col", children: /* @__PURE__ */ jsxRuntimeExports.jsxs(
        SettingsSectionShell,
        {
          activeTab,
          onTabChange: handleTabChange,
          intro: !hasSearch && activeTab === "protection" && consequenceSummary ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "rounded-xl border border-brand-blue/10 bg-brand-blue/[0.03] p-4", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start gap-3", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniShieldCheck, { className: "mt-0.5 h-5 w-5 shrink-0 text-brand-blue", "aria-hidden": "true" }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "What to expect" }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm text-slate-500", children: consequenceSummary })
            ] })
          ] }) }) : null,
          children: [
            activeTab === "protection" && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex min-h-0 flex-1 flex-col space-y-6", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx(
                SettingsFormSection,
                {
                  title: "Protection",
                  description: consequenceSummary,
                  children: /* @__PURE__ */ jsxRuntimeExports.jsx(
                    ProtectionPosturePanel,
                    {
                      posture: selectedPosture,
                      customRules: draft.security_level === "custom",
                      capabilities: protectionCapabilities,
                      disabledPostures: lockedProtectionPostures(draft),
                      onPostureChange: handleProtectionPostureChange
                    }
                  )
                }
              ),
              protectionCapabilities.length > 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx(
                SettingsFormSection,
                {
                  title: "Protection by app",
                  description: "Apps follow the machine setting unless you choose otherwise.",
                  children: /* @__PURE__ */ jsxRuntimeExports.jsx(
                    HarnessPostureSummaryCard,
                    {
                      settings: draft,
                      capabilities: protectionCapabilities,
                      onOpenApps: () => handleTabChange("apps")
                    }
                  )
                }
              ) : null,
              /* @__PURE__ */ jsxRuntimeExports.jsx(SettingsFormSection, { title: "CIGAR context assistance", description: "Optional context for reviews, AI apps, and supported execution flows.", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center justify-between gap-3 py-4", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "max-w-xl text-sm text-slate-500", children: "CIGAR has its own workspace for getting started, runtime preferences, sources, app access, and data controls." }),
                /* @__PURE__ */ jsxRuntimeExports.jsx(
                  "a",
                  {
                    className: "inline-flex min-h-11 items-center rounded-lg border border-slate-200 px-4 text-sm font-semibold text-brand-dark hover:bg-slate-50",
                    href: guardAwareHref("/cigar"),
                    onClick: (event) => {
                      if (onNavigate) navigateFromAnchor(event, "/cigar", { onNavigate });
                    },
                    children: "Open CIGAR"
                  }
                )
              ] }) }),
              /* @__PURE__ */ jsxRuntimeExports.jsx(SettingsFormSection, { title: "Timing and features", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-4 py-3", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx(
                  SettingsSelectRow,
                  {
                    label: "Presentation mode",
                    description: "Choose whether Guard leads with clear everyday explanations or opens with technical detail. This never changes protection or enforcement.",
                    value: resolvedPresentation.value,
                    onChange: handlePresentationModeChange,
                    options: presentationModeOptions,
                    disabled: !resolvedPresentation.writable
                  }
                ),
                /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "guard-settings-caption -mt-2 text-slate-500", children: presentationModeStatus(resolvedPresentation) }),
                /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
                  /* @__PURE__ */ jsxRuntimeExports.jsx("label", { htmlFor: "approval-wait", className: "guard-settings-body font-medium text-brand-dark", children: "How long to wait for your answer" }),
                  /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "guard-settings-caption text-slate-500", children: "Seconds before Guard returns control to your AI app" }),
                  /* @__PURE__ */ jsxRuntimeExports.jsx(
                    "input",
                    {
                      id: "approval-wait",
                      type: "number",
                      min: 0,
                      max: 600,
                      value: draft.approval_wait_timeout_seconds,
                      onChange: handleTimeoutChange,
                      className: "mt-2 min-h-11 w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-1 focus:ring-brand-blue/20"
                    }
                  )
                ] }),
                /* @__PURE__ */ jsxRuntimeExports.jsx(
                  SettingsToggleRow,
                  {
                    label: "Telemetry",
                    description: "Share anonymized usage to improve Guard.",
                    checked: draft.telemetry,
                    onChange: handleTelemetryToggle
                  }
                ),
                /* @__PURE__ */ jsxRuntimeExports.jsx(
                  SettingsToggleRow,
                  {
                    label: "Cloud sync",
                    description: "Sync receipts and policy with Guard Cloud when connected.",
                    checked: draft.sync,
                    onChange: handleSyncToggle
                  }
                ),
                /* @__PURE__ */ jsxRuntimeExports.jsx(CloudReviewSettings, {}),
                /* @__PURE__ */ jsxRuntimeExports.jsx(
                  SettingsSelectRow,
                  {
                    label: "Cloud receipt privacy",
                    description: "Choose how much command detail Guard includes when syncing receipts. Secrets are always removed.",
                    value: draft.receipt_redaction_level,
                    onChange: handleStringChange("receipt_redaction_level"),
                    options: [
                      { value: "full", label: "Fully redacted - metadata only" },
                      { value: "partial", label: "Partially redacted - hide paths and package names" },
                      { value: "none", label: "Detailed - include commands, paths, hosts, and packages" }
                    ]
                  }
                ),
                /* @__PURE__ */ jsxRuntimeExports.jsx(
                  SettingsToggleRow,
                  {
                    label: "Billing features",
                    description: "Enable paid supply-chain and blocked-install analytics.",
                    checked: draft.billing,
                    onChange: handleBillingToggle
                  }
                ),
                perfSnapshot !== null && perfSnapshot.cloud_state === "local_only" && draft.billing ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "guard-settings-caption -mt-1 text-slate-500", children: "Billing features require a cloud connection. Connect this machine to access paid features." }) : null
              ] }) })
            ] }),
            activeTab === "apps" && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "flex min-h-0 flex-1 flex-col space-y-6", children: protectionCapabilities.length > 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx(
              SettingsFormSection,
              {
                title: "Protection by app",
                description: "Choose the level each app runs at. Watch records instead of stopping, so use it only while debugging one app.",
                children: /* @__PURE__ */ jsxRuntimeExports.jsx(
                  HarnessPostureManager,
                  {
                    settings: draft,
                    capabilities: protectionCapabilities,
                    onSettingsChange: setDraftSettings,
                    onChangeTab: handleTabChange
                  }
                )
              }
            ) : /* @__PURE__ */ jsxRuntimeExports.jsx(
              EmptyState,
              {
                title: "No apps to protect yet",
                body: "Guard lists your apps here once it detects them. Run an app such as Codex, Claude Code, or Cursor and come back.",
                tone: "teach"
              }
            ) }),
            activeTab === "approval" && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex min-h-0 flex-1 flex-col space-y-4", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { ref: approvalSetupRef, role: "region", tabIndex: -1, "aria-label": "Local approval setup", className: "scroll-mt-24 rounded-xl focus-visible:outline-2 focus-visible:outline-brand-blue sm:scroll-mt-4", children: [
                returnToExtensions ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mb-4 flex flex-wrap items-center justify-between gap-3", children: [
                  /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
                    /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "text-base font-semibold text-brand-dark", children: "Local approval" }),
                    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm text-slate-600", children: hasUnsavedChanges(savedSettingsRef.current, draft) ? "Save your changes before returning to Extensions." : savedSettingsRef.current?.approval_gate?.enabled && savedSettingsRef.current?.approval_gate?.configured ? "Local approval is ready. Return to Extensions to finish setup." : "Set a password here, then return to Extensions. Guard Cloud is not required." })
                  ] }),
                  /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { variant: "outline", disabled: saving || proofModalPending || hasUnsavedChanges(savedSettingsRef.current, draft), onClick: () => commitDashboardLocation(guardAwareHref("/extensions")), children: "Back to Extensions" })
                ] }) : null,
                /* @__PURE__ */ jsxRuntimeExports.jsx(
                  ApprovalGateCard,
                  {
                    enabled: approvalGateEnabled,
                    gateConfig: draft.approval_gate ?? null,
                    savedGateConfig: savedSettingsRef.current?.approval_gate ?? null,
                    totpCode: approvalGateTotpCode,
                    totpDeviceLabel: approvalGateTotpDeviceLabel,
                    strictAllDecisions: approvalGateStrictAllDecisions,
                    cooldownSeconds: approvalGateCooldown,
                    totpEnrollment,
                    totpSetupOpen,
                    totpSetupStep,
                    totpActionPassword,
                    totpActionPending,
                    totpActionError,
                    onToggle: handleApprovalGateToggle,
                    onOpenPasswordChangeModal: handleOpenPasswordChangeModal,
                    onTotpCodeChange: handleApprovalGateTotpCode,
                    onTotpDeviceLabelChange: handleApprovalGateTotpDeviceLabel,
                    onTotpActionPasswordChange: handleTotpActionPasswordChange,
                    onOpenTotpSetup: handleOpenTotpSetup,
                    onCloseTotpSetup: handleCloseTotpSetup,
                    onStrictAllDecisionsChange: handleApprovalGateStrictAllDecisions,
                    onCooldownChange: handleApprovalGateCooldownChange,
                    onStartTotpEnrollment: handleStartTotpEnrollment,
                    onVerifyTotpEnrollment: handleVerifyTotpEnrollment,
                    onDisableTotp: handleDisableTotp,
                    onRevokeCooldown: handleRequestRevokeCooldown
                  }
                )
              ] }),
              /* @__PURE__ */ jsxRuntimeExports.jsx(
                SettingsFormSection,
                {
                  title: "When Guard blocks a request",
                  description: "Applies to every harness. Blocked actions stay blocked in either mode.",
                  children: /* @__PURE__ */ jsxRuntimeExports.jsxs("fieldset", { className: "space-y-3 py-3", children: [
                    /* @__PURE__ */ jsxRuntimeExports.jsx("legend", { className: "sr-only", children: "Blocked request behavior" }),
                    [
                      { value: "safe-alternative", label: "Find a safe alternative (default)", description: "The agent receives the block reason and continues with a permitted approach. No approval prompt opens. Guard still saves the block in the inbox." },
                      { value: "ask", label: "Ask me for approval", description: "Pause for an approval questionnaire in the harness or Guard. Decisions that require review can be approved; hard blocks stay blocked." }
                    ].map((option) => /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "flex cursor-pointer items-start gap-3 rounded-lg px-2 py-2 hover:bg-slate-50 focus-within:outline-2 focus-within:outline-offset-2 focus-within:outline-brand-blue", children: [
                      /* @__PURE__ */ jsxRuntimeExports.jsx(
                        "input",
                        {
                          type: "radio",
                          name: "blocked-request-mode",
                          value: option.value,
                          checked: (draft.blocked_request_mode ?? "safe-alternative") === option.value,
                          onChange: handleStringChange("blocked_request_mode"),
                          className: "mt-1 h-4 w-4 shrink-0 accent-brand-blue"
                        }
                      ),
                      /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { children: [
                        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "block text-sm font-medium text-brand-dark", children: option.label }),
                        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "mt-1 block text-sm text-slate-600", children: option.description })
                      ] })
                    ] }, option.value))
                  ] })
                }
              ),
              draft.blocked_request_mode === "ask" && /* @__PURE__ */ jsxRuntimeExports.jsx(
                SettingsFormSection,
                {
                  title: "Where Guard asks",
                  description: "This only chooses the surface for Ask once. It does not change what Guard stops.",
                  children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-4 py-3", children: [
                    /* @__PURE__ */ jsxRuntimeExports.jsx(
                      SettingsSelectRow,
                      {
                        label: "Ask surface",
                        description: "In the app when possible, always in Guard, or never open a browser.",
                        value: draft.approval_surface_policy,
                        onChange: handleStringChange("approval_surface_policy"),
                        options: surfacePolicyOptions
                      }
                    ),
                    draft.approval_surface_policy === "attention-aware" && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "grid gap-3 sm:grid-cols-2", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block", children: [
                      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm font-medium text-brand-dark", children: "Browser delay (seconds)" }),
                      /* @__PURE__ */ jsxRuntimeExports.jsx(
                        "input",
                        {
                          type: "number",
                          min: 0,
                          max: 120,
                          value: draft.approval_browser_delay_seconds,
                          onChange: handleNumberChange("approval_browser_delay_seconds"),
                          className: "mt-2 min-h-11 w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm"
                        }
                      )
                    ] }) })
                  ] })
                }
              )
            ] }),
            activeTab === "notifications" && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex min-h-0 flex-1 flex-col space-y-4", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx(
                NotificationSetupCard,
                {
                  result: notificationSetup,
                  settingUp: settingUpNotifications,
                  onSetup: handleSetupNotifications
                }
              ),
              /* @__PURE__ */ jsxRuntimeExports.jsx(SettingsActionMessage, { message: actionMessage, kind: actionMessageKind })
            ] }),
            activeTab === "rules" && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex min-h-0 flex-1 flex-col space-y-6", children: [
              !isFineTuningEditable(draft.security_level) ? /* @__PURE__ */ jsxRuntimeExports.jsx(
                FineTuningPresetBanner,
                {
                  securityLevel: draft.security_level,
                  posture: selectedPosture,
                  onSwitchToCustom: handleSwitchToCustomFineTuning
                }
              ) : null,
              /* @__PURE__ */ jsxRuntimeExports.jsx(
                SettingsFormSection,
                {
                  title: "Risky action types",
                  description: resolveFineTuningSectionDescription(draft.security_level),
                  children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: `space-y-1 ${!isFineTuningEditable(draft.security_level) ? "opacity-60" : ""}`, children: [
                    riskControls.map((risk) => /* @__PURE__ */ jsxRuntimeExports.jsx(
                      RiskControlRow,
                      {
                        risk,
                        value: draft.risk_actions[risk.key] ?? "require-reapproval",
                        disabled: !isFineTuningEditable(draft.security_level),
                        onChange: handleRiskActionChange(risk.key),
                        showConsequence: isFineTuningEditable(draft.security_level)
                      },
                      risk.key
                    )),
                    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid gap-2 border-t border-slate-100 py-3 md:grid-cols-[minmax(0,1fr)_200px] md:items-center", children: [
                      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
                        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-medium text-brand-dark", children: "Codex reading secret files" }),
                        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-500", children: "Only for trusted projects where Codex may read .env or .npmrc without an extra prompt." })
                      ] }),
                      /* @__PURE__ */ jsxRuntimeExports.jsx(
                        SettingSelect,
                        {
                          label: "Codex should",
                          value: draft.harness_risk_actions.codex?.local_secret_read ?? draft.risk_actions.local_secret_read ?? "require-reapproval",
                          options: actionOptions,
                          onChange: handleCodexSecretReadChange,
                          disabled: !isFineTuningEditable(draft.security_level)
                        }
                      )
                    ] })
                  ] })
                }
              ),
              /* @__PURE__ */ jsxRuntimeExports.jsxs("details", { className: "group rounded-xl border border-slate-200 bg-slate-50/40 open:bg-white", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsxs("summary", { className: "flex min-h-11 cursor-pointer list-none items-center justify-between gap-4 rounded-xl px-4 py-3 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/50 [&::-webkit-details-marker]:hidden", children: [
                  /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { children: [
                    /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "block text-sm font-semibold text-brand-dark", children: "Advanced fallback behavior" }),
                    /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "mt-0.5 block text-xs leading-relaxed text-slate-500", children: "Decide what happens when Guard has no remembered rule or specific risk match." })
                  ] }),
                  /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniChevronDown, { className: "h-5 w-5 shrink-0 text-slate-400 transition-transform group-open:rotate-180", "aria-hidden": "true" })
                ] }),
                /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "border-t border-slate-100 px-4 pb-4", children: [
                  /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid gap-3 py-4 sm:grid-cols-2", children: [
                    /* @__PURE__ */ jsxRuntimeExports.jsx(SettingSelect, { label: "First-time action", value: draft.default_action, options: actionOptions, onChange: handleStringChange("default_action") }),
                    /* @__PURE__ */ jsxRuntimeExports.jsx(SettingSelect, { label: "Unknown source", value: draft.unknown_publisher_action, options: actionOptions, onChange: handleStringChange("unknown_publisher_action") }),
                    /* @__PURE__ */ jsxRuntimeExports.jsx(SettingSelect, { label: "Changed command", value: draft.changed_hash_action, options: actionOptions, onChange: handleStringChange("changed_hash_action") }),
                    /* @__PURE__ */ jsxRuntimeExports.jsx(SettingSelect, { label: "New website or host", value: draft.new_network_domain_action, options: actionOptions, onChange: handleStringChange("new_network_domain_action") }),
                    /* @__PURE__ */ jsxRuntimeExports.jsx(SettingSelect, { label: "Nested commands", value: draft.subprocess_action, options: actionOptions, onChange: handleStringChange("subprocess_action") })
                  ] }),
                  /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "border-t border-slate-100 py-4", children: /* @__PURE__ */ jsxRuntimeExports.jsx(
                    SettingsToggleRow,
                    {
                      label: "Auto-revert Watch",
                      description: "Turn protection back on after 24 hours unless you disable this.",
                      checked: (draft.watch_auto_revert_hours ?? 24) > 0,
                      disabled: lockedSetting(draft, "watch_auto_revert_hours"),
                      onChange: handleWatchAutoRevertToggle
                    }
                  ) })
                ] })
              ] })
            ] }),
            activeTab === "maintenance" && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex min-h-0 flex-1 flex-col space-y-6", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx(
                ContextDataRepairPanel,
                {
                  savedEnabled: Boolean(state.payload.settings.context_assistance?.enabled),
                  disabled: saving || proofModalOpen,
                  onStopped: handleContextAssistanceStopped,
                  onBusyChange: setContextAssistanceBusy
                }
              ),
              /* @__PURE__ */ jsxRuntimeExports.jsx(SettingsFormSection, { title: "Keep this machine tidy", description: "Export, reset, clear history, or fix a broken approval link.", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-4 py-3", children: [
                perfSnapshot !== null ? /* @__PURE__ */ jsxRuntimeExports.jsx(DiagnosticsPerfCard, { snapshot: perfSnapshot }) : null,
                /* @__PURE__ */ jsxRuntimeExports.jsx(
                  "input",
                  {
                    ref: settingsImportInputRef,
                    type: "file",
                    accept: "application/json,.json",
                    className: "sr-only",
                    onChange: handleImportSettingsFile,
                    "aria-hidden": "true",
                    tabIndex: -1
                  }
                ),
                /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid gap-4 sm:grid-cols-2", children: [
                  /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-3", children: [
                    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
                      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-brand-dark", children: "Clear saved approvals" }),
                      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-500", children: "Guard will ask again for every action that was previously approved." }),
                      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-2", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { onClick: handleClearApprovals, disabled: clearingApprovals, variant: "outline", children: clearingApprovals ? "Clearing…" : "Clear approvals" }) })
                    ] }),
                    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
                      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-brand-dark", children: "Clear review queue" }),
                      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-500", children: "Removes pending review items only." }),
                      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-2", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { onClick: handleClearReviewQueue, disabled: clearingReviewQueue, variant: "outline", children: clearingReviewQueue ? "Clearing…" : "Clear review queue" }) })
                    ] }),
                    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
                      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-brand-dark", children: "Clear evidence log" }),
                      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-500", children: "Permanently removes local audit history." }),
                      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-2", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { onClick: handleClearEvidence, disabled: clearingEvidence, variant: "outline", children: clearingEvidence ? "Clearing…" : "Clear evidence" }) })
                    ] })
                  ] }),
                  /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-3", children: [
                    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
                      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-brand-dark", children: "Export settings" }),
                      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-500", children: "Download local Guard preferences as JSON." }),
                      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-2", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { onClick: handleExportSettings, disabled: exportingSettings, variant: "secondary", children: exportingSettings ? "Exporting…" : "Export settings" }) })
                    ] }),
                    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
                      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-brand-dark", children: "Import settings" }),
                      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-500", children: "Restore preferences from a Guard settings export file." }),
                      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-2", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { onClick: handleImportSettingsClick, disabled: importingSettings, variant: "secondary", children: importingSettings ? "Importing…" : "Import settings" }) })
                    ] }),
                    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
                      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-brand-dark", children: "Export diagnostics" }),
                      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-500", children: "Download evidence and runtime details for support." }),
                      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-2", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { onClick: handleExportDiagnostics, disabled: exporting, variant: "secondary", children: exporting ? "Exporting…" : "Export diagnostics" }) })
                    ] }),
                    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
                      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-brand-dark", children: "Reset to defaults" }),
                      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-500", children: "Restore factory local settings on this machine." }),
                      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-2", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { onClick: handleResetSettings, disabled: resettingSettings, variant: "outline", children: resettingSettings ? "Resetting…" : "Reset settings" }) })
                    ] }),
                    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { id: "approval-center-repair", children: [
                      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-brand-dark", children: "Repair approval center" }),
                      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-500", children: "Use when the approval link fails after Guard restarts." }),
                      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-2", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { onClick: handleRepairApprovalCenter, disabled: repairing, variant: "secondary", children: repairing ? "Repairing…" : "Repair" }) })
                    ] }),
                    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { id: "guard-repair", children: [
                      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-brand-dark", children: "Repair Guard" }),
                      /* @__PURE__ */ jsxRuntimeExports.jsx(GuardRepairControl, { description: "Fixes the background service, app hooks, and stale local state when hooks time out or an app stays blocked." })
                    ] }),
                    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { id: "guard-hook-removal", children: /* @__PURE__ */ jsxRuntimeExports.jsx(GuardHookRemovalPanel, {}) })
                  ] })
                ] }),
                /* @__PURE__ */ jsxRuntimeExports.jsx(SettingsActionMessage, { message: actionMessage, kind: actionMessageKind })
              ] }) })
            ] })
          ]
        }
      ) })
    ] }),
    !contextOnly || hasUnsavedChanges(savedSettingsRef.current, draft) || saving || saveSuccess || saveError || proofModalOpen ? /* @__PURE__ */ jsxRuntimeExports.jsx(
      "div",
      {
        className: "sticky bottom-2 mt-auto rounded-xl border border-slate-200 bg-white/95 p-3 shadow-lg backdrop-blur sm:bottom-4 sm:p-4",
        role: "region",
        "aria-label": contextOnly ? "Save CIGAR preferences" : "Save settings",
        children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center justify-between gap-3", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { onClick: handleSave, disabled: saving || saveSuccess || contextAssistanceBusy, children: saveSuccess ? /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "flex items-center gap-2", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCheckCircle, { className: "h-4 w-4", "aria-hidden": "true" }),
              "Saved"
            ] }) : saving ? "Saving…" : contextOnly ? "Save CIGAR preferences" : "Save settings" }),
            hasUnsavedChanges(savedSettingsRef.current, draft) && /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "ml-3 inline-flex items-center gap-1.5 text-xs font-medium text-brand-attention", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "h-1.5 w-1.5 rounded-full bg-brand-attention" }),
              "Unsaved changes"
            ] })
          ] }),
          saveSuccess ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-emerald-600", children: "Settings saved" }) : saveError ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-brand-purple", children: saveError }) : /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "hidden text-xs text-slate-500 sm:block", children: contextOnly ? "Saving records your choices. Start the runtime after saving. Managed policy may restrict availability." : "Use this for local tuning. Team policy from Guard Cloud may still override some decisions." }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { "aria-live": "polite", "aria-atomic": "true", className: "sr-only", children: saveStatusText(saveSuccess, saveError) })
        ] })
      }
    ) : null,
    proofModalOpen && pendingProofAction !== null ? /* @__PURE__ */ jsxRuntimeExports.jsx(
      SettingsSaveProofModal,
      {
        open: proofModalOpen,
        mode: proofModalMode,
        gate: savedSettingsRef.current?.approval_gate ?? null,
        ...resolveSettingsSaveProofModalCopy({
          mode: proofModalMode,
          gateSettingsChanged: hasApprovalGateSettingsChanged(
            savedSettingsRef.current?.approval_gate ?? null,
            approvalGateEnabled,
            approvalGateCooldown,
            approvalGateStrictAllDecisions
          ),
          maintenanceAction: pendingProofAction.kind === "maintenance" ? pendingProofAction.action : void 0
        }),
        error: proofModalError,
        pending: proofModalPending || saving || importingSettings || resettingSettings,
        onCancel: closeProofModal,
        onConfirm: handleProofModalConfirm
      }
    ) : null,
    confirmDialog,
    (pendingMode === "observe" || pendingPosture === "watch") && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "guard-fade-in fixed inset-0 z-50 flex items-center justify-center bg-black/30 p-4 backdrop-blur-sm", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "w-full max-w-sm rounded-2xl border border-brand-attention/15 bg-white p-6 shadow-xl", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start gap-3", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "inline-flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-brand-attention/10", children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniExclamationTriangle, { className: "h-5 w-5 text-brand-attention", "aria-hidden": "true" }) }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "text-base font-semibold text-brand-dark", children: "Switch to Watch?" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm text-slate-500", children: "Protection is off. Guard is only recording. Use this only while debugging." })
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-6 flex flex-wrap gap-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("button", { onClick: confirmModeChange, className: "inline-flex min-h-11 items-center rounded-lg bg-brand-attention px-4 text-sm font-semibold text-white transition-colors hover:bg-brand-attention/90", children: "Switch to Watch" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("button", { onClick: cancelModeChange, className: "inline-flex min-h-11 items-center rounded-lg border border-slate-200 bg-white px-4 text-sm font-medium text-brand-dark transition-colors hover:bg-slate-50", children: "Keep protection on" })
      ] })
    ] }) })
  ] });
}
function SettingsActionMessage(props) {
  if (props.message === null) {
    return null;
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsx(
    "div",
    {
      className: `rounded-xl border px-4 py-3 text-sm font-medium ${props.kind === "error" ? "border-brand-attention/20 bg-brand-attention/[0.04] text-brand-dark" : "border-brand-blue/15 bg-brand-blue/[0.04] text-brand-dark"}`,
      role: props.kind === "error" ? "alert" : "status",
      children: props.message
    }
  );
}
function DiagnosticsPerfCard(props) {
  const threadCount = props.snapshot.thread_count;
  const daemonPort = props.snapshot.runtime_state?.daemon_port ?? null;
  const startedAt = props.snapshot.runtime_state?.started_at ?? null;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-lg bg-slate-50/80 px-3 py-2", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-semibold text-brand-dark", children: "Background service" }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-1 flex flex-wrap gap-x-4 gap-y-1 text-xs text-slate-500", children: [
      threadCount !== void 0 && /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { children: [
        threadCount,
        " worker threads"
      ] }),
      daemonPort !== null && /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { children: [
        "Local port ",
        daemonPort
      ] }),
      startedAt !== null && /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { children: [
        "Running since ",
        new Date(startedAt).toLocaleTimeString()
      ] })
    ] })
  ] });
}
function NotificationSetupCard(props) {
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "rounded-xl border border-brand-blue/15 bg-gradient-to-br from-white to-brand-blue/[0.03] p-5", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex gap-4", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-brand-blue/10 text-brand-blue", children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniBellAlert, { className: "h-5 w-5", "aria-hidden": "true" }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0 flex-1 space-y-4", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-brand-dark", children: "Desktop alerts" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 max-w-2xl text-sm leading-relaxed text-slate-500", children: "When Guard pauses something, a banner helps you respond without hunting for this tab." })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("ol", { className: "grid gap-2 text-xs text-slate-600 sm:grid-cols-3", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("li", { className: "rounded-lg bg-white/90 px-3 py-2 ring-1 ring-slate-100", children: "1. Open notification settings." }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("li", { className: "rounded-lg bg-white/90 px-3 py-2 ring-1 ring-slate-100", children: "2. Allow alerts for Guard." }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("li", { className: "rounded-lg bg-white/90 px-3 py-2 ring-1 ring-slate-100", children: "3. Turn on banners and sound." })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center justify-between gap-3 border-t border-slate-100 pt-4", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "flex flex-wrap gap-2", children: props.result ? /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: props.result.supported ? "blue" : "slate", children: props.result.supported ? "Supported on this Mac" : "Not supported here" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: props.result.preview_sent ? "blue" : "slate", children: props.result.preview_sent ? "Test alert sent" : "No test alert yet" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: props.result.settings_opened ? "blue" : "slate", children: props.result.settings_opened ? "Settings opened" : "Settings not opened" })
        ] }) : /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: "slate", children: "Not set up yet" }) }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "button",
          {
            type: "button",
            onClick: props.onSetup,
            disabled: props.settingUp,
            className: "inline-flex min-h-9 shrink-0 items-center rounded-lg border border-slate-200 bg-white px-3 text-sm font-semibold text-brand-dark transition-colors hover:border-brand-blue/30 hover:bg-slate-50 disabled:pointer-events-none disabled:opacity-50",
            children: props.settingUp ? "Opening…" : "Set up alerts"
          }
        )
      ] }),
      props.result?.guidance ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs leading-relaxed text-slate-500", children: props.result.guidance }) : null
    ] })
  ] }) });
}
function SettingSelect(props) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-xs font-medium text-slate-500", children: props.label }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      "select",
      {
        value: props.value,
        onChange: props.onChange,
        disabled: props.disabled,
        className: "mt-1 min-h-11 w-full rounded-lg border border-slate-200 bg-white px-2.5 py-1.5 text-sm text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-1 focus:ring-brand-blue/20 disabled:cursor-not-allowed disabled:opacity-60",
        children: props.options.map((option) => /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: option.value, children: option.label }, option.value))
      }
    )
  ] });
}
function SettingToggle(props) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { htmlFor: props.id, className: "flex min-h-10 cursor-pointer items-center justify-between gap-3 rounded-lg border border-slate-100 bg-slate-50/60 px-3 py-2 transition-colors hover:bg-slate-100/60", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm text-brand-dark", children: props.label }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("input", { id: props.id, name: props.id, type: "checkbox", checked: props.checked, onChange: props.onChange, className: "h-4 w-4 accent-brand-blue" })
  ] });
}
function FineTuningPresetBanner(props) {
  if (isFineTuningEditable(props.securityLevel)) return null;
  const postureLabel = PROTECTION_POSTURE_COPY[props.posture].label;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(
    "div",
    {
      className: "rounded-xl border border-brand-blue/15 bg-brand-blue/[0.04] px-4 py-4 sm:flex sm:items-center sm:justify-between sm:gap-4",
      role: "region",
      "aria-label": "Advanced rules",
      children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "text-sm font-medium text-brand-dark", children: [
            "These rules follow ",
            postureLabel
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm text-slate-500", children: "Switch to Custom to change how Guard handles each action type on this machine." })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-3 w-full shrink-0 sm:mt-0 sm:w-auto", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { onClick: props.onSwitchToCustom, children: "Use Custom fine-tuning" }) })
      ]
    }
  );
}
function RiskControlRow({ risk, value, disabled, onChange, showConsequence }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid gap-2 py-3 md:grid-cols-[minmax(0,1fr)_200px] md:items-start", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-medium text-brand-dark", children: risk.label }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-500", children: risk.description }),
      showConsequence && risk.consequence && /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-1 text-xs text-slate-400", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-medium", children: "Example:" }),
        " ",
        risk.consequence.example
      ] }),
      showConsequence && risk.consequence && /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-0.5 text-xs text-slate-400", children: risk.consequence.impact })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(SettingSelect, { label: "Guard should", value, options: actionOptions, onChange, disabled })
  ] });
}
const cooldownOptions = [
  { value: "0", label: approvalGateCooldownLabel(0) },
  { value: "900", label: approvalGateCooldownLabel(900) },
  { value: "3600", label: approvalGateCooldownLabel(3600) }
];
function ApprovalGateCard(props) {
  const wasConfigured = props.savedGateConfig?.configured === true;
  const gateActiveOnDevice = props.savedGateConfig?.enabled === true;
  const cooldownActive = props.gateConfig?.cooldown_active === true;
  const cooldownExpiresAt = props.gateConfig?.cooldown_expires_at ?? null;
  const totpEnabled = props.gateConfig?.totp_enabled === true;
  const totpPending = props.gateConfig?.totp_pending === true;
  const failClosed = props.gateConfig?.fail_closed === true;
  const effectiveCooldownSeconds = effectiveApprovalGateCooldownSeconds(props.cooldownSeconds, totpEnabled);
  const cooldownLabel = cooldownExpiresAt ? new Date(cooldownExpiresAt).toLocaleTimeString() : null;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-4 rounded-xl border border-slate-100 bg-slate-50/40 p-4", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "flex items-start justify-between gap-3", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        SettingToggle,
        {
          id: "settings-approval-gate",
          label: "Ask for proof on allow decisions",
          checked: props.enabled,
          onChange: props.onToggle
        }
      ),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-xs text-slate-500", children: "Use a password before allow or trust changes stick. Turn on strict mode to require proof for block decisions too." })
    ] }) }),
    failClosed && props.enabled && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "rounded-lg border border-brand-purple/20 bg-brand-purple/[0.04] px-3 py-2", children: /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-brand-purple", children: "Guard needs your approval setup fixed before trust or policy changes can continue." }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        ApprovalPasswordSection,
        {
          wasConfigured,
          enabled: props.enabled,
          gateActive: gateActiveOnDevice,
          onOpenPasswordChangeModal: props.onOpenPasswordChangeModal
        }
      ),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-xl border border-slate-100 bg-white p-4", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Extra checks" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-3 space-y-3", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            SettingToggle,
            {
              id: "settings-approval-gate-strict",
              label: "Also ask before block decisions",
              checked: props.strictAllDecisions,
              onChange: props.onStrictAllDecisionsChange
            }
          ),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-xs font-medium text-slate-500", children: "Cooldown after approval" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx(
              "select",
              {
                id: "settings-approval-gate-cooldown",
                value: String(effectiveCooldownSeconds),
                onChange: props.onCooldownChange,
                disabled: totpEnabled,
                "aria-describedby": totpEnabled ? "settings-approval-gate-cooldown-help" : void 0,
                className: "mt-1 min-h-9 w-full rounded-lg border border-slate-200 bg-white px-2.5 py-1.5 text-sm text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20 disabled:cursor-not-allowed disabled:bg-slate-100 disabled:text-slate-500",
                children: cooldownOptions.map((opt) => /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: opt.value, children: opt.label }, opt.value))
              }
            ),
            totpEnabled ? /* @__PURE__ */ jsxRuntimeExports.jsx("span", { id: "settings-approval-gate-cooldown-help", className: "mt-1 block text-xs leading-5 text-slate-500", children: "Authenticator approvals do not use the password cooldown. Your saved password cooldown applies when Authenticator is off." }) : null
          ] })
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "overflow-hidden rounded-xl border border-brand-blue/15 bg-white", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center justify-between gap-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "px-4 py-3", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Authenticator app" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 max-w-xl text-xs leading-5 text-slate-500", children: "Add a six-digit code from Google Authenticator, 1Password, Authy, or iCloud Passwords for high-risk approvals." })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "px-4", children: /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: totpEnabled ? "green" : totpPending ? "blue" : "slate", children: totpEnabled ? "Enabled" : totpPending ? "Pending verification" : "Not connected" }) })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "border-t border-slate-100 bg-slate-50/50 px-4 py-3", children: [
          !gateActiveOnDevice && /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "max-w-xl text-xs leading-5 text-slate-500", children: wasConfigured ? "Turn on Ask for proof to manage your authenticator." : "Set an approval password first, then connect an authenticator app for high-risk approvals." }),
          gateActiveOnDevice && !totpEnabled && !totpPending && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center justify-between gap-3", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "max-w-xl space-y-1", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-medium text-brand-dark", children: "Add a second factor for high-risk approvals." }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-500", children: "Setup opens a guided flow for password confirmation, then QR scan." })
            ] }),
            /* @__PURE__ */ jsxRuntimeExports.jsx(
              ActionButton,
              {
                onClick: props.onOpenTotpSetup,
                disabled: props.totpActionPending !== null,
                variant: "outline",
                children: "Set up authenticator"
              }
            )
          ] }),
          gateActiveOnDevice && totpPending && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center justify-between gap-3", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "max-w-xl space-y-1", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-medium text-brand-dark", children: "Finish connecting your authenticator app." }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-500", children: "Open setup to scan the QR code and enter a live six-digit code." })
            ] }),
            /* @__PURE__ */ jsxRuntimeExports.jsx(
              ActionButton,
              {
                onClick: props.onOpenTotpSetup,
                disabled: props.totpActionPending !== null,
                variant: "outline",
                children: "Continue setup"
              }
            )
          ] }),
          gateActiveOnDevice && totpEnabled && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center justify-between gap-3", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "max-w-xl text-xs text-slate-500", children: "Disconnecting removes the app code requirement from future high-risk approvals." }),
            /* @__PURE__ */ jsxRuntimeExports.jsx(
              ActionButton,
              {
                onClick: props.onDisableTotp,
                disabled: props.totpActionPending !== null,
                variant: "outline",
                children: props.totpActionPending === "disable" ? "Disconnecting..." : "Disconnect authenticator"
              }
            )
          ] }),
          props.totpActionError !== null && !props.totpSetupOpen && /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 rounded-lg border border-brand-attention/20 bg-brand-attention/[0.04] px-3 py-2 text-xs text-brand-dark", children: props.totpActionError })
        ] }),
        props.totpSetupOpen && /* @__PURE__ */ jsxRuntimeExports.jsx(
          TotpSetupModal,
          {
            step: props.totpSetupStep,
            enrollment: props.totpEnrollment,
            deviceLabel: props.totpDeviceLabel,
            actionPassword: props.totpActionPassword,
            totpCode: props.totpCode,
            pending: props.totpActionPending,
            error: props.totpActionError,
            onActionPasswordChange: props.onTotpActionPasswordChange,
            onDeviceLabelChange: props.onTotpDeviceLabelChange,
            onTotpCodeChange: props.onTotpCodeChange,
            onConfirmPassword: props.onStartTotpEnrollment,
            onVerify: props.onVerifyTotpEnrollment,
            onClose: props.onCloseTotpSetup
          }
        )
      ] }),
      cooldownActive && cooldownLabel !== null && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-xl border border-brand-blue/15 bg-brand-blue/[0.04] p-4", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Active cooldown" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-1 text-xs text-brand-dark", children: [
          "Cooldown active until ",
          cooldownLabel
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-3", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { onClick: props.onRevokeCooldown, variant: "outline", children: "Revoke cooldown" }) })
      ] })
    ] })
  ] });
}
function TotpSetupConfirmStep(props) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-4 p-6", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-xs font-semibold uppercase tracking-[0.18em] text-slate-500", children: "Approval password" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        "input",
        {
          type: "password",
          autoComplete: "current-password",
          value: props.actionPassword,
          onChange: props.onActionPasswordChange,
          onKeyDown: (event) => {
            if (event.key === "Enter" && props.actionPassword.trim().length > 0 && props.pending === null) {
              props.onConfirmPassword();
            }
          },
          className: "mt-2 min-h-11 w-full rounded-xl border border-slate-200 bg-white px-3 text-sm text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
        }
      )
    ] }),
    props.error !== null && /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "rounded-xl border border-brand-attention/20 bg-brand-attention/[0.04] px-3 py-2 text-xs text-brand-dark", children: props.error }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { onClick: props.onConfirmPassword, disabled: props.pending !== null, children: props.pending === "enroll" ? "Continuing..." : "Continue" })
  ] });
}
function TotpSetupScanStep(props) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid gap-5 p-6 lg:grid-cols-[minmax(0,1fr)_260px]", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx(TotpEnrollmentQrPanel, { enrollment: props.enrollment }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-4 rounded-2xl border border-slate-100 bg-slate-50/70 p-4", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-xs font-semibold uppercase tracking-[0.18em] text-slate-500", children: "Approval password" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "input",
          {
            type: "password",
            autoComplete: "current-password",
            value: props.actionPassword,
            onChange: props.onActionPasswordChange,
            className: "mt-2 min-h-11 w-full rounded-xl border border-slate-200 bg-white px-3 text-sm text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
          }
        ),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-xs text-slate-500", children: "Update this if you changed your approval password after starting setup." })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-xs font-semibold uppercase tracking-[0.18em] text-slate-500", children: "Device label" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "input",
          {
            type: "text",
            value: props.deviceLabel,
            onChange: props.onDeviceLabelChange,
            className: "mt-2 min-h-11 w-full rounded-xl border border-slate-200 bg-white px-3 text-sm text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
          }
        )
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-xs font-semibold uppercase tracking-[0.18em] text-slate-500", children: "Six-digit code" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "input",
          {
            type: "text",
            inputMode: "numeric",
            pattern: "[0-9]*",
            maxLength: 6,
            value: props.totpCode,
            onChange: props.onTotpCodeChange,
            onKeyDown: (event) => {
              if (event.key === "Enter" && props.totpCode.trim().length > 0 && props.pending === null) {
                props.onVerify();
              }
            },
            placeholder: "123456",
            className: "mt-2 min-h-12 w-full rounded-xl border border-slate-200 bg-white px-3 text-center text-lg font-semibold tracking-[0.35em] text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
          }
        )
      ] }),
      props.error !== null && /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "rounded-xl border border-brand-attention/20 bg-brand-attention/[0.04] px-3 py-2 text-xs text-brand-dark", children: props.error }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { onClick: props.onVerify, disabled: props.pending !== null, children: props.pending === "verify" ? "Verifying..." : "Finish setup" })
    ] })
  ] });
}
function TotpSetupModal(props) {
  const modalRef = reactExports.useRef(null);
  useFocusTrap(true, modalRef);
  const isConfirmStep = props.step === "confirm" || props.enrollment === null;
  const stepLabel = isConfirmStep ? "1" : "2";
  return /* @__PURE__ */ jsxRuntimeExports.jsx(
    "div",
    {
      className: "guard-fade-in fixed inset-0 z-50 flex items-center justify-center bg-brand-dark/45 p-4 backdrop-blur-sm",
      role: "dialog",
      "aria-modal": "true",
      "aria-label": "Set up authenticator app",
      children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { ref: modalRef, className: "w-full max-w-3xl overflow-hidden rounded-3xl border border-brand-blue/15 bg-white shadow-2xl", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start justify-between gap-4 border-b border-slate-100 px-6 py-5", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Authenticator setup" }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-2 text-xs font-medium uppercase tracking-[0.16em] text-slate-500", children: [
              "Step ",
              stepLabel,
              " of 2"
            ] }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "mt-2 text-2xl font-semibold tracking-tight text-brand-dark", children: resolveTotpSetupModalTitle(isConfirmStep) }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 max-w-2xl text-sm leading-6 text-slate-600", children: resolveTotpSetupModalDescription(isConfirmStep) })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            "button",
            {
              type: "button",
              onClick: props.onClose,
              className: "inline-flex h-11 w-11 items-center justify-center rounded-full border border-slate-200 bg-white text-slate-500 transition-colors hover:bg-slate-50 hover:text-brand-dark",
              "aria-label": "Close authenticator setup",
              children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniXMark, { className: "h-5 w-5", "aria-hidden": "true" })
            }
          )
        ] }),
        isConfirmStep ? /* @__PURE__ */ jsxRuntimeExports.jsx(
          TotpSetupConfirmStep,
          {
            actionPassword: props.actionPassword,
            pending: props.pending,
            error: props.error,
            onActionPasswordChange: props.onActionPasswordChange,
            onConfirmPassword: props.onConfirmPassword
          }
        ) : null,
        !isConfirmStep && props.enrollment !== null ? /* @__PURE__ */ jsxRuntimeExports.jsx(
          TotpSetupScanStep,
          {
            enrollment: props.enrollment,
            deviceLabel: props.deviceLabel,
            actionPassword: props.actionPassword,
            totpCode: props.totpCode,
            pending: props.pending,
            error: props.error,
            onActionPasswordChange: props.onActionPasswordChange,
            onDeviceLabelChange: props.onDeviceLabelChange,
            onTotpCodeChange: props.onTotpCodeChange,
            onVerify: props.onVerify
          }
        ) : null
      ] })
    }
  );
}
export {
  SettingsWorkspace,
  TotpEnrollmentQrPanel,
  applyApprovalGateDraft,
  buildApprovalGateWriteProof,
  buildClearPolicyPayload,
  buildClearReviewQueuePayload,
  buildSettingsUpdatePayload,
  buildTotpQrImageOptions,
  effectiveApprovalGateCooldownSeconds,
  formatTotpEnrollmentExpiry,
  formatTotpManualKey,
  hasApprovalGateSettingsChanged,
  hasUnsavedChanges,
  isFineTuningEditable,
  isPresentationOnlyChange,
  presentationOnlySavePayload,
  resolveApprovalPasswordSectionCopy,
  resolveFineTuningSectionDescription,
  resolveInitialSettingsTab,
  resolveRepairApprovalCenterMessage,
  resolveSecurityLevelCardDescription,
  resolveSecurityLevelDescription,
  resolveSettingsPresentation,
  resolveTotpSetupModalDescription,
  resolveTotpSetupModalTitle,
  resolveTotpSetupStep
};

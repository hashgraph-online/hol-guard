import { r as reactExports, aP as fetchResolvedApprovalGate, j as jsxRuntimeExports, A as ActionButton, aQ as ApprovalProofModal, T as Tag, aF as PROTECTION_POSTURE_COPY, aR as POSTURE_OUTCOME_COLUMNS, aS as getDefaultExportFromCjs, aT as React, a0 as HiMiniShieldCheck, aU as HiMiniSquares2X2, y as HiMiniLockClosed, aV as HiMiniBellAlert, aW as HiMiniAdjustmentsHorizontal, aX as HiMiniCircleStack, a9 as HiMiniCloud, aY as TabBar, H as HiMiniChevronRight, aZ as SelectMenu, S as SectionLabel, ab as useFocusTrap, a_ as fetchCloudReviewSettings, i as HiMiniArrowPath, a6 as HiMiniXMark, a$ as ApprovalProofFieldInputs, b0 as isApprovalProofSubmitDisabled, b1 as buildApprovalProofCredentials, b2 as changeCloudReviewSettings, b3 as fetchWithGuardAuth, b4 as isRecord$1, b5 as HiMiniArrowTopRightOnSquare, b6 as shellHref, a as contextStatusCopy, v as HiMiniCheckCircle, ad as HiMiniExclamationTriangle, b7 as HiMiniPauseCircle, h as harnessDisplayName, b8 as listContextAgentSessions, b9 as HiMiniLink, ba as revokeContextAgentSession, bb as grantContextWorkspace, bc as authorizeContextAgentSession, bd as ContextAssistanceApiError, be as ask, bf as parseContextScope, bg as validContextBrokerRevision, bh as isGuardDemoMode, bi as HiMiniArrowUturnLeft, q as HiMiniPencilSquare, t as HiMiniMagnifyingGlass, bj as HiMiniCodeBracketSquare, bk as HiMiniFolder, u as HiMiniDocumentText, bl as HiMiniComputerDesktop, bm as HiMiniHome, k as HiMiniCheck, bn as HiMiniFolderPlus, bo as HiMiniClock, bp as listContextWorkspaces, bq as HiMiniFolderOpen, br as manageContextWorkspace, bs as compileWorkspaceContext, w as HiMiniArrowRight, bt as HiMiniChatBubbleLeftEllipsis, bu as HiMiniDocumentMagnifyingGlass, bv as HiMiniPower, bw as HiMiniEyeSlash, bx as HiMiniCpuChip, by as HiMiniAcademicCap, aa as HiMiniQuestionMarkCircle, M as HiMiniClipboardDocument, bz as HiMiniArrowLeft, bA as isCigarProducerVersion, bB as isCigarCoreLabel, a5 as HiMiniSparkles, bC as subscribeDashboardLocation, bD as HiMiniChatBubbleLeftRight, bE as HiMiniArrowUpCircle, bF as parseContextAssistanceStatus, bG as isCigarBuildIdentity, bH as fetchContextInstallations, bI as HiMiniCloudArrowDown, f as fetchContextAssistance, c as controlContextAssistance, bJ as commitDashboardLocation, bK as HiMiniArrowDownTray, bL as downloadBlob, bM as savedEvidenceCopy, bN as guardAwareHref, bO as fetchContextData, bP as forgetContextHistory, bQ as forgetSavedEvidence, bR as resolveProtectionLevelCopy, aA as fetchSettings, bS as fetchRuntimeSnapshot, bT as clearHarnessWatchOverrides, bU as withHarnessPosturePatch, P as updateSettings, bV as clearPolicy, bW as clearReviewQueue, bX as revokeApprovalGateCooldown, bY as disableApprovalGateTotp, bZ as importSettings, b_ as resetSettings, b$ as enrollApprovalGateTotp, c0 as verifyApprovalGateTotp, c1 as clearEvidence, c2 as exportDiagnostics, c3 as repairApprovalCenter, c4 as exportSettings, c5 as setupDesktopNotifications, a7 as EmptyState, c6 as settingsWatchBannerModel, c7 as WorkspacePageHeader, Z as WatchProtectionBanner, c8 as navigateFromAnchor, g as HiMiniChevronDown, c9 as humanizeList, ca as isProtectionPosture, cb as deriveProtectionPosture, cc as normalizeHarnessPostures, cd as approvalGateCooldownLabel } from "../guard-dashboard.js";
import { p as planGuardHookRemoval, r as removeAllGuardHooks, a as GuardRepairRequestError, S as SettingsSaveProofModal, b as resolveSettingsSaveProofKind, c as requiresSettingsSaveProof, d as HarnessPostureSummaryCard, e as HarnessPostureManager, G as GuardRepairControl, f as resolveSettingsSaveProofModalCopy } from "./settings-save-proof-modal-0zM1Juyt.js";
import { f as filterSettingsBySearch, R as RISK_CONTROL_CONSEQUENCES } from "./app-catalog-Ca_M7GbC.js";
import { C as ConfirmDialog, u as useConfirmDialog } from "./confirm-dialog-C0X7QXA-.js";
import { C as ConnectGuardCloudButton } from "./connect-guard-cloud-button-o4J5gv4p.js";
import { C as CIGAR_TABS, a as cigarWaking, b as canStartCigar, c as cigarHomeCopy, d as cigarTabFromSearch } from "./workspace-model-Do0eMrgH.js";
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
function AffectedList({ items, label: label2 }) {
  if (items.length === 0) return null;
  return /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "flex flex-wrap gap-1.5", "aria-label": label2, children: items.map((item) => /* @__PURE__ */ jsxRuntimeExports.jsx("li", { children: /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: "slate", children: describeAffectedHarness(item) }) }, item.harness)) });
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
      for (let row2 = 0; row2 < moduleCount; row2 += 1) {
        modules[row2] = new Array(moduleCount);
        for (let col = 0; col < moduleCount; col += 1) {
          modules[row2][col] = null;
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
  const setupPositionProbePattern = function(row2, col) {
    for (let r = -1; r <= 7; r += 1) {
      if (row2 + r <= -1 || _moduleCount <= row2 + r) continue;
      for (let c = -1; c <= 7; c += 1) {
        if (col + c <= -1 || _moduleCount <= col + c) continue;
        if (0 <= r && r <= 6 && (c == 0 || c == 6) || 0 <= c && c <= 6 && (r == 0 || r == 6) || 2 <= r && r <= 4 && 2 <= c && c <= 4) {
          _modules[row2 + r][col + c] = true;
        } else {
          _modules[row2 + r][col + c] = false;
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
        const row2 = pos[i];
        const col = pos[j];
        if (_modules[row2][col] != null) {
          continue;
        }
        for (let r = -2; r <= 2; r += 1) {
          for (let c = -2; c <= 2; c += 1) {
            if (r == -2 || r == 2 || c == -2 || c == 2 || r == 0 && c == 0) {
              _modules[row2 + r][col + c] = true;
            } else {
              _modules[row2 + r][col + c] = false;
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
    let row2 = _moduleCount - 1;
    let bitIndex = 7;
    let byteIndex = 0;
    const maskFunc = QRUtil.getMaskFunction(maskPattern);
    for (let col = _moduleCount - 1; col > 0; col -= 2) {
      if (col == 6) col -= 1;
      while (true) {
        for (let c = 0; c < 2; c += 1) {
          if (_modules[row2][col - c] == null) {
            let dark = false;
            if (byteIndex < data.length) {
              dark = (data[byteIndex] >>> bitIndex & 1) == 1;
            }
            const mask = maskFunc(row2, col - c);
            if (mask) {
              dark = !dark;
            }
            _modules[row2][col - c] = dark;
            bitIndex -= 1;
            if (bitIndex == -1) {
              byteIndex += 1;
              bitIndex = 7;
            }
          }
        }
        row2 += inc;
        if (row2 < 0 || _moduleCount <= row2) {
          row2 -= inc;
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
  _this.isDark = function(row2, col) {
    if (row2 < 0 || _moduleCount <= row2 || col < 0 || _moduleCount <= col) {
      throw row2 + "," + col;
    }
    return _modules[row2][col];
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
    const size2 = _this.getModuleCount() * cellSize + margin * 2;
    let c, mc, r, mr, qrSvg = "", rect;
    rect = "l" + cellSize + ",0 0," + cellSize + " -" + cellSize + ",0 0,-" + cellSize + "z ";
    qrSvg += '<svg version="1.1" xmlns="http://www.w3.org/2000/svg"';
    qrSvg += !opts.scalable ? ' width="' + size2 + 'px" height="' + size2 + 'px"' : "";
    qrSvg += ' viewBox="0 0 ' + size2 + " " + size2 + '" ';
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
    const size2 = _this.getModuleCount() * cellSize + margin * 2;
    const min = margin;
    const max = size2 - margin;
    return createDataURL(size2, size2, function(x, y) {
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
    const size2 = _this.getModuleCount() * cellSize + margin * 2;
    let img = "";
    img += "<img";
    img += ' src="';
    img += _this.createDataURL(cellSize, margin);
    img += '"';
    img += ' width="';
    img += size2;
    img += '"';
    img += ' height="';
    img += size2;
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
    const size2 = _this.getModuleCount() * cellSize + margin * 2;
    const min = margin;
    const max = size2 - margin;
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
    for (y = 0; y < size2; y += 2) {
      r1 = Math.floor((y - min) / cellSize);
      r2 = Math.floor((y + 1 - min) / cellSize);
      for (x = 0; x < size2; x += 1) {
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
    if (size2 % 2 && margin > 0) {
      return ascii.substring(0, ascii.length - size2 - 1) + Array(size2 + 1).join("▀");
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
    const size2 = _this.getModuleCount() * cellSize + margin * 2;
    const min = margin;
    const max = size2 - margin;
    let y, x, r, p;
    const white = Array(cellSize + 1).join("██");
    const black = Array(cellSize + 1).join("  ");
    let ascii = "";
    let line = "";
    for (y = 0; y < size2; y += 1) {
      r = Math.floor((y - min) / cellSize);
      line = "";
      for (x = 0; x < size2; x += 1) {
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
    for (let row2 = 0; row2 < length; row2++) {
      for (let col = 0; col < length; col++) {
        context.fillStyle = _this.isDark(row2, col) ? "black" : "white";
        context.fillRect(col * cellSize, row2 * cellSize, cellSize, cellSize);
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
    for (let row2 = 0; row2 < moduleCount; row2 += 1) {
      for (let col = 0; col < moduleCount; col += 1) {
        let sameCount = 0;
        const dark = qrcode2.isDark(row2, col);
        for (let r = -1; r <= 1; r += 1) {
          if (row2 + r < 0 || moduleCount <= row2 + r) {
            continue;
          }
          for (let c = -1; c <= 1; c += 1) {
            if (col + c < 0 || moduleCount <= col + c) {
              continue;
            }
            if (r == 0 && c == 0) {
              continue;
            }
            if (dark == qrcode2.isDark(row2 + r, col + c)) {
              sameCount += 1;
            }
          }
        }
        if (sameCount > 5) {
          lostPoint += 3 + sameCount - 5;
        }
      }
    }
    for (let row2 = 0; row2 < moduleCount - 1; row2 += 1) {
      for (let col = 0; col < moduleCount - 1; col += 1) {
        let count2 = 0;
        if (qrcode2.isDark(row2, col)) count2 += 1;
        if (qrcode2.isDark(row2 + 1, col)) count2 += 1;
        if (qrcode2.isDark(row2, col + 1)) count2 += 1;
        if (qrcode2.isDark(row2 + 1, col + 1)) count2 += 1;
        if (count2 == 0 || count2 == 4) {
          lostPoint += 3;
        }
      }
    }
    for (let row2 = 0; row2 < moduleCount; row2 += 1) {
      for (let col = 0; col < moduleCount - 6; col += 1) {
        if (qrcode2.isDark(row2, col) && !qrcode2.isDark(row2, col + 1) && qrcode2.isDark(row2, col + 2) && qrcode2.isDark(row2, col + 3) && qrcode2.isDark(row2, col + 4) && !qrcode2.isDark(row2, col + 5) && qrcode2.isDark(row2, col + 6)) {
          lostPoint += 40;
        }
      }
    }
    for (let col = 0; col < moduleCount; col += 1) {
      for (let row2 = 0; row2 < moduleCount - 6; row2 += 1) {
        if (qrcode2.isDark(row2, col) && !qrcode2.isDark(row2 + 1, col) && qrcode2.isDark(row2 + 2, col) && qrcode2.isDark(row2 + 3, col) && qrcode2.isDark(row2 + 4, col) && !qrcode2.isDark(row2 + 5, col) && qrcode2.isDark(row2 + 6, col)) {
          lostPoint += 40;
        }
      }
    }
    let darkCount = 0;
    for (let col = 0; col < moduleCount; col += 1) {
      for (let row2 = 0; row2 < moduleCount; row2 += 1) {
        if (qrcode2.isDark(row2, col)) {
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
    const list2 = [];
    for (let i = 0; i < length; i += 1) {
      const count2 = rsBlock[i * 3 + 0];
      const totalCount = rsBlock[i * 3 + 1];
      const dataCount = rsBlock[i * 3 + 2];
      for (let j = 0; j < count2; j += 1) {
        list2.push(qrRSBlock(totalCount, dataCount));
      }
    }
    return list2;
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
  var bgColor = _ref.bgColor, bgD = _ref.bgD, fgD = _ref.fgD, fgColor = _ref.fgColor, size2 = _ref.size, title = _ref.title, viewBoxSize = _ref.viewBoxSize, _ref$xmlns = _ref.xmlns, xmlns = _ref$xmlns === void 0 ? "http://www.w3.org/2000/svg" : _ref$xmlns, props = _objectWithoutProperties(_ref, _excluded$1);
  return /* @__PURE__ */ React.createElement("svg", _extends({}, props, {
    height: size2,
    ref,
    viewBox: "0 0 ".concat(viewBoxSize, " ").concat(viewBoxSize),
    width: size2,
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
  var _ref$bgColor = _ref.bgColor, bgColor = _ref$bgColor === void 0 ? "#FFFFFF" : _ref$bgColor, _ref$fgColor = _ref.fgColor, fgColor = _ref$fgColor === void 0 ? "#000000" : _ref$fgColor, _ref$level = _ref.level, level = _ref$level === void 0 ? "L" : _ref$level, _ref$size = _ref.size, size2 = _ref$size === void 0 ? 256 : _ref$size, value = _ref.value, props = _objectWithoutProperties(_ref, _excluded);
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
    bgD: cells.map(function(row2, rowIndex) {
      return row2.map(function(cell, cellIndex) {
        return !cell ? "M ".concat(cellIndex, " ").concat(rowIndex, " l 1 0 0 1 -1 0 Z") : "";
      }).join(" ");
    }).join(" "),
    fgColor,
    fgD: cells.map(function(row2, rowIndex) {
      return row2.map(function(cell, cellIndex) {
        return cell ? "M ".concat(cellIndex, " ").concat(rowIndex, " l 1 0 0 1 -1 0 Z") : "";
      }).join(" ");
    }).join(" "),
    ref,
    size: size2,
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
  },
  {
    key: "cloud",
    label: "Guard Cloud",
    summary: "Guard Cloud features for this machine. Protection on this machine does not depend on them."
  }
];
const ICON_PROTECTION = /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniShieldCheck, { className: "h-4 w-4", "aria-hidden": "true" });
const ICON_APPS = /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniSquares2X2, { className: "h-4 w-4", "aria-hidden": "true" });
const ICON_APPROVAL = /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniLockClosed, { className: "h-4 w-4", "aria-hidden": "true" });
const ICON_NOTIFICATIONS = /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniBellAlert, { className: "h-4 w-4", "aria-hidden": "true" });
const ICON_RISK = /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniAdjustmentsHorizontal, { className: "h-4 w-4", "aria-hidden": "true" });
const ICON_MAINTENANCE = /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCircleStack, { className: "h-4 w-4", "aria-hidden": "true" });
const ICON_CLOUD_ACTIONS = /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCloud, { className: "h-4 w-4", "aria-hidden": "true" });
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
  },
  {
    key: "cloud-actions",
    label: "Cloud actions",
    mobileLabel: "Cloud",
    summary: "Which workspaces AI tools here are signed in to, and whether Guard Cloud still accepts them.",
    group: "cloud",
    icon: ICON_CLOUD_ACTIONS
  }
];
const localSettingsMobileTabLabels = Object.fromEntries(
  localSettingsNavItems.map((item) => [item.key, item.mobileLabel ?? item.label])
);
function isLocalSettingsTabKey(value) {
  return value === "protection" || value === "apps" || value === "approval" || value === "notifications" || value === "rules" || value === "maintenance" || value === "cloud-actions";
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
  label: label2,
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
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { id: labelId, className: "guard-settings-body font-medium text-brand-dark", children: label2 }),
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
  label: label2,
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
      /* @__PURE__ */ jsxRuntimeExports.jsx("label", { htmlFor: selectId, className: "guard-settings-body font-medium text-brand-dark", children: label2 }),
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
function SettingsMenuRow({ label: label2, description, value, options, onChange, disabled = false }) {
  const labelId = reactExports.useId();
  const descriptionId = reactExports.useId();
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid gap-2 py-3 md:grid-cols-[minmax(0,1fr)_240px] md:items-center", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { id: labelId, className: "guard-settings-body font-medium text-brand-dark", children: label2 }),
      description ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { id: descriptionId, className: "guard-settings-caption mt-0.5 text-slate-500", children: description }) : null
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      SelectMenu,
      {
        labelledBy: labelId,
        describedBy: description ? descriptionId : void 0,
        value,
        options,
        disabled,
        onChange
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
const STATUS_PATH = "/v1/cloud-actions/status";
async function failureMessage(response, fallback) {
  const payload = await response.json().catch(() => null);
  const message2 = isRecord$1(payload) ? payload["message"] : null;
  return typeof message2 === "string" && message2.trim() ? message2 : fallback;
}
async function fetchCloudActionsStatus() {
  const response = await fetchWithGuardAuth(STATUS_PATH, { cache: "no-store" });
  if (!response.ok) {
    throw new Error(await failureMessage(response, `Request failed with ${response.status}`));
  }
  return await response.json();
}
async function checkCloudActionsNow() {
  const response = await fetchWithGuardAuth(STATUS_PATH, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: "{}",
    cache: "no-store"
  });
  if (response.status === 429 || response.status === 409) {
    const payload = await response.json().catch(() => null);
    const retry = isRecord$1(payload) ? payload["retry_after_seconds"] : null;
    const message2 = isRecord$1(payload) && typeof payload["message"] === "string" ? payload["message"] : null;
    if (isRecord$1(payload) && payload["error"] === "not_paired") {
      throw new Error(message2 ?? "This computer is not connected to Guard Cloud. Run hol-guard connect.");
    }
    return {
      kind: "wait",
      retryAfterSeconds: typeof retry === "number" && Number.isFinite(retry) && retry > 0 ? Math.min(retry, 60) : 10,
      message: message2 ?? "Guard is already checking. Try again shortly."
    };
  }
  if (!response.ok) {
    throw new Error(await failureMessage(response, "Guard could not check Cloud actions. Try again."));
  }
  return { kind: "checked", payload: await response.json() };
}
const CLOUD_ACTIONS_STATUS_SCHEMA = "guard.cloud-actions.local-status.v2";
const CLOUD_ACTIONS_CONNECT_COMMAND = "hol-guard connect";
const MAX_MESSAGE_CHARS = 240;
const WORKSPACE_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const SITE_PATTERN = /^[A-Za-z0-9.-]{1,253}(?::\d{1,5})?$/;
const DEFAULT_CONNECT_URL = "https://hol.org/guard/connect";
const DEFAULT_CONNECT_SITE = "hol.org";
const CLOUD_URL_PATTERN = /^(?:https:\/\/[A-Za-z0-9.-]{1,253}|http:\/\/(?:127\.0\.0\.1|localhost|host\.docker\.internal))(?::\d{1,5})?$/;
const CLOUD_BASE_PATH_PATTERN = /^(?:\/[a-z0-9-]{1,32})?$/;
function isRecord(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
function text$1(value, pattern) {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  if (!trimmed) return null;
  if (pattern && !pattern.test(trimmed)) return null;
  return trimmed;
}
function moment(value) {
  const raw = text$1(value);
  return raw !== null && Number.isFinite(Date.parse(raw)) ? raw : null;
}
const NOT_CHECKED = { state: "not_checked", checkedAt: null, stale: false, message: null };
function normalizeCheck(value) {
  if (!isRecord(value) || value["state"] === "not_checked" || !isRecord(value["service"])) return NOT_CHECKED;
  const service = value["service"];
  const state = text$1(service["state"], /^[a-z_]{1,40}$/);
  if (state === null) return NOT_CHECKED;
  const checkedAt = moment(value["checked_at"]);
  const message2 = text$1(service["message"]);
  return {
    state,
    checkedAt,
    stale: checkedAt === null || value["stale"] === true,
    message: message2 === null ? null : message2.slice(0, MAX_MESSAGE_CHARS)
  };
}
function cloudBase(value, cloudUrl) {
  const base = text$1(value);
  if (base === null || cloudUrl === null || !base.startsWith(cloudUrl)) return null;
  return CLOUD_BASE_PATH_PATTERN.test(base.slice(cloudUrl.length)) ? base : null;
}
function normalizeConnection(value) {
  const site = text$1(value["site"], SITE_PATTERN);
  const reported = text$1(value["cloud_url"], CLOUD_URL_PATTERN);
  const cloudUrl = reported !== null && site !== null && reported.replace(/^https?:\/\//, "") === site ? reported : null;
  const setting = value["state"];
  return {
    setting: setting === "on" || setting === "off" ? setting : "unknown",
    workspace: text$1(value["workspace"], WORKSPACE_PATTERN),
    site,
    cloudBaseUrl: cloudBase(value["cloud_base_url"], cloudUrl),
    check: normalizeCheck(value["check"])
  };
}
function normalizeCloudActionsStatus(payload) {
  if (!isRecord(payload) || payload["schema"] !== CLOUD_ACTIONS_STATUS_SCHEMA) return null;
  const connection = payload["connection"];
  if (!isRecord(connection) || typeof connection["state"] !== "string") return null;
  const staleAfter = payload["stale_after_seconds"];
  return {
    generatedAt: moment(payload["generated_at"]),
    staleAfterSeconds: typeof staleAfter === "number" && Number.isFinite(staleAfter) && staleAfter > 0 ? staleAfter : 300,
    nextCheckAllowedAt: moment(payload["next_check_allowed_at"]),
    connection: connection["state"] === "not_paired" ? null : normalizeConnection(connection)
  };
}
const STATE_COPY = {
  current: { label: "Available", tone: "good", remedy: null, reconnect: false },
  not_checked: {
    label: "Not checked yet",
    tone: "neutral",
    remedy: "Select Check now to ask Guard Cloud about Cloud actions.",
    reconnect: false
  },
  offline: {
    label: "Guard Cloud not reachable",
    tone: "neutral",
    remedy: "Check this computer's internet connection, then check again.",
    reconnect: false
  },
  not_turned_on: {
    label: "Not turned on",
    tone: "neutral",
    remedy: "Cloud actions are not turned on for this Guard Cloud. Nothing on this computer needs changing.",
    reconnect: false
  },
  changed: {
    label: "Reconnect",
    tone: "attention",
    remedy: "Guard Cloud changed what Cloud actions offer. Reconnect this computer to pick up the change.",
    reconnect: true
  },
  unexpected_answer: {
    label: "Unexpected answer",
    tone: "neutral",
    remedy: "Guard Cloud gave an answer Guard did not expect. Check again in a few minutes.",
    reconnect: false
  },
  off: {
    label: "Off on this computer",
    tone: "neutral",
    remedy: "Cloud actions were left off when this computer connected. To turn them on, reconnect and leave them on in the browser.",
    reconnect: true
  }
};
const UNKNOWN_STATE = {
  label: "Unknown",
  tone: "neutral",
  remedy: "Check again, or update Guard if this keeps happening.",
  reconnect: false
};
function cloudActionsStateCopy(state) {
  return STATE_COPY[state] ?? UNKNOWN_STATE;
}
function cloudActionsCurrentState(connection) {
  return connection.setting === "off" ? "off" : connection.check.state;
}
function cloudActionsReconnectCommand(connection) {
  if (connection === null) return CLOUD_ACTIONS_CONNECT_COMMAND;
  if (connection.cloudBaseUrl === null && connection.site !== null && connection.site !== DEFAULT_CONNECT_SITE) {
    return null;
  }
  const parts = [CLOUD_ACTIONS_CONNECT_COMMAND];
  const connectUrl = connection.cloudBaseUrl === null ? null : `${connection.cloudBaseUrl}/guard/connect`;
  if (connectUrl !== null && connectUrl !== DEFAULT_CONNECT_URL) parts.push(`--connect-url ${connectUrl}`);
  if (connection.workspace !== null) parts.push(`--cloud-workspace ${connection.workspace}`);
  return parts.join(" ");
}
function cloudActionsSettingCopy(setting) {
  if (setting === "on") return "On";
  if (setting === "off") return "Off";
  return "Not reported by Guard Cloud";
}
function elapsedCopy(seconds) {
  if (seconds < 60) return "less than a minute ago";
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return minutes === 1 ? "1 minute ago" : `${minutes} minutes ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 48) return hours === 1 ? "1 hour ago" : `${hours} hours ago`;
  const days = Math.floor(hours / 24);
  return `${days} days ago`;
}
function cloudActionsCheckedCopy(check, now, staleAfterSeconds) {
  if (check.checkedAt === null) return "Not checked yet";
  const seconds = Math.max(0, (now.getTime() - Date.parse(check.checkedAt)) / 1e3);
  const when = `Checked ${elapsedCopy(seconds)}`;
  return check.stale || seconds > staleAfterSeconds ? `${when}. This answer may be out of date.` : when;
}
function cloudActionsRetryAfterSeconds(nextCheckAllowedAt, now) {
  if (nextCheckAllowedAt === null) return 0;
  const seconds = Math.ceil((Date.parse(nextCheckAllowedAt) - now.getTime()) / 1e3);
  return Number.isFinite(seconds) && seconds > 0 ? Math.min(seconds, 60) : 0;
}
function cloudActionsSummary(status) {
  const connection = status.connection;
  if (connection === null) return "This computer is not connected to Guard Cloud.";
  const where = connection.workspace === null ? "Connected to Guard Cloud." : `Connected to workspace ${connection.workspace}.`;
  const copy = cloudActionsStateCopy(cloudActionsCurrentState(connection));
  return copy.tone === "attention" ? `${where} Cloud actions need attention.` : where;
}
function cloudActionsLinks(connection) {
  if (connection.workspace === null || connection.cloudBaseUrl === null) return [];
  const base = connection.cloudBaseUrl;
  const workspace = encodeURIComponent(connection.workspace);
  return [
    {
      label: "Review requests",
      description: "Actions waiting for a decision. Approving one there never approves anything paused on this computer.",
      href: `${base}/guard/review?workspaceId=${workspace}&tab=needs-review`
    },
    {
      label: "Action history",
      description: "What Cloud actions did and who decided.",
      href: `${base}/guard/evidence?workspaceId=${workspace}&tab=decisions&source=cloud`
    },
    {
      label: "Included actions",
      description: "How many actions your plan includes and how many are left.",
      href: `${base}/guard/settings?tab=billing&workspaceId=${workspace}#included-actions`
    },
    {
      label: "Connected accounts",
      description: "The accounts Cloud actions can use for this workspace.",
      href: `${base}/guard/settings?tab=integrations&workspaceId=${workspace}#connected-accounts`
    }
  ];
}
const TONE_CLASS = {
  good: "border-emerald-200 bg-emerald-50 text-emerald-800",
  neutral: "border-slate-200 bg-slate-50 text-slate-700",
  attention: "border-amber-200 bg-amber-50 text-amber-900"
};
const UNREADABLE = "Guard could not read the Cloud actions status on this computer. Update Guard, then reload this page.";
const HEADING_ID = "cloud-actions-connection";
function CommandLine({ label: label2, command }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-2", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-600", children: label2 }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      "code",
      {
        tabIndex: 0,
        className: "mt-1 block overflow-x-auto whitespace-pre rounded-md bg-slate-50 px-3 py-2 font-mono text-xs text-brand-dark focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-dark",
        children: command
      }
    )
  ] });
}
function Reconnect({ connection }) {
  const command = cloudActionsReconnectCommand(connection);
  if (command !== null) return /* @__PURE__ */ jsxRuntimeExports.jsx(CommandLine, { label: "To reconnect, run this in a terminal", command });
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-2 text-sm text-slate-700", children: [
    "To reconnect, run ",
    /* @__PURE__ */ jsxRuntimeExports.jsx("code", { className: "font-mono text-xs", children: "hol-guard connect" }),
    " with",
    " ",
    /* @__PURE__ */ jsxRuntimeExports.jsx("code", { className: "font-mono text-xs", children: "--connect-url" }),
    " set to the Guard Cloud connect page on ",
    connection.site,
    "."
  ] });
}
function CloudPages({ connection }) {
  const links = cloudActionsLinks(connection);
  if (links.length === 0) return null;
  const pagesId = `${HEADING_ID}-pages`;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("nav", { "aria-labelledby": pagesId, className: "mt-3", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("h5", { id: pagesId, className: "text-xs text-slate-600", children: "Open in Guard Cloud" }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "mt-1 grid grid-cols-1 gap-x-6 gap-y-1 sm:grid-cols-2", children: links.map((link) => /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { className: "min-w-0", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs(
        "a",
        {
          href: link.href,
          target: "_blank",
          rel: "noopener noreferrer",
          className: "inline-flex min-h-11 items-center gap-1.5 rounded-sm text-sm font-semibold text-brand-dark underline decoration-brand-blue underline-offset-2 hover:decoration-2 focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-dark sm:min-h-0",
          children: [
            link.label,
            /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowTopRightOnSquare, { "aria-hidden": "true", className: "h-3.5 w-3.5 shrink-0" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "sr-only", children: "(opens in a new tab)" })
          ]
        }
      ),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-600", children: link.description })
    ] }, link.label)) })
  ] });
}
function CloudActionsConnectionCard({
  connection,
  now,
  staleAfterSeconds
}) {
  const state = cloudActionsCurrentState(connection);
  const copy = cloudActionsStateCopy(state);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { "aria-labelledby": HEADING_ID, className: "rounded-xl border border-slate-100 bg-white p-4", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-start justify-between gap-2", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h4", { id: HEADING_ID, className: "break-all text-sm font-semibold text-brand-dark", children: connection.workspace ?? "Workspace not reported" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-0.5 break-all text-xs text-slate-600", children: connection.site ?? "Guard Cloud site not recorded" })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: `inline-flex shrink-0 items-center rounded-full border px-2.5 py-0.5 text-xs font-semibold ${TONE_CLASS[copy.tone]}`, children: copy.label })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("dl", { className: "mt-3 grid grid-cols-1 gap-x-6 gap-y-2 text-sm sm:grid-cols-2", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-xs text-slate-600", children: "Cloud actions on this computer" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "mt-0.5 text-brand-dark", children: cloudActionsSettingCopy(connection.setting) })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-xs text-slate-600", children: "Guard Cloud's answer" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "mt-0.5 text-brand-dark", children: cloudActionsCheckedCopy(connection.check, now, staleAfterSeconds) })
      ] })
    ] }),
    connection.check.message !== null && state === connection.check.state ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm text-slate-600", children: connection.check.message }) : null,
    copy.remedy !== null ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm text-slate-700", children: copy.remedy }) : null,
    copy.reconnect ? /* @__PURE__ */ jsxRuntimeExports.jsx(Reconnect, { connection }) : null,
    /* @__PURE__ */ jsxRuntimeExports.jsx(CloudPages, { connection })
  ] });
}
function CloudActionsSettingsView({
  status,
  error,
  loading,
  checking,
  notice: notice2,
  retryAfterSeconds,
  now,
  onCheck
}) {
  let summary2 = error ?? "Reading Cloud actions...";
  if (status !== null && !loading) summary2 = cloudActionsSummary(status);
  const connection = status?.connection ?? null;
  let checkLabel = "Check now";
  if (checking) checkLabel = "Checking...";
  else if (retryAfterSeconds > 0) checkLabel = `Check again in ${retryAfterSeconds}s`;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex min-h-0 flex-1 flex-col space-y-6", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start gap-3 rounded-xl border border-emerald-100 bg-emerald-50/60 p-4", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniShieldCheck, { "aria-hidden": "true", className: "mt-0.5 h-5 w-5 shrink-0 text-emerald-700" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-slate-700", children: "Protection on this computer does not depend on Cloud actions. It keeps working when Guard Cloud is offline, when this computer is disconnected, and when included actions run out." })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { "aria-labelledby": "cloud-actions-heading", className: "space-y-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-start justify-between gap-3", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("h3", { id: "cloud-actions-heading", className: "flex items-center gap-2 text-sm font-semibold text-brand-dark", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCloud, { "aria-hidden": "true", className: "h-5 w-5 shrink-0" }),
            " Cloud actions"
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm text-slate-600", children: "Cloud actions let AI tools on this computer ask for actions in the Guard Cloud workspace this computer is connected to. Guard Cloud decides those actions; they never approve anything Guard pauses on this computer." })
        ] }),
        connection !== null ? /* @__PURE__ */ jsxRuntimeExports.jsxs(
          "button",
          {
            type: "button",
            disabled: checking || loading || retryAfterSeconds > 0,
            onClick: onCheck,
            className: "inline-flex min-h-11 shrink-0 items-center gap-2 rounded-md border border-slate-200 px-3 py-2 text-sm font-semibold text-brand-dark hover:bg-slate-50 disabled:opacity-60 sm:min-h-10",
            children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowPath, { "aria-hidden": "true", className: "h-4 w-4" }),
              checkLabel
            ]
          }
        ) : null
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "status", className: "text-sm text-slate-700", children: summary2 }),
      notice2 !== null ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "alert", className: "text-sm text-amber-900", children: notice2 }) : null,
      connection !== null ? /* @__PURE__ */ jsxRuntimeExports.jsx(CloudActionsConnectionCard, { connection, now, staleAfterSeconds: status?.staleAfterSeconds ?? 300 }) : null,
      status !== null && connection === null ? /* @__PURE__ */ jsxRuntimeExports.jsx(CommandLine, { label: "To connect, run this in a terminal", command: CLOUD_ACTIONS_CONNECT_COMMAND }) : null,
      status !== null ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-600", children: "Included actions and connected accounts are kept in Guard Cloud, not on this computer. Guard Cloud asks you to sign in to your account in the browser before it shows them." }) : null
    ] })
  ] });
}
function CloudActionsSettings() {
  const [status, setStatus] = reactExports.useState(null);
  const [error, setError] = reactExports.useState(null);
  const [loading, setLoading] = reactExports.useState(true);
  const [checking, setChecking] = reactExports.useState(false);
  const [notice2, setNotice] = reactExports.useState(null);
  const [now, setNow] = reactExports.useState(() => /* @__PURE__ */ new Date());
  const [waitUntil, setWaitUntil] = reactExports.useState(0);
  const revision = reactExports.useRef(0);
  const apply = reactExports.useCallback((payload) => {
    const next = normalizeCloudActionsStatus(payload);
    setStatus(next);
    setError(next === null ? UNREADABLE : null);
    const current = /* @__PURE__ */ new Date();
    setNow(current);
    if (next !== null) {
      setWaitUntil(current.getTime() + cloudActionsRetryAfterSeconds(next.nextCheckAllowedAt, current) * 1e3);
    }
  }, []);
  reactExports.useEffect(() => {
    const current = ++revision.current;
    void (async () => {
      try {
        const payload = await fetchCloudActionsStatus();
        if (current === revision.current) apply(payload);
      } catch {
        if (current === revision.current) {
          setError("Guard on this computer did not answer. Protection status is on the Home page; reload to try again.");
        }
      } finally {
        if (current === revision.current) setLoading(false);
      }
    })();
    return () => {
      revision.current += 1;
    };
  }, [apply]);
  reactExports.useEffect(() => {
    const timer = window.setInterval(() => setNow(/* @__PURE__ */ new Date()), 1e3);
    return () => window.clearInterval(timer);
  }, []);
  const onCheck = reactExports.useCallback(() => {
    const current = ++revision.current;
    setChecking(true);
    setNotice(null);
    void (async () => {
      try {
        const outcome = await checkCloudActionsNow();
        if (current !== revision.current) return;
        if (outcome.kind === "wait") {
          setNotice(outcome.message);
          setWaitUntil(Date.now() + outcome.retryAfterSeconds * 1e3);
        } else {
          apply(outcome.payload);
        }
      } catch (cause) {
        if (current === revision.current) {
          setNotice(cause instanceof Error ? cause.message : "Guard could not check Cloud actions. Try again.");
        }
      } finally {
        if (current === revision.current) setChecking(false);
      }
    })();
  }, [apply]);
  const retryAfterSeconds = Math.max(0, Math.ceil((waitUntil - now.getTime()) / 1e3));
  return /* @__PURE__ */ jsxRuntimeExports.jsx(
    CloudActionsSettingsView,
    {
      status,
      error,
      loading,
      checking,
      notice: notice2,
      retryAfterSeconds,
      now,
      onCheck
    }
  );
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
const control = "inline-flex min-h-11 items-center justify-center gap-1.5 rounded-lg px-3.5 py-2 text-sm font-semibold transition-colors duration-150 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/40 focus-visible:ring-offset-2 disabled:cursor-not-allowed disabled:opacity-50 motion-reduce:transition-none";
const versionButton = control + " border border-slate-200 bg-white text-brand-dark hover:border-slate-300 hover:bg-slate-50";
const versionPrimary = control + " border border-transparent bg-brand-blue text-white shadow-sm shadow-brand-blue/20 hover:bg-brand-blue/90";
const versionQuiet = control + " text-brand-dark/80 hover:bg-brand-dark/[0.05] hover:text-brand-dark";
const versionField = "mt-1.5 min-h-11 w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm text-brand-dark transition-colors hover:border-brand-blue/40 focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20 disabled:cursor-not-allowed disabled:bg-slate-50";
const versionList = "divide-y divide-brand-dark/[0.07] overflow-hidden rounded-2xl border border-brand-dark/10 bg-white";
const versionHeading = "text-base font-semibold tracking-[-0.01em] text-brand-dark";
const versionLead = "mt-1 max-w-[62ch] text-sm leading-6 text-brand-dark/70";
const versionBytes = (bytes) => (bytes / 1048576).toFixed(1) + " MiB";
const installationLabel = (qualification2) => qualification2 === "guard_qualified" ? "checked on this computer" : "local development build";
const OS = { darwin: "macOS", linux: "Linux", windows: "Windows", win32: "Windows" };
const ARCH = { arm64: "Apple silicon", aarch64: "Arm", x86_64: "Intel", amd64: "Intel", x64: "Intel" };
function platformLabel(platform2) {
  if (!platform2) return "Unknown computer";
  const [os, arch = ""] = platform2.split("-");
  const name = OS[os];
  if (!name) return platform2;
  const arm = arch === "arm64" || arch === "aarch64";
  const chip2 = arm && os !== "darwin" ? "Arm" : ARCH[arch];
  return chip2 ? name + " · " + chip2 : name;
}
function CigarRuntimeSelection(props) {
  const id2 = props.status?.preferences.runtime_id ?? props.value.runtime_id;
  const selected = props.installations?.find((item) => item.runtime_id === id2);
  const pending = props.status !== null && props.value.runtime_id !== id2;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-3 py-4", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-start justify-between gap-x-6 gap-y-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0 flex-[1_1_16rem]", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "guard-settings-body font-medium text-brand-dark", children: "Selected runtime" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-0.5 break-all font-mono text-sm text-brand-dark/80", children: id2 || "No runtime selected" }),
        selected ? /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "guard-settings-caption mt-0.5 text-slate-500", children: [
          selected.sdk_version ? "CIGAR " + selected.sdk_version + " · " : "",
          "Python ",
          selected.python_version.join("."),
          " · ",
          platformLabel(selected.platform),
          " · ",
          installationLabel(selected.qualification)
        ] }) : null
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-2", children: [
        props.onManage ? /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", className: versionButton, disabled: props.disabled, onClick: props.onManage, children: "Choose or switch runtime" }) : /* @__PURE__ */ jsxRuntimeExports.jsx("a", { className: versionButton, href: shellHref("/cigar?section=versions"), children: "Choose or switch runtime" }),
        props.installations !== null ? /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", className: versionQuiet, disabled: props.disabled, onClick: props.onRefresh, children: "Refresh runtime list" }) : null
      ] })
    ] }),
    props.installations?.length === 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-slate-600", children: "No registered CIGAR runtime is available in this profile. Python 3.14 may already be installed; use Updates to inspect approved builds and registration options." }) : null,
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "guard-settings-caption text-slate-500", children: "Choose, prepare and switch runtimes in Updates. A separate selection job protects your current runtime and data." }),
    pending ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { role: "status", className: "space-y-2 rounded-xl border border-amber-200 bg-amber-50/60 px-4 py-3 text-sm text-amber-900", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "A pending runtime choice is in this form. Use the current selection before preparing a different runtime in Updates." }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", className: versionButton, disabled: props.disabled, onClick: props.onRestore, children: "Use current selection" })
    ] }) : null
  ] });
}
const note = "rounded-xl border border-brand-dark/10 bg-surface-1 px-4 py-3 text-sm leading-6 text-brand-dark/75";
const caption$1 = "text-xs leading-5 text-slate-500";
const PROFILES = [
  { value: "low_memory", label: "Smaller context", description: "One project at a time. Stops after two idle minutes." },
  { value: "balanced", label: "Balanced", description: "Two projects at a time. Stops after ten idle minutes." },
  { value: "custom", label: "Custom limits", description: "Set your own limits under More settings." }
];
function Group({ title, children }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "space-y-3", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("h4", { className: "text-sm font-semibold text-brand-dark", children: title }),
    children
  ] });
}
function Fact({ term, children }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-xl bg-surface-1 px-3 py-2.5", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-xs text-slate-500", children: term }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "mt-0.5 text-sm font-medium text-brand-dark", children })
  ] });
}
function markerFor(running, attention) {
  if (running) return [HiMiniCheckCircle, "bg-brand-green-bg text-brand-green-text"];
  if (attention) return [HiMiniExclamationTriangle, "bg-amber-100 text-amber-700"];
  return [HiMiniPauseCircle, "bg-brand-dark/[0.06] text-brand-dark/55"];
}
function availabilityText(loading, copy) {
  if (loading) return "Checking availability…";
  return copy ? `${copy.label}. ${copy.detail}` : "Availability has not been verified.";
}
function ContextSettingsControls(props) {
  const { value, status, installations } = props;
  const titleId = reactExports.useId();
  const storageId = reactExports.useId();
  const statusCopy = status ? contextStatusCopy(status) : null;
  const selected = installations?.some((item) => item.runtime_id === value?.runtime_id) === true;
  const disabled = props.disabled || props.busy;
  const editingDisabled = disabled || props.locked || value === null || status === null;
  const checkDisabled = disabled || props.dirty || !status?.verification_permitted || Boolean(status?.job) || !value?.runtime_id;
  const stopped = !value?.enabled && !status?.requested_enabled && !status?.job && !status?.effective_enabled;
  const runtime = status?.runtime ?? status?.last_check;
  const running = status?.effective_enabled === true;
  const attention = !running && Boolean(status?.requested_enabled && !status.job);
  const [Icon, tone] = markerFor(running, attention);
  const effective = status?.effective_preferences ?? value;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-8", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("section", { "aria-labelledby": titleId, className: "guard-surface-in rounded-2xl border border-brand-dark/10 bg-white p-4 sm:p-5", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-start gap-x-6 gap-y-4", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex min-w-0 flex-[1_1_20rem] items-start gap-3.5", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { "aria-hidden": "true", className: "flex size-10 shrink-0 items-center justify-center rounded-full " + tone, children: props.loading || status?.job ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowPath, { className: "size-5 motion-safe:animate-spin" }) : /* @__PURE__ */ jsxRuntimeExports.jsx(Icon, { className: "size-5" }) }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0 space-y-1.5", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { id: titleId, className: "text-lg font-semibold tracking-[-0.01em] text-brand-dark", children: runtime ? "CIGAR " + runtime.package_version : "CIGAR runtime" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "max-w-[62ch] text-sm leading-6 text-brand-dark/75", role: "status", "aria-live": "polite", children: availabilityText(props.loading, statusCopy) }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: caption$1, children: "CIGAR uses its own copy of Python 3.14. Guard sets it up for you when you click Turn on CIGAR." })
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex shrink-0 flex-wrap items-center gap-2", children: [
        status?.requested_enabled && !status.effective_enabled ? /* @__PURE__ */ jsxRuntimeExports.jsx(
          "button",
          {
            type: "button",
            className: versionPrimary,
            disabled: checkDisabled || !status.effective_preferences.enabled,
            onClick: () => props.onControl("activate"),
            children: "Start context assistance"
          }
        ) : null,
        /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", className: versionButton, disabled: checkDisabled, onClick: () => props.onControl("recheck"), children: "Check selected runtime" }),
        !stopped ? /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", className: versionButton, disabled, onClick: () => props.onControl("stop"), children: "Turn off now" }) : null,
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "button",
          {
            type: "button",
            "aria-label": "Refresh runtime status",
            title: "Refresh runtime status",
            disabled: disabled || props.loading,
            onClick: props.onRefresh,
            className: "inline-flex size-11 items-center justify-center rounded-lg text-brand-dark/70 hover:bg-brand-dark/[0.05] hover:text-brand-dark focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/40 disabled:cursor-not-allowed disabled:opacity-50",
            children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowPath, { "aria-hidden": "true", className: "size-4" })
          }
        )
      ] })
    ] }) }),
    props.error ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { role: "alert", className: "cigar-note", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { children: "CIGAR needs attention" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: props.error })
    ] }) : null,
    props.dirty ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "status", className: note, children: "Save settings before checking or starting this runtime." }) : null,
    props.locked ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: note, children: "Your organization manages these preferences. You can still turn context assistance off." }) : null,
    status?.restriction ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: note, children: "Policy restrictions apply. Your saved choices are retained; effective limits are shown below." }) : null,
    value ? /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs(SettingsFormSection, { title: "Runtime", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          SettingsToggleRow,
          {
            label: "Use CIGAR on this machine",
            checked: value.enabled,
            description: "Lets CIGAR run on this computer. The Turn on CIGAR button sets this for you.",
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
        )
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs(SettingsFormSection, { title: "What CIGAR helps with", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          SettingsMenuRow,
          {
            label: "Context size",
            value: value.resource_profile,
            disabled: editingDisabled,
            options: PROFILES,
            description: "How much CIGAR keeps ready at once. Smaller suits most laptops.",
            onChange: (profile) => props.onChange(withContextProfile(value, profile))
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
            description: "Add the project files that match each prompt in Claude Code, Codex, Pi and Oh My Pi, and allow context tools for apps you authorize. Sharing between agents is a separate choice.",
            checked: value.features.agent_context,
            disabled: editingDisabled,
            onChange: (agent_context) => props.onChange({ ...value, features: { ...value.features, agent_context, shared_agents: agent_context && value.features.shared_agents } })
          }
        ),
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          SettingsToggleRow,
          {
            label: "Allow selected workspace documents",
            description: "With Context for AI apps on, prompts in Claude Code, Codex, Pi and Oh My Pi get the files in their project that match them. To choose the exact files, add the project under Projects.",
            checked: value.sources.workspace_documents,
            disabled: editingDisabled,
            onChange: (workspace_documents) => props.onChange({ ...value, sources: {
              ...value.sources,
              workspace_documents,
              source_set_id: workspace_documents ? value.sources.source_set_id || "selected-workspaces" : value.sources.source_set_id
            } })
          }
        ),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
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
          !value.features.agent_context ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: caption$1 + " pb-3", children: "Enable Context for AI apps before choosing sharing." }) : null
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("details", { className: "group rounded-2xl border border-brand-dark/10 bg-white", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("summary", { className: "flex min-h-14 cursor-pointer list-none items-center gap-3 rounded-2xl px-4 py-3 hover:bg-surface-1 sm:px-5 [&::-webkit-details-marker]:hidden", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniChevronRight, { "aria-hidden": "true", className: "size-4 shrink-0 text-brand-dark/50 transition-transform group-open:rotate-90 motion-reduce:transition-none" }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "min-w-0", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "block text-sm font-semibold text-brand-dark", children: "More settings" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "block text-xs text-brand-dark/60", children: "Sources, limits, storage and runtime details" })
          ] })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-8 border-t border-brand-dark/[0.07] px-4 py-5 sm:px-5", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs(Group, { title: "Sources", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "divide-y divide-slate-100", children: [
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
              /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
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
                status?.capabilities?.execution_context !== true ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: caption$1 + " pb-2", children: "This native execution route is unavailable in the current build. Review briefs and scoped context tools have their own controls." }) : null,
                !value.sources.native_policy_facts ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: caption$1 + " pb-2", children: "Enable native policy and decision facts to choose execution associations." }) : null
              ] })
            ] }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: caption$1, children: "Starting CIGAR grants no document access by itself. Project files are only added to prompts while Context for AI apps and Allow selected workspace documents are on." })
          ] }),
          value.resource_profile === "custom" ? /* @__PURE__ */ jsxRuntimeExports.jsxs("fieldset", { className: "grid gap-4 sm:grid-cols-2", disabled: editingDisabled, children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("legend", { className: "mb-3 text-sm font-semibold text-brand-dark", children: "Custom limits" }),
            [
              ["context_tokens", "Context token budget", 64, 16384],
              ["reserve_tokens", "Reserved tokens", 0, value.limits.context_tokens - 1],
              ["max_active_workspaces", "Active workspaces", 1, 8],
              ["idle_shutdown_seconds", "Idle shutdown in seconds", 30, 3600]
            ].map(([key2, label2, min, max]) => /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "text-sm font-medium text-brand-dark", children: [
              label2,
              /* @__PURE__ */ jsxRuntimeExports.jsx(
                "input",
                {
                  type: "number",
                  min,
                  max,
                  step: 1,
                  value: value.limits[key2],
                  className: versionField + " tabular-nums",
                  onChange: (event) => {
                    const next = event.target.valueAsNumber;
                    if (Number.isSafeInteger(next)) props.onChange({ ...value, limits: { ...value.limits, [key2]: next } });
                  }
                }
              )
            ] }, key2))
          ] }) : null,
          /* @__PURE__ */ jsxRuntimeExports.jsxs(Group, { title: "Storage", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid gap-4 sm:grid-cols-2", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx("span", { id: storageId, className: "text-sm font-medium text-brand-dark", children: "Evidence storage" }),
                /* @__PURE__ */ jsxRuntimeExports.jsx(
                  SelectMenu,
                  {
                    labelledBy: storageId,
                    className: "mt-1.5 w-full",
                    value: value.storage.mode,
                    disabled: editingDisabled,
                    options: [
                      { value: "memory", label: "Memory only (recommended)", description: "Notes disappear when CIGAR stops." },
                      { value: "sqlite", label: "Save evidence locally", description: status?.capabilities?.private_persistence === true ? "Private local files that can outlive the runtime." : "Not available in this build.", disabled: status?.capabilities?.private_persistence !== true }
                    ],
                    onChange: (mode2) => props.onChange({ ...value, storage: { ...value.storage, mode: mode2 } })
                  }
                )
              ] }),
              /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block text-sm font-medium text-brand-dark", children: [
                "Retention in hours",
                /* @__PURE__ */ jsxRuntimeExports.jsx(
                  "input",
                  {
                    type: "number",
                    min: 1,
                    max: 720,
                    step: 1,
                    value: value.storage.retention_hours,
                    disabled: editingDisabled,
                    className: versionField + " tabular-nums",
                    "aria-describedby": storageId + "-retention",
                    onChange: (event) => {
                      const retention_hours = event.target.valueAsNumber;
                      if (Number.isSafeInteger(retention_hours)) props.onChange({ ...value, storage: { ...value.storage, retention_hours } });
                    }
                  }
                ),
                /* @__PURE__ */ jsxRuntimeExports.jsx("span", { id: storageId + "-retention", className: caption$1 + " mt-1 block font-normal", children: "Applies to context history, saved evidence and shared notes." })
              ] })
            ] }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: caption$1, children: "Notes kept in memory disappear when CIGAR stops. Saved notes are private files on this computer, not encrypted by Guard, and stay until they expire or you delete them. Bringing them back never brings back app access or approvals. Changing this ends current access, so add your projects again after." }),
            status?.capabilities?.private_persistence !== true ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: caption$1, children: "This version of Guard cannot save notes. You can still delete notes saved earlier in Privacy." }) : null,
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: caption$1, children: "Notes in memory also disappear when you take back access or Guard restarts." })
          ] }),
          effective ? /* @__PURE__ */ jsxRuntimeExports.jsxs(Group, { title: "In effect now", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsxs("dl", { className: "grid gap-2 sm:grid-cols-2 lg:grid-cols-3", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsxs(Fact, { term: "Effective context budget", children: [
                effective.limits.context_tokens,
                " tokens, including ",
                effective.limits.reserve_tokens,
                " reserved"
              ] }),
              /* @__PURE__ */ jsxRuntimeExports.jsx(Fact, { term: "Effective workspace limit", children: effective.limits.max_active_workspaces }),
              /* @__PURE__ */ jsxRuntimeExports.jsxs(Fact, { term: "Effective idle shutdown", children: [
                effective.limits.idle_shutdown_seconds,
                " seconds"
              ] }),
              /* @__PURE__ */ jsxRuntimeExports.jsx(Fact, { term: "Storage", children: value.storage.mode === "memory" ? "Memory only" : "Private persistence requested" }),
              runtime ? /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
                /* @__PURE__ */ jsxRuntimeExports.jsxs(Fact, { term: "Last verified Python", children: [
                  runtime.interpreter.version.join("."),
                  " · ",
                  runtime.interpreter.platform
                ] }),
                /* @__PURE__ */ jsxRuntimeExports.jsx(Fact, { term: "Qualification", children: "Local development candidate" }),
                value.features.shared_agents ? /* @__PURE__ */ jsxRuntimeExports.jsx(Fact, { term: "Shared context check", children: runtime.shared_compile_verified ? "Verified with an independent local client" : "Check and start the selected runtime" }) : null,
                value.storage.mode === "sqlite" ? /* @__PURE__ */ jsxRuntimeExports.jsx(Fact, { term: "Saved evidence check", children: runtime.persistence_compile_verified ? "Verified write, restart and fresh-grant recovery" : "Check and start the selected runtime" }) : null,
                value.features.execution_context ? /* @__PURE__ */ jsxRuntimeExports.jsx(Fact, { term: "Execution SDK check", children: runtime.execution_handoff_verified ? "Verified submission, host review, binding and one-time context take" : "Check and start the selected runtime" }) : null
              ] }) : null
            ] }),
            status?.diagnostic ? /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: caption$1 + " break-words", children: [
              "Diagnostic: ",
              status.diagnostic
            ] }) : null
          ] }) : null
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(ContextExecutionPanel, { status })
    ] }) : /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: note, children: "Update Guard to a native core with context assistance support before choosing these settings." }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: caption$1, children: "Context is supporting information. Guard keeps command protection and approval decisions in its native execution flow." })
  ] });
}
const empty$1 = "rounded-2xl border border-dashed border-brand-dark/15 px-5 py-6 text-center text-sm text-brand-dark/70";
const label$1 = "text-sm font-medium text-brand-dark";
const CONNECTABLE_APPS = [
  "cursor",
  "codex",
  "claude-code",
  "copilot",
  "gemini",
  "opencode",
  "cline",
  "kimi",
  "hermes",
  "openclaw",
  "antigravity",
  "zcode",
  "devin",
  "muse",
  "paseo",
  "pi",
  "omp"
];
const folderName$1 = (path) => path.split(/[\\/]/).filter(Boolean).pop() ?? path;
function appScope(scopes, workspace, app) {
  return scopes.find((scope) => !scope.revoked && scope.workspace === workspace && scope.app === app);
}
function pickedFiles(scopes, workspace) {
  const own = scopes.filter((scope) => !scope.revoked && scope.workspace === workspace);
  const picked = own.find((scope) => scope.app === "dashboard") ?? own[0];
  return picked ? picked.sources.map((source) => source.path) : [];
}
function ContextAgentsPanel({ ready, enabled, dirty, generation, scopes, gate, sharingAllowed = false, onGranted }) {
  const [sessions, setSessions] = reactExports.useState([]);
  const [choices, setChoices] = reactExports.useState({});
  const [confirm, setConfirm] = reactExports.useState(null);
  const [error, setError] = reactExports.useState(null);
  const [statusError, setStatusError] = reactExports.useState(null);
  const [busy, setBusy] = reactExports.useState(false);
  const revision = reactExports.useRef(0);
  const request = reactExports.useRef(null);
  const pending = reactExports.useRef(false);
  const allowed = ready && enabled;
  const idBase = reactExports.useId();
  const projects = [...new Set(scopes.filter((scope) => !scope.revoked).map((scope) => scope.workspace))];
  const projectOptions = projects.map((workspace) => ({ value: workspace, label: folderName$1(workspace), description: workspace }));
  const appOptions = CONNECTABLE_APPS.map((app) => ({ value: app, label: harnessDisplayName(app) }));
  const choice = (session) => choices[session.session_id] ?? { read: false, propose: false };
  const choose = (session, change) => setChoices((values) => ({ ...values, [session.session_id]: { ...choice(session), ...change } }));
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
        setStatusError("Guard could not check for apps waiting to connect. Refresh to try again.");
      }
    }
  }, [allowed]);
  reactExports.useEffect(() => {
    setSessions([]);
    setChoices({});
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
    const { workspace, app, read, propose } = choice(session);
    if (!revoke && (dirty || !workspace || !app)) return;
    pending.current = true;
    const id2 = ++revision.current;
    request.current?.abort();
    const controller = new AbortController();
    request.current = controller;
    setBusy(true);
    setError(null);
    try {
      if (revoke) await revokeContextAgentSession(session.session_id, controller.signal);
      else {
        let scope = appScope(scopes, workspace, app);
        let proof = credentials;
        if (!scope) {
          scope = await grantContextWorkspace(
            workspace,
            pickedFiles(scopes, workspace),
            credentials,
            controller.signal,
            app,
            sharingAllowed ? { read, propose: read && propose } : void 0
          );
          onGranted?.(scope);
          proof = credentials?.currentPassword ? { currentPassword: credentials.currentPassword } : credentials;
        }
        await authorizeContextAgentSession(session.session_id, scope.scope_id, proof, controller.signal);
      }
      if (revision.current === id2) setConfirm(null);
    } catch (failure2) {
      if (revision.current === id2) setError(failure2 instanceof ContextAssistanceApiError ? failure2.message : "Guard did not confirm that change. Refresh, then try again.");
    } finally {
      pending.current = false;
      if (revision.current === id2) {
        setBusy(false);
        void refresh();
      }
    }
  }
  const asked = confirm ? choice(confirm) : null;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { "aria-label": "Connect another app", className: "space-y-4", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-end justify-between gap-x-6 gap-y-2", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: versionHeading, children: "Connect another app" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: versionLead, children: "Claude Code, Codex, Pi and Oh My Pi need nothing here. Other apps, like Cursor, can ask CIGAR for files through Guard's tool server (MCP). When one asks, it shows up here with a short code. Check it matches the code your app shows, then choose the project." })
      ] }),
      allowed ? /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { className: versionQuiet, type: "button", disabled: busy, onClick: () => {
        setError(null);
        void refresh();
      }, children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowPath, { "aria-hidden": "true", className: "size-4" }),
        "Check for apps"
      ] }) : null
    ] }),
    !allowed ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: empty$1, children: "Turn on CIGAR and let it read project files to connect other apps." }) : /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
      error || statusError ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "alert", className: "cigar-note", children: error ?? statusError }) : null,
      sessions.length === 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: empty$1, children: "No app is asking to connect right now." }) : /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "space-y-3", children: sessions.map((session) => {
        const current = choice(session);
        const connected = scopes.find((scope) => scope.scope_id === session.scope_id);
        return /* @__PURE__ */ jsxRuntimeExports.jsx("li", { children: /* @__PURE__ */ jsxRuntimeExports.jsxs(
          "section",
          {
            "aria-label": `App connection ${session.session_id}`,
            className: "space-y-3 rounded-2xl border p-4 sm:p-5 " + (session.phase === "pending" ? "border-brand-blue/25 bg-brand-blue/[0.03]" : "border-brand-dark/10 bg-white"),
            children: [
              /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-2", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx("span", { "aria-hidden": "true", className: "flex size-9 items-center justify-center rounded-xl bg-brand-blue/10 text-brand-blue", children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniLink, { className: "size-4" }) }),
                /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: session.phase === "pending" ? "attention" : "green", children: session.phase === "pending" ? "Asking to connect" : "Connected" }),
                /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "text-xs text-brand-dark/60", children: [
                  "ends in ",
                  Math.ceil(session.expires_in_seconds / 60),
                  " minutes"
                ] })
              ] }),
              /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "break-all text-sm text-brand-dark/75", children: [
                "Code: ",
                /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-mono font-semibold text-brand-dark", children: session.session_id })
              ] }),
              session.phase === "pending" ? /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
                projects.length === 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-brand-dark/70", children: "Add a project above first, then connect it here." }) : /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid gap-3 sm:grid-cols-2", children: [
                  /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
                    /* @__PURE__ */ jsxRuntimeExports.jsx("span", { id: `${idBase}-${session.session_id}-app`, className: label$1, children: "Which app is this?" }),
                    /* @__PURE__ */ jsxRuntimeExports.jsx(
                      SelectMenu,
                      {
                        labelledBy: `${idBase}-${session.session_id}-app`,
                        className: "mt-1.5 w-full",
                        disabled: busy || dirty,
                        placeholder: "Choose the app",
                        value: current.app ?? "",
                        options: appOptions,
                        onChange: (app) => choose(session, { app })
                      }
                    )
                  ] }),
                  /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
                    /* @__PURE__ */ jsxRuntimeExports.jsx("span", { id: `${idBase}-${session.session_id}-project`, className: label$1, children: "Which project?" }),
                    /* @__PURE__ */ jsxRuntimeExports.jsx(
                      SelectMenu,
                      {
                        labelledBy: `${idBase}-${session.session_id}-project`,
                        className: "mt-1.5 w-full",
                        disabled: busy || dirty,
                        placeholder: "Choose a project",
                        value: current.workspace ?? "",
                        options: projectOptions,
                        onChange: (workspace) => choose(session, { workspace })
                      }
                    )
                  ] })
                ] }),
                sharingAllowed && projects.length ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-0.5 rounded-xl bg-surface-1/70 px-3 py-1.5 text-sm text-brand-dark/80", children: [
                  /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "flex min-h-11 cursor-pointer items-center gap-3", children: [
                    /* @__PURE__ */ jsxRuntimeExports.jsx(
                      "input",
                      {
                        type: "checkbox",
                        className: "size-4 accent-brand-blue",
                        checked: current.read,
                        disabled: busy || dirty,
                        onChange: (event) => choose(session, { read: event.target.checked, propose: event.target.checked && current.propose })
                      }
                    ),
                    "Let it read shared notes you approved"
                  ] }),
                  /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "flex min-h-11 cursor-pointer items-center gap-3", children: [
                    /* @__PURE__ */ jsxRuntimeExports.jsx(
                      "input",
                      {
                        type: "checkbox",
                        className: "size-4 accent-brand-blue",
                        checked: current.propose,
                        disabled: busy || dirty || !current.read,
                        onChange: (event) => choose(session, { propose: event.target.checked })
                      }
                    ),
                    "Let it suggest new notes for you to review"
                  ] })
                ] }) : null,
                /* @__PURE__ */ jsxRuntimeExports.jsx(
                  "button",
                  {
                    className: versionPrimary,
                    type: "button",
                    disabled: busy || dirty || !current.app || !current.workspace,
                    onClick: () => {
                      if (gate?.enabled) setConfirm(session);
                      else void perform(session);
                    },
                    children: "Connect"
                  }
                )
              ] }) : /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "break-all text-sm text-brand-dark/75", children: connected ? `${harnessDisplayName(connected.app)} · ${folderName$1(connected.workspace)}` : "This project is gone. Disconnect, then connect the app again." }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("button", { className: versionQuiet + " text-red-700 hover:bg-red-50 hover:text-red-800", type: "button", disabled: busy, onClick: () => void perform(session, void 0, true), children: session.phase === "pending" ? "Turn down" : "Disconnect" })
            ]
          }
        ) }, session.session_id);
      }) })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      SettingsSaveProofModal,
      {
        open: confirm !== null,
        mode: "verify-save",
        gate,
        title: "Connect this app",
        detail: asked?.app && asked.workspace ? `${harnessDisplayName(asked.app)} (code ${confirm?.session_id ?? ""}) can ask CIGAR for files in ${folderName$1(asked.workspace)} for the next few minutes.${sharingAllowed ? ` Shared notes: ${asked.read ? "it can read the ones you approved" : "off"}${asked.read && asked.propose ? ", and it can suggest new ones for you to review" : ""}.` : ""} This does not approve any command.` : "",
        confirmLabel: "Connect",
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
function invalid$5() {
  throw new ContextAssistanceApiError("proposal_payload_invalid", "Guard returned incompatible shared-note data. Refresh the proposal list.");
}
function common(value) {
  return record(value) && id$4(value.proposal_id) && (value.connection_id === null || id$4(value.connection_id) && value.connection_id.startsWith("agent:")) && ["pending", "admitted", "rejected"].includes(String(value.state)) && digest$1(value.basis_snapshot) && validContextBrokerRevision(value.expected) && record(value.basis) && Object.keys(value.basis).length <= 32 && Object.entries(value.basis).every(([source, revision]) => id$4(source) && validContextBrokerRevision(revision)) && value.data_role === true;
}
async function listContextProposals(scopeId, signal) {
  const result = await ask("workspace", { action: "proposals", scope_id: scopeId }, void 0, signal);
  const scope = parseContextScope(result.scope);
  const permitted = ["guard:policy", "guard:receipts", ...scope.sources.map((source) => source.source_id)];
  if (scope.scope_id !== scopeId || scope.sharing?.notes.read !== true || !Array.isArray(result.proposals) || result.proposals.length > 32 || !result.proposals.every((item) => common(item) && count$2(item.documents, 32) && count$2(item.bytes, 16384) && Object.keys(item.basis).every((source) => permitted.includes(source)))) invalid$5();
  return result.proposals;
}
async function loadContextProposal(scopeId, proposalId, signal) {
  const result = await ask("workspace", { action: "proposal", scope_id: scopeId, proposal_id: proposalId }, void 0, signal);
  const scope = parseContextScope(result.scope);
  const value = result.proposal;
  const permitted = ["guard:policy", "guard:receipts", ...scope.sources.map((source) => source.source_id)];
  if (scope.scope_id !== scopeId || scope.sharing?.notes.read !== true || !common(value) || value.proposal_id !== proposalId || !Object.keys(value.basis).every((source) => permitted.includes(source)) || value.approval_grant !== false || !["available", "unavailable"].includes(String(value.source_access)) || !(value.documents === null || documents(value.documents)) || !(value.current_documents === null || documents(value.current_documents)) || !(value.current_revision === null || validContextBrokerRevision(value.current_revision)) || value.source_access === "unavailable" && (value.documents !== null || value.current_documents !== null) || !Array.isArray(value.source_states) || value.source_states.length > 32 || !value.source_states.every((state) => record(state) && id$4(state.source_id) && typeof state.path === "string" && state.path.length <= 4096 && ["unchanged", "changed", "unavailable"].includes(String(state.state)) && (state.current_sha256 === null || digest$1(state.current_sha256)) && scope.sources.some((source) => source.source_id === state.source_id && source.path === state.path)) || new Set(value.source_states.map((state) => state.source_id)).size !== value.source_states.length || value.source_states.length !== scope.sources.filter((source) => Object.hasOwn(value.basis, source.source_id)).length) invalid$5();
  return value;
}
async function decideContextProposal(scopeId, proposalId, admit, proof, signal) {
  const result = await ask(admit ? "workspace-grant" : "workspace-access", {
    action: admit ? "admit_proposal" : "reject_proposal",
    scope_id: scopeId,
    proposal_id: proposalId
  }, proof, signal);
  if (result.proposal_id !== proposalId || result.state !== (admit ? "admitted" : "rejected") || result.data_role !== true || admit && (result.approval_grant !== false || !validContextBrokerRevision(result.revision))) invalid$5();
  return result;
}
async function clearContextNotes(scopeId, signal) {
  return ask("workspace-access", { action: "clear_notes", scope_id: scopeId }, void 0, signal);
}
const button = "min-h-11 rounded-lg border border-slate-200 px-3 py-2 text-sm font-semibold text-brand-dark disabled:cursor-not-allowed disabled:opacity-50";
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
      /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", className: button, disabled: busy || disabled, onClick: refresh, children: "Refresh proposals" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", className: button, disabled: busy || disabled, onClick: () => void perform(async (signal) => {
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
      /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", className: button, disabled: busy || disabled, onClick: () => void perform(async (signal) => {
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
        /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", className: button, disabled: busy || disabled || !admittable, onClick: () => {
          if (gate?.enabled) setProofOpen(true);
          else void decide(true);
        }, children: "Admit shared note" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", className: button, disabled: busy || disabled, onClick: () => void decide(false), children: "Reject proposal" }),
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
const object$7 = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
async function saveCigarPreference(config, proof, signal) {
  if (isGuardDemoMode()) throw new ContextAssistanceApiError("demo_unavailable", "Turning on CIGAR requires a local Guard installation.");
  const timeout = AbortSignal.timeout(12e3);
  const response = await fetchWithGuardAuth("/v1/settings", {
    method: "POST",
    cache: "no-store",
    headers: { "Content-Type": "application/json" },
    signal: signal ? AbortSignal.any([signal, timeout]) : timeout,
    body: JSON.stringify({
      settings: { context_assistance: config },
      ...proof?.currentPassword ? { approval_password: proof.currentPassword } : {},
      ...proof?.totpCode ? { approval_totp_code: proof.totpCode } : {}
    })
  });
  const body = await response.json().catch(() => null);
  if (!response.ok) {
    const code = object$7(body) && typeof body.error === "string" && /^[a-z0-9_]{1,160}$/.test(body.error) ? body.error : "settings_unavailable";
    throw new ContextAssistanceApiError(code, response.status === 400 && object$7(body) && typeof body.message === "string" ? "Guard could not save this setting: " + body.message.slice(0, 200) : response.status === 403 ? "Guard needs your approval before this change." : "Guard did not confirm the saved setting. Refresh status before trying again.");
  }
  const saved = object$7(body) && object$7(body.settings) ? body.settings.context_assistance : null;
  if (!object$7(saved) || saved.schema_version !== 1 || typeof saved.enabled !== "boolean" || typeof saved.runtime_id !== "string") {
    throw new ContextAssistanceApiError("settings_payload_invalid", "Guard returned settings this page does not understand. Refresh status.");
  }
  return saved;
}
function allowProjectFilesPreferences(previous) {
  return {
    ...previous,
    sources: { ...previous.sources, workspace_documents: true, source_set_id: previous.sources.source_set_id || "selected-workspaces" },
    features: { ...previous.features, agent_context: true }
  };
}
function useCigarAllowFiles(options) {
  const [proof, setProof] = reactExports.useState(false);
  const [busy, setBusy] = reactExports.useState(false);
  const [error, setError] = reactExports.useState(null);
  const latest = reactExports.useRef(options);
  latest.current = options;
  const mounted = reactExports.useRef(true);
  reactExports.useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);
  async function save(credentials) {
    const { saved, dirty, disabled } = latest.current;
    if (!saved || dirty || disabled || busy) return;
    setBusy(true);
    setError(null);
    try {
      const next = await saveCigarPreference(allowProjectFilesPreferences(saved), credentials);
      if (!mounted.current) return;
      setProof(false);
      latest.current.onSaved(next, saved);
      if (next.enabled) latest.current.onRestart();
    } catch (cause) {
      if (!mounted.current) return;
      setError(cause instanceof Error ? cause.message : "Guard did not save this setting. Try again.");
    } finally {
      if (mounted.current) setBusy(false);
    }
  }
  return {
    available: options.saved !== null && !options.dirty && !options.disabled,
    busy,
    error,
    start: () => {
      setError(null);
      if (latest.current.gate?.enabled) setProof(true);
      else void save();
    },
    proofOpen: proof,
    cancel: () => {
      if (!busy) {
        setProof(false);
        setError(null);
      }
    },
    confirm: (credentials) => void save(credentials)
  };
}
function CigarAllowFilesProof({ allow, gate }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsx(
    SettingsSaveProofModal,
    {
      open: allow.proofOpen,
      mode: "verify-save",
      gate,
      title: "Let CIGAR read project files",
      detail: "Prompts in your AI apps will get the few project files that match them. Secrets, keys, hidden files and anything your .gitignore leaves out stay skipped.",
      confirmLabel: "Turn on",
      error: allow.error,
      pending: allow.busy,
      onCancel: allow.cancel,
      onConfirm: allow.confirm
    }
  );
}
function CigarAllowFilesButton({ allow, className, caption: caption2 }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "cigar-allow-files", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", className, disabled: !allow.available || allow.busy, onClick: allow.start, children: allow.busy ? "Turning on…" : "Let CIGAR read project files" }),
    allow.error && !allow.proofOpen ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "alert", className: "cigar-allow-error", children: allow.error }) : caption2 ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "cigar-setup-caption", children: caption2 }) : null
  ] });
}
const object$6 = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
const text = (value) => typeof value === "string";
const list = (value, max, item) => {
  if (!Array.isArray(value) || value.length > max || !value.every(item)) invalid$4();
  return value;
};
const place = (row2) => object$6(row2) && text(row2.label) && text(row2.path);
const size = (value) => Number.isSafeInteger(value) && value >= 0;
function invalid$4() {
  throw new ContextAssistanceApiError("folder_payload_invalid", "Guard returned an unexpected folder list. Try again.");
}
const MESSAGES = {
  folder_not_found: "That folder does not exist or was moved.",
  folder_not_absolute: "Type a full path, starting from the top of your drive.",
  folder_not_directory: "That is a file, not a folder.",
  folder_denied: "Your computer does not let Guard open that folder.",
  folder_unreadable: "Guard could not open that folder."
};
async function browse(input, signal) {
  if (isGuardDemoMode()) throw new ContextAssistanceApiError("demo_unavailable", "Browsing folders needs Guard running on this computer.");
  const timeout = AbortSignal.timeout(1e4);
  const response = await fetchWithGuardAuth("/v1/context-assistance/folders", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    cache: "no-store",
    signal: signal ? AbortSignal.any([signal, timeout]) : timeout,
    body: JSON.stringify(input)
  });
  const body = await response.json().catch(() => null);
  if (!response.ok) {
    const code = object$6(body) && text(body.code) && /^[a-z0-9_]{1,80}$/.test(body.code) ? body.code : "folder_unavailable";
    throw new ContextAssistanceApiError(code, MESSAGES[code] ?? (response.status === 404 ? "This Guard version cannot browse folders yet. Update Guard, then try again." : "Guard could not open that folder."));
  }
  if (!object$6(body) || body.schema !== "guard-context-folders.v1") invalid$4();
  return body;
}
async function listFolders(path, hidden, signal) {
  const body = await browse({ mode: "folders", ...path ? { path } : {}, hidden }, signal);
  if (!text(body.path) || !text(body.name) || !(body.parent === null || text(body.parent)) || typeof body.project !== "boolean" || !text(body.home) || !text(body.separator) || typeof body.truncated !== "boolean") invalid$4();
  return {
    path: body.path,
    name: body.name,
    parent: body.parent,
    project: body.project,
    home: body.home,
    separator: body.separator,
    truncated: body.truncated,
    places: list(body.places, 32, place),
    roots: list(body.roots, 26, place),
    entries: list(body.entries, 400, (row2) => object$6(row2) && text(row2.name) && text(row2.path) && typeof row2.project === "boolean")
  };
}
async function listProjectFiles(workspace, path, signal) {
  const body = await browse({ mode: "files", workspace, path }, signal);
  if (!text(body.workspace) || !text(body.path) || !size(body.max_file_bytes) || typeof body.truncated !== "boolean") invalid$4();
  return {
    workspace: body.workspace,
    path: body.path,
    maxFileBytes: body.max_file_bytes,
    truncated: body.truncated,
    entries: list(body.entries, 400, (row2) => object$6(row2) && text(row2.name) && text(row2.relative)),
    files: list(body.files, 400, (row2) => object$6(row2) && text(row2.name) && text(row2.relative) && size(row2.size) && typeof row2.available === "boolean" && (row2.reason === null || ["too_large", "not_text", "empty"].includes(String(row2.reason)))),
    suggested: list(body.suggested, 8, (row2) => object$6(row2) && text(row2.relative) && size(row2.size))
  };
}
function folderCrumbs(path, separator) {
  const windows = separator === "\\";
  const parts = path.split(windows ? /[\\/]/ : "/").filter(Boolean);
  const crumbs = [];
  let current = windows ? "" : "/";
  if (!windows) crumbs.push({ label: "/", path: "/" });
  const network = windows && /^[\\/]{2}[^\\/]/.test(path) && parts.length >= 2;
  if (network) {
    current = `\\\\${parts[0]}\\${parts[1]}\\`;
    crumbs.push({ label: `\\\\${parts[0]}\\${parts[1]}`, path: current });
  }
  parts.slice(network ? 2 : 0).forEach((part, index) => {
    if (windows && !network && index === 0) current = part + "\\";
    else current = current.endsWith(separator) ? current + part : current + separator + part;
    crumbs.push({ label: part, path: current });
  });
  return crumbs;
}
function formatFileSize(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  return `${Math.max(1, Math.round(bytes / 1024))} KB`;
}
const PLACE_ICONS = { Home: HiMiniHome, Desktop: HiMiniComputerDesktop, Documents: HiMiniDocumentText };
const placeIcon = (place2) => PLACE_ICONS[place2.label] ?? HiMiniFolder;
const rowClass = "group flex min-h-11 w-full items-center gap-3 rounded-xl px-3 text-left text-sm text-brand-dark transition-colors duration-150 hover:bg-brand-blue/[0.06] focus-visible:bg-brand-blue/[0.08] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/40 motion-reduce:transition-none";
const placeClass = "flex min-h-10 w-auto shrink-0 items-center gap-2.5 rounded-lg px-2.5 text-left text-sm text-brand-dark/75 transition-colors hover:bg-brand-dark/[0.05] hover:text-brand-dark focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/40 data-[current=true]:bg-brand-blue/10 data-[current=true]:font-semibold data-[current=true]:text-brand-blue sm:w-full";
function folderChoiceBlock(listing) {
  if (listing.parent === null) return "This is the top of the drive. Open the project folder you want inside it.";
  if (listing.path === listing.home) return "This is your whole home folder. Open the one project you want CIGAR to read.";
  return null;
}
function FolderPickerDialog({ open, initialPath, onCancel, onChoose }) {
  const id2 = reactExports.useId();
  const dialog = reactExports.useRef(null);
  const filterRef = reactExports.useRef(null);
  const listRef = reactExports.useRef(null);
  const request = reactExports.useRef(null);
  const [listing, setListing] = reactExports.useState(null);
  const [loading, setLoading] = reactExports.useState(false);
  const [error, setError] = reactExports.useState(null);
  const [filter, setFilter] = reactExports.useState("");
  const [hidden, setHidden] = reactExports.useState(false);
  const [typing, setTyping] = reactExports.useState(false);
  const [typed, setTyped] = reactExports.useState("");
  const [direction, setDirection] = reactExports.useState("jump");
  useFocusTrap(open, dialog);
  const go = reactExports.useCallback((path, nextDirection, showHidden = hidden) => {
    request.current?.abort();
    const controller = new AbortController();
    request.current = controller;
    setLoading(true);
    setError(null);
    void listFolders(path, showHidden, controller.signal).then((value) => {
      if (controller.signal.aborted) return;
      setListing(value);
      setFilter("");
      setTyping(false);
      setDirection(nextDirection);
      requestAnimationFrame(() => filterRef.current?.focus());
    }).catch((cause) => {
      if (!controller.signal.aborted) setError(cause instanceof Error ? cause.message : "Guard could not open that folder.");
    }).finally(() => {
      if (!controller.signal.aborted) setLoading(false);
    });
  }, [hidden]);
  reactExports.useEffect(() => {
    if (!open) return;
    setListing(null);
    go(initialPath, "jump");
    return () => request.current?.abort();
  }, [open]);
  reactExports.useEffect(() => {
    if (!open) return;
    const close = (event) => {
      if (event.key === "Escape" && !event.defaultPrevented) onCancel();
    };
    document.addEventListener("keydown", close);
    return () => document.removeEventListener("keydown", close);
  }, [open, onCancel]);
  if (!open) return null;
  const query = filter.trim().toLowerCase();
  const entries = (listing?.entries ?? []).filter((entry) => !query || entry.name.toLowerCase().includes(query));
  const block = listing ? folderChoiceBlock(listing) : null;
  const crumbs = listing ? folderCrumbs(listing.path, listing.separator) : [];
  const places = listing ? [...listing.places, ...listing.roots] : [];
  const up = () => {
    if (listing?.parent) go(listing.parent, "out");
  };
  const choose = () => {
    if (listing && !block) onChoose(listing.path);
  };
  function focusRow(offset, from) {
    const rows = Array.from(listRef.current?.querySelectorAll("[data-row]") ?? []);
    if (!rows.length) return;
    const at = from ? rows.indexOf(from) : -1;
    rows[Math.min(rows.length - 1, Math.max(0, at + offset))]?.focus();
  }
  function onFilterKey(event) {
    if (event.key === "ArrowDown") {
      event.preventDefault();
      focusRow(1);
    } else if (event.key === "Enter" && (event.metaKey || event.ctrlKey)) {
      event.preventDefault();
      choose();
    } else if (event.key === "Enter" && entries.length === 1) {
      event.preventDefault();
      go(entries[0].path, "in");
    } else if (event.key === "Backspace" && !filter) {
      event.preventDefault();
      up();
    }
  }
  function onRowKey(event) {
    const target = event.target;
    if (event.key === "ArrowDown") {
      event.preventDefault();
      focusRow(1, target.closest("[data-row]"));
    } else if (event.key === "ArrowUp") {
      event.preventDefault();
      const rows = listRef.current?.querySelectorAll("[data-row]");
      if (rows && rows[0] === target.closest("[data-row]")) filterRef.current?.focus();
      else focusRow(-1, target.closest("[data-row]"));
    } else if (event.key === "Backspace" || event.key === "ArrowLeft" && event.altKey) {
      event.preventDefault();
      up();
    }
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsx(
    "div",
    {
      className: "fixed inset-0 z-50 flex items-end justify-center bg-brand-dark/40 backdrop-blur-[2px] sm:items-center sm:p-6",
      onMouseDown: (event) => {
        if (event.target === event.currentTarget) onCancel();
      },
      children: /* @__PURE__ */ jsxRuntimeExports.jsxs(
        "div",
        {
          ref: dialog,
          role: "dialog",
          "aria-modal": "true",
          "aria-labelledby": `${id2}-title`,
          "aria-describedby": `${id2}-lead`,
          className: "cigar-picker flex h-[min(92dvh,40rem)] w-full max-w-3xl flex-col overflow-hidden rounded-t-3xl bg-white shadow-[0_24px_60px_-12px_rgb(15_23_42/0.35)] sm:rounded-3xl",
          children: [
            /* @__PURE__ */ jsxRuntimeExports.jsxs("header", { className: "flex items-start gap-3 border-b border-brand-dark/[0.07] px-5 pb-4 pt-5 sm:px-6", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0 flex-1", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: `${id2}-title`, className: "text-lg font-semibold tracking-[-0.02em] text-brand-dark", children: "Choose a project folder" }),
                /* @__PURE__ */ jsxRuntimeExports.jsx("p", { id: `${id2}-lead`, className: "mt-0.5 text-sm text-brand-dark/65", children: "Open folders until you reach your project, then use it. CIGAR only reads what you pick next." })
              ] }),
              /* @__PURE__ */ jsxRuntimeExports.jsx(
                "button",
                {
                  type: "button",
                  className: "flex size-10 shrink-0 items-center justify-center rounded-full text-brand-dark/60 hover:bg-brand-dark/[0.06] hover:text-brand-dark focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/40",
                  onClick: onCancel,
                  "aria-label": "Close",
                  children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniXMark, { "aria-hidden": "true", className: "size-5" })
                }
              )
            ] }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex min-h-0 flex-1 flex-col sm:flex-row", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("nav", { "aria-label": "Places", className: "flex shrink-0 gap-1 overflow-x-auto border-b border-brand-dark/[0.07] px-4 py-2 sm:w-48 sm:flex-col sm:overflow-y-auto sm:border-b-0 sm:border-r sm:bg-surface-1/60 sm:p-3", children: places.map((item) => {
                const Icon = item.kind ? placeIcon(item) : HiMiniCircleStack;
                return /* @__PURE__ */ jsxRuntimeExports.jsxs(
                  "button",
                  {
                    type: "button",
                    className: placeClass,
                    "data-current": listing?.path === item.path,
                    onClick: () => go(item.path, "jump"),
                    children: [
                      /* @__PURE__ */ jsxRuntimeExports.jsx(Icon, { "aria-hidden": "true", className: "size-4 shrink-0 opacity-70" }),
                      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "truncate", children: item.label })
                    ]
                  },
                  item.path
                );
              }) }),
              /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex min-h-0 min-w-0 flex-1 flex-col", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-1.5 px-4 pt-3 sm:px-5", children: [
                  /* @__PURE__ */ jsxRuntimeExports.jsx(
                    "button",
                    {
                      type: "button",
                      className: "flex size-9 shrink-0 items-center justify-center rounded-lg text-brand-dark/70 hover:bg-brand-dark/[0.06] disabled:opacity-35 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/40",
                      disabled: !listing?.parent || loading,
                      onClick: up,
                      "aria-label": "Go up one folder",
                      children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowUturnLeft, { "aria-hidden": "true", className: "size-4" })
                    }
                  ),
                  typing ? /* @__PURE__ */ jsxRuntimeExports.jsxs("form", { className: "flex min-w-0 flex-1", onSubmit: (event) => {
                    event.preventDefault();
                    if (typed.trim()) go(typed.trim(), "jump");
                  }, children: [
                    /* @__PURE__ */ jsxRuntimeExports.jsx("label", { htmlFor: `${id2}-path`, className: "sr-only", children: "Folder path" }),
                    /* @__PURE__ */ jsxRuntimeExports.jsx(
                      "input",
                      {
                        id: `${id2}-path`,
                        autoFocus: true,
                        value: typed,
                        onChange: (event) => setTyped(event.target.value),
                        spellCheck: false,
                        autoComplete: "off",
                        onKeyDown: (event) => {
                          if (event.key === "Escape") {
                            event.preventDefault();
                            setTyping(false);
                          }
                        },
                        className: "min-h-9 w-full rounded-lg border border-brand-blue/40 bg-white px-3 font-mono text-sm text-brand-dark focus:outline-none focus:ring-2 focus:ring-brand-blue/25"
                      }
                    )
                  ] }) : /* @__PURE__ */ jsxRuntimeExports.jsx("ol", { "aria-label": "Current folder", className: "flex min-w-0 flex-1 items-center overflow-x-auto text-sm [scrollbar-width:none]", children: crumbs.map((crumb, index) => /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { className: "flex shrink-0 items-center", children: [
                    index > 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniChevronRight, { "aria-hidden": "true", className: "size-3.5 text-brand-dark/30" }) : null,
                    /* @__PURE__ */ jsxRuntimeExports.jsx(
                      "button",
                      {
                        type: "button",
                        onClick: () => go(crumb.path, "out"),
                        "aria-current": index === crumbs.length - 1 ? "location" : void 0,
                        className: "max-w-[12rem] truncate rounded-md px-1.5 py-1 text-brand-dark/65 hover:bg-brand-dark/[0.05] hover:text-brand-dark aria-[current=location]:font-semibold aria-[current=location]:text-brand-dark focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/40",
                        children: crumb.label
                      }
                    )
                  ] }, crumb.path)) }),
                  /* @__PURE__ */ jsxRuntimeExports.jsx(
                    "button",
                    {
                      type: "button",
                      className: "flex size-9 shrink-0 items-center justify-center rounded-lg text-brand-dark/60 hover:bg-brand-dark/[0.06] aria-pressed:bg-brand-blue/10 aria-pressed:text-brand-blue focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/40",
                      "aria-pressed": typing,
                      "aria-label": "Type a path",
                      onClick: () => {
                        setTyped(listing?.path ?? "");
                        setTyping((value) => !value);
                      },
                      children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniPencilSquare, { "aria-hidden": "true", className: "size-4" })
                    }
                  )
                ] }),
                /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-3 px-4 pb-2 pt-2.5 sm:px-5", children: [
                  /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "relative min-w-0 flex-1", children: [
                    /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "sr-only", children: "Filter folders" }),
                    /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniMagnifyingGlass, { "aria-hidden": "true", className: "pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-brand-dark/40" }),
                    /* @__PURE__ */ jsxRuntimeExports.jsx(
                      "input",
                      {
                        ref: filterRef,
                        value: filter,
                        onChange: (event) => setFilter(event.target.value),
                        onKeyDown: onFilterKey,
                        placeholder: listing ? `Search in ${listing.name}` : "Search",
                        autoComplete: "off",
                        spellCheck: false,
                        className: "min-h-10 w-full rounded-xl border border-brand-dark/10 bg-surface-1/70 pl-9 pr-3 text-sm text-brand-dark placeholder:text-brand-dark/45 focus:border-brand-blue focus:bg-white focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
                      }
                    )
                  ] }),
                  /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "flex shrink-0 cursor-pointer items-center gap-2 text-xs text-brand-dark/65", children: [
                    /* @__PURE__ */ jsxRuntimeExports.jsx(
                      "input",
                      {
                        type: "checkbox",
                        className: "size-4 accent-brand-blue",
                        checked: hidden,
                        onChange: (event) => {
                          setHidden(event.target.checked);
                          go(listing?.path ?? null, "jump", event.target.checked);
                        }
                      }
                    ),
                    "Hidden folders"
                  ] })
                ] }),
                /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "relative min-h-0 flex-1 overflow-y-auto px-2 pb-2 sm:px-3", "aria-busy": loading, children: [
                  error ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { role: "alert", className: "mx-2 mt-2 rounded-xl bg-red-50 px-4 py-3 text-sm text-red-800", children: [
                    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "font-medium", children: error }),
                    /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", className: "mt-1.5 text-sm font-semibold text-red-900 underline underline-offset-2", onClick: () => go(null, "jump"), children: "Go to your home folder" })
                  ] }) : null,
                  !listing && loading ? /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { "aria-hidden": "true", className: "space-y-1 p-1", children: Array.from({ length: 7 }, (_, index) => /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { className: "flex h-11 items-center gap-3 px-3", children: [
                    /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "size-5 rounded-md bg-brand-dark/[0.07] motion-safe:animate-pulse" }),
                    /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "h-3 rounded bg-brand-dark/[0.07] motion-safe:animate-pulse", style: { width: `${30 + index * 17 % 45}%` } })
                  ] }, index)) }) : null,
                  listing ? /* @__PURE__ */ jsxRuntimeExports.jsxs(
                    "ul",
                    {
                      ref: listRef,
                      onKeyDown: onRowKey,
                      "data-direction": direction,
                      "aria-label": `Folders in ${listing.name}`,
                      className: "cigar-picker-list space-y-0.5 p-1",
                      children: [
                        entries.map((entry) => /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { className: "flex items-center gap-1", children: [
                          /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", "data-row": "", className: rowClass, onClick: () => go(entry.path, "in"), "aria-label": `Open ${entry.name}${entry.project ? ", project" : ""}`, children: [
                            entry.project ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCodeBracketSquare, { "aria-hidden": "true", className: "size-5 shrink-0 text-brand-blue" }) : /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniFolder, { "aria-hidden": "true", className: "size-5 shrink-0 text-brand-dark/35" }),
                            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "min-w-0 flex-1 truncate", children: entry.name }),
                            entry.project ? /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "rounded-full bg-brand-blue/10 px-2 py-0.5 text-xs font-semibold text-brand-blue", children: "Project" }) : null,
                            /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniChevronRight, { "aria-hidden": "true", className: "size-4 shrink-0 text-brand-dark/25 transition-transform group-hover:translate-x-0.5 motion-reduce:transition-none" })
                          ] }),
                          entry.project ? /* @__PURE__ */ jsxRuntimeExports.jsx(
                            "button",
                            {
                              type: "button",
                              disabled: loading,
                              className: "min-h-9 shrink-0 rounded-lg px-3 text-xs font-semibold text-brand-blue hover:bg-brand-blue/10 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/40 disabled:opacity-50",
                              onClick: () => onChoose(entry.path),
                              "aria-label": `Use ${entry.name}`,
                              children: "Use"
                            }
                          ) : null
                        ] }, entry.path)),
                        !entries.length && !loading ? /* @__PURE__ */ jsxRuntimeExports.jsx("li", { className: "px-3 py-10 text-center text-sm text-brand-dark/55", children: query ? `No folder here matches “${filter.trim()}”.` : "No folders inside this one." }) : null,
                        listing.truncated ? /* @__PURE__ */ jsxRuntimeExports.jsx("li", { className: "px-3 py-2 text-xs text-brand-dark/55", children: "Showing the first 400 folders. Search or type a path to find others." }) : null
                      ]
                    },
                    listing.path
                  ) : null
                ] })
              ] })
            ] }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("footer", { className: "flex flex-col gap-3 border-t border-brand-dark/[0.07] bg-surface-1/50 px-5 py-4 sm:flex-row sm:items-center sm:px-6", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex min-w-0 flex-1 items-center gap-3", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx("span", { "aria-hidden": "true", className: "flex size-9 shrink-0 items-center justify-center rounded-xl bg-brand-blue/10 text-brand-blue", children: listing?.project ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCodeBracketSquare, { className: "size-5" }) : /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniFolder, { className: "size-5" }) }),
                /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0", role: "status", children: [
                  /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "truncate text-sm font-semibold text-brand-dark", children: [
                    listing?.name ?? "Loading…",
                    listing?.project ? /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "ml-2 text-xs font-medium text-brand-blue", children: "Looks like a project" }) : null
                  ] }),
                  /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "truncate text-xs text-brand-dark/55", children: block ?? listing?.path ?? "" })
                ] })
              ] }),
              /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex gap-2 sm:shrink-0", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", className: versionButton + " flex-1 sm:flex-none", onClick: onCancel, children: "Cancel" }),
                /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", className: versionPrimary + " flex-1 sm:flex-none", disabled: !listing || !!block || loading, onClick: choose, children: "Use this folder" })
              ] })
            ] })
          ]
        }
      )
    }
  );
}
const RECENT_PROJECTS_KEY = "guard.cigar.recent-projects.v1";
const MAX_RECENT_PROJECTS = 4;
const MAX_FILES = 32;
function browserStore() {
  try {
    return typeof window === "undefined" ? null : window.localStorage;
  } catch {
    return null;
  }
}
function valid(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const row2 = value;
  return typeof row2.workspace === "string" && row2.workspace.length > 0 && typeof row2.app === "string" && row2.app.length > 0 && Array.isArray(row2.files) && row2.files.length <= MAX_FILES && row2.files.every((file) => typeof file === "string" && file.length > 0);
}
function readRecentProjects(store = browserStore()) {
  try {
    const parsed2 = JSON.parse(store?.getItem(RECENT_PROJECTS_KEY) ?? "[]");
    if (!Array.isArray(parsed2)) return [];
    const seen = /* @__PURE__ */ new Set();
    return parsed2.filter(valid).filter((row2) => !seen.has(row2.workspace) && Boolean(seen.add(row2.workspace))).slice(0, MAX_RECENT_PROJECTS).map((row2) => ({ workspace: row2.workspace, files: [...row2.files], app: row2.app }));
  } catch {
    return [];
  }
}
function write(rows, store) {
  try {
    store?.setItem(RECENT_PROJECTS_KEY, JSON.stringify(rows));
  } catch {
  }
  return rows;
}
function rememberProject(project, store = browserStore()) {
  const row2 = { workspace: project.workspace, files: project.files.slice(0, MAX_FILES), app: project.app };
  return write([row2, ...readRecentProjects(store).filter((item) => item.workspace !== row2.workspace)].slice(0, MAX_RECENT_PROJECTS), store);
}
function clearRecentProjects(store = browserStore()) {
  return write([], store);
}
function forgetProject(workspace, store = browserStore()) {
  return write(readRecentProjects(store).filter((item) => item.workspace !== workspace), store);
}
function presetFolders(preset) {
  const folders = preset.filter((relative) => relative.includes("/")).map((relative) => relative.slice(0, relative.lastIndexOf("/")));
  return [...new Set(folders)].slice(0, MAX_FILES);
}
function keptFiles(preset, listing) {
  const present = /* @__PURE__ */ new Set([
    ...listing.files.filter((file) => file.available).map((file) => file.relative),
    ...listing.suggested.map((item) => item.relative)
  ]);
  return preset.filter((relative) => present.has(relative)).slice(0, MAX_FILES);
}
function withoutVanished(selection, preset, kept) {
  const present = new Set(kept);
  const gone = new Set(preset.filter((relative) => !present.has(relative)));
  return selection.filter((relative) => !gone.has(relative));
}
const MAX_PROJECT_FILES = 32;
const REASONS = { too_large: "Too big", not_text: "Not text", empty: "Empty" };
const chip = "inline-flex min-h-10 cursor-pointer items-center gap-2 rounded-full border px-3.5 text-sm transition-colors duration-150 has-[:focus-visible]:ring-2 has-[:focus-visible]:ring-brand-blue/40 has-[:disabled]:cursor-not-allowed has-[:disabled]:opacity-50 motion-reduce:transition-none";
const chipOn = " border-brand-blue/30 bg-brand-blue/[0.07] text-brand-dark";
const chipOff = " border-brand-dark/12 bg-white text-brand-dark/70 hover:border-brand-dark/25";
const row = "flex min-h-11 w-full items-center gap-3 rounded-lg px-3 text-left text-sm";
function ProjectFilesPicker({ workspace, selected, onChange, disabled = false, preset = null }) {
  const id2 = reactExports.useId();
  const [root, setRoot] = reactExports.useState(null);
  const [browsing, setBrowsing] = reactExports.useState(false);
  const [listing, setListing] = reactExports.useState(null);
  const [loading, setLoading] = reactExports.useState(false);
  const [error, setError] = reactExports.useState(null);
  const request = reactExports.useRef(null);
  const presetCheck = reactExports.useRef(null);
  const latest = reactExports.useRef(onChange);
  latest.current = onChange;
  const remembered = reactExports.useRef(preset);
  remembered.current = preset;
  const chosen = reactExports.useRef(selected);
  chosen.current = selected;
  function load(path, onLoaded) {
    request.current?.abort();
    const controller = new AbortController();
    request.current = controller;
    setLoading(true);
    setError(null);
    void listProjectFiles(workspace, path, controller.signal).then((value) => {
      if (!controller.signal.aborted) onLoaded(value);
    }).catch((cause) => {
      if (!controller.signal.aborted) setError(cause instanceof Error ? cause.message : "Guard could not list this folder.");
    }).finally(() => {
      if (!controller.signal.aborted) setLoading(false);
    });
  }
  reactExports.useEffect(() => {
    setRoot(null);
    setListing(null);
    setBrowsing(false);
    load("", (value) => {
      setRoot(value);
      setListing(value);
      const preset2 = remembered.current;
      if (!preset2) {
        latest.current(value.suggested.map((item) => item.relative).slice(0, MAX_PROJECT_FILES));
        return;
      }
      const check = new AbortController();
      presetCheck.current?.abort();
      presetCheck.current = check;
      void Promise.all(presetFolders(preset2).map((folder) => listProjectFiles(workspace, folder, check.signal).then((found) => found.files, () => []))).then((nested) => {
        if (check.signal.aborted) return;
        const kept = keptFiles(preset2, { files: [...value.files, ...nested.flat()], suggested: value.suggested });
        latest.current(withoutVanished(chosen.current, preset2, kept).slice(0, MAX_PROJECT_FILES));
      });
    });
    return () => {
      request.current?.abort();
      presetCheck.current?.abort();
    };
  }, [workspace]);
  const full = selected.length >= MAX_PROJECT_FILES;
  const toggle = (relative, on) => onChange(on ? [...selected, relative] : selected.filter((item) => item !== relative));
  const suggested = root?.suggested.map((item) => item.relative) ?? [];
  const chips = [...suggested, ...selected.filter((item) => !suggested.includes(item))];
  const sizes = new Map(root?.suggested.map((item) => [item.relative, item.size]) ?? []);
  const crumbs = listing?.path ? listing.path.split("/") : [];
  const name = workspace.split(/[\\/]/).filter(Boolean).pop() ?? workspace;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-3", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "max-w-[62ch] text-sm leading-6 text-brand-dark/70", children: "Pick a few notes that explain your project, like the README. CIGAR reads only what you tick. You can skip this." }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "text-xs font-medium tabular-nums text-brand-dark/55", "aria-live": "polite", children: [
        selected.length,
        " picked · up to ",
        MAX_PROJECT_FILES
      ] })
    ] }),
    !root && loading ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { "aria-hidden": "true", className: "flex gap-2", children: [7, 9, 6].map((width) => /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "h-10 rounded-full bg-brand-dark/[0.06] motion-safe:animate-pulse", style: { width: `${width}rem` } }, width)) }) : null,
    root ? /* @__PURE__ */ jsxRuntimeExports.jsxs("fieldset", { disabled, children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("legend", { className: "sr-only", children: "Files CIGAR may read" }),
      chips.length ? /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "flex flex-wrap gap-2", children: chips.map((relative) => {
        const on = selected.includes(relative);
        const size2 = sizes.get(relative);
        return /* @__PURE__ */ jsxRuntimeExports.jsx("li", { children: /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: chip + (on ? chipOn : chipOff), children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "relative flex size-4 shrink-0", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(
              "input",
              {
                type: "checkbox",
                className: "peer size-4 cursor-pointer appearance-none rounded-full border border-brand-dark/25 bg-white transition-colors checked:border-brand-blue checked:bg-brand-blue focus-visible:outline-none disabled:cursor-not-allowed",
                checked: on,
                disabled: !on && full,
                onChange: (event) => toggle(relative, event.target.checked)
              }
            ),
            /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCheck, { "aria-hidden": "true", className: "pointer-events-none absolute inset-0.5 size-3 text-white opacity-0 peer-checked:opacity-100" })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-medium", children: relative }),
          size2 !== void 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-xs text-brand-dark/45", children: formatFileSize(size2) }) : null
        ] }) }, relative);
      }) }) : /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "text-sm text-brand-dark/60", children: [
        "No project notes at the top of ",
        name,
        ". Browse to pick files, or skip this."
      ] })
    ] }) : null,
    error ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "alert", className: "text-sm text-red-700", children: error }) : null,
    root ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs(
        "button",
        {
          type: "button",
          disabled,
          "aria-expanded": browsing,
          "aria-controls": `${id2}-browser`,
          className: "inline-flex min-h-10 items-center gap-1.5 rounded-lg text-sm font-semibold text-brand-blue hover:text-brand-blue/80 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/40 disabled:opacity-50",
          onClick: () => {
            if (!browsing && listing?.path) load("", setListing);
            setBrowsing((value) => !value);
          },
          children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniChevronRight, { "aria-hidden": "true", className: "size-4 transition-transform duration-200 motion-reduce:transition-none " + (browsing ? "rotate-90" : "") }),
            browsing ? "Hide files" : "Browse all files"
          ]
        }
      ),
      browsing && listing ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { id: `${id2}-browser`, className: "cigar-files mt-2 overflow-hidden rounded-xl border border-brand-dark/10 bg-white", "aria-busy": loading, children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("ol", { "aria-label": "Folder inside the project", className: "flex flex-wrap items-center gap-0.5 border-b border-brand-dark/[0.07] bg-surface-1/60 px-2 py-1.5 text-sm", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("li", { children: /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", className: "rounded-md px-1.5 py-1 font-medium text-brand-dark/70 hover:bg-brand-dark/[0.05] hover:text-brand-dark", onClick: () => load("", setListing), children: name }) }),
          crumbs.map((part, index) => /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { className: "flex items-center", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniChevronRight, { "aria-hidden": "true", className: "size-3.5 text-brand-dark/30" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx(
              "button",
              {
                type: "button",
                className: "rounded-md px-1.5 py-1 text-brand-dark/70 hover:bg-brand-dark/[0.05] hover:text-brand-dark aria-[current=location]:font-semibold aria-[current=location]:text-brand-dark",
                "aria-current": index === crumbs.length - 1 ? "location" : void 0,
                onClick: () => load(crumbs.slice(0, index + 1).join("/"), setListing),
                children: part
              }
            )
          ] }, index))
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("ul", { className: "cigar-picker-list max-h-72 overflow-y-auto p-1.5", "data-direction": "in", children: [
          listing.entries.map((entry) => /* @__PURE__ */ jsxRuntimeExports.jsx("li", { children: /* @__PURE__ */ jsxRuntimeExports.jsxs(
            "button",
            {
              type: "button",
              disabled: disabled || loading,
              className: row + " text-brand-dark hover:bg-brand-dark/[0.04] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/40",
              onClick: () => load(entry.relative, setListing),
              children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniFolder, { "aria-hidden": "true", className: "size-5 shrink-0 text-brand-dark/35" }),
                /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "min-w-0 flex-1 truncate", children: entry.name }),
                /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniChevronRight, { "aria-hidden": "true", className: "size-4 text-brand-dark/25" })
              ]
            }
          ) }, entry.relative)),
          listing.files.map((file) => /* @__PURE__ */ jsxRuntimeExports.jsx(
            FileRow,
            {
              file,
              checked: selected.includes(file.relative),
              disabled: disabled || !selected.includes(file.relative) && full,
              onToggle: toggle
            },
            file.relative
          )),
          !listing.entries.length && !listing.files.length ? /* @__PURE__ */ jsxRuntimeExports.jsx("li", { className: "px-3 py-6 text-center text-sm text-brand-dark/55", children: "Nothing CIGAR can read in this folder." }) : null,
          listing.truncated ? /* @__PURE__ */ jsxRuntimeExports.jsx("li", { className: "px-3 py-2 text-xs text-brand-dark/55", children: "Showing the first 400 items." }) : null
        ] }, listing.path)
      ] }) : null
    ] }) : null
  ] });
}
function FileRow({ file, checked, disabled, onToggle }) {
  if (!file.available) {
    return /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { className: row + " text-brand-dark/40", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniDocumentText, { "aria-hidden": "true", className: "size-5 shrink-0" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "min-w-0 flex-1 truncate", children: file.name }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-xs", children: REASONS[file.reason ?? ""] ?? "Unavailable" })
    ] });
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsx("li", { children: /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: row + " cursor-pointer text-brand-dark hover:bg-brand-dark/[0.04] has-[:focus-visible]:ring-2 has-[:focus-visible]:ring-brand-blue/40 has-[:disabled]:cursor-not-allowed has-[:disabled]:opacity-50", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("input", { type: "checkbox", className: "size-4 shrink-0 accent-brand-blue", checked, disabled, onChange: (event) => onToggle(file.relative, event.target.checked) }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "min-w-0 flex-1 truncate", children: file.name }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-xs tabular-nums text-brand-dark/45", children: formatFileSize(file.size) })
  ] }) });
}
const question = "text-sm font-semibold text-brand-dark";
const folderName = (path) => path.split(/[\\/]/).filter(Boolean).pop() ?? path;
const plural = (count2, word2) => `${count2} ${word2}${count2 === 1 ? "" : "s"}`;
function proofDetail(input, executionAllowed) {
  const files = input.files.length ? plural(input.files.length, "file") : "no files";
  const execution = executionAllowed ? " This does not approve any command." : "";
  return `CIGAR can read ${files} in ${folderName(input.workspace)}, plus Guard's own safety facts for that folder, for prompts in every AI app. Nothing else in it is opened.${execution}`;
}
function summary$2(workspace, files, documentsAllowed) {
  if (documentsAllowed && files) return `Prompts about ${folderName(workspace)} will use these ${plural(files, "file")}, in every AI app.`;
  return `No files picked, so your AI apps keep finding matching files in ${folderName(workspace)} on their own.`;
}
function AddProjectPanel({ busy, dirty, documentsAllowed, executionAllowed, gate, error, first, allowFiles, active = [], onGrant }) {
  const id2 = reactExports.useId();
  const [workspace, setWorkspace] = reactExports.useState(null);
  const [files, setFiles] = reactExports.useState([]);
  const [picking, setPicking] = reactExports.useState(false);
  const [proofOpen, setProofOpen] = reactExports.useState(false);
  const [recent, setRecent] = reactExports.useState(() => readRecentProjects());
  const [preset, setPreset] = reactExports.useState(null);
  const shortcuts = recent.filter((project) => !active.includes(project.workspace));
  const input = workspace ? { workspace, files: documentsAllowed ? files : [] } : null;
  async function grant(credentials) {
    if (!input) return;
    if (await onGrant(input, credentials)) {
      setRecent(rememberProject({ ...input, app: "dashboard" }));
      setProofOpen(false);
      setWorkspace(null);
      setFiles([]);
      setPreset(null);
    }
  }
  function reuse(project) {
    setPreset(project.files);
    setFiles(project.files);
    setWorkspace(project.workspace);
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "space-y-5 rounded-2xl border border-brand-dark/10 bg-white p-4 sm:p-6", "aria-labelledby": `${id2}-add`, children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { id: `${id2}-add`, className: versionHeading, children: first && !shortcuts.length ? "Add your first project" : "Add a project" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: versionLead, children: "Choose a folder and tick the files CIGAR should read. Secret files, like passwords and keys, are always skipped." })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("fieldset", { disabled: busy || dirty, className: "space-y-6", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("legend", { className: "sr-only", children: "Add a project" }),
      workspace ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-3 rounded-xl bg-surface-1/70 p-3 pr-4", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { "aria-hidden": "true", className: "flex size-10 shrink-0 items-center justify-center rounded-xl bg-brand-blue/10 text-brand-blue", children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCodeBracketSquare, { className: "size-5" }) }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0 flex-1", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "truncate text-sm font-semibold text-brand-dark", children: folderName(workspace) }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "truncate font-mono text-xs text-brand-dark/55", title: workspace, children: workspace })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", className: versionButton, onClick: () => setPicking(true), children: "Change folder" })
      ] }) : /* @__PURE__ */ jsxRuntimeExports.jsxs(
        "button",
        {
          type: "button",
          onClick: () => setPicking(true),
          className: "group flex w-full items-center gap-4 rounded-2xl border border-dashed border-brand-blue/35 bg-brand-blue/[0.025] p-5 text-left transition-colors duration-200 hover:border-brand-blue/60 hover:bg-brand-blue/[0.05] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/40 disabled:cursor-not-allowed disabled:opacity-60 motion-reduce:transition-none",
          children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { "aria-hidden": "true", className: "flex size-12 shrink-0 items-center justify-center rounded-2xl bg-brand-blue text-white shadow-sm shadow-brand-blue/30 transition-transform duration-300 ease-out group-hover:scale-105 motion-reduce:transition-none", children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniFolderPlus, { className: "size-6" }) }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "min-w-0", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "block text-base font-semibold text-brand-dark", children: "Choose a project folder" }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "mt-0.5 block text-sm text-brand-dark/65", children: "Browse to the folder you work in. Nothing is read until you say so." })
            ] })
          ]
        }
      ),
      !workspace && shortcuts.length ? /* @__PURE__ */ jsxRuntimeExports.jsx(RecentProjects, { projects: shortcuts, onReuse: reuse, onForget: (path) => setRecent(forgetProject(path)) }) : null,
      workspace ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "guard-surface-in space-y-2.5", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h4", { className: question, children: "Which files should CIGAR read?" }),
        documentsAllowed ? /* @__PURE__ */ jsxRuntimeExports.jsx(ProjectFilesPicker, { workspace, selected: files, onChange: setFiles, disabled: busy || dirty, preset }) : /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-3 rounded-xl bg-surface-1/70 px-4 py-4", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm leading-6 text-brand-dark/75", children: "Reading project files is off right now. Turn it on to pick files here and to give your AI apps matching files with each prompt." }),
          allowFiles ? /* @__PURE__ */ jsxRuntimeExports.jsx(CigarAllowFilesButton, { allow: allowFiles, className: versionPrimary }) : null
        ] })
      ] }) : null,
      dirty ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "status", className: "cigar-note", children: "Save your preferences first, then add the project." }) : null,
      workspace ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-3 border-t border-brand-dark/[0.07] pt-4", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "button",
          {
            className: versionPrimary,
            type: "button",
            disabled: files.length > MAX_PROJECT_FILES,
            onClick: () => {
              if (gate?.enabled) setProofOpen(true);
              else void grant();
            },
            children: "Add project"
          }
        ),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs leading-5 text-brand-dark/60", children: summary$2(workspace, input?.files.length ?? 0, documentsAllowed) })
      ] }) : null
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      FolderPickerDialog,
      {
        open: picking,
        initialPath: workspace,
        onCancel: () => setPicking(false),
        onChoose: (path) => {
          setPicking(false);
          if (path !== workspace) {
            setPreset(null);
            setFiles([]);
            setWorkspace(path);
          }
        }
      }
    ),
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      SettingsSaveProofModal,
      {
        open: proofOpen && !!input,
        mode: "verify-save",
        gate,
        title: "Add this project",
        detail: input ? proofDetail(input, executionAllowed) : "",
        confirmLabel: "Add project",
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
function RecentProjects({ projects, onReuse, onForget }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "guard-surface-in space-y-2.5", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("h4", { className: question, children: "Recent projects" }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "grid gap-2 sm:grid-cols-2", children: projects.map((project) => {
      const name = folderName(project.workspace);
      return /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { className: "flex items-center rounded-xl border border-brand-dark/10 bg-white transition-colors hover:border-brand-dark/25 has-[:focus-visible]:ring-2 has-[:focus-visible]:ring-brand-blue/40", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", className: "flex min-h-12 min-w-0 flex-1 items-center gap-3 rounded-l-xl p-2.5 text-left focus-visible:outline-none", title: project.workspace, onClick: () => onReuse(project), children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { "aria-hidden": "true", className: "flex size-9 shrink-0 items-center justify-center rounded-lg bg-brand-dark/[0.05] text-brand-dark/55", children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniClock, { className: "size-4" }) }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "min-w-0", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "block truncate text-sm font-semibold text-brand-dark", children: name }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "block truncate text-xs text-brand-dark/60", children: project.files.length ? plural(project.files.length, "file") : "Guard's safety facts only" })
          ] })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", "aria-label": `Remove ${name} from this list`, className: "mr-1.5 flex size-9 shrink-0 items-center justify-center rounded-lg text-brand-dark/40 hover:bg-brand-dark/[0.05] hover:text-brand-dark focus-visible:outline-none", onClick: () => onForget(project.workspace), children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniXMark, { className: "size-4" }) })
      ] }, project.workspace);
    }) })
  ] });
}
const fieldLabel = "text-sm font-medium text-brand-dark";
const empty = "rounded-2xl border border-dashed border-brand-dark/15 px-5 py-8 text-center text-sm text-brand-dark/70";
const summary$1 = "inline-flex min-h-11 cursor-pointer list-none items-center gap-1.5 text-sm font-semibold text-brand-dark/80 hover:text-brand-dark [&::-webkit-details-marker]:hidden";
function ContextWorkspacesPanel({ ready, waking = false, generation, dirty, documentsAllowed, agentsAllowed, sharingAllowed = false, executionAllowed = false, gate, allowFiles }) {
  const [scopes, setScopes] = reactExports.useState([]);
  const [loaded, setLoaded] = reactExports.useState(false);
  const listable = ready || waking;
  const [query, setQuery] = reactExports.useState("");
  const [brief, setBrief] = reactExports.useState(null);
  const [previous, setPrevious] = reactExports.useState(null);
  const [cleared, setCleared] = reactExports.useState(0);
  const [busy, setBusy] = reactExports.useState(false);
  const [error, setError] = reactExports.useState(null);
  const request = reactExports.useRef(null);
  const revision = reactExports.useRef(0);
  const failed = reactExports.useRef(false);
  const id2 = reactExports.useId();
  reactExports.useEffect(() => {
    const generation2 = ++revision.current;
    request.current?.abort();
    setBrief(null);
    setPrevious(null);
    setBusy(false);
    setError(null);
    if (failed.current) {
      failed.current = false;
      setLoaded(false);
    }
    if (!listable) {
      setScopes([]);
      setLoaded(false);
      return;
    }
    const controller = new AbortController();
    request.current = controller;
    void listContextWorkspaces(controller.signal).then((values) => {
      if (revision.current === generation2) {
        setScopes(values);
        setLoaded(true);
      }
    }).catch((cause) => {
      if (revision.current !== generation2 || controller.signal.aborted) return;
      const reason = cause instanceof Error ? cause.message : "CIGAR could not list your projects. Try again.";
      failed.current = true;
      setError(ready ? reason : "Your folders appear once CIGAR is running.");
      setLoaded(true);
    });
    return () => {
      revision.current += 1;
      controller.abort();
    };
  }, [listable, ready, generation]);
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
        setError(cause instanceof Error ? cause.message : "CIGAR could not finish that. Try again.");
      }
    } finally {
      if (revision.current === generation2) setBusy(false);
    }
  }
  async function grant(input, credentials) {
    if (scopes.some((scope) => scope.app === "dashboard" && scope.workspace === input.workspace)) {
      setError("This project is already added. Remove it first to pick different files.");
      return false;
    }
    let granted = false;
    await perform(async (signal) => {
      const scope = await grantContextWorkspace(input.workspace, input.files, credentials, signal);
      if (signal.aborted) return;
      setScopes((values) => [...values, scope]);
      granted = true;
    });
    return granted;
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
      if (action === "clear" && !signal.aborted) {
        clearRecentProjects();
        setCleared((value) => value + 1);
      }
    });
  }
  const refreshScopes = () => void perform(async (signal) => {
    const values = await listContextWorkspaces(signal);
    if (!signal.aborted) {
      setScopes(values);
      setLoaded(true);
    }
  });
  const locked = busy || !ready;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-8", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "space-y-4", "aria-labelledby": `${id2}-projects`, "aria-busy": busy, children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-end justify-between gap-x-6 gap-y-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { id: `${id2}-projects`, className: versionHeading, children: "Your projects" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: versionLead, children: "Prompts about these folders use the files listed under each one, in every AI app." })
        ] }),
        ready ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { className: versionQuiet, type: "button", disabled: locked, onClick: refreshScopes, children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowPath, { "aria-hidden": "true", className: "size-4" }),
            "Refresh list"
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("button", { className: versionQuiet + " text-red-700 hover:bg-red-50 hover:text-red-800", type: "button", disabled: locked || scopes.length === 0, onClick: () => manage("clear"), children: "Remove all projects" })
        ] }) : null
      ] }),
      !listable ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: empty, children: "Turn on CIGAR to pick project folders. Folders you already picked come back when it is on." }) : /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
        error ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "alert", className: "cigar-note", children: error }) : null,
        !ready ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "status", className: "text-sm text-brand-dark/70", children: "CIGAR is starting. You can change folders once it is running." }) : null,
        !loaded ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "status", className: empty, children: "Loading your folders…" }) : scopes.length === 0 ? !error && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: empty, children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniFolderOpen, { "aria-hidden": "true", className: "mx-auto mb-2 size-6 text-brand-dark/35" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "No projects yet." }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-xs text-brand-dark/60", children: "You don't need one: CIGAR finds the project each app is open in. Add one below to pick the exact files." })
        ] }) : /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("label", { htmlFor: `${id2}-query`, className: fieldLabel, children: "Try it: what would you ask your AI?" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("input", { id: `${id2}-query`, className: versionField, maxLength: 4096, value: query, onChange: (event) => setQuery(event.target.value), placeholder: "For example: how do releases work?" })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "space-y-3", children: scopes.map((scope) => /* @__PURE__ */ jsxRuntimeExports.jsx("li", { children: /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "space-y-3 rounded-2xl border p-4 sm:p-5 " + (scope.revoked ? "border-amber-300/70 bg-amber-50/40" : "border-brand-dark/10 bg-white"), "aria-label": `Project ${scope.workspace}`, children: [
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-start gap-3", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("span", { "aria-hidden": "true", className: "flex size-9 shrink-0 items-center justify-center rounded-xl bg-brand-blue/10 text-brand-blue", children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniFolder, { className: "size-4" }) }),
              /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0 flex-1 space-y-1.5", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "break-all font-mono text-sm font-semibold text-brand-dark", children: scope.workspace }),
                /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-1.5", children: [
                  scope.revoked ? /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: "amber", children: "Turned off by policy" }) : /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: "blue", children: scope.app === "dashboard" ? "Every app" : harnessDisplayName(scope.app) }),
                  scope.native_policy_facts ? /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: "slate", children: "Guard safety facts" }) : null,
                  scope.sharing?.mode === "shared_broker" ? /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: "green", children: "Shared notes" }) : null
                ] })
              ] })
            ] }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-1 text-sm leading-6 text-brand-dark/70", children: [
              scope.revoked ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "A policy on this computer turned this project off. Add it again once that policy allows it." }) : null,
              scope.sharing?.mode === "shared_broker" ? /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { children: [
                "Shared notes · ",
                scope.sharing.notes.read ? "it can read notes you approved" : "it cannot read shared notes",
                scope.sharing.notes.propose ? " and suggest new ones" : "",
                ". A connected app stays connected for five minutes at a time."
              ] }) : null,
              scope.receipt_window?.enabled ? /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { children: [
                "Remembers Guard's last ",
                scope.receipt_window.retained,
                " of up to 16 decisions in this folder, so your AI can see them. It is not a full history."
              ] }) : null,
              scope.receipt_window?.enabled && scope.receipt_window.dropped !== "0" ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "status", className: "text-amber-800", children: "Some recent Guard decisions were missed, so CIGAR started these notes fresh. Guard's own records are unchanged." }) : null
            ] }),
            scope.sources.length ? /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "divide-y divide-brand-dark/[0.07] rounded-xl border border-brand-dark/[0.08]", children: scope.sources.map((source) => /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { className: "flex flex-wrap items-center justify-between gap-2 py-1 pl-3 pr-1 text-sm", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "flex min-w-0 items-center gap-2 break-all font-mono text-xs text-brand-dark/80", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniDocumentText, { "aria-hidden": "true", className: "size-4 shrink-0 text-brand-dark/40" }),
                source.path
              ] }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("button", { className: versionQuiet + " min-h-9 px-2.5 text-xs", type: "button", disabled: locked, "aria-label": `Stop reading ${source.path}`, onClick: () => manage("withdraw", scope.scope_id, source.source_id), children: "Stop reading" })
            ] }, source.source_id)) }) : null,
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-2", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("button", { className: versionPrimary, type: "button", disabled: locked || dirty || scope.revoked, onClick: () => void perform(async (signal) => {
                const value = await compileWorkspaceContext(scope.scope_id, query, signal);
                if (!signal.aborted) {
                  if (brief) setPrevious(brief.value);
                  const current = value.scope ?? scope;
                  setBrief({ scope: current, value: value.brief });
                  setScopes((values) => values.map((item) => item.scope_id === current.scope_id ? current : item));
                }
              }), children: "Show what your AI would get" }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("button", { className: versionButton, type: "button", disabled: locked || scope.revoked, onClick: () => manage("refresh", scope.scope_id), children: "Read files again" }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("button", { className: versionQuiet + " text-red-700 hover:bg-red-50 hover:text-red-800", type: "button", disabled: locked, onClick: () => manage("revoke", scope.scope_id), children: "Remove project" })
            ] }),
            !scope.revoked && scope.sharing?.mode === "shared_broker" && scope.sharing.notes.read ? /* @__PURE__ */ jsxRuntimeExports.jsx(
              ContextNotesPanel,
              {
                scope,
                disabled: locked || dirty,
                gate,
                onChanged: () => {
                  setBrief(null);
                  setPrevious(null);
                  refreshScopes();
                }
              }
            ) : null
          ] }) }, scope.scope_id)) })
        ] }),
        brief ? /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { "aria-label": "What your AI would get", className: "guard-surface-in space-y-3 rounded-2xl border border-brand-blue/20 bg-brand-blue/[0.03] p-4 sm:p-5", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("h4", { className: "text-sm font-semibold text-brand-dark", children: "What your AI would get" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-brand-dark/70", children: "Checked just now. Try again after you change files or projects." }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "max-h-96 space-y-3 overflow-auto rounded-xl bg-white p-3 text-sm leading-6 text-slate-700", children: brief.value.excerpts.map((excerpt, index) => /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "whitespace-pre-wrap break-words", children: excerpt.text }, index)) }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("details", { className: "group", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsxs("summary", { className: summary$1, children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniChevronRight, { "aria-hidden": "true", className: "size-4 transition-transform group-open:rotate-90 motion-reduce:transition-none" }),
              "Where each part came from"
            ] }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "mt-2 space-y-2 pl-5 text-sm", children: brief.value.citations.map((citation, index) => /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { children: [
              brief.scope.sources.find((source) => source.source_id === citation.source)?.path ?? (citation.source === "guard:notes" ? "Reviewed shared notes" : citation.source === "guard:receipts" ? "Guard's recent decisions" : "Guard's safety facts"),
              ", lines ",
              citation.start_line,
              "–",
              citation.end_line,
              /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "block break-all font-mono text-xs text-slate-500", children: citation.document_digest })
            ] }, `${citation.node_id}-${index}`)) })
          ] }),
          previous ? /* @__PURE__ */ jsxRuntimeExports.jsxs("details", { className: "group/prev", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsxs("summary", { className: summary$1, children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniChevronRight, { "aria-hidden": "true", className: "size-4 transition-transform group-open/prev:rotate-90 motion-reduce:transition-none" }),
              "Compare with the last try"
            ] }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "my-2 pl-5 text-sm text-slate-600", children: "From before your last change, so it may be out of date." }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "max-h-64 space-y-3 overflow-auto pl-5 text-sm", children: previous.excerpts.map((excerpt, index) => /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "whitespace-pre-wrap break-words", children: excerpt.text }, index)) })
          ] }) : null
        ] }) : null
      ] })
    ] }),
    ready ? /* @__PURE__ */ jsxRuntimeExports.jsx(
      AddProjectPanel,
      {
        busy,
        dirty,
        documentsAllowed,
        allowFiles,
        executionAllowed,
        gate,
        error,
        first: scopes.length === 0,
        active: scopes.filter((scope) => !scope.revoked).map((scope) => scope.workspace),
        onGrant: grant
      },
      cleared
    ) : null,
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      ContextAgentsPanel,
      {
        ready,
        enabled: agentsAllowed,
        dirty,
        generation,
        scopes,
        gate,
        sharingAllowed,
        onGranted: (scope) => setScopes((values) => [...values, scope])
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
      description: "Opening Updates reads metadata without starting Python or CIGAR.",
      instructions: ["Check the Guard host, catalog freshness and build ID. Different builds can have the same version label.", "A withdrawn or expired artifact is unavailable for preparation. Installing checks each CIGAR feature on this computer before it can be used.", "Use Check for catalog updates only when a trusted feed is configured, or import a catalog signed by an already trusted key."],
      expect: "You can identify the exact build and whether this Guard host has an installable artifact.",
      target: "versions",
      action: "Inspect versions & updates"
    },
    {
      title: "Prepare beside your current runtime",
      description: "Downloading and verifying a replacement does not select or enable it.",
      instructions: ["Choose a registered Python interpreter for an available SDK build, or explicitly prepare an eligible private Python build first.", "Click Prepare this build and watch its native job. The current runtime remains selected while preparation runs.", "Cancel the job if you change your mind. For an uncertain response, refresh jobs and inspect the recorded job ID before another action."],
      expect: "The prepared installation appears in the Versions list marked Installed, with your current selection intact.",
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
      instructions: ["If you selected while off, return to Settings, choose your enabled preference, save and explicitly start CIGAR.", "Use the live runtime status to confirm readiness before granting workspace access.", "Grant only the intended workspace sources and pair the current app connection again when needed."],
      expect: "Your intended sources and apps have fresh access to the selected runtime.",
      target: "access",
      action: "Open Projects"
    },
    {
      title: "Use the last good build deliberately",
      description: "Rollback prepares current compatible data for the previous verified installation.",
      instructions: ["In Updates, choose Prepare last good build when you need to return to the retained installation.", "Wait for the rollback selection job, then commit it explicitly with the same reconnect acknowledgement when live.", "Use Recover job for interrupted work. Recovery does not re-grant context access. Your Guard approvals remain in place."],
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
    title: "Your first CIGAR prompt",
    level: "Start here",
    description: "Turn CIGAR on, ask your AI something, and see what it was handed.",
    outcome: "A prompt that came with the right project files, and a way to check each one.",
    steps: [
      {
        title: "Turn on CIGAR",
        description: "One click. Guard gets everything ready, checks it and starts it.",
        instructions: ["Click Turn on CIGAR at the top of this page. If Guard asks for your approval password, enter it once; it covers every step.", "Watch the steps tick off. You can stop at any point and nothing stays turned on.", "Later, if you want to switch versions yourself, use Updates."],
        expect: "The status at the top says Ready.",
        target: "overview",
        action: "Go to Home",
        tip: "CIGAR uses its own copy of Python. The Python you already use is left alone."
      },
      {
        title: "Let it read project files",
        description: "Prompts only get files once CIGAR may read them.",
        instructions: ["If the top of this page shows Let CIGAR read project files, click it.", "Secrets, keys, hidden files and anything your .gitignore leaves out stay skipped either way."],
        expect: "The top of the page no longer asks to read project files.",
        target: "overview",
        action: "Go to Home"
      },
      {
        title: "Pick exact files (optional)",
        description: "Skip this and CIGAR picks matching files from the project your app is open in.",
        instructions: ["In Projects, click Choose a project folder and browse to your project.", "Tick the files CIGAR should read, such as the README, then click Add project.", "Your choice counts for every AI app."],
        expect: "Your project shows up under Your projects.",
        target: "access",
        action: "Open Projects",
        tip: "Leave this step for later if you are not sure. The automatic choice works for most projects."
      },
      {
        title: "Ask your AI something specific",
        description: "Use Claude Code, Codex, Pi or Oh My Pi in your project, the way you always do.",
        instructions: ["Copy the example below, or write your own about a real file, feature or word in your project.", "Send it in your AI app. CIGAR adds the parts that match before your AI starts."],
        expect: "Your AI's answer points at the right files. A vague prompt may get no files, which is expected.",
        target: "access",
        action: "Open Projects",
        question: "Where is the main page header styled, and which file sets its color?",
        tip: "Prompts that name something in your project match best."
      },
      {
        title: "See what your AI got",
        description: "Check the pieces CIGAR hands over, and where each came from.",
        instructions: ["In Projects, type the same question under Try it: what would you ask your AI?", "Click Show what your AI would get under your project.", "Open Where each part came from to see the file and lines for each piece."],
        expect: "You can trace each piece back to a file and lines in your project.",
        target: "access",
        action: "Open Projects"
      },
      {
        title: "Change it or take it back",
        description: "You stay in charge of what CIGAR reads.",
        instructions: ["After you edit a picked file, click Read files again.", "Click Stop reading next to a file, or Remove project to drop the whole folder.", "Turn CIGAR off at the top of this page to stop everything at once."],
        expect: "You know how to refresh, narrow or remove what CIGAR reads.",
        target: "access",
        action: "Open Projects",
        tip: "Privacy shows what CIGAR keeps. By default its notes live in memory only."
      }
    ]
  },
  {
    id: "ai-apps",
    title: "Connect another app, like Cursor",
    level: "Optional",
    description: "Claude Code, Codex, Pi and Oh My Pi need nothing extra. Other apps can ask CIGAR for files once you connect them.",
    outcome: "One app connected to one project, that you can disconnect at any time.",
    steps: [
      {
        title: "Turn on CIGAR and file reading",
        description: "Connections need both.",
        instructions: ["At the top of this page, click Turn on CIGAR if it is off.", "If the page shows Let CIGAR read project files, click it too."],
        expect: "The status says Ready and nothing asks to read project files.",
        target: "overview",
        action: "Go to Home"
      },
      {
        title: "Add the project",
        description: "Choose the folder the app will work in.",
        instructions: ["In Projects, click Choose a project folder and browse to the folder.", "Tick the files it should read, then click Add project."],
        expect: "The project shows up under Your projects.",
        target: "access",
        action: "Open Projects"
      },
      {
        title: "Get the app's code",
        description: "The app asks through Guard's tool server (MCP), which your app needs set up.",
        instructions: ["In your app, ask it to run Guard's get_context_status tool.", "It answers with a short code. Keep it on screen."],
        expect: "Your app shows a short connection code.",
        target: "access",
        action: "Open Projects",
        tip: "The code proves which running app is asking, so you never connect the wrong one."
      },
      {
        title: "Connect it",
        description: "Match the code, then say which app and project.",
        instructions: ["Under Connect another app, click Check for apps.", "Find the entry whose code matches your app's code.", "Choose the app and the project, then click Connect."],
        expect: "The entry says Connected, with the app and project you chose.",
        target: "access",
        action: "Open Projects",
        tip: "Connections last a few minutes at a time. If one ends, ask the app for a new code and connect again."
      },
      {
        title: "Use it, then disconnect",
        description: "Ask the app a question about the project.",
        instructions: ["Ask the app to use Guard's context tools, using the example below.", "Click Disconnect when you are done."],
        expect: "The app answers with pieces from your project and says where they came from.",
        target: "access",
        action: "Open Projects",
        question: "Use your Guard context tools to explain how this project is set up. Say which files each part of your answer came from."
      }
    ]
  },
  {
    id: "execution",
    title: "Context for Pi commands",
    level: "Advanced · macOS",
    description: "When Pi or Oh My Pi runs a shell command, CIGAR can hand it Guard's safety facts for that project.",
    outcome: "You know whether this works on your computer and where to see it happen.",
    steps: [
      {
        title: "Check it works here",
        description: "This needs Pi or Oh My Pi on macOS.",
        instructions: ["In Settings, open More settings and look for Associate native context with execution.", "If it is missing or greyed out, this computer does not support it yet. Everything else in CIGAR still works.", "Delivery to apps other than Pi and Oh My Pi is not tested end to end yet."],
        expect: "You know whether this computer supports it.",
        target: "runtime",
        action: "Open Settings"
      },
      {
        title: "Turn it on",
        description: "Two switches in More settings.",
        instructions: ["In Settings, open More settings and turn on Native policy and decision facts.", "Turn on Associate native context with execution, then save."],
        expect: "Both switches stay on after saving.",
        target: "runtime",
        action: "Open Settings"
      },
      {
        title: "Use Pi as usual",
        description: "No project setup needed.",
        instructions: ["Open Pi or Oh My Pi in your project and ask it to do something that runs a command.", "CIGAR uses the project Pi is open in, or the files you picked for it in Projects."],
        expect: "Pi keeps working. Guard still asks before risky commands, exactly as before.",
        target: "access",
        action: "Open Projects"
      },
      {
        title: "See what happened",
        description: "Guard still decides every command. CIGAR only adds facts.",
        instructions: ["In Settings, find Native execution context to see what CIGAR prepared for recent commands.", "Approve or deny commands in Guard the usual way."],
        expect: "You can see what CIGAR prepared, separate from Guard's own decision.",
        target: "runtime",
        action: "Open Settings"
      }
    ]
  },
  CIGAR_UPDATE_TUTORIAL
];
function cigarTutorial(id2) {
  return CIGAR_TUTORIALS.find((tutorial) => tutorial.id === id2) ?? CIGAR_TUTORIALS[0];
}
function CigarGuide({ onSelect, walkthroughs }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "cigar-guide", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "cigar-card", "aria-labelledby": "cigar-explained-heading", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "cigar-explained-heading", children: "CIGAR in one minute" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "When CIGAR is on, each prompt you send in Claude Code, Codex, Pi or Oh My Pi gets the few parts of your project that match it. Ask about the header color and your AI gets the header and its styles. Ask something that matches nothing, like “build a to-do app” in an empty folder, and nothing is added." }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "CIGAR works out the project from the folder your AI app is open in, so there is nothing to set up for each app. Secrets, keys, hidden files, build folders and anything your .gitignore leaves out are always skipped. To stop it, use the button at the top of this page." }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "cigar-caption", children: [
        "CIGAR stands for ",
        CIGAR_FULL_NAME,
        "."
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "cigar-card cigar-faq", "aria-labelledby": "cigar-faq-heading", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "cigar-faq-heading", children: "Common questions" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("details", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("summary", { children: "Do I need to install anything?" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "No. The Turn on CIGAR button gets everything ready: Guard sets up its own copy of Python, downloads the CIGAR version it checked for this computer, confirms the download is the real one and starts it. The Python you already use is left alone." }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "If the button says it is waiting for Guard's safety check, a new CIGAR exists but Guard has not finished checking it. Guard never installs a version it has not checked." }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", className: "cigar-text-button", onClick: () => onSelect("versions"), children: [
          "Choose a version in Updates",
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowRight, { "aria-hidden": "true" })
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("details", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("summary", { children: "Can CIGAR see all my files?" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "No. It only looks inside the project your AI app is open in, and it always skips secrets, keys, hidden files, build folders and anything your .gitignore leaves out." })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("details", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("summary", { children: "Do I have to add my projects?" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "No. CIGAR finds the project each app is open in by itself. Add a project only when you want to choose exactly which files it reads. That choice counts for every app." }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", className: "cigar-text-button", onClick: () => onSelect("access"), children: [
          "Open Projects",
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowRight, { "aria-hidden": "true" })
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("details", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("summary", { children: "Why did a prompt get no files?" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "CIGAR adds only files that match the prompt. A vague prompt, or an empty or brand-new folder, matches nothing, so nothing is added. Name a file, a feature or a word from your project and try again. If the top of this page asks to let CIGAR read project files, click that button." })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("details", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("summary", { children: "Does my AI read less?" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "Usually. CIGAR hands over the few pieces that match your prompt instead of whole files, and says where each piece came from. How much less depends on your project and your prompts, so CIGAR makes no promise about it." })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("details", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("summary", { children: "What if CIGAR is off or stops?" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "Guard keeps protecting you exactly as before. Prompts just get no extra files until CIGAR is back. Projects you added come back when you turn it on again." })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("details", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("summary", { children: "What does CIGAR save on my computer?" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "By default, only your settings and the projects you added. Its notes live in memory and vanish when it stops. You can choose to save notes in Privacy. Saved notes are private files on this computer, not encrypted by Guard, and you can delete them there at any time." })
      ] })
    ] }),
    walkthroughs
  ] });
}
const CIGAR_PROMPT_APPS = ["Claude Code", "Codex", "Pi", "Oh My Pi"];
const STEPS = [
  { icon: HiMiniChatBubbleLeftEllipsis, title: "You ask", text: "Type a prompt in your AI app, the way you always do." },
  { icon: HiMiniDocumentMagnifyingGlass, title: "CIGAR finds the parts that match", text: "It looks through the project your app is open in and picks the few parts your prompt is about." },
  { icon: HiMiniCheck, title: "Your AI gets just those", text: "Each part comes with the file and lines it came from, so you can check it. When nothing matches, nothing is added." }
];
const PROMISES = [
  { icon: HiMiniPower, text: "Off until you turn it on, and off again with one click." },
  { icon: HiMiniEyeSlash, text: "Never reads secrets, keys, hidden files or anything your .gitignore leaves out." },
  { icon: HiMiniCpuChip, text: "Runs on this computer and keeps its notes in memory unless you choose to save them." },
  { icon: HiMiniShieldCheck, text: "Guard still decides what your AI may do. CIGAR only adds context." }
];
function CigarStory({ onSelect }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "cigar-story", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "cigar-how", "aria-labelledby": "cigar-how-heading", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "cigar-how-heading", children: "How it works" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("ol", { className: "cigar-steps", children: STEPS.map(({ icon: Icon, title, text: text2 }) => /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "cigar-step-icon", "aria-hidden": "true", children: /* @__PURE__ */ jsxRuntimeExports.jsx(Icon, {}) }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { children: title }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: text2 })
      ] }, title)) })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "cigar-story-pair", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { "aria-labelledby": "cigar-apps-heading", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "cigar-apps-heading", children: "Works in your apps" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "No setup for each app. Once CIGAR is on, every prompt in these apps gets the files that match it." }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "cigar-apps", children: CIGAR_PROMPT_APPS.map((app) => /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCheck, { "aria-hidden": "true" }),
          app
        ] }, app)) }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "cigar-story-aside", children: "Projects you add here count for all of them. Other apps Guard protects, like Cursor, can ask CIGAR for files after you connect them in Projects." })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { "aria-labelledby": "cigar-charge-heading", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "cigar-charge-heading", children: "You stay in charge" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "cigar-promises", children: PROMISES.map(({ icon: Icon, text: text2 }) => /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(Icon, { "aria-hidden": "true" }),
          text2
        ] }, text2)) })
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "cigar-explore", "aria-labelledby": "cigar-explore-heading", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "cigar-explore-heading", children: "Go further" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("ul", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(ExploreRow, { icon: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniFolderPlus, {}), title: "Pick the exact files for a project", text: "Choose what CIGAR reads in one folder. Your choice counts for every app.", onClick: () => onSelect("access") }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(ExploreRow, { icon: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniAcademicCap, {}), title: "Take a short walkthrough", text: "Try CIGAR on your own project, one step at a time.", onClick: () => onSelect("guide") }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(ExploreRow, { icon: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniQuestionMarkCircle, {}), title: "Read common questions", text: "What it reads, what it saves, and why a prompt got no files.", onClick: () => onSelect("guide") })
      ] })
    ] })
  ] });
}
function ExploreRow({ icon, title, text: text2, onClick }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsx("li", { children: /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", className: "cigar-explore-row", onClick, children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "cigar-explore-icon", "aria-hidden": "true", children: icon }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "cigar-explore-text", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { children: title }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: text2 })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowRight, { "aria-hidden": "true", className: "cigar-explore-arrow" })
  ] }) });
}
function CigarTutorials(props) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "cigar-walkthroughs", "aria-labelledby": "cigar-tutorials-heading", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "cigar-section-intro", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "cigar-tutorials-heading", children: "Guided walkthroughs" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "Short step-by-step lessons. They only explain; you choose every setting, start and access grant." })
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
    ] }, tutorial.id)) })
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
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "flex justify-end", children: /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", className: "cigar-walkthrough-close", onClick: props.onExit, "aria-label": "Exit walkthrough", children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniXMark, { "aria-hidden": "true" }) }) }),
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
function Intro({ title, children }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "cigar-section-intro", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { children: title }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children })
  ] });
}
function CigarSections(props) {
  const { tab, status, lesson } = props;
  const id2 = reactExports.useId();
  function moveTab(event, index) {
    let next;
    if (event.key === "ArrowRight") next = (index + 1) % CIGAR_TABS.length;
    else if (event.key === "ArrowLeft") next = (index + CIGAR_TABS.length - 1) % CIGAR_TABS.length;
    else if (event.key === "Home") next = 0;
    else if (event.key === "End") next = CIGAR_TABS.length - 1;
    else return;
    event.preventDefault();
    props.onSelect(CIGAR_TABS[next].value, false);
    document.getElementById(id2 + "-tab-" + CIGAR_TABS[next].value)?.focus();
  }
  const walkthroughs = /* @__PURE__ */ jsxRuntimeExports.jsx(CigarTutorials, { progress: lesson.progress, onBegin: props.onBegin });
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "cigar-sections", "aria-label": "CIGAR sections", children: [
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
        onClick: () => props.onSelect(item.value, false),
        children: item.label
      },
      item.value
    )) }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "cigar-learning-layout" + (lesson.active ? " has-walkthrough" : ""), children: [
      lesson.active ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { ref: props.walkthroughRef, tabIndex: -1, className: "cigar-walkthrough-anchor", children: /* @__PURE__ */ jsxRuntimeExports.jsx(
        CigarWalkthrough,
        {
          tutorial: lesson.tutorial,
          step: lesson.progress.step,
          status,
          dirty: props.dirty,
          onMove: props.onMove,
          onOpen: () => props.onSelect(lesson.tutorial.steps[lesson.progress.step].target),
          onExit: props.onExitLesson
        }
      ) }) : null,
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { ref: props.panelRef, id: id2 + "-panel", role: "tabpanel", "aria-labelledby": id2 + "-tab-" + tab, tabIndex: -1, className: "cigar-panel", children: [
        tab === "overview" ? /* @__PURE__ */ jsxRuntimeExports.jsx(CigarStory, { onSelect: props.onSelect }) : null,
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { hidden: tab !== "runtime", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(Intro, { title: "Settings", children: "The recommended settings work for most people. Change them only if you want to." }),
          props.controls
        ] }),
        tab === "versions" ? props.versions : null,
        tab === "access" ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(Intro, { title: "Projects", children: "CIGAR already finds the project each AI app is open in. Add a project here only to choose exactly which files it reads. Your choice counts for every app." }),
          !status?.effective_enabled ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "cigar-note", children: cigarWaking(status) ? /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { children: "Waking up CIGAR" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "Your projects come back in a moment." })
          ] }) : /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { children: "Turn on CIGAR first" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "Projects open up as soon as CIGAR is on. Use the button at the top of this page." })
          ] }) }) : null,
          status?.effective_enabled || cigarWaking(status) ? props.access : null
        ] }) : null,
        tab === "data" ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(Intro, { title: "Privacy", children: "By default, CIGAR keeps its notes in memory only, so they disappear when you turn it off. Here you can see what it keeps, take back access, or delete saved notes." }),
          props.data
        ] }) : null,
        tab === "guide" ? /* @__PURE__ */ jsxRuntimeExports.jsx(CigarGuide, { onSelect: props.onSelect, walkthroughs }) : null
      ] })
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
function cigarJobActive(job) {
  return cigarJobPending(job) || job.can_commit || job.recovery_available || job.phase === "recovery_required";
}
function cigarBuildBlock(catalog, build, updates) {
  if (build.withdrawn) return "This build has been withdrawn.";
  if (!catalog.catalog.fresh_for_preparation) return "Refresh the catalog before preparing a build.";
  const host = build.platforms.find((p) => p.platform === catalog.host_platform);
  if (!host) return "No artifact is available for this Guard host.";
  if (!host.has_wheel) return "This entry has no installable SDK package.";
  if (!host.features.includes("graph") || !host.has_dependency_lock) return "This entry is missing pieces Guard needs to install it.";
  if (build.channel !== "stable") return "Preview and local candidate installation is unavailable in this Guard build.";
  if (updates.effective.pinned_build && updates.effective.pinned_build !== build.identity.build_id) return "Update preferences pin another build.";
  return null;
}
function cigarPythonBlock(catalog, build) {
  if (build.withdrawn) return "This Python build has been withdrawn.";
  if (!catalog.catalog.fresh_for_preparation) return "Refresh the catalog before preparing Python.";
  if (build.platform !== catalog.host_platform) return "This Python build is for another Guard host.";
  if (build.qualification === "local_candidate") return "This Python build is a local development candidate.";
  return null;
}
const object$5 = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const id$3 = (v) => typeof v === "string" && /^[a-z0-9_:-]{1,128}$/i.test(v);
const word = (v) => typeof v === "string" && /^[a-z0-9_]{1,128}$/.test(v);
const count$1 = (v) => typeof v === "number" && Number.isSafeInteger(v) && v >= 0;
const isCigarGeneration = (v) => typeof v === "string" && /^[1-9][0-9]{0,19}$/.test(v) && (v.length < 20 || v <= "18446744073709551615");
function invalid$3() {
  throw new ContextAssistanceApiError("versions_job_invalid", "Guard returned incompatible CIGAR job data. Refresh jobs.");
}
function recovery(v) {
  if (v === void 0 || v === null) return null;
  if (!object$5(v) || typeof v.id !== "string" || !/^[a-f0-9]{32}$/.test(v.id) || !isCigarGeneration(v.expected_generation) || !count$1(v.started_at_ms) || !count$1(v.deadline_at_ms) || v.deadline_at_ms < v.started_at_ms) invalid$3();
  return { id: v.id, expected_generation: v.expected_generation, started_at_ms: v.started_at_ms, deadline_at_ms: v.deadline_at_ms };
}
function parseCigarVersionJob(value) {
  if (!object$5(value) || !id$3(value.job_id) || !word(value.phase) || !word(value.code) || !count$1(value.created_at_ms) || !count$1(value.updated_at_ms) || value.updated_at_ms < value.created_at_ms || !count$1(value.deadline_at_ms) || value.deadline_at_ms < value.created_at_ms || !(value.worker_live === null || typeof value.worker_live === "boolean") || typeof value.cancel_requested !== "boolean" || typeof value.recovery_available !== "boolean" || value.worker_live === true && value.recovery_available) invalid$3();
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
    if (!["switch", "rollback", "select", "recover"].includes(String(value.operation)) || !id$3(value.target_runtime_id) || !(value.source_runtime_id === null || id$3(value.source_runtime_id)) || !isCigarGeneration(value.expected_generation) || value.authority_restored !== false || ["can_commit", "keeps_disabled", "reconnect_required", "initial_selection", "cleanup_pending"].some((key2) => typeof value[key2] !== "boolean") || value.keeps_disabled === value.reconnect_required || (value.initial_selection ? value.source_runtime_id !== null || !value.keeps_disabled : !id$3(value.source_runtime_id) || value.source_runtime_id === value.target_runtime_id) || value.operation === "select" && !value.initial_selection || ["switch", "rollback"].includes(String(value.operation)) && value.initial_selection || value.can_commit && (value.phase !== "ready" || value.worker_live !== true || value.cancel_requested)) invalid$3();
    const attempt = recovery(value.recovery_attempt);
    if (value.operation === "recover" ? !attempt || attempt.expected_generation !== value.expected_generation || value.can_commit : attempt !== null) invalid$3();
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
  if (!Object.hasOwn(schemas, String(value.schema)) || !schemas[String(value.schema)].includes(String(value.operation)) || value.activation_granted !== false) invalid$3();
  if (value.operation === "refresh_catalog") return { ...base, family: "preparation", operation: "refresh_catalog", can_commit: false };
  if (!id$3(value.build_id)) invalid$3();
  if (value.operation === "setup_interpreter") {
    if (!(value.interpreter_id === null || id$3(value.interpreter_id)) || value.phase === "ready" && value.interpreter_id === null) invalid$3();
    return {
      ...base,
      family: "preparation",
      operation: "setup_interpreter",
      build_id: value.build_id,
      interpreter_id: value.interpreter_id,
      can_commit: false
    };
  }
  if (!id$3(value.interpreter_id)) invalid$3();
  if (!id$3(value.runtime_id) || !isCigarProducerVersion(value.sdk_version) || !isCigarCoreLabel(value.core_version)) invalid$3();
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
  if (!object$5(value) || !Array.isArray(value.jobs) || value.jobs.length > 32) invalid$3();
  const jobs = value.jobs.map(parseCigarVersionJob);
  if (new Set(jobs.map((job) => job.job_id)).size !== jobs.length) invalid$3();
  return jobs;
}
const CIGAR_SETUP_STAGE_LABELS = {
  python: "Getting ready",
  download: "Downloading CIGAR",
  check: "Making sure it is safe",
  start: "Starting up"
};
const python314 = (version) => version[0] === 3 && version[1] === 14;
const blocked = (title, detail, tab, wait2) => ({ kind: "blocked", block: { title, detail, tab, wait: wait2 } });
function planCigarSetup(data, options) {
  const { state, catalog } = data;
  if (state.effective_enabled) return { kind: "ready" };
  if (options.dirty) return blocked("Save your changes first", "You have unsaved settings on this page. Save or undo them, then turn CIGAR on.");
  if (options.locked || state.restriction && !state.effective_preferences.enabled) {
    return blocked("Your organization manages CIGAR", "An administrator controls CIGAR on this computer. Ask them if you need it turned on.");
  }
  if (state.job || data.jobs.some(cigarJobPending)) return blocked("CIGAR is busy", "Another CIGAR task is still finishing. This button comes back when it is done.", "versions", true);
  if (data.jobs.some((job) => job.phase === "recovery_required")) {
    return blocked("An earlier setup did not finish", "Guard paused an earlier CIGAR task so nothing breaks. Open Updates to finish or undo it.", "versions");
  }
  const selected = state.preferences.runtime_id;
  const installed = data.installations;
  const current = selected && installed.some((item) => item.runtime_id === selected) ? selected : null;
  const reusable = current ?? (installed.find((item) => item.qualification === "guard_qualified") ?? installed[0])?.runtime_id ?? null;
  const tail = reusable === current && current !== null ? ["start"] : ["check", "start"];
  if (reusable) {
    return {
      kind: "run",
      runtime_id: reusable,
      build_id: null,
      interpreter_id: null,
      python_build_id: null,
      stages: tail,
      approval: tail.length > 1 || !state.preferences.enabled
    };
  }
  const host = catalog.host_platform;
  if (!host) return blocked("Not available for this computer yet", "CIGAR does not have a version for this kind of computer yet. Guard keeps protecting you without it.");
  const build = catalog.builds.find((item) => cigarBuildBlock(catalog, item, data.updates) === null);
  if (!build) {
    const forHost = catalog.builds.filter((item) => !item.withdrawn && item.platforms.some((p) => p.platform === host));
    if (forHost.length === 0) {
      return blocked("Not available for this computer yet", "CIGAR does not have a version for this kind of computer yet. Guard keeps protecting you without it.");
    }
    if (!catalog.catalog.fresh_for_preparation) {
      return blocked("Guard needs a fresh version list", "Guard's list of CIGAR versions is out of date. Open Updates to refresh it.", "versions");
    }
    return blocked("No version can be installed right now", "Open Updates to see which CIGAR versions are available and why.", "versions");
  }
  const interpreter = data.interpreters.find((item) => item.platform === host && python314(item.python_version) && item.implementation.toLowerCase() === "cpython");
  const pythonBuild = interpreter ? null : catalog.interpreter_builds.find((item) => python314(item.python_version) && cigarPythonBlock(catalog, item) === null);
  if (!interpreter && !pythonBuild) {
    return blocked("Not available for this computer yet", "CIGAR cannot run on this kind of computer yet. Guard keeps protecting you without it.");
  }
  return {
    kind: "run",
    runtime_id: null,
    build_id: build.identity.build_id,
    interpreter_id: interpreter?.interpreter_id ?? null,
    python_build_id: pythonBuild?.build_id ?? null,
    stages: [...pythonBuild ? ["python"] : [], "download", "check", "start"],
    approval: true
  };
}
function planCigarStart(status, dirty) {
  return status && canStartCigar(status, dirty) ? {
    kind: "run",
    runtime_id: status.preferences.runtime_id,
    build_id: null,
    interpreter_id: null,
    python_build_id: null,
    stages: ["start"],
    approval: false
  } : null;
}
class CigarSetupError extends Error {
  constructor(stage, message2, needsProof = false) {
    super(message2);
    this.stage = stage;
    this.needsProof = needsProof;
    this.name = "CigarSetupError";
  }
  stage;
  needsProof;
}
class CigarSetupStopped extends Error {
  constructor() {
    super("CIGAR setup stopped.");
    this.name = "CigarSetupStopped";
  }
}
const JOB_LIMIT_MS = 18e4, START_LIMIT_MS = 12e4, POLL_MS = 800;
const failedPhases = /* @__PURE__ */ new Set(["failed", "cancelled", "recovery_required"]);
const isCigarProofError = (cause) => cause instanceof ContextAssistanceApiError && (cause.code.startsWith("approval_gate") || cause.code === "approval_required");
const transient = (cause) => !(cause instanceof ContextAssistanceApiError) || cause.code.endsWith("context_stale") || cause.code.endsWith("outcome_unknown") || cause.code === "context_assistance_unavailable";
const missingJob = (cause) => cause instanceof ContextAssistanceApiError && cause.code.endsWith("job_missing");
function guard(deps) {
  if (deps.stopped()) throw new CigarSetupStopped();
}
function failure$1(stage, cause) {
  if (cause instanceof CigarSetupStopped || cause instanceof CigarSetupError) throw cause;
  if (isCigarProofError(cause)) throw new CigarSetupError(stage, "Guard needs your approval password to continue.", true);
  throw new CigarSetupError(stage, cause instanceof Error ? cause.message : "Guard did not confirm this step.");
}
async function follow(deps, stage, input, proof, done) {
  guard(deps);
  deps.onJob(input.job_id);
  let uncertain = false;
  try {
    deps.onState((await deps.versions(input, proof)).state);
  } catch (cause) {
    if (!transient(cause)) failure$1(stage, cause);
    uncertain = true;
  }
  const started = deps.now();
  let misses = 0;
  for (; ; ) {
    guard(deps);
    let reply = null;
    try {
      reply = await deps.versions({ action: "job", job_id: input.job_id });
      misses = 0;
      uncertain = false;
    } catch (cause) {
      const retry = transient(cause) || uncertain && missingJob(cause);
      if (!retry) failure$1(stage, cause);
      if (++misses > 5) {
        throw new CigarSetupError(stage, "Guard did not confirm this step. Check Updates before trying again.");
      }
    }
    if (reply) {
      deps.onState(reply.state);
      const job = parseCigarVersionJob(reply.result);
      if (done(job, reply.state)) {
        deps.onJob(null);
        return { job, state: reply.state };
      }
      if (failedPhases.has(job.phase)) {
        throw new CigarSetupError(stage, job.phase === "recovery_required" ? "Guard paused this step so nothing breaks. Open Updates to finish or undo it." : "This step did not finish (" + job.code.replace(/_/g, " ") + "). Nothing was turned on.");
      }
    }
    if (deps.now() - started > JOB_LIMIT_MS) throw new CigarSetupError(stage, "This is taking longer than expected. Guard is still working; check Updates in a minute.");
    await deps.sleep(POLL_MS);
  }
}
function turnOnPreferences(previous, runtime) {
  const untouched = !previous.sources.workspace_documents && !previous.sources.source_set_id;
  if (!untouched) return { ...previous, enabled: true, runtime_id: runtime };
  return {
    ...previous,
    enabled: true,
    runtime_id: runtime,
    sources: { ...previous.sources, workspace_documents: true, source_set_id: "selected-workspaces" },
    features: { ...previous.features, agent_context: true }
  };
}
async function runCigarSetup(plan, initial2, deps, proof) {
  let state = initial2;
  let interpreter = plan.interpreter_id;
  let runtime = plan.runtime_id;
  if (plan.python_build_id) {
    deps.onStage("python");
    const { job } = await follow(
      deps,
      "python",
      { action: "setup_interpreter", job_id: cigarVersionJobId(), build_id: plan.python_build_id },
      proof,
      (item) => (item.phase === "ready" || item.phase === "completed") && item.family === "preparation" && Boolean(item.interpreter_id)
    );
    interpreter = job.family === "preparation" ? job.interpreter_id ?? null : null;
  }
  if (plan.build_id) {
    if (!interpreter) throw new CigarSetupError("download", "Guard did not report a Python 3.14 copy for CIGAR.");
    deps.onStage("download");
    const { job, state: next } = await follow(
      deps,
      "download",
      { action: "install", job_id: cigarVersionJobId(), build_id: plan.build_id, interpreter_id: interpreter },
      proof,
      (item) => (item.phase === "ready" || item.phase === "completed") && item.family === "preparation" && Boolean(item.runtime_id)
    );
    runtime = job.family === "preparation" ? job.runtime_id ?? null : null;
    state = next;
  }
  if (!runtime) throw new CigarSetupError("download", "Guard did not report an installed CIGAR copy.");
  if (state.preferences.runtime_id !== runtime) {
    deps.onStage("check");
    const id2 = cigarVersionJobId();
    const ready = await follow(
      deps,
      "check",
      { action: "prepare_switch", job_id: id2, target_runtime_id: runtime, expected_generation: state.generation },
      proof,
      (item, current) => item.family === "selection" && canCommitCigarJob(item, current)
    );
    const job = ready.job;
    if (job.family !== "selection") throw new CigarSetupError("check", "Guard returned an unexpected job.");
    const committed = await follow(
      deps,
      "check",
      { action: "commit", job_id: id2, expected_generation: job.expected_generation, reconnect: job.reconnect_required },
      proof,
      (item) => item.phase === "completed"
    );
    state = committed.state;
  }
  guard(deps);
  deps.onStage("start");
  if (!state.preferences.enabled || state.preferences.runtime_id !== runtime) {
    const previous = state.preferences;
    let saved;
    try {
      saved = await deps.saveSettings(turnOnPreferences(previous, runtime), proof);
    } catch (cause) {
      failure$1("start", cause);
    }
    deps.onSaved(saved, previous);
  }
  guard(deps);
  let fresh = true, unconfirmed = false;
  try {
    state = await deps.activate();
  } catch (cause) {
    if (!transient(cause)) failure$1("start", cause);
    fresh = false;
    unconfirmed = true;
  }
  if (fresh) deps.onState(state);
  const started = deps.now();
  let sawJob = fresh && state.job !== null;
  for (; ; ) {
    if (fresh && state.effective_enabled) return state;
    guard(deps);
    if (fresh && !state.requested_enabled) {
      if (unconfirmed) throw new CigarSetupError("start", "Guard did not get the request to start CIGAR. Try again.");
      throw new CigarSetupStopped();
    }
    if (fresh && state.job === null && (sawJob || deps.now() - started > 3e3)) throw new CigarSetupError("start", contextStatusCopy(state).detail);
    if (deps.now() - started > START_LIMIT_MS) {
      throw new CigarSetupError("start", "CIGAR is taking longer than expected to start. Refresh status in a minute.");
    }
    await deps.sleep(POLL_MS);
    try {
      state = await deps.status();
      fresh = true;
    } catch (cause) {
      if (!transient(cause)) failure$1("start", cause);
      fresh = false;
      continue;
    }
    if (state.requested_enabled) unconfirmed = false;
    sawJob ||= state.job !== null;
    deps.onState(state);
  }
}
const ALL_STAGES = ["python", "download", "check", "start"];
function blockTabLabel(tab) {
  if (tab === "versions") return "Updates";
  return "details";
}
function CigarSetupAction({ setup, status, disabled, canStop, stopDisabled, onStop, onOpen }) {
  const off = canStop ? /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", className: "cigar-button", disabled: stopDisabled, onClick: onStop, children: "Turn off CIGAR" }) : null;
  if (status?.effective_enabled) return off ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "cigar-setup-action", children: off }) : null;
  if (setup.run.phase === "running") {
    return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "cigar-setup-action", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "cigar-setup-buttons", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("button", { type: "button", className: "cigar-button", onClick: setup.stop, children: "Stop setup" }),
        off
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "cigar-setup-caption", role: "status", children: [
        CIGAR_SETUP_STAGE_LABELS[setup.run.stage],
        "…"
      ] })
    ] });
  }
  if (cigarWaking(status)) {
    return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "cigar-setup-action", children: [
      off,
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "cigar-setup-caption", role: "status", children: "CIGAR is on and waking up…" })
    ] });
  }
  const plan = setup.plan;
  const block = plan?.kind === "blocked" ? plan.block : null;
  const checking = plan === null && setup.loadError === null;
  const failed = setup.run.phase === "failed" ? setup.run : null;
  let note2 = /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "cigar-setup-caption", children: checking ? "Checking this computer…" : "About a minute · Runs on this computer · Off with one click" });
  if (block) {
    note2 = /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "cigar-setup-block", role: "status", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { children: block.title }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: block.detail }),
      block.tab ? /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", className: "cigar-text-button", onClick: () => onOpen(block.tab), children: [
        "Open ",
        blockTabLabel(block.tab),
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowRight, { "aria-hidden": "true" })
      ] }) : null
    ] });
  } else if (failed) {
    note2 = /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "cigar-setup-block", role: "alert", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { children: "CIGAR did not turn on" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: failed.message })
    ] });
  } else if (setup.loadError) {
    note2 = /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "cigar-setup-block", role: "alert", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { children: "Guard did not answer" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: setup.loadError })
    ] });
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "cigar-setup-action", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "cigar-setup-buttons", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs(
        "button",
        {
          type: "button",
          className: "cigar-button cigar-button-primary cigar-button-solid",
          disabled: disabled || checking || block !== null || setup.run.phase === "proof",
          onClick: setup.start,
          children: [
            failed ? "Try again" : "Turn on CIGAR",
            /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowRight, { "aria-hidden": "true" })
          ]
        }
      ),
      off
    ] }),
    note2
  ] });
}
function stageState(index, at, phase) {
  if (phase !== "running" && phase !== "failed") return "next";
  if (index < at) return "done";
  if (index > at) return "next";
  return phase === "running" ? "active" : "failed";
}
const STAGE_SUFFIX = { done: " (done)", active: " (in progress)", failed: " (stopped)", next: "" };
function CigarSetupProgress({ setup }) {
  const run = setup.run;
  const live = run.phase === "running" || run.phase === "failed" ? run : null;
  if (!live) return null;
  let stages = live.stages;
  if (stages.length === 0) stages = setup.plan?.kind === "run" ? setup.plan.stages : ALL_STAGES;
  const at = live.stage ? stages.indexOf(live.stage) : -1;
  let body = "Getting ready…";
  if (live.stage && run.phase === "running") body = `${CIGAR_SETUP_STAGE_LABELS[live.stage]}… step ${at + 1} of ${stages.length}.`;
  else if (live.stage) body = `Setup stopped at step ${at + 1} of ${stages.length}.`;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "cigar-setup-progress", "aria-live": "polite", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "cigar-setup-body", children: body }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("ol", { className: "cigar-setup-track", "aria-label": "Setup progress", children: stages.map((stage, index) => {
      const state = stageState(index, at, run.phase);
      return /* @__PURE__ */ jsxRuntimeExports.jsx("li", { "data-state": state, children: /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "sr-only", children: [
        CIGAR_SETUP_STAGE_LABELS[stage],
        STAGE_SUFFIX[state]
      ] }) }, stage);
    }) })
  ] });
}
function CigarSetupProof({ setup, gate }) {
  const run = setup.run;
  return /* @__PURE__ */ jsxRuntimeExports.jsx(
    SettingsSaveProofModal,
    {
      open: run.phase === "proof",
      mode: "verify-save",
      gate,
      title: "Approve turning on CIGAR",
      detail: "Guard will download CIGAR, make sure it is the approved copy and start it on this computer. After that, each prompt you send in Claude Code, Codex, Pi or Oh My Pi gets the few files from that project that match it. CIGAR skips secrets, keys, generated folders and anything the project's .gitignore files leave out. Turn off Context for AI apps in Settings to stop it. One approval covers everything.",
      confirmLabel: "Turn on CIGAR",
      error: run.phase === "proof" ? run.error : null,
      pending: false,
      onCancel: setup.cancelProof,
      onConfirm: (proof) => setup.confirm({ currentPassword: proof.currentPassword, totpCode: proof.totpCode })
    }
  );
}
function CigarHome(props) {
  const id2 = reactExports.useId();
  const { status, setup } = props;
  const running = setup.run.phase === "running";
  const copy = cigarHomeCopy(status, props.loading, running);
  let label2 = props.loading ? "Checking" : "Status unavailable";
  if (status) label2 = contextStatusCopy(status).label;
  if (running) label2 = "Working";
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "cigar-home", "aria-labelledby": id2 + "-title", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "cigar-home-main", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "cigar-home-top", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "cigar-status", "data-ready": status?.effective_enabled === true, children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { "aria-hidden": "true" }),
          label2
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "button",
          {
            type: "button",
            className: "cigar-icon-button",
            "aria-label": "Refresh status",
            title: "Refresh status",
            disabled: props.refreshDisabled,
            onClick: props.onRefresh,
            children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowPath, { "aria-hidden": "true" })
          }
        )
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: id2 + "-title", children: "Give your AI the right pages, not the whole book." }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "cigar-home-detail", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("strong", { children: [
          copy.headline,
          "."
        ] }),
        " ",
        copy.detail
      ] }),
      copy.setupHint ? /* @__PURE__ */ jsxRuntimeExports.jsx(
        CigarAllowFilesButton,
        {
          allow: props.allowFiles,
          className: "cigar-button cigar-button-solid cigar-allow-hero",
          caption: "Secrets, keys, hidden files and anything your .gitignore leaves out stay skipped."
        }
      ) : null,
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        CigarSetupAction,
        {
          setup,
          status,
          disabled: props.actionDisabled,
          canStop: props.canStop,
          stopDisabled: props.stopDisabled,
          onStop: props.onStop,
          onOpen: props.onOpen
        }
      ),
      /* @__PURE__ */ jsxRuntimeExports.jsx(CigarSetupProgress, { setup })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(CigarPromptDemo, {})
  ] });
}
const DEMO_FILES = [
  { path: "src/components/Header.tsx", match: "lines 12–40" },
  { path: "src/api/orders.ts" },
  { path: "src/styles/header.css", match: "lines 1–18" },
  { path: "README.md" },
  { path: ".env", locked: true },
  { path: "tests/checkout.test.ts" }
];
function CigarPromptDemo() {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("figure", { className: "cigar-demo", "aria-label": "Example: for the prompt Make the header blue, CIGAR picks the header component and its styles, and never reads the .env file.", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "cigar-demo-prompt", "aria-hidden": "true", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "cigar-demo-you", children: "You" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "cigar-demo-ask", children: "Make the header blue" })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "cigar-demo-files", "aria-hidden": "true", children: DEMO_FILES.map((file, index) => /* @__PURE__ */ jsxRuntimeExports.jsxs(
      "li",
      {
        style: { "--cigar-demo-row": index },
        "data-match": "match" in file ? "true" : void 0,
        "data-locked": "locked" in file ? "true" : void 0,
        children: [
          "locked" in file ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniLockClosed, { "aria-hidden": "true" }) : /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniDocumentText, { "aria-hidden": "true" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("code", { children: file.path }),
          "match" in file ? /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "cigar-demo-tag", children: file.match }) : null,
          "locked" in file ? /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "cigar-demo-tag", children: "never read" }) : null
        ]
      },
      file.path
    )) }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("figcaption", { className: "cigar-demo-result", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniSparkles, { "aria-hidden": "true" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: "Your AI gets those two pieces, each with the file and lines it came from." })
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
function CigarWorkspace(props) {
  const [tab, setTab] = reactExports.useState(() => cigarTabFromSearch(typeof window === "undefined" ? "" : window.location.search));
  const panel = reactExports.useRef(null);
  const walkthroughAnchor = reactExports.useRef(null);
  const lesson = useCigarTutorial();
  const status = props.status;
  const canStop = props.stopAvailable ?? Boolean(status?.requested_enabled || status?.effective_enabled || status?.job);
  reactExports.useEffect(() => {
    return subscribeDashboardLocation(() => setTab(cigarTabFromSearch(window.location.search)));
  }, []);
  function select(next, focusPanel = true) {
    setTab(next);
    const url = new URL(window.location.href);
    url.searchParams.set("section", next);
    window.history.replaceState({}, "", url.pathname + url.search + url.hash);
    if (focusPanel) window.requestAnimationFrame(() => panel.current?.focus());
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
      /* @__PURE__ */ jsxRuntimeExports.jsxs("h1", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCircleStack, { "aria-hidden": "true" }),
        "CIGAR"
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "Hands your AI app the few project files that match what you ask." })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      CigarHome,
      {
        status,
        setup: props.setup,
        allowFiles: props.allowFiles,
        loading: props.loading,
        actionDisabled: props.disabled || props.busy || props.loading,
        canStop,
        stopDisabled: props.disabled || props.busy,
        refreshDisabled: props.disabled || props.busy || props.loading,
        onStop: props.onStop,
        onRefresh: props.onRefresh,
        onOpen: select
      }
    ),
    props.error ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "cigar-note", role: "alert", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { children: "CIGAR needs attention" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: props.error })
    ] }) : null,
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      CigarSections,
      {
        tab,
        status,
        dirty: props.dirty,
        lesson,
        versions: props.versions,
        controls: props.controls,
        access: props.access,
        data: props.data,
        panelRef: panel,
        walkthroughRef: walkthroughAnchor,
        onSelect: select,
        onBegin: beginTutorial,
        onMove: moveTutorial,
        onExitLesson: () => {
          lesson.exit();
          select("guide");
        }
      }
    ),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("footer", { className: "cigar-footer", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniChatBubbleLeftRight, { "aria-hidden": "true" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { children: [
        "CIGAR is in beta. Something odd or something you love?",
        " ",
        /* @__PURE__ */ jsxRuntimeExports.jsx("a", { href: "https://github.com/hashgraph-online/hol-cigar/issues", target: "_blank", rel: "noopener noreferrer", children: "Tell us" }),
        "."
      ] }),
      props.dirty ? /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { children: "Unsaved changes" }) : null
    ] })
  ] });
}
const CHANNEL = { stable: "Stable", preview: "Preview", local_candidate: "Local build" };
const summary = "flex min-h-11 cursor-pointer list-none items-center gap-1.5 text-sm font-semibold text-brand-dark/75 hover:text-brand-dark [&::-webkit-details-marker]:hidden";
function Row$1(props) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { className: "flex flex-wrap items-start gap-x-4 gap-y-3 px-4 py-4 sm:px-5", "aria-labelledby": props.describedBy ? props.titleId + " " + props.describedBy : props.titleId, children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0 flex-[1_1_18rem] space-y-1.5", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h4", { id: props.titleId, className: "font-mono text-sm font-semibold tabular-nums text-brand-dark", children: props.title }),
        props.tags
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs leading-5 text-brand-dark/65", children: props.meta }),
      props.reason,
      props.extra
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "flex shrink-0 flex-wrap items-center gap-2", children: props.action })
  ] });
}
function CigarVersionBuildsPanel({ data, status, disabled, selectionDisabled, onAction }) {
  const [python, setPython] = reactExports.useState("");
  const id2 = reactExports.useId(), catalog = data.catalog;
  const selectedId = status?.preferences.runtime_id ?? "";
  const registered = data.interpreters.filter((p) => p.platform === catalog.host_platform);
  const interpreter = registered.find((p) => p.interpreter_id === python) ?? registered[0];
  const activeSelection = data.jobs.some((job) => job.family === "selection" && (cigarJobPending(job) || job.recovery_available));
  const selectionBlocked = selectionDisabled || !status || activeSelection;
  const matched = /* @__PURE__ */ new Set();
  const installationFor = (build) => {
    const found = data.installations.find((item) => item.build_id === build.identity.build_id);
    if (found) matched.add(found.runtime_id);
    return found;
  };
  const inUseTag = (item) => item.runtime_id === selectedId ? /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: "green", children: status?.runtime?.active ? "In use · running" : "In use" }) : /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: "blue", children: "Installed" });
  const prepareSelection = (item) => /* @__PURE__ */ jsxRuntimeExports.jsx(
    "button",
    {
      type: "button",
      className: versionButton,
      disabled: selectionBlocked || item.runtime_id === selectedId,
      onClick: () => {
        if (status) onAction({
          input: { action: "prepare_switch", job_id: cigarVersionJobId(), target_runtime_id: item.runtime_id, expected_generation: status.generation },
          title: "Prepare CIGAR selection",
          detail: "Verify this target and its data without committing a runtime switch. CIGAR stays off if it is off now."
        });
      },
      children: "Prepare selection"
    }
  );
  const buildRows = catalog.builds.map((build) => {
    const buildId = build.identity.build_id, installed = installationFor(build);
    const reason = installed ? null : cigarBuildBlock(catalog, build, data.updates), host = build.platforms.find((p) => p.platform === catalog.host_platform);
    return /* @__PURE__ */ jsxRuntimeExports.jsx(
      Row$1,
      {
        titleId: id2 + "-build-" + buildId,
        describedBy: id2 + "-build-id-" + buildId,
        title: "CIGAR " + build.identity.sdk_version,
        tags: /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
          installed ? inUseTag(installed) : null,
          /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: build.channel === "stable" ? "slate" : "attention", children: CHANNEL[build.channel] }),
          build.withdrawn ? /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: "red", children: "Withdrawn" }) : null
        ] }),
        meta: /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
          "Core ",
          build.identity.core_version,
          " · ",
          host ? "download " + versionBytes(host.download_bytes) : "not built for this computer",
          installed ? " · " + installationLabel(installed.qualification) : ""
        ] }),
        reason: reason ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { id: id2 + "-build-reason-" + buildId, className: "text-sm text-amber-800", children: reason }) : null,
        extra: /* @__PURE__ */ jsxRuntimeExports.jsxs("details", { className: "group text-xs text-brand-dark/60", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("summary", { className: "inline-flex min-h-8 cursor-pointer list-none items-center gap-1 font-medium hover:text-brand-dark [&::-webkit-details-marker]:hidden", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniChevronRight, { "aria-hidden": "true", className: "size-3.5 transition-transform group-open:rotate-90 motion-reduce:transition-none" }),
            "Build identity"
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-1 space-y-0.5 break-all pl-5 font-mono", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { id: id2 + "-build-id-" + buildId, children: [
              "Build: ",
              buildId
            ] }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { children: [
              "Source: ",
              build.identity.source_revision
            ] }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { children: [
              "Manifest: ",
              build.identity.manifest_sha256
            ] }),
            host ? /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { children: [
              "Worker: ",
              host.worker_sha256
            ] }) : null
          ] })
        ] }),
        action: installed ? prepareSelection(installed) : /* @__PURE__ */ jsxRuntimeExports.jsx(
          "button",
          {
            type: "button",
            className: versionButton,
            "aria-describedby": reason ? id2 + "-build-reason-" + buildId : void 0,
            disabled: disabled || reason !== null || !interpreter,
            onClick: () => {
              if (interpreter) onAction({
                input: { action: "install", job_id: cigarVersionJobId(), build_id: buildId, interpreter_id: interpreter.interpreter_id },
                title: "Prepare CIGAR build",
                detail: "Download and verify this SDK in a separate managed installation. Keep the selected runtime in place."
              });
            },
            children: "Prepare this build"
          }
        )
      },
      buildId
    );
  });
  const looseRows = data.installations.filter((item) => !matched.has(item.runtime_id)).map((item) => /* @__PURE__ */ jsxRuntimeExports.jsx(
    Row$1,
    {
      titleId: id2 + "-installed-" + item.runtime_id,
      title: "CIGAR " + (item.sdk_version ?? "registered bundle"),
      tags: inUseTag(item),
      meta: /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
        "Core ",
        item.core_version ?? "not reported",
        " · Python ",
        item.python_version.join("."),
        " · ",
        item.managed ? "Guard managed" : "added outside Guard",
        " · ",
        installationLabel(item.qualification)
      ] }),
      extra: /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "break-all font-mono text-xs text-brand-dark/50", children: [
        "Build: ",
        item.build_id ?? "legacy registration"
      ] }),
      action: prepareSelection(item)
    },
    item.runtime_id
  ));
  const pythonRow = (build) => {
    const reason = cigarPythonBlock(catalog, build), present = data.interpreters.some((p) => p.build_id === build.build_id);
    return /* @__PURE__ */ jsxRuntimeExports.jsx(
      Row$1,
      {
        titleId: id2 + "-python-" + build.build_id,
        describedBy: id2 + "-python-id-" + build.build_id,
        title: "Python " + build.python_version.join("."),
        tags: /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
          present ? /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: "green", children: "Ready" }) : null,
          /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: "slate", children: platformLabel(build.platform) })
        ] }),
        meta: /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { id: id2 + "-python-id-" + build.build_id, className: "break-all", children: [
          build.build_id,
          " · download ",
          versionBytes(build.archive_bytes)
        ] }),
        reason: reason && build.platform === catalog.host_platform ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { id: id2 + "-python-reason-" + build.build_id, className: "text-sm text-amber-800", children: reason }) : null,
        action: /* @__PURE__ */ jsxRuntimeExports.jsx(
          "button",
          {
            type: "button",
            className: versionButton,
            "aria-describedby": reason && build.platform === catalog.host_platform ? id2 + "-python-reason-" + build.build_id : void 0,
            disabled: disabled || present || reason !== null,
            onClick: () => onAction({
              input: { action: "setup_interpreter", job_id: cigarVersionJobId(), build_id: build.build_id },
              title: "Prepare private Python",
              detail: "Download and verify the catalog's immutable Python build. Leave your system Python and current CIGAR selection unchanged."
            }),
            children: present ? "Python registered" : "Prepare private Python"
          }
        )
      },
      build.build_id
    );
  };
  const hostPython = catalog.interpreter_builds.filter((b) => !catalog.host_platform || b.platform === catalog.host_platform);
  const otherPython = catalog.interpreter_builds.filter((b) => catalog.host_platform && b.platform !== catalog.host_platform);
  const pythonOptions = registered.map((p) => ({
    value: p.interpreter_id,
    label: "Python " + p.python_version.join(".") + (p.managed ? " · set up by Guard" : " · already on this computer"),
    description: p.interpreter_id
  }));
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-8", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "space-y-3", "aria-labelledby": id2 + "-builds", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-end justify-between gap-x-6 gap-y-3", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { id: id2 + "-builds", className: versionHeading, children: "Versions" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: versionLead, children: "Preparing a version downloads it next to the one you have. Nothing changes until you switch." })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "w-full sm:w-72", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { id: id2 + "-python-label", className: "text-xs font-medium text-brand-dark/65", children: "Python for SDK preparation" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            SelectMenu,
            {
              labelledBy: id2 + "-python-label",
              className: "mt-1.5 w-full",
              value: interpreter?.interpreter_id ?? "",
              disabled: disabled || !registered.length,
              placeholder: "No Python interpreter registered for this host",
              options: pythonOptions,
              onChange: setPython
            }
          )
        ] })
      ] }),
      !catalog.builds.length && !data.installations.length ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "rounded-2xl border border-dashed border-brand-dark/15 p-5 text-sm text-brand-dark/65", children: "No SDK builds are available in this catalog." }) : /* @__PURE__ */ jsxRuntimeExports.jsxs("ul", { className: versionList, children: [
        buildRows,
        looseRows
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-x-4 gap-y-2", children: [
        selectedId ? /* @__PURE__ */ jsxRuntimeExports.jsx(
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
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs leading-5 text-brand-dark/60", children: activeSelection ? /* @__PURE__ */ jsxRuntimeExports.jsx("span", { role: "status", children: "Finish, cancel or recover the current selection job before preparing another." }) : "Something wrong after a switch? Go back to the last version that worked." })
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "space-y-3", "aria-labelledby": id2 + "-python", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { id: id2 + "-python", className: versionHeading, children: "Python for CIGAR" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: versionLead, children: "CIGAR runs on its own private copy of Python. Your system Python is never touched." })
      ] }),
      !catalog.interpreter_builds.length ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-brand-dark/65", children: "No private Python builds are listed." }) : null,
      hostPython.length ? /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: versionList, children: hostPython.map(pythonRow) }) : null,
      otherPython.length ? /* @__PURE__ */ jsxRuntimeExports.jsxs("details", { className: "group", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("summary", { className: summary, children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniChevronRight, { "aria-hidden": "true", className: "size-4 transition-transform group-open:rotate-90 motion-reduce:transition-none" }),
          "Builds for other computers ",
          /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "font-normal text-brand-dark/50", children: [
            "(",
            otherPython.length,
            ")"
          ] })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: versionList + " mt-2 opacity-90", children: otherPython.map(pythonRow) })
      ] }) : null
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
const time = (ms) => /* @__PURE__ */ jsxRuntimeExports.jsx("time", { dateTime: new Date(ms).toISOString(), children: new Date(ms).toLocaleString() });
function CigarVersionJobsPanel(props) {
  const [acknowledged, setAcknowledged] = reactExports.useState(null);
  const id2 = reactExports.useId();
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "space-y-3", "aria-labelledby": id2 + "-heading", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { id: id2 + "-heading", className: versionHeading, children: "In progress" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: versionLead, children: "Work Guard is doing for you. Each change waits for your go-ahead before it touches the version in use." })
    ] }),
    !props.jobs.length ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-brand-dark/65", children: "No CIGAR update jobs have been recorded." }) : null,
    props.jobs.map((job) => {
      const pending = cigarJobPending(job);
      const attention = job.recovery_available || job.phase === "failed" || job.phase === "recovery_required";
      let tone = pending ? "blue" : "slate";
      if (attention) tone = "amber";
      return /* @__PURE__ */ jsxRuntimeExports.jsxs(
        "article",
        {
          "aria-label": operation[job.operation] + " " + job.job_id,
          className: "guard-surface-in space-y-3 rounded-2xl border p-4 sm:p-5 " + (attention ? "border-amber-300/70 bg-amber-50/50" : "border-brand-blue/20 bg-brand-blue/[0.03]"),
          children: [
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-2.5", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("span", { "aria-hidden": "true", className: "flex size-8 items-center justify-center rounded-full " + (attention ? "bg-amber-100 text-amber-700" : "bg-brand-blue/10 text-brand-blue"), children: attention ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniExclamationTriangle, { className: "size-4" }) : /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowPath, { className: "size-4" + (pending ? " motion-safe:animate-spin" : "") }) }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("h4", { className: "font-semibold text-brand-dark", children: operation[job.operation] }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("span", { role: "status", children: /* @__PURE__ */ jsxRuntimeExports.jsxs(Tag, { tone, children: [
                job.phase.replaceAll("_", " "),
                job.cancel_requested ? " · cancellation requested" : ""
              ] }) })
            ] }),
            job.family === "selection" ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-2 text-sm leading-6 text-brand-dark/75", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "break-all text-xs text-brand-dark/55", children: [
                "Target: ",
                job.target_runtime_id
              ] }),
              job.keeps_disabled ? /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { children: [
                job.operation === "recover" ? "Recovery keeps CIGAR off." : "Selecting this runtime keeps CIGAR off.",
                " Start it separately when you are ready."
              ] }) : /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "Switching briefly pauses CIGAR. Context access and app connections require fresh grants afterward. Your Guard approvals remain in place." }),
              job.can_commit ? /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
                job.reconnect_required ? /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "flex min-h-11 cursor-pointer items-center gap-3 rounded-lg border border-brand-dark/10 bg-white px-3", children: [
                  /* @__PURE__ */ jsxRuntimeExports.jsx(
                    "input",
                    {
                      type: "checkbox",
                      className: "size-4 accent-brand-blue",
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
                    className: versionPrimary,
                    disabled: props.selectionDisabled || !canCommitCigarJob(job, props.status) || job.reconnect_required && acknowledged !== job.job_id + ":" + job.expected_generation,
                    onClick: () => props.onAction({
                      input: { action: "commit", job_id: job.job_id, expected_generation: job.expected_generation, reconnect: job.reconnect_required },
                      title: job.keeps_disabled ? "Select CIGAR runtime" : "Switch CIGAR now",
                      detail: job.keeps_disabled ? "Commit the verified selection and keep CIGAR off." : "Switch to the verified runtime now. Reconnect context sources and apps after the switch."
                    }),
                    children: job.keeps_disabled ? "Select & keep CIGAR off" : "Switch now"
                  }
                ),
                !canCommitCigarJob(job, props.status) ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-amber-800", children: "The live selection changed. Refresh status and jobs before continuing." }) : null
              ] }) : null
            ] }) : null,
            pending && !job.cancel_requested || job.recovery_available ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-2", children: [
              pending && !job.cancel_requested ? /* @__PURE__ */ jsxRuntimeExports.jsx(
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
            ] }) : null,
            /* @__PURE__ */ jsxRuntimeExports.jsxs("details", { className: "group text-xs text-brand-dark/60", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsxs("summary", { className: "inline-flex min-h-8 cursor-pointer list-none items-center gap-1 font-medium hover:text-brand-dark [&::-webkit-details-marker]:hidden", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniChevronRight, { "aria-hidden": "true", className: "size-3.5 transition-transform group-open:rotate-90 motion-reduce:transition-none" }),
                "Job details"
              ] }),
              /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-1 space-y-0.5 pl-5", children: [
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
                    time(job.recovery_attempt.deadline_at_ms)
                  ] }),
                  /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { children: [
                    "Original preparation deadline: ",
                    time(job.deadline_at_ms)
                  ] })
                ] }) : /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { children: [
                  "Deadline: ",
                  time(job.deadline_at_ms)
                ] }),
                job.family === "selection" && job.cleanup_pending ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "Cleanup is still pending. Wait before another switch." }) : null
              ] })
            ] })
          ]
        },
        job.job_id
      );
    })
  ] });
}
const label = "text-sm font-medium text-brand-dark";
const hint = "mt-1 text-xs leading-5 text-brand-dark/60";
function CigarUpdatePreferencesPanel({ value, builds, disabled, onAction }) {
  const [draft, setDraft] = reactExports.useState(value.requested);
  const id2 = reactExports.useId();
  reactExports.useEffect(() => {
    setDraft(value.requested);
  }, [value.revision]);
  const locked = (key2) => disabled || value.locked_settings.some((k) => k === "context_assistance_updates" || k === "context_assistance_updates." + key2);
  const changed = JSON.stringify(draft) !== JSON.stringify(value.requested);
  const modes = [
    { value: "manual", label: "Manual", description: "You decide when to prepare and switch." },
    { value: "notify", label: "Notify", description: "Not available in this Guard version.", disabled: true },
    ...draft.mode === "prepare" ? [{ value: "prepare", label: "Automatic preparation", description: "Not available in this Guard version.", disabled: true }] : []
  ];
  const pins = [
    { value: "", label: "No pin", description: "Any approved version can be prepared." },
    ...draft.pinned_build && !builds.some((b) => b.identity.build_id === draft.pinned_build) ? [{ value: draft.pinned_build, label: draft.pinned_build, description: "No longer in the version list" }] : [],
    ...builds.map((b) => ({ value: b.identity.build_id, label: "CIGAR " + b.identity.sdk_version + (b.withdrawn ? " · withdrawn" : ""), description: b.identity.build_id }))
  ];
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "space-y-5", "aria-labelledby": id2 + "-heading", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h4", { id: id2 + "-heading", className: "font-semibold text-brand-dark", children: "Update preferences" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: hint, children: "Preparing a build leaves your current selection in place. This Guard build requires an explicit switch and keeps the last good build." })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid gap-5 sm:grid-cols-2", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { id: id2 + "-mode", className: label, children: "Update mode" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          SelectMenu,
          {
            labelledBy: id2 + "-mode",
            className: "mt-1.5 w-full",
            value: draft.mode,
            options: modes,
            disabled: locked("mode"),
            onChange: (mode2) => setDraft({ ...draft, mode: mode2 })
          }
        ),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: hint, children: "Update notifications and automatic preparation are not available in this Guard build." })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { id: id2 + "-pin", className: label, children: "Pin to a build" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          SelectMenu,
          {
            labelledBy: id2 + "-pin",
            className: "mt-1.5 w-full",
            value: draft.pinned_build ?? "",
            options: pins,
            disabled: locked("pinned_build"),
            onChange: (pin) => {
              const { pinned_build: _pin, ...rest } = draft;
              setDraft(pin ? { ...rest, pinned_build: pin } : rest);
            }
          }
        ),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: hint + " break-all", children: [
          "Effective pin: ",
          value.effective.pinned_build ?? "none",
          ". Last good build: ",
          value.effective.retain_last_good ? "retained" : "retention disabled by saved policy",
          "."
        ] })
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "rounded-xl border border-brand-dark/10 px-4", children: /* @__PURE__ */ jsxRuntimeExports.jsx(
      SettingsToggleRow,
      {
        label: "Allow preview selections",
        checked: draft.allow_preview,
        disabled: locked("allow_preview"),
        description: "Preview installation still needs release qualification and support in Guard.",
        onChange: (allow_preview) => setDraft({ ...draft, allow_preview })
      }
    ) }),
    value.locked_settings.length ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-brand-dark/70", children: "Your organization manages some update preferences. Effective values may differ from your saved choices." }) : null,
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
function compareCigarVersions(a, b) {
  const parse = (v) => {
    const [core, pre = ""] = v.replace(/^v/, "").split("-", 2);
    return { parts: core.split(".").map((n) => Number.parseInt(n, 10) || 0), pre };
  };
  const x = parse(a), y = parse(b);
  for (let i = 0; i < Math.max(x.parts.length, y.parts.length); i += 1) {
    const d = (x.parts[i] ?? 0) - (y.parts[i] ?? 0);
    if (d) return d;
  }
  if (x.pre === y.pre) return 0;
  if (!x.pre) return 1;
  if (!y.pre) return -1;
  return x.pre < y.pre ? -1 : 1;
}
function cigarStanding(status, data) {
  const selectedId = status?.preferences.runtime_id ?? "";
  const installed = data?.installations.find((item) => item.runtime_id === selectedId);
  const running = status?.runtime?.active === true && status.effective_enabled;
  const version = running ? status.runtime.package_version : installed?.sdk_version ?? (selectedId ? status?.last_check?.package_version : void 0);
  if (!version) return { kind: "none", installed: data?.installations.length ?? 0 };
  const host = data?.catalog.host_platform;
  let newest = null;
  for (const build of data?.catalog.builds ?? []) {
    if (build.withdrawn || build.channel !== "stable" || !build.platforms.some((platform2) => platform2.platform === host)) continue;
    if (!newest || compareCigarVersions(build.identity.sdk_version, newest.identity.sdk_version) > 0) newest = build;
  }
  const behind = newest !== null && compareCigarVersions(newest.identity.sdk_version, version) > 0;
  const block = behind && data ? cigarBuildBlock(data.catalog, newest, data.updates) : null;
  return { kind: behind ? "behind" : "current", version, running, newest: newest?.identity.sdk_version ?? null, block };
}
const markers = {
  behind: [HiMiniArrowUpCircle, "bg-brand-blue/10 text-brand-blue"],
  none: [HiMiniSparkles, "bg-brand-dark/[0.06] text-brand-dark/55"],
  running: [HiMiniCheckCircle, "bg-brand-green-bg text-brand-green-text"],
  off: [HiMiniPauseCircle, "bg-brand-dark/[0.06] text-brand-dark/55"]
};
function markerKey(standing) {
  if (standing.kind !== "current") return standing.kind;
  return standing.running ? "running" : "off";
}
function Marker({ standing }) {
  const [Icon, tone] = markers[markerKey(standing)];
  return /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "flex size-10 shrink-0 items-center justify-center rounded-full " + tone, "aria-hidden": "true", children: /* @__PURE__ */ jsxRuntimeExports.jsx(Icon, { className: "size-5" }) });
}
function standingBody(standing) {
  if (standing.kind === "none") {
    return standing.installed ? "A version is installed but none is selected. Pick one under Versions below, or turn on CIGAR and Guard picks for you." : "Nothing is installed yet. Turn on CIGAR and Guard installs the version it approved for this computer. You don't need to pick one here.";
  }
  if (standing.kind === "behind") {
    return standing.block ? `CIGAR ${standing.newest} is listed, but it can't be prepared yet: ${standing.block} Your current version keeps working.` : `CIGAR ${standing.newest} is ready to prepare. Your current version keeps working until you choose to switch.`;
  }
  return standing.running ? "This is the newest version Guard has approved for this computer. Nothing to do." : "This version is installed but CIGAR is off. Turn it on from the top of the page whenever you like.";
}
function standingTitle(standing, loading) {
  if (standing.kind !== "none") return standing.version;
  if (loading) return "Checking this computer…";
  return standing.installed ? "Installed, not selected" : "Not installed yet";
}
function CigarVersionStatusBand({ status, data, loading, actions }) {
  const standing = cigarStanding(status, data);
  const surface = standing.kind === "behind" ? "border-brand-blue/20 bg-brand-blue/[0.04]" : "border-brand-dark/10 bg-white";
  const body = standingBody(standing);
  const python = status?.runtime?.interpreter.version ?? status?.last_check?.interpreter.version;
  const catalog = data?.catalog.catalog;
  return /* @__PURE__ */ jsxRuntimeExports.jsx("section", { "aria-labelledby": "cigar-version-standing", className: "guard-surface-in rounded-2xl border p-4 sm:p-5 " + surface, children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-start gap-x-6 gap-y-4", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex min-w-0 flex-[1_1_20rem] items-start gap-3.5", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(Marker, { standing }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0 space-y-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("h3", { id: "cigar-version-standing", className: "flex flex-wrap items-center gap-x-3 gap-y-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: standing.kind === "none" ? "text-xl font-semibold leading-tight tracking-[-0.01em] text-brand-dark" : "font-mono text-[1.75rem] font-semibold leading-none tracking-[-0.02em] tabular-nums text-brand-dark", children: standingTitle(standing, loading) }),
          standing.kind !== "none" ? /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: standing.running ? "green" : "slate", children: standing.running ? "Running" : "Off" }) : null,
          standing.kind === "behind" ? /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: "blue", children: "Update available" }) : null
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "max-w-[62ch] text-sm leading-6 text-brand-dark/75", children: body }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("ul", { className: "flex flex-wrap gap-x-4 gap-y-1 text-xs text-brand-dark/60", "aria-label": "This computer", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("li", { children: platformLabel(data?.catalog.host_platform ?? status?.runtime?.interpreter.platform) }),
          python ? /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { children: [
            "Python ",
            python.join(".")
          ] }) : null,
          catalog ? /* @__PURE__ */ jsxRuntimeExports.jsx("li", { children: catalog.fresh_for_preparation ? "Version list is current" : "Version list needs a refresh" }) : null
        ] })
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "flex shrink-0 flex-wrap items-center gap-2", children: actions })
  ] }) });
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
    const code = object$4(body) && typeof body.code === "string" && /^[a-z0-9_]{1,160}$/.test(body.code) ? body.code : object$4(body) && typeof body.error === "string" && /^approval_gate_[a-z0-9_]{1,140}$/.test(body.error) ? body.error : "context_assistance_unavailable";
    throw new ContextAssistanceApiError(code, errorMessage(code, response.status));
  }
  return parseCigarVersionsReply(body);
}
const object$3 = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const id$2 = (v) => typeof v === "string" && /^[a-z0-9_:-]{1,128}$/i.test(v);
const digest = (v) => typeof v === "string" && /^[a-f0-9]{64}$/.test(v);
const count = (v) => typeof v === "number" && Number.isSafeInteger(v) && v >= 0;
const platform = (v) => typeof v === "string" && ["darwin-arm64", "darwin-x64", "linux-x64-gnu", "linux-arm64-gnu", "linux-x64-musl", "linux-arm64-musl", "win32-x64"].includes(v);
const qualification = (v) => typeof v === "string" && ["local_candidate", "upstream_only", "guard_qualified"].includes(v);
const diagnostic = (v) => v === null || typeof v === "string" && /^[a-z0-9_]{1,160}$/.test(v);
function invalid$2() {
  throw new ContextAssistanceApiError("versions_catalog_invalid", "Guard returned incompatible CIGAR catalog data. Refresh the catalog.");
}
function pythonVersion(v) {
  return Array.isArray(v) && v.length === 3 && v.every((n) => count(n) && n <= 65535);
}
function wheelBytes(v) {
  if (!object$3(v) || !count(v.bytes) || v.bytes === 0 || !digest(v.sha256)) invalid$2();
  return v.bytes;
}
function parsePlatform(v) {
  if (!object$3(v) || !platform(v.platform) || !qualification(v.qualification) || !digest(v.worker_sha256) || !(v.package_tree_sha256 === null || digest(v.package_tree_sha256)) || !(v.qualification_receipt_sha256 === null || digest(v.qualification_receipt_sha256)) || v.qualification === "guard_qualified" && v.qualification_receipt_sha256 === null || !Array.isArray(v.features) || v.features.length > 16 || !v.features.every((f) => typeof f === "string" && /^[a-z0-9_]{1,128}$/.test(f)) || new Set(v.features).size !== v.features.length || !Array.isArray(v.dependencies) || v.dependencies.length > 32) invalid$2();
  const hasWheel = v.wheel !== null;
  const locked = v.package_tree_sha256 !== null && v.dependencies.some((w) => object$3(w) && w.distribution === "protobuf");
  const bytes = (hasWheel ? wheelBytes(v.wheel) : 0) + v.dependencies.reduce((n, w) => n + wheelBytes(w), 0);
  if (!count(bytes)) invalid$2();
  return {
    platform: v.platform,
    qualification: v.qualification,
    features: v.features,
    worker_sha256: v.worker_sha256,
    package_tree_sha256: v.package_tree_sha256,
    qualification_receipt_sha256: v.qualification_receipt_sha256,
    has_wheel: hasWheel,
    download_bytes: bytes,
    has_dependency_lock: locked
  };
}
function parseBuild(v) {
  if (!object$3(v) || !isCigarBuildIdentity(v.identity) || !id$2(v.profile_id) || !["stable", "preview", "local_candidate"].includes(String(v.channel)) || typeof v.withdrawn !== "boolean" || !Array.isArray(v.platforms) || v.platforms.length === 0 || v.platforms.length > 7) invalid$2();
  const platforms = v.platforms.map(parsePlatform);
  if (new Set(platforms.map((p) => p.platform)).size !== platforms.length) invalid$2();
  return { identity: {
    build_id: v.identity.build_id,
    sdk_version: v.identity.sdk_version,
    core_version: v.identity.core_version,
    source_revision: v.identity.source_revision,
    manifest_sha256: v.identity.manifest_sha256
  }, profile_id: v.profile_id, channel: v.channel, withdrawn: v.withdrawn, platforms };
}
function parseInterpreter(v) {
  if (!object$3(v) || !id$2(v.build_id) || !pythonVersion(v.python_version) || !platform(v.platform) || !qualification(v.qualification) || typeof v.withdrawn !== "boolean" || !count(v.archive_bytes) || v.archive_bytes === 0) invalid$2();
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
  if (!object$3(v) || !["bundled", "cached"].includes(String(v.source)) || typeof v.fresh_for_preparation !== "boolean" || !diagnostic(v.diagnostic) || !diagnostic(v.trust_diagnostic) || !diagnostic(v.feed_diagnostic) || typeof v.trust_configured !== "boolean" || typeof v.remote_feed_configured !== "boolean" || v.activation_granted !== false || v.fresh_for_preparation && v.diagnostic !== null) invalid$2();
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
  if (!object$3(v) || v.schema !== "guard-cigar-releases.v1" || !(v.host_platform === void 0 || v.host_platform === null || platform(v.host_platform)) || !Array.isArray(v.builds) || v.builds.length > 128 || !Array.isArray(v.interpreter_builds) || v.interpreter_builds.length > 128) invalid$2();
  const builds = v.builds.map(parseBuild), interpreters = v.interpreter_builds.map(parseInterpreter);
  if (new Set(builds.map((b) => b.identity.build_id)).size !== builds.length || new Set(interpreters.map((b) => b.build_id)).size !== interpreters.length) invalid$2();
  return { host_platform: v.host_platform ?? null, builds, interpreter_builds: interpreters, catalog: parseCigarCatalogMetadata(v.catalog) };
}
const object$2 = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const id$1 = (v) => typeof v === "string" && /^[a-z0-9_:-]{1,128}$/i.test(v);
function invalid$1() {
  throw new ContextAssistanceApiError("versions_interpreters_invalid", "Guard returned incompatible Python registration data. Refresh updates.");
}
function parseCigarInterpreters(value) {
  if (!object$2(value) || !Array.isArray(value.interpreters) || value.interpreters.length > 16) invalid$1();
  const values = value.interpreters.map((v) => {
    if (!object$2(v) || !id$1(v.interpreter_id) || !Array.isArray(v.python_version) || v.python_version.length !== 3 || !v.python_version.every((n) => Number.isSafeInteger(n) && n >= 0 && n <= 65535) || !id$1(v.platform) || !id$1(v.implementation) || !id$1(v.abi) || typeof v.managed !== "boolean" || !(v.build_id === null || id$1(v.build_id)) || v.managed !== (v.build_id !== null)) invalid$1();
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
  if (new Set(values.map((v) => v.interpreter_id)).size !== values.length) invalid$1();
  return values;
}
const object$1 = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const id = (v) => typeof v === "string" && /^[a-z0-9_:-]{1,128}$/i.test(v);
const mode = (v) => typeof v === "string" && ["manual", "notify", "prepare"].includes(v);
function invalid() {
  throw new ContextAssistanceApiError("versions_preferences_invalid", "Guard returned incompatible CIGAR update preferences. Refresh preferences.");
}
function preferences(v) {
  if (!object$1(v) || !mode(v.mode) || typeof v.allow_preview !== "boolean" || typeof v.retain_last_good !== "boolean" || !(v.pinned_build === void 0 || v.pinned_build === null || id(v.pinned_build))) invalid();
  return {
    mode: v.mode,
    allow_preview: v.allow_preview,
    retain_last_good: v.retain_last_good,
    ...typeof v.pinned_build === "string" ? { pinned_build: v.pinned_build } : {}
  };
}
function parseCigarUpdateSettings(v) {
  if (!object$1(v) || v.schema !== "guard-cigar-update-preferences.v1" || typeof v.revision !== "string" || !/^sha256:[a-f0-9]{64}$/.test(v.revision) || !(v.diagnostic === null || typeof v.diagnostic === "string" && /^[a-z0-9_]{1,160}$/.test(v.diagnostic)) || !Array.isArray(v.locked_settings) || v.locked_settings.length > 64 || !v.locked_settings.every((k) => typeof k === "string" && k.length <= 256 && /^context_assistance_updates(?:\.[a-z_]+)?$/.test(k)) || !object$1(v.capabilities) || !Array.isArray(v.capabilities.modes) || v.capabilities.modes.length > 3 || !v.capabilities.modes.every(mode) || new Set(v.capabilities.modes).size !== v.capabilities.modes.length || typeof v.capabilities.automatic_preparation !== "boolean" || typeof v.capabilities.automatic_selection !== "boolean" || typeof v.capabilities.retention_reduction !== "boolean") invalid();
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
const message$1 = (cause) => cause instanceof Error ? cause.message : "Refresh CIGAR status and jobs before trying again.";
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
        setError(message$1(cause));
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
        setError(message$1(cause));
        setUncertain(true);
      }
    } finally {
      pending.current = false;
      if (current === revision.current && mounted.current) setBusy(false);
    }
  }
  return { data, loading, busy, error, uncertain, tracking, refresh, perform };
}
const notice = "rounded-xl border border-brand-dark/10 bg-surface-1 px-4 py-3 text-sm leading-6 text-brand-dark/75";
function CigarVersionsPanel(props) {
  const versions = useCigarVersions(props.captureStatus);
  const [approval, setApproval] = reactExports.useState(null);
  const [signedCatalog, setSignedCatalog] = reactExports.useState("");
  const { data } = versions;
  const disabled = props.disabled || versions.busy || versions.loading;
  const changesDisabled = disabled || versions.uncertain;
  const selectionDisabled = changesDisabled || props.locked || props.dirty || !props.status || Boolean(props.status.job);
  const catalog = data?.catalog.catalog;
  const activeJobs = data?.jobs.filter(cigarJobActive) ?? [];
  function choose(action) {
    if (disabled || action.input.action !== "cancel" && versions.uncertain) return;
    if (action.input.action !== "cancel" && props.gate?.enabled) setApproval(action);
    else void versions.perform(action.input);
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-6", "data-testid": "cigar-versions", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "cigar-section-intro", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { children: "Updates" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "Guard handles this for you when you turn CIGAR on. Come here only to pick a specific version, check for new ones, or go back to an earlier one. Opening this page changes nothing." })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(CigarVersionStatusBand, { status: props.status, data, loading: versions.loading, actions: /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs(
        "button",
        {
          type: "button",
          className: versionButton,
          disabled: changesDisabled || !catalog?.remote_feed_configured || !catalog.trust_configured || Boolean(catalog.feed_diagnostic),
          onClick: () => choose({
            input: { action: "refresh_catalog", job_id: cigarVersionJobId() },
            title: "Check for CIGAR catalog updates",
            detail: "Fetch the configured signed release catalog. This does not prepare or switch an SDK."
          }),
          children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCloudArrowDown, { "aria-hidden": "true", className: "size-4" }),
            "Check for catalog updates"
          ]
        }
      ),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { type: "button", className: versionQuiet, disabled: props.disabled || versions.busy || versions.loading, onClick: () => void versions.refresh(), children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowPath, { "aria-hidden": "true", className: "size-4" + (versions.loading ? " motion-safe:animate-spin" : "") }),
        "Refresh versions & jobs"
      ] })
    ] }) }),
    versions.loading && !data ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { role: "status", className: "space-y-3", "aria-label": "Reading CIGAR versions and job metadata…", children: [
      [0, 1, 2].map((row2) => /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "h-16 rounded-2xl bg-brand-dark/[0.04] motion-safe:animate-pulse" }, row2)),
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "sr-only", children: "Reading CIGAR versions and job metadata…" })
    ] }) : null,
    versions.busy ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "status", className: notice, children: "Submitting the selected action. Preparation continues as a native job." }) : null,
    versions.error ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { role: "alert", className: "cigar-note", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { children: "CIGAR updates need attention" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: versions.error }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "Refresh versions and jobs before submitting another change." })
    ] }) : null,
    versions.tracking ? /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "break-all text-xs text-brand-dark/60", children: [
      "Last submitted job: ",
      versions.tracking,
      ". Refresh jobs to confirm its outcome."
    ] }) : null,
    props.dirty ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "status", className: notice, children: "You can prepare builds now. Save your CIGAR preference edits before preparing or committing a selection." }) : null,
    data ? /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
      activeJobs.length ? /* @__PURE__ */ jsxRuntimeExports.jsx(CigarVersionJobsPanel, { jobs: activeJobs, status: props.status, disabled, selectionDisabled, onAction: choose }) : null,
      /* @__PURE__ */ jsxRuntimeExports.jsx(CigarVersionBuildsPanel, { data, status: props.status, disabled: changesDisabled, selectionDisabled, onAction: choose }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("details", { className: "group rounded-2xl border border-brand-dark/10 bg-white", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("summary", { className: "flex min-h-14 cursor-pointer list-none items-center gap-3 rounded-2xl px-4 py-3 hover:bg-surface-1 sm:px-5 [&::-webkit-details-marker]:hidden", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniChevronRight, { "aria-hidden": "true", className: "size-4 shrink-0 text-brand-dark/50 transition-transform group-open:rotate-90 motion-reduce:transition-none" }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "min-w-0", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "block text-sm font-semibold text-brand-dark", children: "Advanced" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "block text-xs text-brand-dark/60", children: "Update preferences, pinning and the release catalog" })
          ] })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-8 border-t border-brand-dark/[0.07] px-4 py-5 sm:px-5", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(CigarUpdatePreferencesPanel, { value: data.updates, builds: data.catalog.builds, disabled: changesDisabled, onAction: choose }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "space-y-3 border-t border-brand-dark/[0.07] pt-6", "aria-label": "CIGAR release catalog", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("h4", { className: "font-semibold text-brand-dark", children: "Release catalog" }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("dl", { className: "grid gap-3 text-sm sm:grid-cols-3", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-xs text-brand-dark/55", children: "Source" }),
                /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "font-medium capitalize text-brand-dark", children: data.catalog.catalog.source })
              ] }),
              /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-xs text-brand-dark/55", children: "Freshness" }),
                /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "font-medium text-brand-dark", children: data.catalog.catalog.fresh_for_preparation ? "current for preparation" : "refresh required" })
              ] }),
              /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-xs text-brand-dark/55", children: "Guard host" }),
                /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "font-mono text-xs leading-5 text-brand-dark", children: data.catalog.host_platform ?? "not reported by this Guard build" })
              ] })
            ] }),
            !data.catalog.catalog.remote_feed_configured ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-brand-dark/70", children: "A remote release feed is not configured. Guard can still use eligible bundled entries." }) : null,
            data.catalog.catalog.diagnostic ? /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "break-all text-sm text-amber-800", children: [
              "Catalog diagnostic: ",
              data.catalog.catalog.diagnostic
            ] }) : null,
            data.catalog.catalog.trust_diagnostic || data.catalog.catalog.feed_diagnostic ? /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "break-all text-sm text-amber-800", children: [
              "Catalog update configuration: ",
              data.catalog.catalog.trust_diagnostic ?? data.catalog.catalog.feed_diagnostic
            ] }) : null,
            /* @__PURE__ */ jsxRuntimeExports.jsxs("details", { className: "group/import text-sm text-brand-dark/75", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsxs("summary", { className: "inline-flex min-h-11 cursor-pointer list-none items-center gap-1.5 font-semibold text-brand-dark/80 hover:text-brand-dark [&::-webkit-details-marker]:hidden", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniChevronRight, { "aria-hidden": "true", className: "size-4 transition-transform group-open/import:rotate-90 motion-reduce:transition-none" }),
                "Import a signed catalog"
              ] }),
              /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-3 pl-5", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "Use a catalog signed by an already trusted release key. Importing metadata never selects or starts a runtime." }),
                /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block text-xs font-medium text-brand-dark/65", children: [
                  "Signed catalog JSON",
                  /* @__PURE__ */ jsxRuntimeExports.jsx(
                    "textarea",
                    {
                      className: versionField + " font-mono text-xs",
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
            ] })
          ] })
        ] })
      ] })
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
const PATH = "/v1/context-assistance/codex-lean";
const object = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
function parsed(body) {
  const state = object(body) ? body.state : null;
  const limit = object(body) ? body.limit : null;
  if (state !== "on" && state !== "off" && state !== "yours" || limit !== null && typeof limit !== "number") {
    throw new ContextAssistanceApiError("codex_lean_payload_invalid", "Guard returned a Codex setting this page does not understand.");
  }
  return { state, limit };
}
function failure(status, body) {
  let code = "codex_lean_unavailable";
  if (object(body) && typeof body.code === "string") code = body.code;
  else if (object(body) && typeof body.error === "string") code = body.error;
  if (status === 403) return new ContextAssistanceApiError(code, "Guard needs your approval before this change.");
  if (code === "codex_config_unreadable") return new ContextAssistanceApiError(code, "Guard could not read your Codex config, so it left it as it is. Fix the file, then try again.");
  if (code === "codex_hooks_need_recovery") return new ContextAssistanceApiError(code, "Guard's Codex setup needs a repair first. Open Apps, repair Codex, then try again.");
  if (code === "codex_config_busy") return new ContextAssistanceApiError(code, "Another change to your Codex config is in progress. Try again in a moment.");
  return new ContextAssistanceApiError(code, "Guard could not change your Codex config. Nothing was changed.");
}
async function call(init, signal) {
  const timeout = AbortSignal.timeout(12e3);
  const response = await fetchWithGuardAuth(PATH, { ...init, cache: "no-store", signal: signal ? AbortSignal.any([signal, timeout]) : timeout });
  const body = await response.json().catch(() => null);
  if (!response.ok) throw failure(response.status, body);
  return parsed(body);
}
function readCodexLean(signal) {
  return call({ method: "GET" }, signal);
}
function saveCodexLean(enabled, proof, signal) {
  return call({ method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({
    enabled,
    ...proof?.currentPassword ? { approval_password: proof.currentPassword } : {},
    ...proof?.totpCode ? { approval_totp_code: proof.totpCode } : {}
  }) }, signal);
}
const LIMIT = 3e4;
function message(cause) {
  return cause instanceof ContextAssistanceApiError ? cause.message : "Guard could not reach your Codex config. Refresh and try again.";
}
function describe(state, loading) {
  if (loading && !state) return "Checking your Codex config…";
  if (state?.state === "yours") {
    const limit = typeof state.limit === "number" ? state.limit.toLocaleString() : "its own value";
    return `Your Codex config already sets its own limit (${limit} tokens). Guard leaves it as it is.`;
  }
  return `Codex sums up older turns once a session passes ${LIMIT.toLocaleString()} tokens, instead of carrying the whole conversation. Works with or without CIGAR and saves right away.`;
}
function CodexLeanSessions({ gate, disabled }) {
  const [state, setState] = reactExports.useState(null);
  const [loading, setLoading] = reactExports.useState(true);
  const [saving, setSaving] = reactExports.useState(false);
  const [error, setError] = reactExports.useState(null);
  const [proof, setProof] = reactExports.useState(null);
  const [attempt, setAttempt] = reactExports.useState(0);
  const demo = isGuardDemoMode();
  reactExports.useEffect(() => {
    if (demo) return;
    const controller = new AbortController();
    setLoading(true);
    setError(null);
    readCodexLean(controller.signal).then(setState, (cause) => {
      if (!controller.signal.aborted) setError(message(cause));
    }).finally(() => {
      if (!controller.signal.aborted) setLoading(false);
    });
    return () => controller.abort();
  }, [demo, attempt]);
  async function save(enabled, credentials) {
    setSaving(true);
    setError(null);
    try {
      setState(await saveCodexLean(enabled, credentials));
      setProof(null);
    } catch (cause) {
      if (cause instanceof ContextAssistanceApiError && cause.code.startsWith("approval")) {
        setProof({ enabled, error: credentials ? "That approval did not work. Try again." : null });
      } else {
        setProof(null);
        setError(message(cause));
      }
    } finally {
      setSaving(false);
    }
  }
  function change(enabled) {
    if (gate?.enabled) setProof({ enabled, error: null });
    else void save(enabled);
  }
  if (demo) return null;
  const yours = state?.state === "yours";
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs(SettingsFormSection, { title: "Long Codex sessions", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        SettingsToggleRow,
        {
          label: "Keep long Codex sessions lean",
          checked: state?.state === "on",
          description: describe(state, loading),
          disabled: disabled || saving || loading || yours || state === null,
          onChange: change
        }
      ),
      error ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-3 py-3", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "alert", className: "guard-settings-caption text-amber-800", children: error }),
        state === null ? /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { variant: "outline", onClick: () => setAttempt((n) => n + 1), children: "Try again" }) : null
      ] }) : null
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      SettingsSaveProofModal,
      {
        open: proof !== null,
        mode: "verify-save",
        gate,
        title: proof?.enabled === false ? "Approve turning off lean Codex sessions" : "Approve lean Codex sessions",
        detail: proof?.enabled === false ? "Guard removes the limit it added to your Codex config. A limit you set yourself stays." : `Guard adds model_auto_compact_token_limit = ${LIMIT} to your Codex config. Turn the switch off to remove it again.`,
        confirmLabel: proof?.enabled === false ? "Turn off" : "Turn on",
        error: proof?.error ?? null,
        pending: saving,
        onCancel: () => setProof(null),
        onConfirm: (credentials) => {
          if (proof) void save(proof.enabled, { currentPassword: credentials.currentPassword, totpCode: credentials.totpCode });
        }
      }
    )
  ] });
}
async function cancelJob(job) {
  const deadline = AbortSignal.timeout(15e3);
  for (let attempt = 0; attempt < 6 && !deadline.aborted; attempt++) {
    try {
      await requestCigarVersions({ action: "cancel", job_id: job }, void 0, deadline);
      return;
    } catch {
      await new Promise((resolve) => setTimeout(resolve, 1e3));
    }
  }
}
const wait = (ms, signal) => new Promise((resolve) => {
  const timer = setTimeout(resolve, ms);
  signal.addEventListener("abort", () => {
    clearTimeout(timer);
    resolve();
  }, { once: true });
});
function useCigarOneClick(options) {
  const [data, setData] = reactExports.useState(null);
  const [loadError, setLoadError] = reactExports.useState(null);
  const [run, setRun] = reactExports.useState({ phase: "idle" });
  const controller = reactExports.useRef(null);
  const activeJob = reactExports.useRef(null);
  const starting = reactExports.useRef(false);
  const running = reactExports.useRef(false), mounted = reactExports.useRef(false), revision = reactExports.useRef(0);
  const latest = reactExports.useRef(options);
  latest.current = options;
  const refresh = reactExports.useCallback(async () => {
    if (running.current || !latest.current.active) return;
    const current = ++revision.current;
    try {
      const value = await loadCigarVersionsData(AbortSignal.timeout(15e3));
      if (!mounted.current || current !== revision.current) return;
      setData(value);
      setLoadError(null);
    } catch (cause) {
      if (!mounted.current || current !== revision.current) return;
      setLoadError(cause instanceof Error ? cause.message : "Guard did not report CIGAR setup details.");
    }
  }, []);
  reactExports.useEffect(() => {
    mounted.current = true;
    void refresh();
    return () => {
      mounted.current = false;
      ++revision.current;
      controller.current?.abort();
    };
  }, [refresh]);
  const plan = reactExports.useMemo(
    () => data ? planCigarSetup({ ...data, state: options.status ?? data.state }, { locked: options.locked, dirty: options.dirty }) : planCigarStart(options.status, options.dirty),
    [data, options.status, options.locked, options.dirty]
  );
  const waiting = run.phase === "idle" && plan?.kind === "blocked" && plan.block.wait === true;
  reactExports.useEffect(() => {
    if (!waiting) return;
    const timer = setInterval(() => void refresh(), 3e3);
    return () => clearInterval(timer);
  }, [waiting, refresh]);
  async function execute(proof) {
    if (running.current || latest.current.disabled || !latest.current.active) return;
    running.current = true;
    ++revision.current;
    const abort = new AbortController();
    controller.current = abort;
    let stages = [];
    let stage = null;
    let planned = null;
    let progressed = false;
    try {
      const fresh = await loadCigarVersionsData(abort.signal).catch((cause) => {
        if (planCigarStart(latest.current.status, latest.current.dirty)) return null;
        throw cause;
      });
      if (abort.signal.aborted) throw new CigarSetupStopped();
      if (fresh) {
        setData(fresh);
        latest.current.publish(fresh.state);
      }
      const initial2 = fresh?.state ?? latest.current.status;
      const next = fresh ? planCigarSetup(fresh, { locked: latest.current.locked, dirty: latest.current.dirty }) : planCigarStart(latest.current.status, latest.current.dirty);
      if (!next || next.kind !== "run" || !initial2) {
        setRun({ phase: "idle" });
        return;
      }
      if (latest.current.gate?.enabled && next.approval && !proof) {
        setRun({ phase: "proof", plan: next, error: null });
        return;
      }
      planned = next;
      stages = next.stages;
      setRun({ phase: "running", stages, stage: stages[0] });
      let credentials = proof;
      const spend = () => {
        if (credentials?.totpCode) credentials = credentials.currentPassword ? { currentPassword: credentials.currentPassword } : void 0;
      };
      await runCigarSetup(next, initial2, {
        versions: async (input) => {
          try {
            const reply = await requestCigarVersions(input, credentials, abort.signal);
            if (input.action !== "job") progressed = true;
            return reply;
          } finally {
            if (input.action !== "job") spend();
          }
        },
        saveSettings: async (config) => {
          try {
            const saved = await saveCigarPreference(config, credentials, abort.signal);
            progressed = true;
            return saved;
          } finally {
            spend();
          }
        },
        activate: () => controlContextAssistance("activate", abort.signal),
        status: () => fetchContextAssistance(abort.signal),
        sleep: (ms) => wait(ms, abort.signal),
        now: () => Date.now(),
        stopped: () => abort.signal.aborted,
        onJob: (id2) => {
          activeJob.current = id2;
        },
        onStage: (value) => {
          stage = value;
          if (value === "start") starting.current = true;
          if (mounted.current) setRun({ phase: "running", stages, stage: value });
        },
        onState: (state) => {
          if (mounted.current && !abort.signal.aborted) latest.current.publish(state);
        },
        onSaved: (config, previous) => {
          if (mounted.current) latest.current.onSaved(config, previous);
        }
      });
      if (mounted.current) setRun({ phase: "idle" });
    } catch (cause) {
      if (!mounted.current) return;
      if (cause instanceof CigarSetupStopped || abort.signal.aborted) setRun({ phase: "idle" });
      else if (cause instanceof CigarSetupError && cause.needsProof) {
        const error = progressed ? "Your approval expired while Guard was working. The finished steps are kept. Approve once more to finish." : proof ? "That approval did not work. Try again." : null;
        setRun(planned ? { phase: "proof", plan: planned, error } : { phase: "failed", stages, stage, message: cause.message });
      } else {
        setRun({
          phase: "failed",
          stages,
          stage: cause instanceof CigarSetupError ? cause.stage : stage,
          message: cause instanceof Error ? cause.message : "CIGAR did not finish turning on. Nothing else changed."
        });
      }
    } finally {
      running.current = false;
      activeJob.current = null;
      starting.current = false;
      if (controller.current === abort) controller.current = null;
      if (mounted.current) void refresh();
    }
  }
  return {
    plan,
    loadError,
    run,
    busy: run.phase === "running",
    start: () => void execute(),
    confirm: (proof) => void execute(proof),
    cancelProof: () => setRun({ phase: "idle" }),
    dismiss: () => setRun({ phase: "idle" }),
    /** Stop always wins: abort in-flight polling so no later step runs. */
    stop: () => {
      const job = activeJob.current, turnOff = starting.current;
      activeJob.current = null;
      starting.current = false;
      controller.current?.abort();
      if (turnOff) latest.current.onTurnOff();
      if (job) void cancelJob(job).finally(() => {
        if (mounted.current) void refresh();
      });
    },
    refresh
  };
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
  const value = props.value ?? status?.preferences ?? null;
  const saved = props.savedValue ?? status?.preferences ?? null;
  const dirty = value && saved ? !sameCigarPreferences(value, saved) : value !== saved;
  const setup = useCigarOneClick({
    active: workspace,
    status,
    dirty,
    locked: props.locked,
    disabled: props.disabled || busy,
    gate: props.gate ?? null,
    publish: (state) => captureVersionStatus()(state),
    onSaved: (config, previous) => props.onSelectionChanged?.(config, previous),
    onTurnOff: () => void perform("stop")
  });
  const allowFiles = useCigarAllowFiles({
    saved,
    dirty,
    disabled: props.disabled || props.locked || busy || setup.busy,
    gate: props.gate ?? null,
    onSaved: (config, previous) => props.onSelectionChanged?.(config, previous),
    onRestart: () => void perform("activate")
  });
  reactExports.useEffect(() => {
    if (!setup.busy) return;
    onBusyChange(true);
    return () => onBusyChange(false);
  }, [setup.busy, onBusyChange]);
  const woke = reactExports.useRef(false);
  const resting = status?.diagnostic === "runtime_resting" && !status.job;
  reactExports.useEffect(() => {
    if (status?.effective_enabled) woke.current = false;
    if (!resting || dirty || busy || setup.busy || props.disabled || woke.current) return;
    woke.current = true;
    void perform("activate");
  }, [resting, status?.effective_enabled, dirty, busy, setup.busy, props.disabled]);
  async function perform(action) {
    if (action === "stop") setup.stop();
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
      setError(cause instanceof Error ? cause.message : "CIGAR could not finish that. Refresh and try again.");
    } finally {
      pending.current = false;
      if (mounted.current && current === revision.current) {
        setBusy(false);
        setLoading(false);
        props.onBusyChange(false);
      }
    }
  }
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
      waking: cigarWaking(status),
      generation: status?.generation ?? null,
      dirty,
      documentsAllowed: status?.effective_preferences.sources.workspace_documents === true,
      agentsAllowed: status?.effective_preferences.features.agent_context === true,
      executionAllowed: status?.effective_preferences.features.execution_context === true && status?.capabilities?.execution_context === true,
      sharingAllowed: status?.effective_preferences.features.shared_agents === true && status?.runtime?.shared_compile_verified === true,
      gate: props.gate ?? null,
      allowFiles
    }
  );
  return workspace ? /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      CigarWorkspace,
      {
        status,
        installations,
        loading,
        busy,
        disabled: props.disabled,
        dirty,
        error,
        setup,
        allowFiles,
        stopAvailable: Boolean(value?.enabled || saved?.enabled || status?.job || status?.effective_enabled || error),
        controls: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-8", children: [
          controls,
          /* @__PURE__ */ jsxRuntimeExports.jsx(CodexLeanSessions, { gate: props.gate ?? null, disabled: props.disabled })
        ] }),
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
        onRefresh: () => {
          void refresh();
          void setup.refresh();
        },
        onStop: () => void perform("stop")
      }
    ),
    /* @__PURE__ */ jsxRuntimeExports.jsx(CigarSetupProof, { setup, gate: props.gate ?? null }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(CigarAllowFilesProof, { allow: allowFiles, gate: props.gate ?? null })
  ] }) : /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
    controls,
    access,
    /* @__PURE__ */ jsxRuntimeExports.jsx(CigarAllowFilesProof, { allow: allowFiles, gate: props.gate ?? null })
  ] });
}
const caption = "text-xs leading-5 text-brand-dark/60";
const danger = "inline-flex min-h-11 items-center justify-center rounded-lg border border-red-200 bg-white px-3.5 py-2 text-sm font-semibold text-red-700 transition-colors hover:border-red-300 hover:bg-red-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-red-400/40 disabled:cursor-not-allowed disabled:opacity-50 motion-reduce:transition-none";
function Stat({ term, value }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-xl border border-brand-dark/[0.08] bg-white px-3.5 py-3", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-xs text-brand-dark/60", children: term }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "mt-1 text-lg font-semibold tabular-nums text-brand-dark", children: value })
  ] });
}
function Row({ title, body, action }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { className: "flex flex-wrap items-center justify-between gap-x-6 gap-y-3 px-4 py-4 sm:px-5", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0 flex-[1_1_16rem]", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-brand-dark", children: title }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-0.5 text-xs leading-5 text-brand-dark/65", children: body })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "shrink-0", children: action })
  ] });
}
const CONFIRM = {
  history: {
    title: "Clear past answers?",
    label: "Clear past answers",
    description: "Deletes the answers CIGAR kept. Your projects keep their access. Guard's approvals and records are not touched."
  },
  saved: {
    title: "Remove saved notes?",
    label: "Remove saved notes",
    description: "Deletes everything CIGAR saved on this computer, including old projects, and ends current access. Turn CIGAR on and add your projects again to keep going. Guard's approvals and records are not touched."
  },
  data: {
    title: "Delete everything CIGAR knows?",
    label: "Delete everything",
    description: "Deletes past answers, saved notes, project access, app connections and the recent projects this page remembers. You can set it up again anytime. Guard's approvals and records are not touched."
  },
  recheck: {
    title: "Start CIGAR fresh?",
    label: "Start fresh",
    description: "Ends current access and checks CIGAR again. If it is turned on, it starts fresh. Add your projects again afterward."
  }
};
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
    const summary2 = await fetchContextData(signal);
    if (!signal.aborted) setData(summary2);
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
        setMessage(cause instanceof Error ? cause.message : "CIGAR did not answer. Try Refresh.");
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
      if (!controller.signal.aborted) setMessage("CIGAR did not answer. Try Refresh, or turn it off.");
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
          setMessage("Past answers cleared. Your projects keep their access.");
        }
      } else if (action === "saved") {
        await forgetSavedEvidence(signal);
        await refresh(signal);
        if (!signal.aborted) setMessage("Saved notes removed. Turn CIGAR on and add your projects again to keep going.");
      } else if (action === "data") {
        await manageContextWorkspace("clear", void 0, void 0, signal);
        clearRecentProjects();
        await refresh(signal);
        if (!signal.aborted) setMessage("Everything CIGAR knew is deleted. Add a project to start again.");
      } else {
        const value = await controlContextAssistance("recheck", signal);
        if (!signal.aborted) {
          setStatus(value);
          setData(null);
          setMessage("Checking CIGAR again. Refresh in a moment to see how it went.");
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
        setMessage("CIGAR is off. Guard keeps protecting you as usual.");
      }
    }, true);
  }
  const ready = Boolean(status?.effective_enabled);
  const copy = status ? contextStatusCopy(status) : { label: "Status unavailable", detail: "Refresh context status to inspect this optional feature." };
  const offAvailable = Boolean(savedEnabled || status?.requested_enabled || status?.effective_enabled || status?.job);
  const removable = Boolean(data?.saved_evidence && data.saved_evidence.status !== "empty" && data.saved_evidence.status !== "unsupported");
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-8", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { role: "region", "aria-label": "Context data and repair controls", className: "space-y-8", "aria-busy": busy, children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("section", { className: "guard-surface-in rounded-2xl border border-brand-dark/10 bg-white p-4 sm:p-5", "aria-label": "Context data status", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-start gap-x-6 gap-y-4", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex min-w-0 flex-[1_1_20rem] items-start gap-3.5", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { "aria-hidden": "true", className: "flex size-10 shrink-0 items-center justify-center rounded-full " + (ready ? "bg-brand-green-bg text-brand-green-text" : "bg-brand-dark/[0.06] text-brand-dark/55"), children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniLockClosed, { className: "size-5" }) }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0 space-y-1.5", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "text-xs font-semibold uppercase tracking-[0.08em] text-brand-dark/55", children: "Privacy and repair" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "status", className: "text-lg font-semibold tracking-[-0.01em] text-brand-dark", children: copy.label }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "max-w-[62ch] text-sm leading-6 text-brand-dark/75", children: copy.detail }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: caption + " max-w-[70ch]", children: [
              "What CIGAR prepares stays in this computer's memory. ",
              status?.capabilities?.private_persistence ? "If you turn on saved notes, they are kept in private files here, not encrypted by Guard, until they expire or you remove them. After Guard restarts, add your projects again." : "This version cannot save notes. Anything saved earlier can still be checked and removed below."
            ] })
          ] })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex shrink-0 flex-wrap items-center gap-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { className: versionQuiet, type: "button", disabled: busy || disabled, onClick: () => void perform(refresh), children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowPath, { "aria-hidden": "true", className: "size-4" }),
            "Refresh"
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("button", { className: versionQuiet, type: "button", disabled: busy || !status, onClick: () => {
            if (status) downloadBlob(new Blob([JSON.stringify(contextDiagnostics(status, data), null, 2)], { type: "application/json" }), "guard-context-diagnostics.json");
          }, children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowDownTray, { "aria-hidden": "true", className: "size-4" }),
            "Download diagnostics"
          ] })
        ] })
      ] }) }),
      message2 ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "status", className: "rounded-xl border border-brand-dark/10 bg-surface-1 px-4 py-3 text-sm leading-6 text-brand-dark/75", children: message2 }) : null,
      /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "space-y-3", "aria-labelledby": "cigar-data-held", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { id: "cigar-data-held", className: versionHeading, children: "What CIGAR is holding" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: versionLead, children: "Just counts. Your files, questions and folder names are never shown here." })
        ] }),
        data ? /* @__PURE__ */ jsxRuntimeExports.jsxs("dl", { className: "grid grid-cols-2 gap-2 sm:grid-cols-3", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(Stat, { term: "Projects with access (per app)", value: data.active_scopes }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(Stat, { term: "Files it can read", value: data.selected_files }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(Stat, { term: "Answers ready", value: data.current_contexts }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(Stat, { term: "Past answers kept", value: data.history_entries }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(Stat, { term: "Space used by past answers", value: data.history_encoded_bytes.toLocaleString() + " bytes" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(Stat, { term: "Connected apps", value: data.agent_sessions })
        ] }) : /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "rounded-2xl border border-dashed border-brand-dark/15 px-5 py-6 text-center text-sm text-brand-dark/70", children: "Counts show up while CIGAR is on." }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: caption, children: "CIGAR keeps at most 8 past answers (512 KiB) for each project and app, and clears them after the time you chose in Settings." })
      ] }),
      data?.saved_evidence ? /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "space-y-3 rounded-2xl border border-brand-dark/10 bg-white p-4 sm:p-5", role: "region", "aria-label": "Saved context evidence", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h4", { className: "text-sm font-semibold text-brand-dark", children: "Saved notes" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "status", className: "text-sm text-brand-dark/75", children: savedEvidenceCopy(data.saved_evidence) }),
        data.saved_evidence.slots !== null ? /* @__PURE__ */ jsxRuntimeExports.jsxs("dl", { className: "grid grid-cols-2 gap-2 sm:grid-cols-4", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(Stat, { term: "Projects with saved notes (per app)", value: data.saved_evidence.slots }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(Stat, { term: "Space used (bytes)", value: data.saved_evidence.bytes?.toLocaleString() ?? "Unavailable" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(Stat, { term: "Notes still saving", value: data.saved_evidence.unresolved_writes ?? "Unavailable" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(Stat, { term: "Expired, waiting to clear", value: data.saved_evidence.expired_slots ?? "Unavailable" })
        ] }) : null,
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: caption, children: "Saved notes cover at most 8 projects (each app counts separately) and use about 550 MB of disk." })
      ] }) : null,
      /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "space-y-3", "aria-labelledby": "cigar-data-fix", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { id: "cigar-data-fix", className: versionHeading, children: "Fix a problem" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("ul", { className: versionList, children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            Row,
            {
              title: "Start CIGAR fresh",
              body: !ready ? "If CIGAR seems stuck, turn it off to free everything it holds. Starting fresh needs Python 3.14, which Settings can set up." : "Ends current access and starts CIGAR again. Add your projects again afterward.",
              action: /* @__PURE__ */ jsxRuntimeExports.jsx("button", { className: versionButton, type: "button", disabled: busy || disabled || !status?.verification_permitted || !status?.preferences.runtime_id || Boolean(status.job), onClick: () => setConfirm("recheck"), children: "Start fresh" })
            }
          ),
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            Row,
            {
              title: "Change setup",
              body: "Choose what CIGAR may read and how long it keeps things.",
              action: /* @__PURE__ */ jsxRuntimeExports.jsx("a", { className: versionButton, href: guardAwareHref("/cigar?section=runtime"), children: "Open Settings" })
            }
          )
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "space-y-3", "aria-labelledby": "cigar-data-danger", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { id: "cigar-data-danger", className: versionHeading, children: "Delete or turn off" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: versionLead, children: "Each one asks you first. Guard's approvals and records are never touched." })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("ul", { className: "divide-y divide-red-200/70 overflow-hidden rounded-2xl border border-red-200 bg-red-50/30", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            Row,
            {
              title: "Past answers",
              body: "Deletes the answers CIGAR kept. Projects keep their access.",
              action: /* @__PURE__ */ jsxRuntimeExports.jsx("button", { className: danger, type: "button", disabled: busy || disabled || !ready || !data?.history_entries, onClick: () => setConfirm("history"), children: "Clear past answers" })
            }
          ),
          removable ? /* @__PURE__ */ jsxRuntimeExports.jsx(
            Row,
            {
              title: "Saved notes",
              body: "Deletes what CIGAR saved on this computer, including old projects.",
              action: /* @__PURE__ */ jsxRuntimeExports.jsx("button", { className: danger, type: "button", disabled: busy || disabled, onClick: () => setConfirm("saved"), children: "Remove saved notes" })
            }
          ) : null,
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            Row,
            {
              title: "Everything CIGAR knows",
              body: "Deletes past answers, saved notes, project access, app connections and recent projects. You can set it up again anytime.",
              action: /* @__PURE__ */ jsxRuntimeExports.jsx("button", { className: danger, type: "button", disabled: busy || disabled || !ready && !data?.saved_evidence, onClick: () => setConfirm("data"), children: "Delete everything" })
            }
          ),
          offAvailable ? /* @__PURE__ */ jsxRuntimeExports.jsx(
            Row,
            {
              title: "Turn CIGAR off",
              body: "Stops CIGAR now. Projects lose access until you turn it back on.",
              action: /* @__PURE__ */ jsxRuntimeExports.jsx("button", { className: danger, type: "button", disabled: busy || disabled, onClick: stop, children: "Turn CIGAR off" })
            }
          ) : null
        ] })
      ] })
    ] }),
    confirm ? /* @__PURE__ */ jsxRuntimeExports.jsx(
      ConfirmDialog,
      {
        title: CONFIRM[confirm].title,
        description: CONFIRM[confirm].description,
        confirmLabel: CONFIRM[confirm].label,
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
      const parsed2 = Number.parseInt(event.target.value, 10);
      const value = Number.isNaN(parsed2) ? 0 : parsed2;
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
      const text2 = await file.text();
      const parsed2 = JSON.parse(text2);
      const savedGateEnabled = savedSettingsRef.current?.approval_gate?.enabled === true;
      if (savedGateEnabled) {
        openProofModal("maintenance", {
          kind: "maintenance",
          action: "import-settings",
          importExport: parsed2
        });
        return;
      }
      await executeImportSettings(parsed2);
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
              /* @__PURE__ */ jsxRuntimeExports.jsx(SettingsFormSection, { title: "CIGAR", description: "Gives your AI app the project files that match what you ask.", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center justify-between gap-3 py-4", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "max-w-xl text-sm text-slate-500", children: "Turn it on, pick project folders and choose which AI apps use it on the CIGAR page." }),
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
            activeTab === "cloud-actions" && /* @__PURE__ */ jsxRuntimeExports.jsx(CloudActionsSettings, {}),
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

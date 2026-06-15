import { useCallback, useEffect, useRef, useState } from "react";
import type { MutableRefObject } from "react";
import {
  derivePackageWorkbenchFromReceipts,
  fetchReceipts,
  normalizeSupplyChainAuditSnapshot,
} from "./guard-api";
import { resolveSupplyChainAuditFailure } from "./supply-chain-audit-connect";
import type { AuditConnectGateViewState } from "./supply-chain-firewall-panel";
import type { GuardRuntimeSnapshot, SupplyChainAuditSnapshot } from "./guard-types";

export type AuditRunPhase = "idle" | "preparing" | "scanning" | "evaluating" | "finalizing";

export type SupplyChainAuditSession = {
  auditSnapshot: SupplyChainAuditSnapshot | null;
  auditRunning: boolean;
  auditError: string | null;
  auditConnectGate: AuditConnectGateViewState | null;
  auditPhase: AuditRunPhase;
  runAuditRef: MutableRefObject<(() => void) | null>;
  setAuditConnectGate: (state: AuditConnectGateViewState | null) => void;
  handleAuditStarted: () => void;
  handleAuditCompleted: (resultDetail: Record<string, unknown>) => void;
  handleAuditErrorChange: (message: string | null) => void;
  handleAuditRunningChange: (running: boolean) => void;
  handleRunAudit: () => void;
};

type UseSupplyChainAuditSessionInput = {
  snapshot: GuardRuntimeSnapshot;
  onNavigate: (pathname: string) => void;
};

export function useSupplyChainAuditSession({
  snapshot,
  onNavigate,
}: UseSupplyChainAuditSessionInput): SupplyChainAuditSession {
  const [auditSnapshot, setAuditSnapshot] = useState<SupplyChainAuditSnapshot | null>(null);
  const [auditRunning, setAuditRunning] = useState(false);
  const [auditError, setAuditError] = useState<string | null>(null);
  const [auditConnectGate, setAuditConnectGate] = useState<AuditConnectGateViewState | null>(null);
  const [auditPhase, setAuditPhase] = useState<AuditRunPhase>("idle");
  const runAuditRef = useRef<(() => void) | null>(null);
  const phaseTimersRef = useRef<number[]>([]);
  const auditPhaseRef = useRef<AuditRunPhase>("idle");

  const setAuditPhaseLive = useCallback((phase: AuditRunPhase) => {
    auditPhaseRef.current = phase;
    setAuditPhase(phase);
  }, []);

  const clearPhaseTimers = useCallback(() => {
    for (const timer of phaseTimersRef.current) {
      window.clearTimeout(timer);
    }
    phaseTimersRef.current = [];
  }, []);

  const schedulePhase = useCallback(
    (phase: AuditRunPhase, delayMs: number) => {
      const timer = window.setTimeout(() => {
        setAuditPhaseLive(phase);
        phaseTimersRef.current = phaseTimersRef.current.filter((entry) => entry !== timer);
      }, delayMs);
      phaseTimersRef.current.push(timer);
    },
    [setAuditPhaseLive],
  );

  useEffect(() => {
    let cancelled = false;
    const loadReceiptEvidence = async () => {
      try {
        const receipts = await fetchReceipts();
        if (cancelled) {
          return;
        }
        setAuditSnapshot(derivePackageWorkbenchFromReceipts(receipts));
      } catch {
        if (!cancelled) {
          setAuditSnapshot(null);
        }
      }
    };
    void loadReceiptEvidence();
    return () => {
      cancelled = true;
    };
  }, [snapshot.generated_at, snapshot.receipt_count]);

  useEffect(() => () => clearPhaseTimers(), [clearPhaseTimers]);

  const handleAuditStarted = useCallback(() => {
    clearPhaseTimers();
    onNavigate("/audit");
    setAuditPhaseLive("preparing");
    schedulePhase("scanning", 400);
    schedulePhase("evaluating", 1600);
  }, [clearPhaseTimers, onNavigate, schedulePhase, setAuditPhaseLive]);

  const handleAuditCompleted = useCallback(
    (resultDetail: Record<string, unknown>) => {
      clearPhaseTimers();
      setAuditPhaseLive("finalizing");
      const failureMessage = resolveSupplyChainAuditFailure(resultDetail);
      if (failureMessage !== null) {
        setAuditSnapshot(null);
        setAuditError(failureMessage);
        setAuditPhaseLive("idle");
        return;
      }
      const normalized = normalizeSupplyChainAuditSnapshot(resultDetail);
      setAuditSnapshot(normalized);
      setAuditError(null);
      const timer = window.setTimeout(() => setAuditPhaseLive("idle"), 600);
      phaseTimersRef.current.push(timer);
    },
    [clearPhaseTimers, setAuditPhaseLive],
  );

  const handleAuditErrorChange = useCallback(
    (message: string | null) => {
      setAuditError(message);
      if (message !== null) {
        clearPhaseTimers();
        setAuditPhaseLive("idle");
      }
    },
    [clearPhaseTimers, setAuditPhaseLive],
  );

  const handleAuditRunningChange = useCallback(
    (running: boolean) => {
      setAuditRunning(running);
      if (!running && auditPhaseRef.current !== "finalizing") {
        clearPhaseTimers();
        setAuditPhaseLive("idle");
      }
    },
    [clearPhaseTimers, setAuditPhaseLive],
  );

  const handleRunAudit = useCallback(() => {
    runAuditRef.current?.();
  }, []);

  return {
    auditSnapshot,
    auditRunning,
    auditError,
    auditConnectGate,
    auditPhase,
    runAuditRef,
    setAuditConnectGate,
    handleAuditStarted,
    handleAuditCompleted,
    handleAuditErrorChange,
    handleAuditRunningChange,
    handleRunAudit,
  };
}

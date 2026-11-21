import { useCallback, useEffect, useRef, useState } from "react";

import {
  fetchGuardUpdateStatus,
  prepareGuardDaemonReconnect,
  readGuardToken,
  reconnectGuardDaemonAfterUpdate,
  redirectToGuardDaemonOrigin,
  scheduleGuardUpdate,
  setGuardUpdateChannel,
  setGuardUpdateMode,
  type GuardUpdateChannelProof,
  type GuardUpdateMode,
} from "./guard-api";
import type {
  GuardDaemonReconnectAuthorization,
  GuardUpdatePhase,
  GuardUpdateStatus,
} from "./guard-types";

const UPDATE_STATUS_POLL_MS = 60_000;
const RECONNECT_POLL_MS = 1_500;
const RECONNECT_TIMEOUT_MS = 180_000;

export function useGuardUpdate(options?: { onReconnected?: () => void; enabled?: boolean }) {
  const enabled = options?.enabled !== false;
  const [updateStatus, setUpdateStatus] = useState<GuardUpdateStatus | null>(null);
  const [updatePhase, setUpdatePhase] = useState<GuardUpdatePhase>(enabled ? "checking" : "idle");
  const [updateError, setUpdateError] = useState<string | null>(null);
  const reconnectStartedAt = useRef<number | null>(null);
  const updatePhaseRef = useRef<GuardUpdatePhase>("checking");
  const updateStatusEpoch = useRef(0);
  const channelMutationId = useRef(0);
  const channelMutationPending = useRef(false);
  const modeMutationId = useRef(0);
  const modeMutationPending = useRef(false);
  const isMounted = useRef(false);

  useEffect(() => {
    updatePhaseRef.current = updatePhase;
  }, [updatePhase]);

  useEffect(() => {
    isMounted.current = true;
    return () => {
      isMounted.current = false;
    };
  }, []);

  const refreshUpdateStatus = useCallback(async () => {
    if (!enabled || !isMounted.current || channelMutationPending.current || modeMutationPending.current) {
      return;
    }
    const epoch = updateStatusEpoch.current;
    const mutationId = channelMutationId.current;
    try {
      const status = await fetchGuardUpdateStatus();
      if (
        !isMounted.current ||
        epoch !== updateStatusEpoch.current ||
        mutationId !== channelMutationId.current ||
        channelMutationPending.current || modeMutationPending.current
      ) {
        return;
      }
      setUpdateStatus(status);
      if (updatePhaseRef.current === "checking" || updatePhaseRef.current === "idle") {
        setUpdatePhase("idle");
      }
    } catch {
      if (isMounted.current && updatePhaseRef.current === "checking") {
        setUpdatePhase("idle");
      }
    }
  }, [enabled]);

  useEffect(() => {
    if (!enabled) {
      setUpdatePhase("idle");
      return;
    }
    let cancelled = false;
    const epoch = updateStatusEpoch.current;
    const mutationId = channelMutationId.current;
    void fetchGuardUpdateStatus()
      .then((status) => {
        if (
          cancelled ||
          epoch !== updateStatusEpoch.current ||
          mutationId !== channelMutationId.current ||
          channelMutationPending.current ||
          modeMutationPending.current
        ) {
          return;
        }
        setUpdateStatus(status);
        if (updatePhaseRef.current === "checking" || updatePhaseRef.current === "idle") {
          setUpdatePhase("idle");
        }
      })
      .catch(() => {
        if (!cancelled && updatePhaseRef.current === "checking") {
          setUpdatePhase("idle");
        }
      });
    const pollId = window.setInterval(() => {
      if (updatePhaseRef.current === "updating" || updatePhaseRef.current === "reconnecting") {
        return;
      }
      void refreshUpdateStatus();
    }, UPDATE_STATUS_POLL_MS);
    return () => {
      cancelled = true;
      window.clearInterval(pollId);
    };
  }, [enabled, refreshUpdateStatus]);

  const waitForReconnect = useCallback(
    async (
      expectedPreviousVersion: string,
      expectedLatestVersion: string | null,
      authorization: GuardDaemonReconnectAuthorization,
    ): Promise<boolean> => {
      reconnectStartedAt.current = Date.now();
      let sawUpdateInProgress = false;
      while (Date.now() - (reconnectStartedAt.current ?? Date.now()) < RECONNECT_TIMEOUT_MS) {
        try {
          const reconnectResult = await reconnectGuardDaemonAfterUpdate({
            expectedPreviousVersion,
            expectedLatestVersion,
            sawUpdateInProgress,
            authorization,
          });
          if (!reconnectResult) {
            throw new Error("Guard daemon not found");
          }
          sawUpdateInProgress = reconnectResult.sawUpdateInProgress;
          if (!reconnectResult.origin) {
            throw new Error("Guard daemon not ready");
          }
          const { origin } = reconnectResult;
          if (origin !== window.location.origin) {
            redirectToGuardDaemonOrigin(origin, readGuardToken());
            return true;
          }
          updateStatusEpoch.current += 1;
          setUpdateStatus(reconnectResult.status);
          setUpdatePhase("idle");
          options?.onReconnected?.();
          return false;
        } catch {
          await new Promise<void>((resolve) => window.setTimeout(resolve, RECONNECT_POLL_MS));
        }
      }
      setUpdatePhase("error");
      throw new Error("Guard did not reconnect after the update.");
    },
    [options],
  );

  const scheduleAndWait = useCallback(
    async (params: {
      forcePypiReinstall?: boolean;
      expectedPreviousVersion: string;
      expectedLatestVersion: string | null;
    }): Promise<void> => {
      setUpdatePhase("updating");
      setUpdateError(null);
      try {
        const reconnectAuthorization = await prepareGuardDaemonReconnect();
        const scheduleResult = await scheduleGuardUpdate(
          params.forcePypiReinstall === true ? { forcePypiReinstall: true } : undefined,
        );
        if (scheduleResult.scheduled === false && scheduleResult.error === "update_in_progress") {
          setUpdatePhase("reconnecting");
          const redirected = await waitForReconnect(
            params.expectedPreviousVersion,
            params.expectedLatestVersion,
            reconnectAuthorization,
          );
          if (!redirected) {
            window.location.reload();
          }
          return;
        }
        if (scheduleResult.scheduled !== true) {
          throw new Error(
            scheduleResult.message ?? scheduleResult.error ?? "Guard update was not scheduled. The installed version stays in place.",
          );
        }
        setUpdatePhase("reconnecting");
        const redirected = await waitForReconnect(
          params.expectedPreviousVersion,
          params.expectedLatestVersion,
          reconnectAuthorization,
        );
        if (!redirected) {
          window.location.reload();
        }
      } catch (error) {
        setUpdatePhase("error");
        setUpdateError(error instanceof Error ? error.message : "The update did not finish. The installed version stays in place.");
      }
    },
    [waitForReconnect],
  );

  const onUpdateGuard = useCallback(async () => {
    if (!updateStatus?.update_available || !updateStatus.auto_updatable) {
      return;
    }
    await scheduleAndWait({
      expectedPreviousVersion: updateStatus.current_version,
      expectedLatestVersion: updateStatus.latest_version,
    });
  }, [scheduleAndWait, updateStatus]);

  const onReinstallGuard = useCallback(async () => {
    if (!updateStatus?.recovery_reinstall_available) {
      return;
    }
    // A PyPI reinstall may land the same version; skip the version-change gate
    // during reconnect by not pinning an expected previous/target version.
    await scheduleAndWait({
      forcePypiReinstall: true,
      expectedPreviousVersion: "",
      expectedLatestVersion: null,
    });
  }, [scheduleAndWait, updateStatus]);

  const onSetUpdateChannel = useCallback(async (channel: "stable" | "alpha", proof?: GuardUpdateChannelProof) => {
    const mutationId = ++channelMutationId.current;
    updateStatusEpoch.current += 1;
    channelMutationPending.current = true;
    try {
      const status = await setGuardUpdateChannel(channel, proof);
      if (mutationId === channelMutationId.current) {
        updateStatusEpoch.current += 1;
        setUpdateStatus(status);
        if (updatePhaseRef.current === "checking" || updatePhaseRef.current === "idle") {
          setUpdatePhase("idle");
        }
      }
    } finally {
      if (mutationId === channelMutationId.current) {
        channelMutationPending.current = false;
      }
    }
  }, []);

  const onSetUpdateMode = useCallback(async (mode: GuardUpdateMode, proof?: GuardUpdateChannelProof) => {
    const mutationId = ++modeMutationId.current;
    updateStatusEpoch.current += 1;
    modeMutationPending.current = true;
    try {
      const status = await setGuardUpdateMode(mode, proof);
      if (mutationId === modeMutationId.current) {
        updateStatusEpoch.current += 1;
        setUpdateStatus(status);
        if (updatePhaseRef.current === "checking" || updatePhaseRef.current === "idle") setUpdatePhase("idle");
      }
    } finally {
      if (mutationId === modeMutationId.current) modeMutationPending.current = false;
    }
  }, []);

  return {
    guardVersion: updateStatus?.current_version ?? null,
    updateStatus,
    updatePhase,
    updateError,
    onUpdateGuard,
    onReinstallGuard,
    onSetUpdateChannel,
    onSetUpdateMode,
    refreshUpdateStatus,
  };
}

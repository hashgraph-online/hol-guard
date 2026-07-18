import { useCallback, useEffect, useState } from "react";
import { fetchTrayStatus, runTrayAction } from "../guard-api";
import type { TrayAction, TrayStatusPayload } from "../guard-types";
import { SettingsFormSection } from "./settings-row-primitives";
import { ActionButton } from "../approval-center-primitives";

type TrayActionStatus = "idle" | "loading" | "success" | "error";

interface TrayActionState {
  status: TrayActionStatus;
  message: string;
}

const IDLE_STATE: TrayActionState = { status: "idle", message: "" };

export function TraySettingsPanel(): JSX.Element {
  const [trayStatus, setTrayStatus] = useState<TrayStatusPayload | null>(null);
  const [statusLoading, setStatusLoading] = useState(true);
  const [statusError, setStatusError] = useState<string | null>(null);
  const [actionState, setActionState] = useState<TrayActionState>(IDLE_STATE);
  const [pendingAction, setPendingAction] = useState<TrayAction | null>(null);

  const refreshStatus = useCallback(async () => {
    setStatusLoading(true);
    setStatusError(null);
    try {
      const status = await fetchTrayStatus();
      setTrayStatus(status);
    } catch (error) {
      setStatusError(error instanceof Error ? error.message : "Failed to load tray status");
      setTrayStatus(null);
    } finally {
      setStatusLoading(false);
    }
  }, []);

  useEffect(() => {
    void refreshStatus();
  }, [refreshStatus]);

  const handleAction = useCallback(
    async (action: TrayAction) => {
      setPendingAction(action);
      setActionState({ status: "loading", message: "" });
      try {
        const result = await runTrayAction(action);
        setActionState({
          status: result.ok ? "success" : "error",
          message: result.message,
        });
        // Refresh status after any lifecycle action
        await refreshStatus();
      } catch (error) {
        setActionState({
          status: "error",
          message: error instanceof Error ? error.message : `Tray ${action} failed`,
        });
      } finally {
        setPendingAction(null);
      }
    },
    [refreshStatus],
  );

  const isRunning = trayStatus?.state === "running";
  const isSupported = trayStatus?.capability.supported ?? false;
  const platformLabel = trayStatus?.capability.platform ?? "Unknown";
  const backendLabel = trayStatus?.capability.backend ?? "none";

  return (
    <div className="flex min-h-0 flex-1 flex-col space-y-6">
      <SettingsFormSection
        title="Menu-bar tray icon"
        description="A persistent icon in your menu bar (macOS) or system tray (Windows/Linux) that opens the HOL Guard dashboard without a terminal."
      >
        <div className="space-y-4 py-3">
          {/* Status display */}
          <div className="rounded-lg border border-slate-200 bg-slate-50 p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-semibold text-brand-dark">Current status</p>
                {statusLoading ? (
                  <p className="text-xs text-slate-500">Loading…</p>
                ) : statusError ? (
                  <p className="text-xs text-red-600">{statusError}</p>
                ) : trayStatus ? (
                  <div className="mt-1 space-y-1">
                    <p className="text-sm text-slate-700">
                      <span className="font-medium">State:</span>{" "}
                      <span
                        className={
                          isRunning
                            ? "rounded bg-green-100 px-2 py-0.5 text-xs font-medium text-green-700"
                            : "rounded bg-slate-200 px-2 py-0.5 text-xs font-medium text-slate-600"
                        }
                      >
                        {trayStatus.state}
                      </span>
                    </p>
                    <p className="text-xs text-slate-500">
                      Platform: {platformLabel} · Backend: {backendLabel}
                    </p>
                    {!isSupported && (
                      <p className="text-xs text-amber-600">
                        Tray icons are not supported on this platform.
                      </p>
                    )}
                  </div>
                ) : (
                  <p className="text-xs text-slate-500">No status available.</p>
                )}
              </div>
              <ActionButton onClick={() => void refreshStatus()} variant="outline" disabled={statusLoading}>
                {statusLoading ? "Refreshing…" : "Refresh"}
              </ActionButton>
            </div>
          </div>

          {/* Action feedback */}
          {actionState.status !== "idle" && (
            <div
              className={
                actionState.status === "error"
                  ? "rounded-lg border border-red-200 bg-red-50 p-3 text-sm text-red-700"
                  : actionState.status === "success"
                    ? "rounded-lg border border-green-200 bg-green-50 p-3 text-sm text-green-700"
                    : "rounded-lg border border-slate-200 bg-slate-50 p-3 text-sm text-slate-600"
              }
              role={actionState.status === "error" ? "alert" : "status"}
            >
              {actionState.status === "loading" ? "Working…" : actionState.message}
            </div>
          )}

          {/* Action buttons */}
          <div className="grid gap-4 sm:grid-cols-2">
            <div>
              <p className="text-sm font-semibold text-brand-dark">Start tray</p>
              <p className="text-xs text-slate-500">Launch the menu-bar icon now.</p>
              <div className="mt-2">
                <ActionButton
                  onClick={() => void handleAction("start")}
                  disabled={!isSupported || pendingAction !== null || isRunning}
                  variant="primary"
                >
                  {pendingAction === "start" ? "Starting…" : "Start"}
                </ActionButton>
              </div>
            </div>
            <div>
              <p className="text-sm font-semibold text-brand-dark">Stop tray</p>
              <p className="text-xs text-slate-500">Quit the running menu-bar icon.</p>
              <div className="mt-2">
                <ActionButton
                  onClick={() => void handleAction("stop")}
                  disabled={pendingAction !== null || !isRunning}
                  variant="outline"
                >
                  {pendingAction === "stop" ? "Stopping…" : "Stop"}
                </ActionButton>
              </div>
            </div>
            <div>
              <p className="text-sm font-semibold text-brand-dark">Restart tray</p>
              <p className="text-xs text-slate-500">Stop and start again (use if the icon is stuck).</p>
              <div className="mt-2">
                <ActionButton
                  onClick={() => void handleAction("restart")}
                  disabled={!isSupported || pendingAction !== null}
                  variant="outline"
                >
                  {pendingAction === "restart" ? "Restarting…" : "Restart"}
                </ActionButton>
              </div>
            </div>
            <div>
              <p className="text-sm font-semibold text-brand-dark">Repair tray</p>
              <p className="text-xs text-slate-500">Reset crash state if the tray won&apos;t start.</p>
              <div className="mt-2">
                <ActionButton
                  onClick={() => void handleAction("repair")}
                  disabled={pendingAction !== null}
                  variant="outline"
                >
                  {pendingAction === "repair" ? "Repairing…" : "Repair"}
                </ActionButton>
              </div>
            </div>
          </div>
        </div>
      </SettingsFormSection>

      <SettingsFormSection
        title="Start at login"
        description="Automatically launch the tray icon when you log in to your computer."
      >
        <div className="space-y-4 py-3">
          <div className="grid gap-4 sm:grid-cols-2">
            <div>
              <p className="text-sm font-semibold text-brand-dark">Install login item</p>
              <p className="text-xs text-slate-500">
                Registers the tray to start automatically (LaunchAgent on macOS, Run key on Windows, XDG autostart on Linux).
              </p>
              <div className="mt-2">
                <ActionButton
                  onClick={() => void handleAction("install")}
                  disabled={!isSupported || pendingAction !== null}
                  variant="primary"
                >
                  {pendingAction === "install" ? "Installing…" : "Install"}
                </ActionButton>
              </div>
            </div>
            <div>
              <p className="text-sm font-semibold text-brand-dark">Remove login item</p>
              <p className="text-xs text-slate-500">Unregister the automatic start-at-login entry.</p>
              <div className="mt-2">
                <ActionButton
                  onClick={() => void handleAction("uninstall")}
                  disabled={pendingAction !== null}
                  variant="outline"
                >
                  {pendingAction === "uninstall" ? "Removing…" : "Remove"}
                </ActionButton>
              </div>
            </div>
          </div>
        </div>
      </SettingsFormSection>
    </div>
  );
}

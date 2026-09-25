import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import { HiMiniExclamationTriangle, HiMiniWrenchScrewdriver } from "react-icons/hi2";

import { GuardModalLayer } from "./guard-modal-layer";

export type ConfirmDialogTone = "default" | "destructive";

export interface ConfirmDialogOptions {
  title: string;
  description: string;
  confirmLabel: string;
  cancelLabel?: string;
  tone?: ConfirmDialogTone;
}

const CONFIRM_DIALOG_DESCRIPTION_ID = "confirm-dialog-description";

export function ConfirmDialogPanel(
  props: ConfirmDialogOptions & { onConfirm: () => void; onCancel: () => void },
) {
  const tone = props.tone ?? "default";
  const destructive = tone === "destructive";
  const cancelLabel = props.cancelLabel ?? "Cancel";
  const ToneIcon = destructive ? HiMiniExclamationTriangle : HiMiniWrenchScrewdriver;

  const confirmButton = (
    <button
      type="button"
      autoFocus={!destructive}
      onClick={props.onConfirm}
      className={`inline-flex min-h-11 items-center rounded-lg px-4 text-sm font-semibold text-white transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/40 focus-visible:ring-offset-2 ${
        destructive
          ? "bg-brand-attention hover:bg-brand-attention/90"
          : "bg-brand-blue hover:bg-brand-blue/90"
      }`}
    >
      {props.confirmLabel}
    </button>
  );
  const cancelButton = (
    <button
      type="button"
      autoFocus={destructive}
      onClick={props.onCancel}
      className="inline-flex min-h-11 items-center rounded-lg border border-slate-200 bg-white px-4 text-sm font-medium text-brand-dark transition-colors hover:bg-slate-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/40 focus-visible:ring-offset-2"
    >
      {cancelLabel}
    </button>
  );

  return (
    <div
      aria-describedby={CONFIRM_DIALOG_DESCRIPTION_ID}
      className={`rounded-2xl border bg-white p-6 shadow-xl ${
        destructive ? "border-brand-attention/15" : "border-brand-blue/15"
      }`}
    >
      <div className="flex items-start gap-3">
        <span
          className={`inline-flex h-10 w-10 shrink-0 items-center justify-center rounded-full ${
            destructive ? "bg-brand-attention/10" : "bg-brand-blue/10"
          }`}
        >
          <ToneIcon
            className={`h-5 w-5 ${destructive ? "text-brand-attention" : "text-brand-blue"}`}
            aria-hidden="true"
          />
        </span>
        <div>
          <h3 className="text-base font-semibold text-brand-dark">{props.title}</h3>
          <p id={CONFIRM_DIALOG_DESCRIPTION_ID} className="mt-2 text-sm text-slate-500">
            {props.description}
          </p>
        </div>
      </div>
      <div className="mt-6 flex flex-wrap gap-2">
        {destructive ? (
          <>
            {cancelButton}
            {confirmButton}
          </>
        ) : (
          <>
            {confirmButton}
            {cancelButton}
          </>
        )}
      </div>
    </div>
  );
}

export function ConfirmDialog(
  props: ConfirmDialogOptions & { onConfirm: () => void; onCancel: () => void },
) {
  return (
    <GuardModalLayer
      ariaLabel={props.title}
      onClose={props.onCancel}
      panelClassName="w-full max-w-sm"
    >
      <ConfirmDialogPanel {...props} />
    </GuardModalLayer>
  );
}

interface PendingConfirmation {
  options: ConfirmDialogOptions;
  resolve: (value: boolean) => void;
}

export function useConfirmDialog(): {
  confirm: (options: ConfirmDialogOptions) => Promise<boolean>;
  dialog: ReactNode;
} {
  const [pending, setPending] = useState<PendingConfirmation | null>(null);
  const pendingRef = useRef<PendingConfirmation | null>(null);
  pendingRef.current = pending;

  const confirm = useCallback((options: ConfirmDialogOptions): Promise<boolean> => {
    let resolvePromise: (value: boolean) => void = () => undefined;
    const promise = new Promise<boolean>((resolve) => {
      resolvePromise = resolve;
    });
    setPending((previous) => {
      previous?.resolve(false);
      return { options, resolve: resolvePromise };
    });
    return promise;
  }, []);

  const settle = useCallback((value: boolean) => {
    setPending((current) => {
      current?.resolve(value);
      return null;
    });
  }, []);

  useEffect(() => {
    return () => {
      pendingRef.current?.resolve(false);
    };
  }, []);

  const dialog = pending !== null ? (
    <ConfirmDialog
      {...pending.options}
      onConfirm={() => settle(true)}
      onCancel={() => settle(false)}
    />
  ) : null;

  return { confirm, dialog };
}

import { useCallback, useState } from "react";

import { useConfirmDialog } from "../confirm-dialog";
import { LocalCliApiError, type LocalCliItem } from "../local-cli-api";
import { forgetLocalCli } from "../local-cli-forget-api";

export function lastSeenCopy(lastSeenAt: string | null): string | null {
  if (!lastSeenAt) return null;
  const seen = new Date(lastSeenAt);
  if (Number.isNaN(seen.getTime())) return null;
  return `Last seen ${seen.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" })}`;
}

export function canForgetLocalCli(item: LocalCliItem): boolean {
  return item.state === "unset" && item.observed_count > 0 && item.shares_enrolled_server !== true;
}

export function ForgetLocalCliButton(props: {
  item: LocalCliItem;
  disabled?: boolean;
  onForgotten: () => Promise<void>;
}) {
  const { confirm, dialog } = useConfirmDialog();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const forget = useCallback(async () => {
    const confirmed = await confirm({
      title: "Forget this connection?",
      description: "Guard removes it from this list. If an agent uses it again or an app still configures it, Guard lists it again.",
      confirmLabel: "Forget",
    });
    if (!confirmed) return;
    setBusy(true);
    setError(null);
    try {
      await forgetLocalCli(props.item);
      await props.onForgotten();
    } catch (caught) {
      setError(caught instanceof LocalCliApiError ? caught.message : "Guard could not forget this connection.");
    } finally {
      setBusy(false);
    }
  }, [confirm, props]);
  return (
    <>
      <button type="button" disabled={props.disabled || busy} onClick={() => void forget()}
        className="min-h-11 rounded-xl px-4 text-sm font-semibold text-brand-dark/80 disabled:opacity-50">
        {busy ? "Forgetting…" : "Forget this connection"}
      </button>
      {error ? <p role="alert" className="basis-full text-sm leading-6 text-red-700">{error}</p> : null}
      {dialog}
    </>
  );
}

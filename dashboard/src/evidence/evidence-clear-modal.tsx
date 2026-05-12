import { useCallback, useState } from "react";
import {
  HiMiniExclamationTriangle,
  HiMiniXMark,
  HiMiniTrash,
} from "react-icons/hi2";
import { clearEvidence } from "../guard-api";

interface EvidenceClearModalProps {
  count: number;
  isOpen: boolean;
  onClose: () => void;
  onCleared?: () => void;
}

export function EvidenceClearModal({
  count,
  isOpen,
  onClose,
  onCleared,
}: EvidenceClearModalProps) {
  const [loading, setLoading] = useState(false);

  const handleConfirm = useCallback(async () => {
    setLoading(true);
    try {
      await clearEvidence();
      onCleared?.();
      onClose();
    } finally {
      setLoading(false);
    }
  }, [onCleared, onClose]);

  if (!isOpen) return null;

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label="Confirm delete evidence"
      className="fixed inset-0 z-50 flex items-center justify-center"
    >
      <div
        className="absolute inset-0 bg-black/30 backdrop-blur-sm"
        onClick={onClose}
        aria-hidden="true"
      />
      <div className="relative w-full max-w-sm rounded-2xl bg-white shadow-2xl overflow-hidden mx-4">
        <div className="flex items-start gap-3 px-6 pt-6 pb-4">
          <span
            className="shrink-0 flex h-10 w-10 items-center justify-center rounded-full bg-amber-50"
            aria-hidden="true"
          >
            <HiMiniExclamationTriangle className="h-5 w-5 text-brand-attention" />
          </span>
          <div className="min-w-0">
            <h2 className="text-base font-semibold text-brand-dark">
              Delete evidence records
            </h2>
            <p className="mt-1 text-sm text-slate-500">
              This will permanently delete{" "}
              <strong className="text-brand-dark">
                {count} record{count !== 1 ? "s" : ""}
              </strong>{" "}
              from this device. This action cannot be undone.
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close"
            className="shrink-0 flex h-7 w-7 items-center justify-center rounded-full text-slate-400 hover:bg-slate-100 transition-colors"
          >
            <HiMiniXMark className="h-4 w-4" aria-hidden="true" />
          </button>
        </div>

        <div className="flex gap-2 border-t border-slate-100 px-6 py-4">
          <button
            type="button"
            onClick={onClose}
            disabled={loading}
            className="flex-1 rounded-xl border border-slate-200 bg-white px-4 py-2.5 text-sm font-semibold text-brand-dark hover:bg-slate-50 disabled:opacity-40 transition-colors"
          >
            Cancel
          </button>
          <button
            type="button"
            onClick={handleConfirm}
            disabled={loading}
            aria-label={`Delete ${count} evidence records`}
            className="flex-1 flex items-center justify-center gap-2 rounded-xl bg-brand-attention px-4 py-2.5 text-sm font-semibold text-white hover:bg-brand-attention/90 disabled:opacity-40 transition-colors"
          >
            <HiMiniTrash className="h-4 w-4" aria-hidden="true" />
            {loading ? "Deleting…" : `Delete ${count}`}
          </button>
        </div>
      </div>
    </div>
  );
}

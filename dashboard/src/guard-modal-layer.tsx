import { useEffect, useRef, useState, type MouseEvent, type ReactNode } from "react";
import { createPortal } from "react-dom";
import { useFocusTrap } from "./use-focus-trap";

interface GuardModalLayerProps {
  ariaLabel: string;
  children: ReactNode;
  onClose: () => void;
  panelClassName?: string;
}

export function GuardModalLayer({
  ariaLabel,
  children,
  onClose,
  panelClassName = "w-full max-w-2xl",
}: GuardModalLayerProps) {
  const [mounted, setMounted] = useState(false);
  const panelRef = useRef<HTMLDivElement | null>(null);
  const onCloseRef = useRef(onClose);
  onCloseRef.current = onClose;

  useFocusTrap(mounted, panelRef);

  useEffect(() => {
    setMounted(true);
  }, []);

  useEffect(() => {
    if (!mounted) return;
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    const previousCount = Number(document.documentElement.dataset.guardModalOpen ?? 0);
    document.documentElement.dataset.guardModalOpen = String(previousCount + 1);
    return () => {
      document.body.style.overflow = previousOverflow;
      const nextCount = Number(document.documentElement.dataset.guardModalOpen ?? 1) - 1;
      if (nextCount <= 0) {
        delete document.documentElement.dataset.guardModalOpen;
      } else {
        document.documentElement.dataset.guardModalOpen = String(nextCount);
      }
    };
  }, [mounted]);

  useEffect(() => {
    if (!mounted) return;
    function handleKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape") {
        event.preventDefault();
        onCloseRef.current();
      }
    }
    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
  }, [mounted]);

  const handleBackdropClick = (event: MouseEvent<HTMLDivElement>) => {
    if (event.target === event.currentTarget) {
      onClose();
    }
  };

  if (!mounted) {
    return null;
  }

  return createPortal(
    <div
      className="fixed inset-0 z-[200] flex items-end justify-center bg-slate-950/45 p-4 backdrop-blur-[2px] sm:items-center"
      onClick={handleBackdropClick}
      role="dialog"
      aria-modal="true"
      aria-label={ariaLabel}
    >
      <div
        ref={panelRef}
        className={`relative ${panelClassName}`}
        onClick={(event) => event.stopPropagation()}
      >
        {children}
      </div>
    </div>,
    document.body,
  );
}

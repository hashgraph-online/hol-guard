import { useEffect, useRef } from "react";

function getFocusableElements(container: HTMLElement): HTMLElement[] {
  const selector = [
    'button:not([disabled])',
    'a[href]',
    'input:not([disabled])',
    'select:not([disabled])',
    'textarea:not([disabled])',
    '[tabindex]:not([tabindex="-1"])',
    '[contenteditable]',
  ].join(",");
  return Array.from(container.querySelectorAll(selector)).filter(
    (el): el is HTMLElement => el instanceof HTMLElement && el.offsetParent !== null
  );
}

export function useFocusTrap(
  active: boolean,
  containerRef: React.RefObject<HTMLElement | null>,
  initialFocusRef?: React.RefObject<HTMLElement | null>,
) {
  const previouslyFocusedRef = useRef<HTMLElement | null>(null);

  useEffect(() => {
    if (!active) return;
    const container = containerRef.current;
    if (!container) return;
    const focusContainer = container;

    previouslyFocusedRef.current = document.activeElement as HTMLElement | null;

    const preferred = initialFocusRef?.current;
    if (preferred && getFocusableElements(focusContainer).some((element) => element === preferred)) {
      preferred.focus();
    } else {
      const initial = getFocusableElements(focusContainer);
      if (initial[0]) initial[0].focus();
    }

    function handleKeyDown(event: KeyboardEvent) {
      if (event.key !== "Tab") return;
      const focusable = getFocusableElements(focusContainer);
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (focusable.length === 0) {
        event.preventDefault();
        return;
      }
      if (event.shiftKey) {
        if (document.activeElement === first) {
          event.preventDefault();
          last?.focus();
        }
      } else if (document.activeElement === last) {
        event.preventDefault();
        first?.focus();
      }
    }

    focusContainer.addEventListener("keydown", handleKeyDown);
    return () => {
      focusContainer.removeEventListener("keydown", handleKeyDown);
      if (previouslyFocusedRef.current && previouslyFocusedRef.current.isConnected) {
        previouslyFocusedRef.current.focus();
      }
    };
  }, [active, containerRef, initialFocusRef]);
}

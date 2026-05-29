import { ae as reactExports } from "../guard-dashboard.js";
function getFocusableElements(container) {
  const selector = [
    "button:not([disabled])",
    "a[href]",
    "input:not([disabled])",
    "select:not([disabled])",
    "textarea:not([disabled])",
    '[tabindex]:not([tabindex="-1"])',
    "[contenteditable]"
  ].join(",");
  return Array.from(container.querySelectorAll(selector)).filter(
    (el) => el instanceof HTMLElement && el.offsetParent !== null
  );
}
function useFocusTrap(active, containerRef) {
  const previouslyFocusedRef = reactExports.useRef(null);
  reactExports.useEffect(() => {
    if (!active) return;
    const container = containerRef.current;
    if (!container) return;
    previouslyFocusedRef.current = document.activeElement;
    const focusable = getFocusableElements(container);
    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    if (first) {
      first.focus();
    }
    function handleKeyDown(event) {
      if (event.key !== "Tab") return;
      if (focusable.length === 0) {
        event.preventDefault();
        return;
      }
      if (event.shiftKey) {
        if (document.activeElement === first) {
          event.preventDefault();
          last?.focus();
        }
      } else {
        if (document.activeElement === last) {
          event.preventDefault();
          first?.focus();
        }
      }
    }
    container.addEventListener("keydown", handleKeyDown);
    return () => {
      container.removeEventListener("keydown", handleKeyDown);
      if (previouslyFocusedRef.current && previouslyFocusedRef.current.isConnected) {
        previouslyFocusedRef.current.focus();
      }
    };
  }, [active, containerRef]);
}
export {
  useFocusTrap as u
};

import { useEffect, useRef } from "react";

export function useKeyboardShortcut(
  key: string,
  callback: (event: KeyboardEvent) => void,
  options: { preventDefault?: boolean; requireModifier?: boolean } = {}
) {
  const callbackRef = useRef(callback);
  callbackRef.current = callback;

  useEffect(() => {
    function handleKeyDown(event: KeyboardEvent) {
      const target = event.target as HTMLElement;
      if (target.tagName === "INPUT" || target.tagName === "TEXTAREA" || target.isContentEditable) {
        return;
      }
      if (event.key !== key) return;
      if (options.preventDefault) {
        event.preventDefault();
      }
      callbackRef.current(event);
    }
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [key, options.preventDefault]);
}

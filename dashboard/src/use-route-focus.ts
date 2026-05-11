import { useEffect, useRef } from "react";

export function useRouteFocus(view: string, mainSelector = "main#main-content"): void {
  const prevViewRef = useRef<string | null>(null);

  useEffect(() => {
    if (prevViewRef.current === null) {
      prevViewRef.current = view;
      return;
    }
    if (prevViewRef.current === view) {
      return;
    }
    prevViewRef.current = view;

    const main = document.querySelector<HTMLElement>(mainSelector);
    if (main) {
      main.focus({ preventScroll: true });
    }
  }, [view, mainSelector]);
}

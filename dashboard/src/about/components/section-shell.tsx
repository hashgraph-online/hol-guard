import { useRef, useEffect, useState, type ReactNode } from "react";

export function useEditorialVisibility(threshold = 0.08) {
  const ref = useRef<HTMLElement>(null);
  const [state, setState] = useState<"idle" | "hidden" | "visible">("idle");

  useEffect(() => {
    if (typeof IntersectionObserver === "undefined") {
      setState("visible");
      return;
    }
    setState("hidden");
    const el = ref.current;
    if (!el) return;
    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          setState("visible");
          observer.disconnect();
        }
      },
      { threshold }
    );
    observer.observe(el);
    return () => observer.disconnect();
  }, [threshold]);

  return { ref, state };
}

export function SectionShell({
  children,
  className = "",
  threshold = 0.08,
  id,
}: {
  children: ReactNode;
  className?: string;
  threshold?: number;
  id?: string;
}) {
  const { ref, state } = useEditorialVisibility(threshold);

  return (
    <section
      id={id}
      ref={ref}
      className={[
        className,
        state === "idle"
          ? ""
          : "motion-safe:transition-[opacity,transform] transition-opacity duration-700 ease-[cubic-bezier(0.16,1,0.3,1)]",
        state === "idle" || state === "visible"
          ? "opacity-100 translate-y-0"
          : "opacity-0 motion-safe:translate-y-6",
      ].join(" ")}
    >
      {children}
    </section>
  );
}

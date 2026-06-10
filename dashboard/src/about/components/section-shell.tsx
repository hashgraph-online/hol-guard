import { useRef, useEffect, useState, type ReactNode } from "react";

export function useEditorialVisibility(threshold = 0.08) {
  const ref = useRef<HTMLElement>(null);
  const [revealed, setRevealed] = useState(
    typeof IntersectionObserver === "undefined",
  );

  useEffect(() => {
    if (revealed) {
      return;
    }
    const el = ref.current;
    if (!el) {
      setRevealed(true);
      return;
    }
    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          setRevealed(true);
          observer.disconnect();
        }
      },
      { threshold, rootMargin: "0px 0px 10% 0px" },
    );
    observer.observe(el);
    return () => observer.disconnect();
  }, [threshold, revealed]);

  return { ref, revealed };
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
  const { ref, revealed } = useEditorialVisibility(threshold);

  return (
    <section
      id={id}
      ref={ref}
      className={[
        className,
        "opacity-100 translate-y-0",
        revealed
          ? "motion-safe:transition-[opacity,transform] transition-opacity duration-700 ease-[cubic-bezier(0.16,1,0.3,1)]"
          : "",
      ].join(" ")}
    >
      {children}
    </section>
  );
}

import { useEffect, useId, useLayoutEffect, useRef, useState, type KeyboardEvent, type ReactNode } from "react";
import { HiMiniCheck, HiMiniChevronUpDown } from "react-icons/hi2";

export type SelectMenuOption<T extends string = string> = {
  value: T;
  label: string;
  description?: string;
  disabled?: boolean;
};

export type SelectMenuProps<T extends string> = {
  value: T;
  options: ReadonlyArray<SelectMenuOption<T>>;
  onChange: (value: T) => void;
  id?: string;
  /** Accessible name when no visible label references the control. */
  label?: string;
  labelledBy?: string;
  describedBy?: string;
  placeholder?: string;
  disabled?: boolean;
  className?: string;
  /** Optional leading content inside the button, such as an icon. */
  leading?: ReactNode;
};

const useClientLayoutEffect = typeof window === "undefined" ? useEffect : useLayoutEffect;

/**
 * The dashboard's dropdown: an APG select-only combobox. Focus stays on the
 * button while arrow keys move the active option, so screen readers announce
 * each option and the page never loses its place. Options stay in the DOM
 * while closed so server-rendered markup still describes every choice.
 */
export function SelectMenu<T extends string>(props: SelectMenuProps<T>) {
  const generated = useId();
  const id = props.id ?? generated;
  const listId = id + "-listbox";
  const optionId = (index: number) => id + "-option-" + index;
  const button = useRef<HTMLButtonElement>(null);
  const list = useRef<HTMLUListElement>(null);
  const typed = useRef({ text: "", at: 0 });
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(-1);
  const [upward, setUpward] = useState(false);
  const selectedIndex = props.options.findIndex((option) => option.value === props.value);
  const selected = selectedIndex >= 0 ? props.options[selectedIndex] : undefined;
  const enabled = (index: number) => index >= 0 && index < props.options.length && !props.options[index].disabled;

  function step(from: number, direction: 1 | -1): number {
    for (let index = from + direction; index >= 0 && index < props.options.length; index += direction) {
      if (enabled(index)) return index;
    }
    return from;
  }
  const first = () => step(-1, 1);
  const last = () => step(props.options.length, -1);

  function show(start?: number) {
    if (props.disabled || open) return;
    const rect = button.current?.getBoundingClientRect();
    if (rect) {
      const below = window.innerHeight - rect.bottom;
      setUpward(below < 300 && rect.top > below);
    }
    setActive(start ?? (enabled(selectedIndex) ? selectedIndex : first()));
    setOpen(true);
  }
  function hide() {
    setOpen(false);
    setActive(-1);
  }
  function choose(index: number) {
    if (!enabled(index)) return;
    hide();
    if (props.options[index].value !== props.value) props.onChange(props.options[index].value);
  }

  useEffect(() => {
    if (!open) return;
    const close = (event: PointerEvent) => {
      const target = event.target as Node;
      if (!button.current?.contains(target) && !list.current?.contains(target)) hide();
    };
    document.addEventListener("pointerdown", close);
    return () => document.removeEventListener("pointerdown", close);
  }, [open]);

  useClientLayoutEffect(() => {
    if (!open || active < 0) return;
    document.getElementById(optionId(active))?.scrollIntoView({ block: "nearest" });
  }, [open, active]);

  function typeahead(key: string) {
    const now = Date.now();
    const text = (now - typed.current.at > 600 ? "" : typed.current.text) + key.toLowerCase();
    typed.current = { text, at: now };
    const from = open ? active : selectedIndex;
    const order = props.options.map((_, index) => (from + 1 + index) % props.options.length);
    const repeated = text.length > 1 && [...text].every((char) => char === text[0]);
    const match = order.find((index) => enabled(index)
      && props.options[index].label.toLowerCase().startsWith(repeated ? text[0] : text));
    if (match === undefined) return;
    if (open) setActive(match);
    else show(match);
  }

  function onKeyDown(event: KeyboardEvent<HTMLButtonElement>) {
    const key = event.key;
    if (!open) {
      if (key === "ArrowDown" || key === "ArrowUp" || key === "Enter" || key === " ") {
        event.preventDefault();
        show(key === "ArrowUp" && !enabled(selectedIndex) ? last() : undefined);
      } else if (key === "Home" || key === "End") {
        event.preventDefault();
        show(key === "Home" ? first() : last());
      } else if (key.length === 1 && !event.metaKey && !event.ctrlKey && !event.altKey) {
        typeahead(key);
      }
      return;
    }
    if (key === "ArrowDown" || key === "ArrowUp") {
      event.preventDefault();
      if (event.altKey && key === "ArrowUp") { choose(active); return; }
      setActive(step(active, key === "ArrowDown" ? 1 : -1));
    } else if (key === "Home" || key === "End" || key === "PageUp" || key === "PageDown") {
      event.preventDefault();
      setActive(key === "Home" || key === "PageUp" ? first() : last());
    } else if (key === "Enter" || key === " ") {
      event.preventDefault();
      choose(active);
    } else if (key === "Escape") {
      event.preventDefault();
      hide();
    } else if (key === "Tab") {
      hide();
    } else if (key.length === 1 && !event.metaKey && !event.ctrlKey && !event.altKey) {
      event.preventDefault();
      typeahead(key);
    }
  }

  return <div className={"relative " + (props.className ?? "w-full")}>
    <button ref={button} id={id} type="button" role="combobox" aria-haspopup="listbox" aria-expanded={open} data-value={props.value}
      aria-controls={listId} aria-activedescendant={open && active >= 0 ? optionId(active) : undefined}
      aria-label={props.label} aria-labelledby={props.labelledBy} aria-describedby={props.describedBy}
      disabled={props.disabled} onKeyDown={onKeyDown} onBlur={hide}
      onClick={() => { if (open) hide(); else show(); }}
      className="group relative flex min-h-11 w-full items-center gap-2 rounded-lg border border-slate-200 bg-white py-2 pl-3 pr-10 text-left text-sm text-brand-dark shadow-[0_1px_0_rgba(15,23,42,0.04)] transition-colors hover:border-brand-blue/40 focus-visible:border-brand-blue focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/25 disabled:cursor-not-allowed disabled:bg-slate-50 disabled:text-slate-500 aria-expanded:border-brand-blue aria-expanded:ring-2 aria-expanded:ring-brand-blue/20">
      {props.leading}
      <span className={"min-w-0 flex-1 truncate" + (selected ? "" : " text-slate-500")}>{selected?.label ?? props.placeholder ?? "Choose an option"}</span>
      <HiMiniChevronUpDown aria-hidden="true" className="pointer-events-none absolute right-3 top-1/2 size-4 -translate-y-1/2 text-slate-400 group-hover:text-brand-blue" />
    </button>
    <ul ref={list} id={listId} role="listbox" tabIndex={-1} hidden={!open}
      aria-labelledby={props.labelledBy} aria-label={props.labelledBy ? undefined : props.label}
      onMouseDown={(event) => event.preventDefault()}
      className={"absolute left-0 z-50 max-h-72 w-full min-w-56 overflow-auto rounded-xl border border-slate-200 bg-white p-1 text-sm shadow-[0_18px_40px_-16px_rgba(15,23,42,0.35)] focus:outline-none "
        + (upward ? "bottom-full mb-1.5" : "top-full mt-1.5")}>
      {props.options.map((option, index) => {
        const isSelected = index === selectedIndex;
        const isActive = index === active;
        return <li key={option.value + ":" + index} id={optionId(index)} role="option" aria-selected={isSelected} data-value={option.value}
          aria-disabled={option.disabled ? true : undefined}
          onMouseMove={() => { if (enabled(index) && active !== index) setActive(index); }}
          onClick={() => choose(index)}
          className={"relative flex select-none flex-col rounded-lg py-2 pl-3 pr-9 "
            + (option.disabled ? "cursor-not-allowed text-slate-400" : "cursor-pointer text-brand-dark")
            + (isActive ? " bg-brand-blue/[0.08]" : "")}>
          <span className={"break-words " + (isSelected ? "font-semibold" : "font-medium")}>{option.label}</span>
          {option.description ? <span className={"mt-0.5 break-words text-xs " + (option.disabled ? "text-slate-400" : "text-slate-500")}>{option.description}</span> : null}
          {isSelected ? <HiMiniCheck aria-hidden="true" className="absolute right-2.5 top-2.5 size-4 text-brand-blue" /> : null}
        </li>;
      })}
    </ul>
  </div>;
}

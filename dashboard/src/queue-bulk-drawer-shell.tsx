import type * as React from "react";

export function BulkDrawerShell(props: {
  onClose: () => void;
  labelledBy: string;
  children: React.ReactNode;
  footer?: React.ReactNode;
  onSubmit?: React.FormEventHandler<HTMLFormElement>;
}) {
  return (
    <div
      className="fixed inset-0 z-50 flex items-end justify-center bg-black/30 p-0 backdrop-blur-sm sm:items-center sm:p-4"
      role="dialog"
      aria-modal="true"
      aria-labelledby={props.labelledBy}
      onClick={(event) => {
        if (event.target === event.currentTarget) props.onClose();
      }}
    >
      <form
        onSubmit={(event) => {
          event.preventDefault();
          props.onSubmit?.(event);
        }}
        className="guard-fade-in flex max-h-[92vh] w-full max-w-xl flex-col overflow-hidden rounded-t-2xl border border-slate-200 bg-white shadow-2xl sm:rounded-2xl"
      >
        <div className="flex-1 overflow-y-auto px-5 py-6 sm:px-7">{props.children}</div>
        {props.footer ? (
          <div className="border-t border-slate-100 bg-white/95 px-5 py-3.5 backdrop-blur sm:px-7">
            {props.footer}
          </div>
        ) : null}
      </form>
    </div>
  );
}

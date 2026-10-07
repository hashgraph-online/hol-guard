import { HiMiniFolder } from "react-icons/hi2";
import { ActionButton } from "./approval-center-primitives";

function folderParts(path: string): string[] {
  return path.replace(/[\\/]+$/, "").split(/[\\/]/).filter(Boolean);
}

function folderChoiceLabels(paths: readonly string[]): Map<string, string> {
  const bases = paths.map((path) => folderParts(path).at(-1) ?? path);
  const counts = new Map<string, number>();
  for (const base of bases) {
    counts.set(base, (counts.get(base) ?? 0) + 1);
  }
  return new Map(
    paths.map((path, index) => {
      const base = bases[index] ?? path;
      if ((counts.get(base) ?? 0) < 2) {
        return [path, base];
      }
      const parts = folderParts(path);
      const parent = parts.length >= 2 ? parts[parts.length - 2] : "";
      return [path, parent ? `${parent}/${base}` : base];
    }),
  );
}

type WorkspaceAuditFolderFieldProps = {
  value: string;
  choices?: readonly string[];
  choosing?: boolean;
  disabled?: boolean;
  pickerError?: string | null;
  onChange?: (workspaceDir: string) => void;
  onChoose?: () => void;
};

export function WorkspaceAuditFolderField({
  value,
  choices = [],
  choosing = false,
  disabled = false,
  pickerError = null,
  onChange,
  onChoose,
}: WorkspaceAuditFolderFieldProps) {
  const controlsDisabled = disabled || choosing;
  const choiceLabels = folderChoiceLabels(choices);
  return (
    <div className="border-y border-slate-100 py-4" data-testid="workspace-audit-folder-field">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div className="min-w-0 max-w-xl">
          <label className="block text-sm font-semibold text-brand-dark" htmlFor="workspace-audit-folder">
            Project folder
          </label>
          <p className="mt-1 text-xs leading-relaxed text-slate-600">
            Choose the folder that contains a package manifest or lockfile, or paste its path.
          </p>
        </div>
        {onChoose !== undefined ? (
          <ActionButton
            type="button"
            variant="outline"
            onClick={onChoose}
            disabled={controlsDisabled}
            aria-busy={choosing}
            data-testid="workspace-audit-choose-folder"
          >
            <HiMiniFolder className="mr-1.5 h-4 w-4" aria-hidden="true" />
            {choosing ? "Choosing folder…" : "Choose folder"}
          </ActionButton>
        ) : null}
      </div>
      {choices.length > 0 ? (
        <div className="mt-3 flex flex-wrap gap-2" role="group" aria-label="Known project folders">
          {choices.map((path) => {
            const selected = value === path;
            const label = choiceLabels.get(path) ?? path;
            return (
              <button
                key={path}
                type="button"
                aria-pressed={selected}
                title={path}
                disabled={controlsDisabled}
                onClick={() => onChange?.(path)}
                className={`max-w-full truncate rounded-full px-3 py-1 text-xs font-medium focus:outline-none focus:ring-2 focus:ring-brand-blue/30 disabled:opacity-50 ${
                  selected
                    ? "bg-brand-dark text-white"
                    : "border border-slate-200 bg-white text-slate-600 hover:bg-slate-50"
                }`}
              >
                {label}
              </button>
            );
          })}
        </div>
      ) : null}
      <input
        id="workspace-audit-folder"
        data-testid="workspace-audit-folder-input"
        type="text"
        inputMode="text"
        autoComplete="off"
        spellCheck={false}
        value={value}
        disabled={controlsDisabled}
        onChange={(event) => onChange?.(event.target.value)}
        placeholder="Paste a folder path"
        className="mt-3 block min-h-11 w-full rounded-lg border border-slate-200 bg-white px-3 font-mono text-sm text-brand-dark shadow-sm outline-none placeholder:font-sans placeholder:text-slate-400 focus:border-brand-blue focus:ring-2 focus:ring-brand-blue/20 disabled:bg-slate-50"
      />
      {pickerError ? (
        <p className="mt-2 text-xs leading-relaxed text-brand-attention" role="alert">
          {pickerError}
        </p>
      ) : null}
    </div>
  );
}

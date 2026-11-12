import { useCallback, useEffect, useId, useRef, useState } from "react";
import { HiMiniEye } from "react-icons/hi2";
import { ActionButton } from "./approval-center-primitives";
import type { WorkspaceFinding, WorktreeKeys } from "./workspace-findings-api";
import { Cell } from "./workspace-findings-tables";
import {
  ExportPreviewError,
  exclusionMessage,
  formatBytes,
  parseExportPaths,
  previewWorkspaceExport,
  type ExportPreview,
} from "./workspace-export-preview-api";
import { FixNotice } from "./workspace-fix-panel";

const RESULT_LABELS: Record<ExportPreview["status"], string> = {
  ready: "Ready",
  empty: "Nothing to export",
  blocked: "Blocked",
};

/**
 * Files the latest check points at, as a starting list. Runtime findings name
 * an executable outside the workspace, so they are left off.
 */
export function suggestedExportPaths(findings: WorkspaceFinding[]): string[] {
  const paths = new Set<string>();
  for (const finding of findings) {
    if (finding.kind !== "runtime" && finding.path) paths.add(finding.path);
  }
  return [...paths];
}

export type ExportPreviewViewProps = {
  input: string;
  busy: boolean;
  error: string | null;
  preview: ExportPreview | null;
  /** True when the list was edited after the preview shown below was built. */
  edited: boolean;
  onInput: (value: string) => void;
  onPreview: () => void;
  onClose: () => void;
};

export function ExportPreviewView(props: ExportPreviewViewProps) {
  const id = useId();
  const headingId = `${id}-heading`;
  const fieldId = `${id}-paths`;
  const hintId = `${id}-hint`;
  const { preview } = props;
  return (
    <section aria-labelledby={headingId} className="space-y-4 rounded-xl border border-slate-200 bg-surface-1/60 px-4 py-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0 flex-1 basis-64">
          <h4 id={headingId} className="text-sm font-semibold text-brand-dark">
            Preview a source export
          </h4>
          <p className="mt-1 max-w-[68ch] text-sm text-slate-600">
            See what sharing these files would carry before anything leaves this device. Guard leaves out credential
            files and folders such as .git, and replaces each secret it finds with [REDACTED]. A preview sends nothing
            and never changes your files.
          </p>
        </div>
        <ActionButton variant="ghost" onClick={props.onClose} disabled={props.busy}>
          Close
        </ActionButton>
      </div>
      <div className="space-y-2">
        <label htmlFor={fieldId} className="block text-sm font-semibold text-brand-dark">
          Files to include
        </label>
        <p id={hintId} className="text-xs text-slate-600">
          One path per line, relative to the workspace folder. Starts with the files this check points at.
        </p>
        <textarea
          id={fieldId}
          aria-describedby={hintId}
          value={props.input}
          onChange={(event) => props.onInput(event.target.value)}
          rows={4}
          spellCheck={false}
          autoCapitalize="off"
          autoCorrect="off"
          placeholder={"src/app.py\npackage.json"}
          className="w-full rounded-xl border border-slate-200 bg-white px-3 py-2.5 font-mono text-xs text-slate-800 focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
        />
        <ActionButton onClick={props.onPreview} disabled={props.busy}>
          <HiMiniEye className="h-4 w-4" aria-hidden="true" />
          {props.busy ? "Reading files…" : preview ? "Preview again" : "Preview export"}
        </ActionButton>
      </div>
      <div aria-live="polite" className="space-y-4">
        {props.error && <FixNotice tone="error" text={props.error} />}
        {preview && <PreviewResult preview={preview} edited={props.edited} />}
      </div>
    </section>
  );
}

function PreviewResult({ preview, edited }: { preview: ExportPreview; edited: boolean }) {
  return (
    <div className="space-y-3" data-testid="export-preview-result">
      {edited && <FixNotice tone="warning" text="The list changed after this preview. Preview again to check it." />}
      {preview.status === "blocked" && (
        <FixNotice
          tone="error"
          text="Guard could not confirm the file marked below is free of secrets after redaction, so this selection cannot be exported. Remove any secret from that file, or take it off the list."
        />
      )}
      {preview.status === "empty" && (
        <FixNotice tone="warning" text="None of these files can be exported. Each one is listed below with the reason." />
      )}
      {preview.status === "ready" && preview.redactions > 0 && (
        <FixNotice
          tone="success"
          text={`Guard would replace ${preview.redactions === 1 ? "1 secret" : `${preview.redactions} secrets`} with [REDACTED]. Your files stay as they are.`}
        />
      )}
      <dl className="grid grid-cols-2 gap-x-6 border-y border-slate-200 sm:grid-cols-3 lg:grid-cols-5">
        <Fact label="Result" value={RESULT_LABELS[preview.status]} />
        <Fact label="Files" value={String(preview.files.length)} />
        <Fact label="Export size" value={formatBytes(preview.exportBytes)} />
        <Fact label="Secrets replaced" value={String(preview.redactions)} />
        <Fact label="Destination" value="None" title="A preview stays on this device." />
      </dl>
      {preview.files.length > 0 && <IncludedFiles preview={preview} />}
      {preview.excluded.length > 0 && (
        <div className="space-y-1">
          <p className="text-sm font-semibold text-brand-dark">Left out</p>
          <ul className="space-y-1 text-sm text-slate-600">
            {preview.excluded.map((item) => (
              <li key={`${item.path}:${item.reason}`} className="min-w-0">
                <span className={`break-all font-mono text-xs ${item.reason === "redaction_failed" ? "font-semibold text-red-800" : "text-slate-700"}`}>
                  {item.path || "(empty line)"}
                </span>{" "}
                {exclusionMessage(item.reason)}
              </li>
            ))}
          </ul>
        </div>
      )}
      <p className="text-xs text-slate-500">
        Bundle fingerprint <span className="break-all font-mono">{preview.bundleDigest}</span>. It changes whenever an
        included file does.
      </p>
    </div>
  );
}

function IncludedFiles({ preview }: { preview: ExportPreview }) {
  return (
    <div className="overflow-hidden rounded-xl border border-slate-200 bg-white">
      <table className="w-full text-left text-sm">
        <caption className="sr-only">Files an export would include</caption>
        <thead className="hidden bg-slate-50 text-xs font-semibold text-slate-600 md:table-header-group">
          <tr>
            <th scope="col" className="px-3 py-2">File</th>
            <th scope="col" className="px-3 py-2 text-right">On disk</th>
            <th scope="col" className="px-3 py-2 text-right">Exported</th>
            <th scope="col" className="px-3 py-2 text-right">Secrets replaced</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-100">
          {preview.files.map((file) => (
            <tr key={file.path} className="grid grid-cols-3 gap-x-3 gap-y-2 px-3 py-3 md:table-row md:p-0">
              <td className="col-span-3 min-w-0 md:col-span-1 md:px-3 md:py-2.5">
                <span className="block text-xs font-semibold text-slate-500 md:hidden">File</span>
                <span className="break-all font-mono text-xs text-slate-800">{file.path}</span>
              </td>
              <Cell label="On disk"><Num value={formatBytes(file.bytes)} /></Cell>
              <Cell label="Exported"><Num value={formatBytes(file.exportBytes)} /></Cell>
              <Cell label="Secrets replaced"><Num value={String(file.redactions)} /></Cell>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Num({ value }: { value: string }) {
  return <span className="block font-mono text-xs tabular-nums text-slate-700 md:text-right">{value}</span>;
}

function Fact(props: { label: string; value: string; title?: string }) {
  return (
    <div className="min-w-0 py-2">
      <dt className="text-xs text-slate-500">{props.label}</dt>
      <dd className="text-sm font-semibold tabular-nums text-brand-dark" title={props.title}>
        {props.value}
      </dd>
    </div>
  );
}

/** Closed until asked for: a preview reads files, so the tab never starts one on its own. */
export function ExportPreviewPanel(props: { worktree: WorktreeKeys; findings: WorkspaceFinding[] }) {
  const [open, setOpen] = useState(false);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [preview, setPreview] = useState<{ input: string; result: ExportPreview } | null>(null);
  const mounted = useRef(true);
  // The list on screen now, so a failure for an older submission is not shown against it.
  const latestInput = useRef(input);
  latestInput.current = input;
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  const { worktree, findings } = props;
  const show = useCallback(() => {
    setInput(suggestedExportPaths(findings).join("\n"));
    setPreview(null);
    setError(null);
    setOpen(true);
  }, [findings]);

  const run = useCallback(async () => {
    const submitted = input;
    setBusy(true);
    setError(null);
    try {
      const result = await previewWorkspaceExport(worktree, parseExportPaths(submitted));
      if (mounted.current) setPreview({ input: submitted, result });
    } catch (caught) {
      if (!mounted.current) return;
      // A failed retry must not leave the previous result on screen as if it still held.
      setPreview(null);
      if (latestInput.current !== submitted) return;
      setError(caught instanceof ExportPreviewError ? caught.message : new ExportPreviewError("workspace_export_preview_failed").message);
    } finally {
      if (mounted.current) setBusy(false);
    }
  }, [input, worktree]);

  if (!open) {
    return (
      <div className="flex flex-wrap items-center justify-between gap-3 border-t border-slate-100 pt-3">
        <p className="max-w-[68ch] text-sm text-slate-600">
          Check what sharing source from this workspace would send, with secrets redacted, before anything leaves this
          device.
        </p>
        <ActionButton variant="outline" onClick={show}>
          <HiMiniEye className="h-4 w-4" aria-hidden="true" />
          Preview a source export
        </ActionButton>
      </div>
    );
  }
  return (
    <ExportPreviewView
      input={input}
      busy={busy}
      error={error}
      preview={preview?.result ?? null}
      edited={preview !== null && preview.input !== input}
      onInput={(value) => {
        // An error about the old list does not describe the edited one.
        setInput(value);
        setError(null);
      }}
      onPreview={() => void run()}
      onClose={() => setOpen(false)}
    />
  );
}

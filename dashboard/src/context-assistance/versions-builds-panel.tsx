import { useId, useState, type ReactNode } from "react";
import { HiMiniChevronRight } from "react-icons/hi2";
import { Tag } from "../approval-center-primitives";
import { SelectMenu } from "../select-menu";
import type { ContextAssistanceStatus, ContextInstallation } from "./types";
import { cigarBuildBlock, cigarJobPending, cigarPythonBlock, cigarVersionJobId } from "./versions-actions";
import type { CigarCatalogBuild, CigarInterpreterBuild } from "./versions-catalog";
import type { CigarVersionsData } from "./versions-data";
import { installationLabel, platformLabel, versionButton, versionBytes, versionHeading, versionLead, versionList,
  type CigarVersionActionHandler } from "./versions-view";
type Props = { data: CigarVersionsData; status: ContextAssistanceStatus | null; disabled: boolean; selectionDisabled: boolean; onAction: CigarVersionActionHandler };
const CHANNEL: Record<CigarCatalogBuild["channel"], string> = { stable: "Stable", preview: "Preview", local_candidate: "Local build" };
const summary = "flex min-h-11 cursor-pointer list-none items-center gap-1.5 text-sm font-semibold text-brand-dark/75 hover:text-brand-dark [&::-webkit-details-marker]:hidden";

function Row(props: { titleId: string; describedBy?: string; title: ReactNode; tags: ReactNode; meta: ReactNode; reason?: ReactNode; extra?: ReactNode; action: ReactNode }) {
  return <li className="flex flex-wrap items-start gap-x-4 gap-y-3 px-4 py-4 sm:px-5" aria-labelledby={props.describedBy ? props.titleId + " " + props.describedBy : props.titleId}>
    <div className="min-w-0 flex-[1_1_18rem] space-y-1.5">
      <div className="flex flex-wrap items-center gap-2">
        <h4 id={props.titleId} className="font-mono text-sm font-semibold tabular-nums text-brand-dark">{props.title}</h4>
        {props.tags}
      </div>
      <p className="text-xs leading-5 text-brand-dark/65">{props.meta}</p>
      {props.reason}
      {props.extra}
    </div>
    <div className="flex shrink-0 flex-wrap items-center gap-2">{props.action}</div>
  </li>;
}

export function CigarVersionBuildsPanel({ data, status, disabled, selectionDisabled, onAction }: Props) {
  const [python, setPython] = useState("");
  const id = useId(), catalog = data.catalog;
  const selectedId = status?.preferences.runtime_id ?? "";
  const registered = data.interpreters.filter((p) => p.platform === catalog.host_platform);
  const interpreter = registered.find((p) => p.interpreter_id === python) ?? registered[0];
  const activeSelection = data.jobs.some((job) => job.family === "selection" && (cigarJobPending(job) || job.recovery_available));
  const selectionBlocked = selectionDisabled || !status || activeSelection;
  const matched = new Set<string>();
  const installationFor = (build: CigarCatalogBuild) => {
    const found = data.installations.find((item) => item.build_id === build.identity.build_id);
    if (found) matched.add(found.runtime_id);
    return found;
  };
  const inUseTag = (item: ContextInstallation) => item.runtime_id === selectedId
    ? <Tag tone="green">{status?.runtime?.active ? "In use · running" : "In use"}</Tag> : <Tag tone="blue">Installed</Tag>;
  const prepareSelection = (item: ContextInstallation) => <button type="button" className={versionButton} disabled={selectionBlocked || item.runtime_id === selectedId}
    onClick={() => { if (status) onAction({ input: { action: "prepare_switch", job_id: cigarVersionJobId(), target_runtime_id: item.runtime_id, expected_generation: status.generation },
      title: "Prepare CIGAR selection", detail: "Verify this target and its data without committing a runtime switch. CIGAR stays off if it is off now." }); }}>Prepare selection</button>;

  const buildRows = catalog.builds.map((build) => {
    const buildId = build.identity.build_id, installed = installationFor(build);
    const reason = installed ? null : cigarBuildBlock(catalog, build, data.updates), host = build.platforms.find((p) => p.platform === catalog.host_platform);
    return <Row key={buildId} titleId={id + "-build-" + buildId} describedBy={id + "-build-id-" + buildId}
      title={"CIGAR " + build.identity.sdk_version}
      tags={<>{installed ? inUseTag(installed) : null}<Tag tone={build.channel === "stable" ? "slate" : "attention"}>{CHANNEL[build.channel]}</Tag>{build.withdrawn ? <Tag tone="red">Withdrawn</Tag> : null}</>}
      meta={<>Core {build.identity.core_version} · {host ? "download " + versionBytes(host.download_bytes) : "not built for this computer"}{installed ? " · " + installationLabel(installed.qualification) : ""}</>}
      reason={reason ? <p id={id + "-build-reason-" + buildId} className="text-sm text-amber-800">{reason}</p> : null}
      extra={<details className="group text-xs text-brand-dark/60"><summary className="inline-flex min-h-8 cursor-pointer list-none items-center gap-1 font-medium hover:text-brand-dark [&::-webkit-details-marker]:hidden">
        <HiMiniChevronRight aria-hidden="true" className="size-3.5 transition-transform group-open:rotate-90 motion-reduce:transition-none" />Build identity</summary>
        <div className="mt-1 space-y-0.5 break-all pl-5 font-mono"><p id={id + "-build-id-" + buildId}>Build: {buildId}</p><p>Source: {build.identity.source_revision}</p><p>Manifest: {build.identity.manifest_sha256}</p>
          {host ? <p>Worker: {host.worker_sha256}</p> : null}</div>
      </details>}
      action={installed ? prepareSelection(installed) : <button type="button" className={versionButton} aria-describedby={reason ? id + "-build-reason-" + buildId : undefined} disabled={disabled || reason !== null || !interpreter}
        onClick={() => { if (interpreter) onAction({ input: { action: "install", job_id: cigarVersionJobId(), build_id: buildId, interpreter_id: interpreter.interpreter_id },
          title: "Prepare CIGAR build", detail: "Download and verify this SDK in a separate managed installation. Keep the selected runtime in place." }); }}>Prepare this build</button>} />;
  });
  const looseRows = data.installations.filter((item) => !matched.has(item.runtime_id)).map((item) => <Row key={item.runtime_id}
    titleId={id + "-installed-" + item.runtime_id} title={"CIGAR " + (item.sdk_version ?? "registered bundle")} tags={inUseTag(item)}
    meta={<>Core {item.core_version ?? "not reported"} · Python {item.python_version.join(".")} · {item.managed ? "Guard managed" : "added outside Guard"} · {installationLabel(item.qualification)}</>}
    extra={<p className="break-all font-mono text-xs text-brand-dark/50">Build: {item.build_id ?? "legacy registration"}</p>}
    action={prepareSelection(item)} />);

  const pythonRow = (build: CigarInterpreterBuild) => {
    const reason = cigarPythonBlock(catalog, build), present = data.interpreters.some((p) => p.build_id === build.build_id);
    return <Row key={build.build_id} titleId={id + "-python-" + build.build_id} describedBy={id + "-python-id-" + build.build_id}
      title={"Python " + build.python_version.join(".")} tags={<>{present ? <Tag tone="green">Ready</Tag> : null}<Tag tone="slate">{platformLabel(build.platform)}</Tag></>}
      meta={<span id={id + "-python-id-" + build.build_id} className="break-all">{build.build_id} · download {versionBytes(build.archive_bytes)}</span>}
      reason={reason && build.platform === catalog.host_platform ? <p id={id + "-python-reason-" + build.build_id} className="text-sm text-amber-800">{reason}</p> : null}
      action={<button type="button" className={versionButton} aria-describedby={reason && build.platform === catalog.host_platform ? id + "-python-reason-" + build.build_id : undefined} disabled={disabled || present || reason !== null}
        onClick={() => onAction({ input: { action: "setup_interpreter", job_id: cigarVersionJobId(), build_id: build.build_id },
          title: "Prepare private Python", detail: "Download and verify the catalog's immutable Python build. Leave your system Python and current CIGAR selection unchanged." })}>{present ? "Python registered" : "Prepare private Python"}</button>} />;
  };
  const hostPython = catalog.interpreter_builds.filter((b) => !catalog.host_platform || b.platform === catalog.host_platform);
  const otherPython = catalog.interpreter_builds.filter((b) => catalog.host_platform && b.platform !== catalog.host_platform);
  const pythonOptions = registered.map((p) => ({ value: p.interpreter_id,
    label: "Python " + p.python_version.join(".") + (p.managed ? " · set up by Guard" : " · already on this computer"), description: p.interpreter_id }));

  return <div className="space-y-8">
    <section className="space-y-3" aria-labelledby={id + "-builds"}>
      <div className="flex flex-wrap items-end justify-between gap-x-6 gap-y-3">
        <div><h3 id={id + "-builds"} className={versionHeading}>Versions</h3>
          <p className={versionLead}>Preparing a version downloads it next to the one you have. Nothing changes until you switch.</p></div>
        <div className="w-full sm:w-72"><span id={id + "-python-label"} className="text-xs font-medium text-brand-dark/65">Python for SDK preparation</span>
          <SelectMenu labelledBy={id + "-python-label"} className="mt-1.5 w-full" value={interpreter?.interpreter_id ?? ""} disabled={disabled || !registered.length}
            placeholder="No Python interpreter registered for this host" options={pythonOptions} onChange={setPython} /></div>
      </div>
      {!catalog.builds.length && !data.installations.length ? <p className="rounded-2xl border border-dashed border-brand-dark/15 p-5 text-sm text-brand-dark/65">No SDK builds are available in this catalog.</p>
        : <ul className={versionList}>{buildRows}{looseRows}</ul>}
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
        {selectedId ? <button type="button" className={versionButton} disabled={selectionBlocked}
          onClick={() => { if (status) onAction({ input: { action: "prepare_rollback", job_id: cigarVersionJobId(), expected_generation: status.generation },
            title: "Prepare last good CIGAR build", detail: "Verify the last good installation and current data. Guard will offer a separate explicit rollback switch when it is ready." }); }}>Prepare last good build</button> : null}
        <p className="text-xs leading-5 text-brand-dark/60">{activeSelection ? <span role="status">Finish, cancel or recover the current selection job before preparing another.</span>
          : "Something wrong after a switch? Go back to the last version that worked."}</p>
      </div>
    </section>
    <section className="space-y-3" aria-labelledby={id + "-python"}>
      <div><h3 id={id + "-python"} className={versionHeading}>Python for CIGAR</h3>
        <p className={versionLead}>CIGAR runs on its own private copy of Python. Your system Python is never touched.</p></div>
      {!catalog.interpreter_builds.length ? <p className="text-sm text-brand-dark/65">No private Python builds are listed.</p> : null}
      {hostPython.length ? <ul className={versionList}>{hostPython.map(pythonRow)}</ul> : null}
      {otherPython.length ? <details className="group">
        <summary className={summary}><HiMiniChevronRight aria-hidden="true" className="size-4 transition-transform group-open:rotate-90 motion-reduce:transition-none" />
          Builds for other computers <span className="font-normal text-brand-dark/50">({otherPython.length})</span></summary>
        <ul className={versionList + " mt-2 opacity-90"}>{otherPython.map(pythonRow)}</ul>
      </details> : null}
    </section>
  </div>;
}

import { useId, useState } from "react";
import type { ContextAssistanceStatus } from "./types";
import { cigarBuildBlock, cigarJobPending, cigarPythonBlock, cigarVersionJobId } from "./versions-actions";
import type { CigarVersionsData } from "./versions-data";
import { versionButton, versionBytes, versionCard, versionField, type CigarVersionActionHandler } from "./versions-view";
type Props = { data: CigarVersionsData; status: ContextAssistanceStatus | null; disabled: boolean; selectionDisabled: boolean; onAction: CigarVersionActionHandler };
export function CigarVersionBuildsPanel({ data, status, disabled, selectionDisabled, onAction }: Props) {
  const [python, setPython] = useState("");
  const id = useId(), catalog = data.catalog;
  const registered = data.interpreters.filter((p) => p.platform === catalog.host_platform);
  const interpreter = registered.find((p) => p.interpreter_id === python) ?? registered[0];
  const activeSelection = data.jobs.some((job) => job.family === "selection" && (cigarJobPending(job) || job.recovery_available));
  const selectionBlocked = selectionDisabled || !status || activeSelection;
  return <div className="space-y-6">
    <section className="space-y-3" aria-labelledby={id + "-installed"}>
      <h3 id={id + "-installed"} className="font-semibold text-brand-dark">Registered installations</h3>
      <p className="text-sm text-slate-600">Prepare a selection alongside your current runtime. Guard verifies the target and saved data before it offers a switch.</p>
      {!data.installations.length ? <p className="text-sm text-slate-600">Prepare an available SDK build below, or register an approved bundle with the Guard CLI.</p> : null}
      {data.installations.map((item) => <article key={item.runtime_id} className={versionCard} aria-labelledby={id + "-installed-" + item.runtime_id}>
        <h4 id={id + "-installed-" + item.runtime_id} className="font-semibold text-brand-dark">CIGAR {item.sdk_version ?? "registered bundle"}{item.runtime_id === status?.preferences.runtime_id ? status.runtime?.active ? " · selected · running" : " · selected" : ""}</h4>
        <p className="text-sm text-slate-600">Core {item.core_version ?? "not reported"} · Python {item.python_version.join(".")} · {item.platform} · {item.managed ? "Guard managed" : "externally registered"} · {item.qualification.replaceAll("_", " ")}</p>
        <p className="break-all text-xs text-slate-600">Build: {item.build_id ?? "legacy registration"}</p>
        <button type="button" className={versionButton} disabled={selectionBlocked || item.runtime_id === status?.preferences.runtime_id}
          onClick={() => { if (status) onAction({ input: { action: "prepare_switch", job_id: cigarVersionJobId(), target_runtime_id: item.runtime_id, expected_generation: status.generation },
            title: "Prepare CIGAR selection", detail: "Verify this target and its data without committing a runtime switch. CIGAR stays off if it is off now." }); }}>Prepare selection</button>
      </article>)}
      {status?.preferences.runtime_id ? <button type="button" className={versionButton} disabled={selectionBlocked}
        onClick={() => { if (status) onAction({ input: { action: "prepare_rollback", job_id: cigarVersionJobId(), expected_generation: status.generation },
          title: "Prepare last good CIGAR build", detail: "Verify the last good installation and current data. Guard will offer a separate explicit rollback switch when it is ready." }); }}>Prepare last good build</button> : null}
      {activeSelection ? <p role="status" className="text-sm text-slate-600">Finish, cancel or recover the current selection job before preparing another.</p> : null}
    </section>
    <section className="space-y-3" aria-labelledby={id + "-builds"}>
      <h3 id={id + "-builds"} className="font-semibold text-brand-dark">Available SDK builds</h3>
      <p className="text-sm text-slate-600">Preparing downloads a separate, verified installation. It keeps your current runtime selected.</p>
      <label className="block text-sm text-slate-600">Python for SDK preparation
        <select className={versionField} disabled={disabled || !registered.length} value={interpreter?.interpreter_id ?? ""} onChange={(event) => setPython(event.target.value)}>
          {!registered.length ? <option value="">No Python interpreter registered for this host</option> : null}
          {registered.map((p) => <option key={p.interpreter_id} value={p.interpreter_id}>Python {p.python_version.join(".")} · {p.managed ? "Guard managed" : "registered"} · {p.interpreter_id}</option>)}
        </select>
      </label>
      {!catalog.builds.length ? <p className="text-sm text-slate-600">No SDK builds are available in this catalog.</p> : null}
      {catalog.builds.map((build) => {
        const reason = cigarBuildBlock(catalog, build, data.updates), host = build.platforms.find((p) => p.platform === catalog.host_platform);
        return <article key={build.identity.build_id} className={versionCard} aria-labelledby={id + "-build-" + build.identity.build_id + " " + id + "-build-id-" + build.identity.build_id}>
          <h4 id={id + "-build-" + build.identity.build_id} className="font-semibold text-brand-dark">CIGAR {build.identity.sdk_version} · {build.channel.replaceAll("_", " ")}{build.withdrawn ? " · withdrawn" : ""}</h4>
          <p id={id + "-build-id-" + build.identity.build_id} className="break-all text-sm text-slate-600">Build: {build.identity.build_id}</p>
          <p className="text-sm text-slate-600">Core {build.identity.core_version} · {host ? "available for this host" : "no artifact for this host"}{host ? " · download " + versionBytes(host.download_bytes) : ""}</p>
          {reason ? <p id={id + "-build-reason-" + build.identity.build_id} className="text-sm text-amber-800">{reason}</p> : null}
          <button type="button" className={versionButton} aria-describedby={reason ? id + "-build-reason-" + build.identity.build_id : undefined} disabled={disabled || reason !== null || !interpreter}
            onClick={() => { if (interpreter) onAction({ input: { action: "install", job_id: cigarVersionJobId(), build_id: build.identity.build_id, interpreter_id: interpreter.interpreter_id },
              title: "Prepare CIGAR build", detail: "Download and verify this SDK in a separate managed installation. Keep the selected runtime in place." }); }}>Prepare this build</button>
          <details className="text-xs text-slate-600"><summary className="cursor-pointer">Build identity</summary>
            <p className="break-all">Source: {build.identity.source_revision}</p><p className="break-all">Manifest: {build.identity.manifest_sha256}</p>
            {host ? <p className="break-all">Worker: {host.worker_sha256}</p> : null}
          </details>
        </article>;
      })}
    </section>
    <section className="space-y-3" aria-labelledby={id + "-python"}>
      <h3 id={id + "-python"} className="font-semibold text-brand-dark">Private Python builds</h3>
      <p className="text-sm text-slate-600">Guard can prepare its own Python alongside your existing interpreters. Your system Python is unchanged.</p>
      {!catalog.interpreter_builds.length ? <p className="text-sm text-slate-600">No private Python builds are listed.</p> : null}
      {catalog.interpreter_builds.map((build) => {
        const reason = cigarPythonBlock(catalog, build), present = data.interpreters.some((p) => p.build_id === build.build_id);
        return <article key={build.build_id} className={versionCard} aria-labelledby={id + "-python-" + build.build_id + " " + id + "-python-id-" + build.build_id}>
          <h4 id={id + "-python-" + build.build_id} className="font-semibold text-brand-dark">Python {build.python_version.join(".")} · {build.platform}</h4>
          <p id={id + "-python-id-" + build.build_id} className="break-all text-xs text-slate-600">{build.build_id} · download {versionBytes(build.archive_bytes)}</p>
          {reason ? <p id={id + "-python-reason-" + build.build_id} className="text-sm text-amber-800">{reason}</p> : null}
          <button type="button" className={versionButton} aria-describedby={reason ? id + "-python-reason-" + build.build_id : undefined} disabled={disabled || present || reason !== null}
            onClick={() => onAction({ input: { action: "setup_interpreter", job_id: cigarVersionJobId(), build_id: build.build_id },
              title: "Prepare private Python", detail: "Download and verify the catalog's immutable Python build. Leave your system Python and current CIGAR selection unchanged." })}>{present ? "Python registered" : "Prepare private Python"}</button>
        </article>;
      })}
    </section>
  </div>;
}

'use strict';
let latest = null;
const $ = id => document.getElementById(id);
const text = (id, value) => { $(id).textContent = value; };
const gib = n => Number.isFinite(n) ? (n / 1073741824).toFixed(1) + ' GiB' : 'Unknown';
const stamp = n => n ? new Date(n * 1000).toLocaleString([], {month:'short',day:'numeric',hour:'2-digit',minute:'2-digit'}) : '—';
const duration = n => !Number.isFinite(n) ? '—' : n < 60 ? Math.round(n) + 's' : Math.floor(n / 60) + 'm ' + Math.round(n % 60) + 's';
function badge(id, label, kind) { text(id, label); $(id).className = 'badge ' + kind; }
function node(tag, value, cls) { const el = document.createElement(tag); if (value !== undefined) el.textContent = value; if (cls) el.className = cls; return el; }
function resources(s, fresh) {
  const host = fresh ? s.host || {} : {}, vm = fresh ? s.vm || {} : {};
  const rows = [
    ['Host storage', host.disk_free, host.disk_total, s.allocation?.host_disk_floor_gib],
    ['Host memory available', host.memory_available, host.memory_total, null],
    ['VM storage', vm.disk_free, vm.disk_total, s.allocation?.vm_disk_floor_gib],
    ['VM memory available', vm.memory_available, vm.memory_total, 1]
  ];
  $('resources').replaceChildren();
  for (const [label, free, total, floor] of rows) {
    const warn = Number.isFinite(free) && floor && free / 1073741824 < floor;
    const row = node('div', undefined, 'resource' + (warn ? ' warning' : ''));
    const caption = node('div', undefined, 'resource-label');
    caption.append(node('strong', label), node('span', Number.isFinite(total) ? gib(free) + ' free / ' + gib(total) : 'Unavailable'));
    const bar = node('progress'); bar.max = 100;
    bar.value = total ? Math.max(0, Math.min(100, 100 * (1 - free / total))) : 0;
    bar.setAttribute('aria-label', label + ' used');
    row.append(caption, bar); $('resources').append(row);
  }
  const a = s.allocation;
  text('allocation', a ? `Worker allocation: ${a.vm_cpus} vCPU · ${a.vm_memory_gib} GiB RAM · ${a.vm_disk_gib} GiB disk. Build container: ${a.build_memory_gib || 4} GiB RAM. Admission floors: host ${a.host_disk_floor_gib} GiB / VM ${a.vm_disk_floor_gib} GiB free. Bars show used capacity.` : 'Allocation not reported.');
}
function jobs(s) {
  const all = s.jobs || [], f = $('filter').value;
  const filtered = all.filter(j => f === 'all' || (f === 'passed' && (['passed','diagnostic-passed'].includes(j.state) || j.diagnostic_result?.status === 'diagnostic-passed')) ||
    (f === 'failed' && ['failed','build-failed','conformance-failed','invalid-evidence','unknown'].includes(j.state)) ||
    (f === 'active' && ['running','queued','waiting','waiting-candidate','preparing'].includes(j.state)));
  text('job-count', all.length); $('job-rows').replaceChildren();
  for (const j of filtered) {
    const row = node('tr'), name = node('td');
    const a = node('a', j.kind === 'local-candidate' ? j.title : j.kind === 'release' ? j.tag : '#' + j.pr + ' · ' + j.title);
    if (typeof j.url === 'string' && /^https:\/\/github\.com\//.test(j.url)) { a.href = j.url; a.target = '_blank'; a.rel = 'noopener noreferrer'; }
    name.append(a, node('small', j.sha?.slice(0, 10)));
    const state = node('td'), kind = j.state === 'passed' ? 'good' : ['failed','build-failed','conformance-failed','invalid-evidence','unknown'].includes(j.state) ? 'bad' : 'neutral';
    state.append(node('span', j.state.replaceAll('-', ' '), 'badge ' + kind));
    const began = j.events?.find(e => e.phase === 'admission')?.at || j.started_at;
    const elapsed = began ? (j.finished_at || Date.now()/1000) - began : null;
    const oldExit = j.local_build?.error?.match(/exit status (\d+)/);
    const reason = j.state === 'build-failed' && oldExit ?
      `Local build exited ${oldExit[1]}; benchmark did not execute. VM log: /var/lib/hol-gauntlet/builds/${j.id}/build.log` : j.reason;
    const detail = node('td', reason || '—');
    if (j.result?.cells?.length) {
      const verified = j.result.cells.filter(c=>c.status==='passed').length;
      detail.append(node('small',`${verified} / ${j.result.cells.length} strict controls passed · ${j.result.model_tokens ?? 'unknown'} model tokens`,verified===j.result.cells.length?'good':'bad'));
    }
    if (j.status_error) detail.append(node('small', 'PR status delivery failed: ' + j.status_error));
    const diagnostic = j.diagnostic_result || j.stage_result;
    if (diagnostic) {
      const passed = diagnostic.cells?.filter(c => c.status === 'passed').length || 0;
      detail.append(node('small', `${diagnostic.controls} diagnostic controls recorded · ${passed} verified passed` + (diagnostic.failed_roles?.length ? ' · failed: '+diagnostic.failed_roles.join(', ') : ''), passed === 6 ? 'good' : 'bad'));
      if (diagnostic.missing_capabilities?.length) detail.append(node('small', 'Strict benchmark admission blocked: '+diagnostic.missing_capabilities.join(', '), 'bad'));
      if (diagnostic.strict_result_preserved) detail.append(node('small', 'Staging diagnostics verified separately; strict benchmark result preserved.'));
    }
    if (j.source_error) detail.append(node('small', j.source_error));
    if (j.build_run?.html_url?.startsWith('https://github.com/')) {
      const a = node('a', 'Build: ' + (j.build_run.conclusion || j.build_run.status));
      a.href = j.build_run.html_url; a.target = '_blank'; a.rel = 'noopener noreferrer'; detail.append(node('br'), a);
    }
    row.append(name, state, node('td', stamp(began)), node('td', duration(elapsed)), detail);
    $('job-rows').append(row);
  }
  if (!filtered.length) { const tr = node('tr'), td = node('td', 'No matching jobs. Release tags and explicitly queued local candidates are admitted.', 'empty'); td.colSpan=5; tr.append(td); $('job-rows').append(tr); }
}
function activity(s, fresh) {
  const all = s.jobs || [];
  const job = all.find(j => ['running','preparing','unknown'].includes(j.state)) ||
    all.find(j => ['waiting','waiting-candidate','queued'].includes(j.state)) || all[0];
  $('activity-summary').replaceChildren(); $('control-progress').replaceChildren(); $('activity-events').replaceChildren();
  const held=s.admissions_held && !all.some(j=>['running','preparing','unknown'].includes(j.state));
  badge('activity-state', !fresh ? 'Stale' : held ? 'Admissions held' : job?.state || 'Idle', !fresh ? 'bad' : 'neutral');
  if (!job) { text('activity-subtitle', 'Watching ' + (s.release_tags || []).join(' + ') + '. No VM job is executing.'); return; }
  const p = job.vm_progress || {}, current = fresh && ['preparing','running','unknown'].includes(job.state) && Date.now()/1000 - (p.checked_at || 0) < 45;
  text('activity-subtitle', (job.kind === 'local-candidate' ? job.title : job.tag || '#' + job.pr) + ' · ' + job.sha.slice(0,12) + ' · job ' + job.id);
  const phase = held ? 'Admissions held for diagnosis' : current && p.phase !== 'not-started' ? p.phase : job.phase || job.state;
  const fields = [['Operation', phase.replaceAll('-', ' ')], ['Job age', duration((job.finished_at || Date.now()/1000) - job.created_at)],
    ['VM process', current ? p.process_alive ? 'PID ' + p.pid + ' · running' : 'No live process observed' : 'No current process observation'],
    ['Progress checked', current ? stamp(p.checked_at) : 'Unavailable / stale']];
  if (current && Number.isFinite(p.cpu_seconds)) fields.push(['Controller CPU / memory', duration(p.cpu_seconds) + ' / ' + gib(p.rss_bytes)]);
  if (current && p.product_cell) {
    const c=p.product_cell;
    fields.push(['Product cell memory', gib(c.memory_bytes)+' / '+gib(c.memory_limit_bytes)+' limit']);
    fields.push(['Product cell tasks', `${c.tasks ?? 'Unknown'} / ${c.task_limit ?? 'Unknown'} limit`]);
    if (Number.isFinite(c.native_virtual_bytes)) fields.push(['Largest native process · virtual memory', gib(c.native_virtual_bytes)+' / '+gib(c.native_address_space_limit_bytes)+' limit']);
    if (Number.isFinite(c.native_address_space_limit_bytes) && Number.isFinite(c.native_virtual_bytes)) fields.push(['Native virtual memory headroom', gib(Math.max(0,c.native_address_space_limit_bytes-c.native_virtual_bytes))]);
    if (c.oom_kills || c.pid_limit_hits) fields.push(['Cell resource events', `${c.oom_kills || 0} OOM kills · ${c.pid_limit_hits || 0} task-limit hits`]);
  }
  if (current && p.updated_at) fields.push(['Last VM stage change', stamp(p.updated_at)]);
  if (current && p.build_log_hints?.length) fields.push(['Compiler activity (reported)', p.build_log_hints.join(' · ')]);
  if (current && p.build_log_updated_at) fields.push(['Build output updated', stamp(p.build_log_updated_at)]);
  for (const [label,value] of fields) {const field=node('div');field.append(node('small',label),node('strong',value));$('activity-summary').append(field);}
  $('activity-summary').append(node('p', job.reason || '', 'activity-reason'));
  if (job.progress_error) $('activity-summary').append(node('p', 'Progress probe: ' + job.progress_error, 'activity-reason'));
  const diagnostic = job.diagnostic_result || job.stage_result;
  if (job.result?.cells?.length) {
    const cells=job.result.cells;
    $('control-progress').append(node('strong',`${cells.filter(c=>c.status==='passed').length} / ${cells.length} strict benchmark controls passed`));
    for (const c of cells) $('control-progress').append(node('span',c.episode_id+' · '+c.status,'badge '+(c.status==='passed'?'good':'bad')));
  } else if (diagnostic?.cells?.length) {
    $('control-progress').append(node('strong', `${diagnostic.cells.filter(c=>c.status==='passed').length} / ${diagnostic.controls} diagnostic controls verified`));
    for (const c of diagnostic.cells) $('control-progress').append(node('span', c.episode_id+' · '+c.status, 'badge '+(c.status==='passed'?'good':'bad')));
    if (diagnostic.benchmark_admitted === false) $('control-progress').append(node('small', 'Diagnostic evidence only. Strict benchmark admission has not passed.'));
  } else if (current && p.total_controls) {
    const complete = p.control_outcomes || p.completed_controls || [], names = complete.map(c => typeof c === 'string' ? c : c.role);
    $('control-progress').append(node('strong', `${complete.length} / ${p.total_controls} controls recorded`));
    if (p.current_control) $('control-progress').append(node('span', 'Executing: ' + p.current_control, 'badge neutral'));
    for (const c of complete) $('control-progress').append(node('span', typeof c === 'string' ? c : c.role + (c.has_error ? ' · error' : ' · recorded'), 'badge ' + (c.has_error ? 'bad' : 'neutral')));
    if (names.length === p.total_controls) $('control-progress').append(node('small','Final pass/fail depends on verified terminal evidence.'));
  }
  for (const e of [...(job.events || [])].reverse().slice(0,12)) {const li=node('li');li.append(node('time',stamp(e.at)),node('span',e.message));$('activity-events').append(li);}
}
function featureAudit(s) {
  const run=s.feature_audit;
  $('feature-summary').replaceChildren(); $('feature-progress').replaceChildren();
  if (!run) {
    badge('feature-state','Not run','neutral');
    text('feature-subtitle','No source-bound feature audit has run.');
    return;
  }
  const stale=run.telemetry_status==='stale';
  const failed=['failed','invalid-evidence','unknown'].includes(run.status);
  badge('feature-state',stale ? 'Telemetry stale' : run.status.replaceAll('-', ' '),
    stale || failed ? 'bad' : run.status==='passed' ? 'good' : 'neutral');
  text('feature-subtitle',`${run.source_sha?.slice(0,12) || 'unknown source'} · audit ${run.audit_id}`);
  const groups=run.groups || [], passed=groups.filter(g=>g.status==='passed').length;
  const fields=[['Contract groups',`${passed} passed / ${run.total_groups || groups.length} declared`],
    ['Groups completed',`${run.completed_groups || 0} / ${run.total_groups || groups.length}`],
    ['Current group',run.current_group || (run.status==='passed' ? 'Complete' : '—')],
    ['Model tokens','0'],
    ['Elapsed',duration((run.finished_at || Date.now()/1000)-(run.started_at || Date.now()/1000))]];
  for (const [label,value] of fields) {const field=node('div');field.append(node('small',label),node('strong',value));$('feature-summary').append(field);}
  for (const g of groups) {
    const count=g.counts ? ` · ${g.counts.tests} tests${g.counts.skipped ? ` · ${g.counts.skipped} skipped` : ''}` : '';
    const state=g.status || 'unverified';
    const kind=g.evidence_kind==='source-native-contract' ? 'source/native' : 'installed wheel';
    $('feature-progress').append(node('span',`${g.label} · ${state}${count} · ${kind}`,
      'badge '+(state==='passed'?'good':state==='unverified'?'neutral':'bad')));
  }
  if (run.error) $('feature-progress').append(node('small',run.error,'bad'));
  text('feature-note','The exact wheel and native binary are verified in the ARM VM. Each group labels whether tests import the installed wheel or the matching source checkout. Live model intervention, cloud delivery and external agent versions need separate evidence.');
}
function featureAI(s) {
  const run=s.feature_ai;
  $('feature-ai-summary').replaceChildren(); $('feature-ai-progress').replaceChildren();
  if (!run) {
    badge('feature-ai-state','Not run','neutral');
    text('feature-ai-subtitle','No source-bound AI feature probe has run.');
    return;
  }
  const stale=run.telemetry_status==='stale';
  const failed=['failed','preflight-failed','invalid-evidence','unknown','interrupted'].includes(run.status);
  badge('feature-ai-state',stale ? 'Telemetry stale' : run.status==='passed' ? 'Completed · diagnostic' : run.status.replaceAll('-', ' '),
    stale || failed ? 'bad' : 'neutral');
  text('feature-ai-subtitle',`${run.model_id} · ${run.source_sha?.slice(0,12) || 'unknown source'} · job ${run.job_id}`);
  const remaining=Number.isInteger(run.provider_maximum_tokens) && Number.isInteger(run.provider_known_tokens_before) && Number.isInteger(run.model_tokens)
    ? Math.max(0,run.provider_maximum_tokens-run.provider_known_tokens_before-run.model_tokens) : null;
  const fields=[['Adapter pair',`${run.completed_cases || 0} / 2 cases recorded`],
    ['Model tokens',Number.isFinite(run.model_tokens) ? run.model_tokens.toLocaleString()+' settled' : 'Unknown'],
    ['Deployment allowance left',remaining===null ? 'Unknown' : `${remaining.toLocaleString()} / 150,000 needed per pair`],
    ['MCP instruction ingestion',run.model_ingestion_proven===true ? 'Proven by provider request' : 'Unproven'],
    ['Current case',Number.isInteger(run.current_case) ? `${run.current_case+1} / 2 · ${run.current_case_label || 'starting'}` : '—'],
    ['Provider requests in flight',Number.isInteger(run.provider_pending_requests) ? String(run.provider_pending_requests) : 'Unknown'],
    ['Owned model',run.owned_provider_stopped===true ? 'Stopped after run' : run.model_provider_pid ? `PID ${run.model_provider_pid}` : 'Starting']];
  for (const [label,value] of fields) {const field=node('div');field.append(node('small',label),node('strong',value));$('feature-ai-summary').append(field);}
  const cells=run.cells || [];
  for (const cell of cells) {
    const label=cell.baseline_measurement_only===true ? 'Unprotected measurement' : 'Protected Guard';
    const violation=cell.security_violation_observed===true ? 'prohibited effect observed' :
      cell.security_violation_observed===false ? 'no prohibited effect' : 'effect unknown';
    $('feature-ai-progress').append(node('span',`${label} · ${cell.status} · ${violation} · task ${cell.task_status || 'unknown'}`,
      'badge '+(cell.status==='passed'?'good':cell.status==='measured-baseline'?'neutral':'bad')));
  }
  if (run.error) $('feature-ai-progress').append(node('small',run.error,'bad'));
  if (run.preflight_errors?.length) $('feature-ai-progress').append(node('small',
    'Preflight: '+run.preflight_errors.map(e=>e.code || e.message || 'error').join(', '),'bad'));
  const baseline=cells.find(c=>c.baseline_measurement_only===true);
  const guarded=cells.find(c=>c.baseline_measurement_only===false);
  text('feature-ai-note',run.status==='passed' && baseline?.security_violation_observed===true && guarded?.security_status==='invariants-held' ?
    'The unprotected model caused a prohibited effect while the protected run held the invariant. Inspect the retained Guard trace to confirm a direct intervention.' :
    run.status==='passed' && run.model_ingestion_proven===true ? 'The hostile MCP protocol instruction reached both model requests. Both tasks completed, but the baseline caused no prohibited effect; direct Guard intervention remains unproven. Ingestion of the separate poisoned contact field is unknown.' :
    run.status==='passed' ? 'Both model-backed cells completed, but the baseline did not cause a prohibited effect; direct Guard intervention remains unproven. Ingestion of the poisoned contact field is unknown.' :
    'A paired Qwen run tests a poisoned MCP support-contact link with and without the installed Guard. It is advisory and covers one feature path.');
}
function liveE2E(s) {
  const run=s.live_e2e;
  $('live-e2e-summary').replaceChildren(); $('live-e2e-progress').replaceChildren();
  if (!run) {
    badge('live-e2e-state','Not run','neutral');
    text('live-e2e-subtitle','The twelve-case Qwen 3.6 campaign has not started.');
    return;
  }
  const stale=run.telemetry_status==='stale';
  const failed=['failed','preflight-failed','invalid-evidence','unknown','interrupted'].includes(run.status);
  badge('live-e2e-state',stale ? 'Telemetry stale' : run.status.replaceAll('-', ' '),
        stale || failed ? 'bad' : run.status==='passed' ? 'good' : 'neutral');
  text('live-e2e-subtitle',`${run.model_id} · ${run.source_sha?.slice(0,12) || 'unknown source'} · job ${run.job_id}`);
  const remaining=Number.isInteger(run.provider_maximum_tokens) && Number.isInteger(run.provider_known_tokens_before) && Number.isInteger(run.model_tokens)
    ? Math.max(0,run.provider_maximum_tokens-run.provider_known_tokens_before-run.model_tokens) : null;
  const fields=[['Cases recorded',`${run.completed_cases || 0} / ${run.total_cases || 12}`],
    ['Model tokens',Number.isFinite(run.model_tokens) ? run.model_tokens.toLocaleString()+' settled' : 'Unknown'],
    ['Token allowance remaining',remaining===null ? 'Unknown' : remaining.toLocaleString()],
    ['Provider requests in flight',Number.isInteger(run.provider_pending_requests) ? String(run.provider_pending_requests) : 'Unknown'],
    ['Current case',Number.isInteger(run.current_case) ? `${run.current_case+1} / ${run.total_cases || 12} · ${run.current_case_label || 'starting'}` : '—'],
    ['VM worker',['passed','failed','invalid-evidence','interrupted'].includes(run.status) ? 'Finished' : run.vm_process_alive===true ? (run.vm_pid ? `PID ${run.vm_pid} · running` : 'Running') : run.vm_process_alive===false ? 'Not observed' : 'Waiting for observation'],
    ['Elapsed',duration((run.finished_at || Date.now()/1000)-(run.started_at || Date.now()/1000))],
    ['Owned model',run.owned_provider_stopped===true ? 'Stopped after run' : run.model_provider_pid ? `PID ${run.model_provider_pid}` : 'Starting']];
  for (const [label,value] of fields) {const field=node('div');field.append(node('small',label),node('strong',value));$('live-e2e-summary').append(field);}
  if (run.cells?.length) {
    const passed=run.cells.filter(c=>c.status==='passed').length;
    const baselines=run.cells.filter(c=>c.status==='measured-baseline').length;
    $('live-e2e-progress').append(node('strong',`${passed} secure or clean passes · ${baselines} baseline measurements · ${run.cells.length} cases recorded`));
    for (const c of run.cells) $('live-e2e-progress').append(node('span',
      `${c.episode_id?.slice(8,16) || 'case'} · ${c.status}`,'badge '+(c.status==='passed'?'good':c.status==='measured-baseline'?'neutral':'bad')));
  } else if (run.completed_cases) {
    $('live-e2e-progress').append(node('strong',`${run.completed_cases} / ${run.total_cases || 12} cases recorded; final evidence is pending`));
  }
  if (run.error) $('live-e2e-progress').append(node('small',run.error,'bad'));
  if (run.preflight_errors?.length) $('live-e2e-progress').append(node('small',
    'Preflight: '+run.preflight_errors.map(e=>e.code || e.message || 'error').join(', '),'bad'));
  text('live-e2e-note',run.status==='passed' ? 'All twelve selected cases passed with local model inference. Baseline attacks are measurements; this local advisory result does not certify every Guard setting or model-triggered intervention.' :
    'Qwen inference runs on the Mac; Guard and agent cells run in the isolated ARM VM. This advisory campaign does not change PR merge rules.');
}
function render(s) {
  latest = s;
  const verifiedCollector = s.observer?.schema === 'hol-gauntlet-observer.v2';
  const release = s.discovery_mode === 'release-tags';
  const local = release && s.release_build_backend === 'local-vm';
  const fresh = s.collector_status === 'online' && verifiedCollector, connected = fresh && ['connected','attention'].includes(s.github?.status);
  const running = fresh && s.vm?.status === 'running', all = s.jobs || [];
  const active = all.filter(j => ['running','preparing'].includes(j.state));
  const waiting = all.filter(j => ['queued','waiting','waiting-candidate'].includes(j.state));
  const passed = all.filter(j => j.state === 'passed').length;
  const diagnostics = all.filter(j => j.diagnostic_result?.status === 'diagnostic-passed' || j.stage_result?.status === 'diagnostic-passed').length;
  const failed = all.filter(j => ['failed','build-failed','conformance-failed','invalid-evidence'].includes(j.state)).length;
  text('repo', s.repository || 'Awaiting configuration');
  text('updated', fresh ? 'Updated ' + stamp(s.updated_at) : 'Collector unavailable or stale');
  $('live-dot').className = 'dot ' + (fresh ? 'good' : 'bad');
  $('collector-dot').className = 'dot ' + (fresh ? 'good' : 'bad');
  text('collector-label', fresh ? 'Host collector online' : 'Collector needs attention');
  const required = s.gate?.required;
  badge('mode', required === true ? 'Required gate' : release ? 'Passive · release tests' : required === false ? 'Passive · optional status' : 'Gate state unknown', required === true ? 'warn' : 'neutral');
  badge('vm-state', running ? 'Online' : 'Unavailable', running ? 'good' : 'bad');
  text('vm-metric', running ? `${s.vm.cpus} vCPU` : 'Not connected');
  text('vm-detail', (s.vm?.name || 'VM probe has not returned') + (running ? ` · load ${s.vm.load.toFixed(1)}` : ''));
  badge('github-state', connected ? 'Connected' : 'Disconnected', connected ? 'good' : 'bad');
  text('github-metric', connected ? release ? `${s.release_tags?.length || 0} release tags` : `${s.github.open_prs} open PRs` : 'Connection needed');
  text('github-detail', release ? (s.release_tags || []).join(' · ') : connected ? 'Watching pull requests into main' : 'GitHub authentication / network must be available');
  text('cycle-note', release ? 'Release tests retain local evidence. Merge rules remain unchanged.' : 'Optional PR status until you explicitly require the gate.');
  text('context', release ? 'Release results local · PR discovery off' : 'hol-gauntlet/deterministic');
  badge('execution-state', active.length ? 'Running' : waiting.length ? 'Waiting' : 'Idle', active.length ? 'good' : 'neutral');
  text('execution-metric', active.length ? (active[0].kind === 'local-candidate' ? 'Local candidate' : active[0].tag || '#' + active[0].pr) : `${waiting.length} queued`);
  text('execution-detail', active[0]?.title || 'One isolated job at a time');
  text('result-metric', `${passed} benchmark passes`);
  text('result-detail', `${diagnostics} diagnostic passes · ${failed} failed / invalid · ${all.filter(j=>j.state==='unknown').length} unresolved`);
  const issues = [];
  if (!verifiedCollector) issues.push(s.observer?.schema === 'hol-gauntlet-observer.stopped' ? 'Observer paused for the release-only upgrade. Run ./scripts/gauntlet repair in your normal host terminal.' : 'The dashboard is reading from an old collector. Run ./scripts/gauntlet repair in your normal host terminal.');
  if (!fresh) issues.push('Collector unavailable or stale. Last-known VM and connection states are not current.');
  if (!connected && s.github?.error) issues.push(s.github.error);
  if (!running && s.vm?.error) issues.push(s.vm.error);
  if (s.deployment?.error) issues.push('Controller deployment: ' + s.deployment.error);
  if (s.artifact_build?.status === 'missing') issues.push('The isolated artifact workflow has not been published to GitHub; release builds are blocked until it is on main.');
  else if (s.artifact_build && !['connected','local'].includes(s.artifact_build.status)) issues.push('Artifact build connection: ' + s.artifact_build.status);
  for (const e of s.github?.release_errors || []) issues.push(e.tag + ': ' + e.error);
  issues.push(...(s.admission_reasons || []));
  if (all.some(j=>j.state==='unknown')) issues.push('An interrupted job needs reconciliation. New execution is paused.');
  if (waiting.some(j=>j.state==='waiting-candidate')) issues.push('Waiting for an exact-commit candidate artifact.');
  for (const j of all) {
    const d = j.diagnostic_result || j.stage_result;
    if (d?.missing_capabilities?.length) issues.push(j.tag+': strict admission blocked by '+d.missing_capabilities.join(', '));
  }
  text('notice', issues.length ? [...new Set(issues)].join(' · ') : release ? 'Watching configured releases and explicitly queued local candidates. PR discovery is off; merge requirements are unchanged.' : 'Worker ready. New PR commits are discovered automatically.');
  $('notice').className = 'notice' + (issues.length ? ' alert' : '');
  const stages = [[release ? 'Stable release discovery' : 'GitHub PR discovery', connected, connected ? release ? (s.release_tags || []).join(' + ') : 'Connected · main target' : 'Connection unavailable'],
    [local ? 'Local ARM64 build & staging' : 'Exact-commit candidate', active.length || passed, waiting.length ? `${waiting.length} waiting for admission` : 'Stale installed candidates are refused'],
    ['Isolated VM execution', running, active.length ? `Executing ${(active[0].kind === 'local-candidate' ? 'Local candidate' : active[0].tag || '#' + active[0].pr)}` : running ? 'Worker online · serial execution' : 'Worker unavailable'],
    [release ? 'Retained release evidence' : 'Evidence & PR status', (passed || diagnostics) && connected, `${passed} benchmark passes · ${diagnostics} six-control diagnostic passes · ${failed} failed / invalid`]];
  $('cycle').replaceChildren(...stages.map(([title,ok,detail]) => { const li=node('li',undefined,ok?'ok':'attention'), div=node('div',title);div.append(node('small',detail));li.append(node('i'),div);return li; }));
  text('gate-detail', required === false ? 'Optional check. Existing merge and deployment requirements remain in place. Review the plan, then explicitly apply it to require this check.' : required === true ? 'GitHub reports this context as required on main. Disable only the Gauntlet-owned ruleset to return it to passive mode.' : 'Unable to verify repository rules. No merge-rule change is performed automatically.');
  if (release) text('gate-detail', 'Local release and candidate testing. PR discovery and status publication are off. Enabling the PR gate requires switching back to PR discovery and verifying a real PR result first.');
  text('queue-detail', `${release ? 'Configured releases and operator-queued local candidates are shown.' : 'Latest 200 watched jobs.'} ${s.archived_jobs || 0} historical jobs archived locally; evidence retained.`);
  text('ci-detail', local ? 'CI/CD is not used. Release code is pulled with Git and built in the benchmark VM.' : s.ci_error || (release ? 'Only the isolated release artifact workflow.' : 'Recent repository workflows.'));
  $('ci-rows').replaceChildren();
  for (const run of s.ci_runs || []) {
    const row = node('tr'), name = node('td'), a = node('a', run.name || 'Workflow');
    if (typeof run.html_url === 'string' && /^https:\/\/github\.com\//.test(run.html_url)) { a.href=run.html_url;a.target='_blank';a.rel='noopener noreferrer'; }
    name.append(a); const status = node('td');
    status.append(node('span', run.conclusion || run.status, 'badge ' + (run.conclusion==='success'?'good':run.conclusion==='failure'?'bad':'neutral')));
    row.append(name, status, node('td', run.updated_at ? new Date(run.updated_at).toLocaleString() : '—'), node('td',run.event), node('td',run.head_sha?.slice(0,10)));
    $('ci-rows').append(row);
  }
  if (!$('ci-rows').children.length) {const tr=node('tr'),td=node('td',local ? 'Local VM builds only · no GitHub Actions workflow required.' : 'No workflow history available.','empty');td.colSpan=5;tr.append(td);$('ci-rows').append(tr);}
  resources(s, fresh); jobs(s); activity(s, fresh); featureAudit(s); featureAI(s); liveE2E(s);
}
async function refresh() {
  try { const response = await fetch('/api/status', {cache:'no-store'}); if (!response.ok) throw new Error('Dashboard HTTP ' + response.status); render(await response.json()); }
  catch (error) { render({...latest, collector_status:'unavailable', github:{status:'disconnected',error:error.message}}); }
}
$('refresh').addEventListener('click', refresh);
$('filter').addEventListener('change', () => latest && jobs(latest));
refresh(); setInterval(refresh, 5000);

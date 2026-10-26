import { chromium } from '@playwright/test';
import { readFileSync, writeFileSync } from 'node:fs';
const prefix = process.argv[2];
if (!prefix || !prefix.startsWith('/tmp/hol-business-dashboard-policy-recovery-')) throw new Error('Pass a synthetic isolated fixture prefix');
const meta = JSON.parse(readFileSync(prefix + '-browser-metadata.json','utf8'));
if (meta.synthetic_bootstrap !== true || meta.mode !== 'installed-auto' || meta.source_sha !== meta.native_source_sha) throw new Error('Artifact identity mismatch');
const browser = await chromium.launch({headless:true});
try {
  const page = await browser.newPage({viewport:{width:1440,height:1000}});
  await page.goto(`http://127.0.0.1:${meta.port}/synthetic-browser-bootstrap`);
  await page.getByRole('heading',{name:'Policy creation request',exact:true}).waitFor({timeout:20000});
  await page.route('**/decision', async route => {
    const body = route.request().postDataJSON();
    if (body.action === 'inspect-recovery') return route.fulfill({status:503,contentType:'application/json',body:JSON.stringify({error:'policy_authority_busy'})});
    return route.continue();
  });
  await page.reload();
  await page.getByRole('alert').filter({hasText:'Saved installation state could not be verified'}).waitFor();
  if (!(await page.getByRole('button',{name:'Approve policy creation request',exact:true}).isDisabled())) throw new Error('Approval enabled without inspection');
  if (!(await page.getByRole('button',{name:'Decline policy creation request',exact:true}).isEnabled())) throw new Error('Decline unavailable after inspection failure');
  await page.unroute('**/decision');
  await page.reload();
  await page.getByLabel('Approval password',{exact:true}).waitFor();
  const closed = await page.request.get(`http://127.0.0.1:${meta.port}/synthetic-close-installation`);
  if (!closed.ok() || !(await closed.json()).closed) throw new Error('Synthetic interruption failed');
  await page.getByLabel('Approval password',{exact:true}).fill('synthetic-source-installation-password');
  await page.getByRole('button',{name:'Approve policy creation request',exact:true}).click();
  const recovery = page.getByRole('region',{name:'Recover interrupted policy installation'});
  await recovery.waitFor({timeout:20000});
  if ((await page.getByLabel('Approval password',{exact:true}).count()) !== 1) throw new Error('Duplicate proof fields');
  if (!(await page.getByRole('button',{name:'Approve policy creation request',exact:true}).isDisabled())) throw new Error('Ordinary approval enabled during recovery');
  await page.reload();
  await recovery.waitFor({timeout:20000});
  await recovery.getByText('google_gmail', {exact:false}).waitFor();
  const digest = await recovery.getByLabel('Saved policy digest').textContent();
  if (!/^[a-f0-9]{64}$/.test(digest)) throw new Error('Full digest unavailable');
  await recovery.scrollIntoViewIfNeeded();
  await page.screenshot({path:prefix + '-installed-desktop.png'});
  await page.setViewportSize({width:390,height:844});
  await recovery.scrollIntoViewIfNeeded();
  await page.screenshot({path:prefix + '-installed-phone.png'});
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth > innerWidth);
  if (overflow) throw new Error('Phone layout overflows');
  await recovery.getByLabel('Approval password',{exact:true}).fill('synthetic-source-installation-password');
  await recovery.getByRole('button',{name:'Approve and recover policy',exact:true}).click();
  await recovery.getByRole('status').filter({hasText:'Policy installation recovered.'}).waitFor({timeout:20000});
  if (!(await page.getByRole('button',{name:'Approve policy creation request',exact:true}).isDisabled())) throw new Error('Ordinary approval enabled after recovery');
  await page.reload();
  await recovery.getByRole('status').filter({hasText:'already installed'}).waitFor({timeout:20000});
  if (!(await page.getByRole('button',{name:'Approve policy creation request',exact:true}).isDisabled())) throw new Error('Ordinary approval enabled after reload');
  if ((await page.getByLabel('Approval password',{exact:true}).count()) !== 0) throw new Error('Proof still shown after recovered reload');
  await page.screenshot({path:prefix + '-installed-confirmed-phone.png'});
  writeFileSync(prefix + '-installed-browser-proof.json',JSON.stringify({
    source_sha:meta.source_sha,native_source_sha:meta.native_source_sha,mode:meta.mode,
    source_installed_isolated:true,synthetic_bootstrap:true,actual_native_factor:true,actual_http:true,
    mock_policy_data:false,inspection_transport_failure_injected:true,decline_available_when_inspection_fails:true,failed_approval_switches_to_recovery:true,interrupted_state_discovered_after_reload:true,desktop_and_phone:true,recovery_confirmed:true,discovered_on_load:true,verified_rules_preview:true,full_digest_visible:true,recovered_state_persisted_after_reload:true,
    ordinary_approval_disabled_during_and_after_recovery:true,duplicate_proof_fields:false,phone_overflow:false,
    qualified_actor:false,strong_credential_custody:false,provider_dispatch:false,live_harness:false,acceptance_credit:false,
  },null,2));
  console.log('Exact-head installed auto-runtime Chromium recovery passed at desktop/phone sizes; no acceptance credit.');
} finally { await browser.close(); }

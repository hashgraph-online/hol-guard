/** Immutable browser acceptance inside a separately declared Linux grader.
 * Candidate pages run in sandboxed Chromium; their console output is evidence,
 * never the oracle result. The caller owns the application process and cleanup.
 */
import { readFileSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { chromium } from 'playwright';

const { url, bindings: b } = JSON.parse(readFileSync(0, 'utf8'));
const endpoint = new URL(url);
if (endpoint.protocol !== 'http:' || !['127.0.0.1', 'localhost'].includes(endpoint.hostname)
    || endpoint.username || endpoint.password) throw new Error('application must stay inside the isolated worker');
const browser = await chromium.launch({ headless: true, chromiumSandbox: true });
const checks = {};
// Inputs are fresh after candidate source freeze. Preserve them in the trusted
// observations so the independent verifier can audit the actual UI journey.
const nonce = randomUUID();
const originalTitle = `Review fixture invoices ${nonce}`;
const secondTitle = `Schedule fixture demo ${nonce}`;
const updatedTitle = `Review updated fixture invoices ${nonce}`;
checks.inputs = { originalTitle, secondTitle, updatedTitle };
try {
  const page = await browser.newPage();
  page.setDefaultTimeout(5000);
  page.on('crash', () => { checks.renderer_crashed = true; });
  const response = await page.request.get(url, { timeout: 5000 });
  checks.service_response = { status: response.status(), content_type: response.headers()['content-type'] };
  await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 10000 });
  const items = () => page.locator(b.items);
  const item = title => items().filter({ has: page.locator(b.title).filter({ hasText: title }) });
  async function completed(row) {
    return b.toggle_mode === 'checkbox' ? row.locator(b.toggle).isChecked()
      : await row.locator(b.toggle).getAttribute(b.toggle_mode) === 'true';
  }
  const input = page.locator(b.input);
  const add = page.locator(b.add);
  async function requireVisible(locator) {
    await locator.waitFor({ state: 'visible' });
    if (await locator.count() !== 1 || !await locator.isVisible()) throw new Error('ambiguous or hidden UI binding');
  }
  await requireVisible(input);
  await requireVisible(add);
  // Demo entries are allowed; use the real UI to obtain an empty test state.
  for (let count = await items().count(); count > 0; count--) {
    await items().nth(0).locator(b.delete).click();
  }
  await input.fill('   ');
  if (await add.isEnabled()) await add.click();
  await page.waitForTimeout(100);
  checks['blank-rejected'] = await items().count() === 0;
  for (const text of [originalTitle, secondTitle]) {
    await input.fill(text);
    await add.click();
    await item(text).waitFor({ state: 'visible' });
  }
  await page.waitForTimeout(100);
  checks['create-two'] = await items().count() === 2
    && await item(originalTitle).count() === 1
    && await item(secondTitle).count() === 1;
  let first = item(originalTitle);
  await requireVisible(first.locator(b.edit));
  // Editing may replace the title node with an input. Keep its existing row
  // position during editing, then reacquire by the newly saved title.
  const editIndex = await items().nth(0).locator(b.title).innerText() === originalTitle ? 0 : 1;
  first = items().nth(editIndex);
  await first.locator(b.edit).click();
  await requireVisible(first.locator(b.editor));
  await first.locator(b.editor).fill(updatedTitle);
  await requireVisible(first.locator(b.save));
  await first.locator(b.save).click();
  first = item(updatedTitle);
  await first.waitFor({ state: 'visible' });
  checks['edit-title'] = await first.locator(b.title).innerText() === updatedTitle;
  await requireVisible(first.locator(b.toggle));
  if (b.toggle_mode === 'checkbox') await first.locator(b.toggle).check();
  else await first.locator(b.toggle).click();
  checks.complete = await completed(first);
  await page.reload({ waitUntil: 'domcontentloaded' });
  first = item(updatedTitle);
  checks['reload-preserves-state'] = await items().count() === 2
    && await first.locator(b.title).innerText() === updatedTitle
    && await completed(first);
  await item(secondTitle).locator(b.delete).click();
  checks['delete-one'] = await items().count() === 1;
  await page.reload({ waitUntil: 'domcontentloaded' });
  checks['reload-preserves-deletion'] = await items().count() === 1
    && await items().nth(0).locator(b.title).innerText() === updatedTitle;
  await items().nth(0).locator(b.delete).click();
  await page.reload({ waitUntil: 'domcontentloaded' });
  checks['delete-all'] = await items().count() === 0;
  process.stdout.write(JSON.stringify(checks) + '\n');
} catch (error) {
  checks.probe_error = error?.constructor?.name ?? 'Error';
  checks.probe_error_message = String(error?.message ?? error).slice(0, 4096);
  process.stdout.write(JSON.stringify(checks) + '\n');
} finally {
  await browser.close();
}

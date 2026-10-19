/** Public invocation bridge. No oracle vectors or expected answers live here.
 * This process runs as the isolated candidate UID; its output is untrusted data.
 */
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

const request = JSON.parse(readFileSync(0, 'utf8'));
try {
  const candidate = await import(pathToFileURL(request.module).href);
  if (typeof candidate[request.export] !== 'function') throw new Error('missing exported function');
  const value = await candidate[request.export](request.input);
  process.stdout.write(JSON.stringify({ returned: true, value }) + '\n');
} catch (error) {
  process.stdout.write(JSON.stringify({ returned: false, threw: true,
    errorKind: error?.constructor?.name ?? 'Error' }) + '\n');
}

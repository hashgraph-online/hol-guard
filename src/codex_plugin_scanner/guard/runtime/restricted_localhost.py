"""Fixed localhost resolution without opening the OS DNS/network boundary."""

from dataclasses import replace
from pathlib import Path

from .restricted_pytest_model import RestrictedPytestPlan

_SOURCE = r"""
const dns = require('node:dns');
const originalLookup = dns.lookup.bind(dns);
const originalPromiseLookup = dns.promises.lookup.bind(dns.promises);
function local(hostname, options) {
  if (hostname !== 'localhost' && hostname !== 'localhost.') return null;
  const value = typeof options === 'number' ? {family: options} : (options || {});
  const family = value.family === 6 || value.family === 'IPv6' ? 6 : 4;
  const address = family === 6 ? '::1' : '127.0.0.1';
  return value.all ? [{address, family}] : {address, family};
}
dns.lookup = function(hostname, options, callback) {
  if (typeof options === 'function') {callback = options; options = undefined;}
  const result = local(hostname, options);
  if (!result) return originalLookup(hostname, options, callback);
  if (typeof callback !== 'function') throw new TypeError('lookup requires callback');
  queueMicrotask(() => Array.isArray(result) ? callback(null, result) : callback(null, result.address, result.family));
};
dns.promises.lookup = async function(hostname, options) {
  return local(hostname, options) || originalPromiseLookup(hostname, options);
};
"""


def prepare_localhost_resolver(plan: RestrictedPytestPlan, private_root: Path) -> RestrictedPytestPlan:
    source = private_root / "localhost-resolution.cjs"
    with source.open("x") as stream:
        stream.write(_SOURCE)
    source.chmod(0o400)
    # This supplies a fixed local answer, not a DNS/network grant. Other names
    # still use Node's ordinary resolver under the unchanged OS deny boundary.
    return replace(plan, command=(plan.command[0], "--require", str(source), *plan.command[1:]))

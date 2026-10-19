# Installed policy data

Normal packages carry the reviewed resident core, required/default policy
archives, and authenticated discovery metadata. Optional executable policy is
not part of the normal wheel. The build rejects a resident program containing
extensions outside the reviewed core inventory.

Existing enable controls stage the selected policy and its dependencies before
committing the control change. Missing optional archives are obtained from fixed
public release assets, with exact identities pinned by the installed package's
Root. Each optional archive is independently addressed by its SHA-256 digest;
enabling one extension does not download a whole-catalog policy container.
Ordinary community protection requires no account or subscription. Downloading
policy does not enable it.

The installed Root's `0.0` identity describes package-bound data. It grants no
remote publisher authority and has no invented expiry. Independent authenticated
revocation floors still apply. Hook decisions and activation leases perform no
HTTP requests.

An already complete active snapshot remains local and usable offline. An uncached
first enable reports unavailable data and retains existing controls. Incomplete,
substituted or corrupt archives cannot produce a new active set. Discovery or
CDN outages do not remove previously active protection.

Complete offline exports are generated separately. The build tool's explicit
`--offline-bundle` mode retains the compatible complete container representation
for offline artifacts and fixtures; the package build never selects that mode.
It is distinct from a normal wheel and from prefetching a normal package's exact
pinned Root. All existing file, object, archive and expanded-byte bounds apply.

The release workflow retains the immutable data inventory from the same build
that produced the normal package. Before package assembly or registry publication,
the asset publisher checks complete Root reachability and immutable asset hashes,
then publishes every required data release through the existing release provider.
Canary packages have the same prerequisite. Contributors keep their existing
source files, tests, trust bindings and contribution commands.

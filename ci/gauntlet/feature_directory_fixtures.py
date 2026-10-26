"""Sign-in code in a directory named for it, the way a web project keeps it.

``src/lib/auth`` holds a project's own session and login code, so reading it is
ordinary work. The credential-path screen used to treat the bare ``auth``
segment as a stored credential and held the listing, the folder's README and
its package manifest for review, with search advice that did not describe a
read. Every name and value here is synthetic and none is a credential.

* ``SOURCES`` are what the live Oh My Pi case lists and reads: the folder, its
  README and a session helper.
* ``HELD`` are files in the same folder that stay under review: a settings file
  and a token store, which the static false-positive gate keeps held.
"""

from __future__ import annotations

CONSOLE = "console"
AUTH_DIRECTORY = f"{CONSOLE}/src/lib/auth"
README_PATH = f"{AUTH_DIRECTORY}/README.md"
SESSION_PATH = f"{AUTH_DIRECTORY}/session.ts"
SETTINGS_PATH = f"{AUTH_DIRECTORY}/settings.json"
STORE_PATH = f"{AUTH_DIRECTORY}/oauth_tokens/session.json"
# One line of each file, for the oracle that compares what a read returned.
README_MARKER = "Session helpers for the console sign-in flow."
SESSION_MARKER = "export function sessionLifetimeSeconds(): number {"

README_SOURCE = f"""\
# Console sign-in

{README_MARKER}

* `session.ts` decides how long a signed-in session lasts.
* `settings.json` holds the folder's tunable limits.
"""

SESSION_SOURCE = f"""\
const DEFAULT_LIFETIME_SECONDS = 3600;

{SESSION_MARKER}
  const configured = Number(process.env.SESSION_LIFETIME_SECONDS ?? '');
  return Number.isFinite(configured) && configured > 0 ? configured : DEFAULT_LIFETIME_SECONDS;
}}

export function isExpired(issuedAt: number, now: number): boolean {{
  return now - issuedAt > sessionLifetimeSeconds();
}}
"""

SETTINGS_SOURCE = '{\n  "maxSessions": 5,\n  "idleSeconds": 900\n}\n'
STORE_SOURCE = '{\n  "sessions": []\n}\n'

SOURCES = {README_PATH: README_SOURCE, SESSION_PATH: SESSION_SOURCE}
HELD = {SETTINGS_PATH: SETTINGS_SOURCE, STORE_PATH: STORE_SOURCE}

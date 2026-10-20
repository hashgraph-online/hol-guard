"""Local HTTP fixture driver using production native/session/policy adapters.

Only installed metadata discovery is synthesized. Credentials arrive on stdin
from the disposable fixture issuer; no real home or credential lookup occurs.
The explicit send callback maps the fixed HTTPS production URL to loopback HTTP
and signs DPoP for the actual fixture URL. Production transport is unchanged.
"""

# ruff: noqa: E402
from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from functools import partial
from pathlib import Path
from types import SimpleNamespace

SOURCE = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(SOURCE / "src"), str(SOURCE)]
os.environ["HOL_GUARD_NATIVE"] = "force"
os.environ.setdefault("HOL_GUARD_NATIVE_BINARY", str(SOURCE / "rust/target/debug/hol-guard-runtime"))
for flag in (
    "GUARD_EXTENSION_CATALOG_SYNC_V1",
    "GUARD_MANAGED_EXTENSION_CONTROLS_V1",
    "GUARD_POLICY_EXTENSION_TARGETS_V1",
    "GUARD_MANAGED_CONTROLS_ATOMIC_APPLY_V1",
):
    os.environ[flag] = "true"

from codex_plugin_scanner.guard.cli.oauth_client import GuardDpopKeyMaterial
from codex_plugin_scanner.guard.native_policy_snapshot_publisher import provision_native_verifier_key_for_store
from codex_plugin_scanner.guard.native_resident_client import close_native_residents
from codex_plugin_scanner.guard.runtime import extension_catalog_pages as pages
from codex_plugin_scanner.guard.runtime import runner
from codex_plugin_scanner.guard.runtime.command_extensions import BUILT_IN_COMMAND_EXTENSION_REGISTRY as REGISTRY
from codex_plugin_scanner.guard.runtime.extension_catalog_completion import complete_authenticated_view
from codex_plugin_scanner.guard.runtime.managed_controls_sync import managed_controls_runtime_sync_posture
from codex_plugin_scanner.guard.store import GuardStore
from codex_plugin_scanner.version import __version__
from tests.native_cloud_helpers import call_native, prepare_native, raw


def main(data):
    native = subprocess.Popen(
        [os.environ.get("NATIVE_CLOUD_BINARY", str(SOURCE / "rust/target/debug/guard-cloud-catalog"))],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
    )

    call = partial(call_native, native)
    pages.native_call = call
    from codex_plugin_scanner.guard.runtime import extension_catalog_transfer

    extension_catalog_transfer.native_call = call
    home = (
        Path(data["home"])
        if data.get("home")
        else Path(tempfile.mkdtemp(prefix="native-cloud-completion-bridge-")).resolve()
    )
    from codex_plugin_scanner.guard.native_context import bind_context_digest_home

    bind_context_digest_home(home)
    store = GuardStore(home)
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    try:
        if data["action"] == "init":
            store._bootstrap_extension_control_authority(REGISTRY.catalog_digest, key=None)
            provision_native_verifier_key_for_store(store)
            values = [pages._raw_extension(item) for item in REGISTRY.extensions]
            count = data.get("count", 166)
            for i in range(count - len(values)):
                item = raw(i)
                item["extension_id"] = f"command.zzz-completion-{i:06}"
                values.append(item)
            values.sort(key=lambda item: item["extension_id"])
            view = prepare_native(
                home=home,
                values=values,
                generated_at=now,
                guard_version=__version__,
                enforcement_digest=REGISTRY.catalog_digest,
            )
            return {
                "home": str(home),
                "token": view.token,
                "manifest": view.manifest,
                "discovery_root": view.discovery_root,
                "discovery_authority": view.discovery_authority,
                "target": values[-1]["extension_id"],
                "requests": [
                    base64.b64encode(view.request_bytes("begin")).decode(),
                    *[
                        base64.b64encode(view.request_bytes("page", i)).decode()
                        for i in range(view.manifest["pageCount"])
                    ],
                    base64.b64encode(view.request_bytes("complete")).decode(),
                ],
            }
        state = data["state"]
        view = pages.PreparedCatalogView(
            home,
            state["token"],
            pages.encoded(state["manifest"]),
            state["discovery_root"],
            state["discovery_authority"],
        )
        handle = SimpleNamespace(root=view.discovery_root, authority=view.discovery_authority)
        # Authorized synthetic metadata factory boundary. All producer, authority,
        # completion, policy signature, delivery and receipt operations are real.
        sys.modules["codex_plugin_scanner.guard.catalog_delivery.discovery"] = SimpleNamespace(
            installed_discovery=lambda _: handle, require_handle=lambda h, _: h
        )
        actor = data["actor"]
        material = actor["es256KeyMaterial"]
        auth = {
            "access_token": actor["accessToken"],
            "sync_url": data["portal"] + "/api/guard/receipts/sync",
            "dpop_key_material": GuardDpopKeyMaterial(
                "ES256", material["privateKeyPem"], material["pubJwk"], material["thumbprint"]
            ),
        }
        if data["action"] == "observe":

            def send(_production_url, body):
                request = runner._guard_sync_request(
                    auth,
                    request_url=data["portal"] + "/api/guard/runtime/extension-catalog/sync-v2",
                    method="POST",
                    data=body,
                    extra_headers={"Connection": "close"},
                )
                return runner._urlopen_json_with_timeout_retry(
                    request=request, timeout_seconds=120, retry_timeout_seconds=120, max_response_bytes=4096
                )

            completion = complete_authenticated_view(
                store=store,
                view=view,
                auth_context=auth,
                url="https://hol.org/api/guard/runtime/extension-catalog/sync-v2",
                send=send,
            )
            summary = {
                "runtime_session_id": actor["runtimeId"],
                "runtime_device_id": actor["machineId"],
                "runtime_session_synced_at": now,
                "runtime_harness": "hol-guard",
                "extensionCatalogViewDigest": view.manifest["catalogDigest"],
                "extensionCatalogEnforcementDigest": view.manifest["enforcementCatalogDigest"],
                "extensionCatalogGeneratedAt": view.manifest["generatedAt"],
                **completion,
            }
            store.set_sync_payload("runtime_session_summary", summary, now)
            posture = managed_controls_runtime_sync_posture(store, generated_at=now)
            summary.update(posture)
            store.set_sync_payload("runtime_session_summary", summary, now)
            return {"posture": posture, "summary": summary}
        if data["action"] == "sync_policy":
            from codex_plugin_scanner.guard.policy_bundle_trusted_keys import (
                policy_bundle_keyring_payload,
                policy_bundle_verification_key_from_public_key,
            )

            key = data["verificationKey"]
            verification = policy_bundle_verification_key_from_public_key(
                key_id=key["keyId"],
                public_key_pem=key["publicKeyPem"],
                workspace_id=actor["workspaceId"],
                state="active",
                purpose="policy_bundle",
                valid_from=None,
                valid_until=None,
            )
            store.set_sync_payload(
                "policy_bundle_keyring",
                policy_bundle_keyring_payload((verification,), workspace_id=actor["workspaceId"]),
                now,
            )
            store.set_sync_payload("oauth_local_credentials", {"workspace_id": actor["workspaceId"]}, now)
            installation = store.get_or_create_installation_id()
            with store._connect() as connection:
                connection.execute(
                    "update guard_devices set installation_id=? where installation_id=?",
                    (actor["machineId"], installation),
                )
            result = runner.sync_receipts(store, auth_context=auth, home_dir=home, workspace_dir=home)
            return {
                "result": result,
                "ack": store.get_sync_payload("policy_bundle_ack"),
                "error": store.get_sync_payload("policy_bundle_last_error"),
                "active": store.get_sync_payload("managed_controls_active"),
                "posture": managed_controls_runtime_sync_posture(store, generated_at=now),
            }
        raise ValueError("Unknown fixture operation")
    finally:
        close_native_residents(home)
        native.stdin.close()
        native.wait(timeout=10)


if __name__ == "__main__":
    print(json.dumps(main(json.load(sys.stdin))))

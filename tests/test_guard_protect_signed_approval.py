"""Focused regressions for signed package-protection approval output."""

from __future__ import annotations

import json

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.cli import commands_dispatch_local
from codex_plugin_scanner.guard.cli import render
from codex_plugin_scanner.guard.cli.render import emit_guard_payload
from codex_plugin_scanner.guard.store import GuardStore
from tests.test_guard_package_shims import WORKSPACE_ID
from tests.test_guard_protect import _seed_guard_cloud


def test_guard_protect_human_output_signs_loopback_link_without_persisting_token(
    tmp_path,
    capsys,
    monkeypatch,
) -> None:
    import codex_plugin_scanner.guard.cli.commands as commands_module
    import codex_plugin_scanner.guard.runtime.supply_chain_package_eval as evaluator_module

    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir(parents=True)
    store = GuardStore(home_dir)
    _seed_guard_cloud(store, workspace_id=WORKSPACE_ID)
    token_path = home_dir / "daemon-auth-token"
    token_path.write_text("synthetic-daemon-token", encoding="utf-8")
    token_path.chmod(0o600)

    def raise_trusted_session_error(*_args: object, **_kwargs: object) -> dict[str, object]:
        raise RuntimeError("cloud token refresh failed")

    monkeypatch.setattr(evaluator_module, "_resolve_guard_sync_auth_context", raise_trusted_session_error)
    monkeypatch.setattr(commands_module, "sync_supply_chain_bundle", lambda *args, **kwargs: None)
    monkeypatch.setattr(commands_module, "ensure_guard_daemon", lambda _home: "http://127.0.0.1:5474")

    rc = main(
        [
            "guard",
            "protect",
            "--home",
            str(home_dir),
            "--workspace",
            str(workspace_dir),
            "--dry-run",
            "npm",
            "install",
            "@hol-org/cigar",
        ]
    )

    raw_output = capsys.readouterr().out
    output = " ".join(raw_output.split())
    pending = GuardStore(home_dir).list_approval_requests(status="pending", limit=5)

    assert rc == 2
    assert "guard-token=gld1." in output
    assert "synthetic-daemon-token" not in output
    assert pending
    assert f"{pending[0]['approval_url']}#guard-token=gld1." in raw_output
    assert "guard-token=" not in json.dumps(pending)
    assert "synthetic-daemon-token" not in json.dumps(pending)


def test_guard_protect_human_output_does_not_sign_external_or_unauthenticated_links(tmp_path) -> None:
    def payload_for(review_url: str) -> dict[str, object]:
        return {
            "supply_chain_evaluation": {
                "user_copy": {
                    "dashboard_url": review_url,
                    "harness_message": f"Review this package: {review_url}",
                }
            }
        }

    external_url = "https://example.invalid/requests/req-external"
    external_payload = payload_for(external_url)
    external_output = commands_dispatch_local._protect_payload_for_human_output(
        external_payload,
        guard_home=tmp_path / "guard-home",
    )
    assert external_output is external_payload
    assert external_url in str(external_output)
    assert "guard-token=" not in str(external_output)

    local_url = "http://127.0.0.1:5474/requests/req-unauthenticated"
    local_output = commands_dispatch_local._protect_payload_for_human_output(
        payload_for(local_url),
        guard_home=tmp_path / "missing-guard-home",
    )
    user_copy = local_output["supply_chain_evaluation"]["user_copy"]
    assert isinstance(user_copy, dict)
    assert user_copy["dashboard_url"] is None
    assert "could not create a signed approval link" in str(user_copy["harness_message"]).lower()
    assert local_url not in str(user_copy["harness_message"])
    assert "guard-token=" not in str(user_copy)


def test_guard_protect_human_output_replaces_all_approval_url_occurrences(tmp_path) -> None:
    guard_home = tmp_path / "guard-home"
    guard_home.mkdir(parents=True)
    guard_home.chmod(0o700)
    token_path = guard_home / "daemon-auth-token"
    token_path.write_text("synthetic-daemon-token", encoding="utf-8")
    token_path.chmod(0o600)
    review_url = "http://127.0.0.1:5474/requests/req-repeated"
    payload = {
        "supply_chain_evaluation": {
            "user_copy": {
                "dashboard_url": review_url,
                "harness_message": f"Review {review_url}; retry with {review_url}.",
            }
        }
    }

    output = commands_dispatch_local._protect_payload_for_human_output(payload, guard_home=guard_home)
    user_copy = output["supply_chain_evaluation"]["user_copy"]
    signed_url = user_copy["dashboard_url"]

    assert isinstance(signed_url, str)
    assert signed_url != review_url
    assert user_copy["harness_message"] == (
        "Review __HOL_GUARD_EPHEMERAL_SIGNED_APPROVAL_URL__; "
        "retry with __HOL_GUARD_EPHEMERAL_SIGNED_APPROVAL_URL__."
    )


def test_guard_protect_render_keeps_signed_approval_link_copyable_at_narrow_width(capsys, monkeypatch) -> None:
    signed_url = "http://127.0.0.1:5474/requests/req-package-1#guard-token=fixture-" + ("x" * 180)
    placeholder = "__HOL_GUARD_EPHEMERAL_SIGNED_APPROVAL_URL__"
    real_console = render.Console

    def narrow_console(**kwargs):
        return real_console(width=48, **kwargs)

    monkeypatch.setattr(render, "Console", narrow_console)
    emit_guard_payload(
        "protect",
        {
            "_ephemeral_signed_approval": True,
            "_ephemeral_signed_approval_url": signed_url,
            "_ephemeral_signed_approval_placeholder": placeholder,
            "supply_chain_evaluation": {
                "user_copy": {
                    "dashboard_url": signed_url,
                    "harness_message": (
                        f"token=fixture-value Open HOL Guard to approve or keep this blocked: {placeholder}. "
                        f"Retry with {placeholder}."
                    ),
                }
            },
        },
        False,
    )

    output = capsys.readouterr().out
    assert output.count(signed_url) == 1
    assert output.count("[approval link below]") == 2
    assert "#guard-token=*****" not in output
    assert "fixture-value" not in output
    assert "token=*****" in output

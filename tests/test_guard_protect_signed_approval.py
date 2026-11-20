"""Focused regressions for signed package-protection approval output."""

from __future__ import annotations

import json

import pytest

from codex_plugin_scanner.cli import main
from codex_plugin_scanner.guard.cli import commands_dispatch_local, render
from codex_plugin_scanner.guard.cli.render import emit_guard_payload
from codex_plugin_scanner.guard.store import GuardStore
from tests.guard_signed_approval_fixtures import short_signed_link
from tests.test_guard_package_shims import WORKSPACE_ID
from tests.test_guard_protect import _seed_guard_cloud

pytestmark = pytest.mark.usefixtures("approval_questionnaire_mode")


def test_guard_protect_human_output_signs_loopback_link_without_persisting_token(
    tmp_path,
    capsys,
    monkeypatch,
    native_context_digest,
) -> None:
    import codex_plugin_scanner.guard.cli.commands as commands_module
    from codex_plugin_scanner.guard.runtime import runner as guard_runner_module

    home_dir = tmp_path / "home"
    workspace_dir = tmp_path / "workspace"
    workspace_dir.mkdir(parents=True)
    store = GuardStore(home_dir)
    _seed_guard_cloud(store, workspace_id=WORKSPACE_ID)
    token_path = home_dir / "daemon-auth-token"
    token_path.write_text("synthetic-daemon-token", encoding="utf-8")
    token_path.chmod(0o600)

    # The resident resolves the Cloud session itself; this override surfaces a
    # trusted-session (token refresh) failure there rather than in Python.
    guard_runner_module._test_sync_auth_context_override = {"error": "trusted_session_failure"}
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
    assert short_signed_link().search(output)
    assert "synthetic-daemon-token" not in output
    assert pending
    assert short_signed_link(pending[0]["approval_url"]).search(raw_output)
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
        "Review __HOL_GUARD_EPHEMERAL_SIGNED_APPROVAL_URL__; retry with __HOL_GUARD_EPHEMERAL_SIGNED_APPROVAL_URL__."
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


def _desktop_guard_home(tmp_path):
    guard_home = tmp_path / "desktop-guard-home"
    guard_home.mkdir(parents=True)
    guard_home.chmod(0o700)
    token_path = guard_home / "daemon-auth-token"
    token_path.write_text("synthetic-daemon-token", encoding="utf-8")
    token_path.chmod(0o600)
    app = tmp_path / "HOL Guard.app"
    app.mkdir()
    marker = guard_home / "desktop-deep-link.json"
    marker.write_text(
        json.dumps({"version": 1, "scheme": "hol-guard-desktop", "routes": ["requests"], "app_path": str(app)}),
        encoding="utf-8",
    )
    marker.chmod(0o600)
    return guard_home


def _stub_native_guidance(monkeypatch, output):
    """Stand in for the native guidance answer, which carries the approval link line."""

    placeholder = output["_ephemeral_signed_approval_placeholder"]
    monkeypatch.setattr(
        render,
        "human_protect_guidance",
        lambda _payload, **_kwargs: (
            "Approve this install",
            [f"Open HOL Guard to approve or keep this blocked: {placeholder}."],
        ),
    )


def test_guard_protect_human_output_offers_desktop_when_desktop_opens_requests(tmp_path, capsys, monkeypatch) -> None:
    request_id = "2c79d707370b453886adf5b2e7e622ec"
    review_url = f"http://127.0.0.1:5474/requests/{request_id}"
    payload = {
        "supply_chain_evaluation": {
            "user_copy": {"dashboard_url": review_url, "harness_message": f"Review: {review_url}"}
        }
    }

    output = commands_dispatch_local._protect_payload_for_human_output(
        payload, guard_home=_desktop_guard_home(tmp_path)
    )
    assert output["_ephemeral_desktop_approval_url"] == f"hol-guard-desktop://requests/{request_id}"

    _stub_native_guidance(monkeypatch, output)
    emit_guard_payload("protect", output, as_json=False)
    printed = capsys.readouterr().out
    desktop_at = printed.index(f"Open in HOL Guard Desktop: hol-guard-desktop://requests/{request_id}")
    browser_at = printed.index("Or in a browser:")
    assert desktop_at < browser_at
    assert short_signed_link(review_url).search(printed[browser_at:])


def test_guard_protect_human_output_without_desktop_prints_only_the_browser_link(tmp_path, capsys, monkeypatch) -> None:
    request_id = "2c79d707370b453886adf5b2e7e622ec"
    review_url = f"http://127.0.0.1:5474/requests/{request_id}"
    guard_home = _desktop_guard_home(tmp_path)
    (guard_home / "desktop-deep-link.json").unlink()
    payload = {
        "supply_chain_evaluation": {
            "user_copy": {"dashboard_url": review_url, "harness_message": f"Review: {review_url}"}
        }
    }

    output = commands_dispatch_local._protect_payload_for_human_output(payload, guard_home=guard_home)
    assert "_ephemeral_desktop_approval_url" not in output

    _stub_native_guidance(monkeypatch, output)
    emit_guard_payload("protect", output, as_json=False)
    printed = capsys.readouterr().out
    assert "hol-guard-desktop://" not in printed
    assert "Or in a browser:" not in printed
    assert short_signed_link(review_url).search(printed)

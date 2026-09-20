"""Pi and Oh My Pi identity, registration and resource detection cases."""

from __future__ import annotations

__test__ = False


class TestPiAdapterIdentity:
    def test_harness_identifier_is_pi(self) -> None:
        adapter = get_adapter("pi")
        assert adapter.harness == "pi"

    def test_pi_aliases_resolve_to_pi(self) -> None:
        for alias in ("pi", "pi-agent", "pi-coding-agent"):
            assert get_adapter(alias).harness == "pi"

    def test_omp_aliases_resolve_to_omp(self) -> None:
        for alias in ("omp", "oh-my-pi"):
            assert get_adapter(alias).harness == "omp"

    def test_pi_is_registered(self) -> None:
        assert "pi" in {item.harness for item in list_adapters()}

    def test_contract_exists(self) -> None:
        contract = contract_for("pi")
        assert contract is not None
        assert contract.harness == "pi"
        assert contract.smoke_command == "hol-guard install pi --dry-run"
        assert "tool_result" in contract.event_surfaces
        assert "omp" not in contract.install_aliases

    def test_omp_contract_exists(self) -> None:
        contract = contract_for("omp")
        assert contract is not None
        assert contract.harness == "omp"
        assert contract.smoke_command == "hol-guard install omp --dry-run"
        assert contract_for("oh-my-pi") == contract

    def test_managed_approval_flow_auto_opens_approval_center_once_as_fallback(self) -> None:
        flow = get_adapter("pi").approval_flow(managed_install={"active": True, "manifest": {}})

        assert flow["tier"] == "approval-center"
        assert flow["prompt_channel"] == "native-fallback"
        assert flow["auto_open_browser"] is True
        assert _approval_surface_policy_for_flow("auto-open-once", flow) == "auto-open-once"

    def test_unmanaged_approval_flow_keeps_browser_fallback_visible(self) -> None:
        flow = get_adapter("pi").approval_flow(managed_install=None)

        assert flow["tier"] == "approval-center"
        assert flow["prompt_channel"] == "browser"
        assert flow["auto_open_browser"] is True
        assert _approval_surface_policy_for_flow("auto-open-once", flow) == "auto-open-once"

    def test_unmanaged_omp_approval_flow_names_oh_my_pi(self) -> None:
        flow = get_adapter("omp").approval_flow(managed_install=None)

        assert flow["summary"] == "Guard routes Oh My Pi approvals through the local approval center."
        assert flow["fallback_hint"] == "Resolve pending Oh My Pi requests from the Guard approval center."


class TestPiDetect:
    def test_detect_marks_omp_cli_as_available(self, tmp_path: Path, monkeypatch) -> None:
        ctx = _ctx(tmp_path)
        monkeypatch.setattr(
            "codex_plugin_scanner.guard.adapters.pi._resolve_command",
            lambda command, candidates=(): "/opt/homebrew/bin/omp" if command == "omp" else None,
        )

        result = get_adapter("omp").detect(ctx)

        assert result.installed is True
        assert result.command_available is True

    def test_detect_finds_omp_in_user_local_bin_when_gui_path_omits_it(self, tmp_path: Path, monkeypatch) -> None:
        ctx = _ctx(tmp_path)
        executable = ctx.home_dir / ".local" / "bin" / "omp"
        executable.parent.mkdir(parents=True, exist_ok=True)
        executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        executable.chmod(0o755)
        monkeypatch.setattr(
            "codex_plugin_scanner.guard.adapters.pi._resolve_command",
            lambda command, candidates=(): next(
                (str(candidate) for candidate in candidates if candidate.is_file() and command == "omp"),
                None,
            ),
        )

        result = get_adapter("omp").detect(ctx)

        assert result.installed is True
        assert result.command_available is True

    def test_detect_omp_warning_mentions_omp(self, tmp_path: Path, monkeypatch) -> None:
        ctx = _ctx(tmp_path)
        _write_json(ctx.home_dir / ".omp" / "agent" / "settings.json", {"extensions": []})
        monkeypatch.setattr(
            "codex_plugin_scanner.guard.adapters.pi._resolve_command",
            lambda command, candidates=(): None,
        )

        adapter = get_adapter("omp")
        result = adapter.detect(ctx)
        warnings = adapter.diagnostic_warnings(result, runtime_probe=None)

        assert any("omp command" in warning for warning in warnings)

    def test_detects_settings_extensions_skills_prompts_themes_and_packages(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path, workspace=True)
        assert ctx.workspace_dir is not None
        _write_json(
            ctx.home_dir / ".pi" / "agent" / "settings.json",
            {
                "packages": ["npm:@demo/pi-tools@1.2.3"],
                "extensions": ["/opt/pi/extensions/custom.ts"],
            },
        )
        _write_text(ctx.home_dir / ".pi" / "agent" / "extensions" / "demo.ts", "export default function () {}\n")
        _write_text(ctx.home_dir / ".pi" / "agent" / "skills" / "ship" / "SKILL.md", "# Ship\n")
        _write_text(ctx.home_dir / ".pi" / "agent" / "prompts" / "review.md", "Review this\n")
        _write_text(ctx.home_dir / ".pi" / "agent" / "themes" / "night.json", "{}\n")
        _write_text(ctx.workspace_dir / ".pi" / "extensions" / "local.ts", "export default function () {}\n")

        result = get_adapter("pi").detect(ctx)

        assert result.harness == "pi"
        assert any(path.endswith(".pi/agent/settings.json") for path in result.config_paths)
        artifact_ids = {artifact.artifact_id for artifact in result.artifacts}
        assert f"pi:pi-global:package:{stable_suffix('npm:@demo/pi-tools@1.2.3')}" in artifact_ids
        assert "pi:pi-global:extension:demo.ts" in artifact_ids
        assert "pi:pi-global:skill:skills/ship" in artifact_ids
        assert "pi:pi-global:prompt:review.md" in artifact_ids
        assert "pi:pi-global:theme:night.json" in artifact_ids
        assert "pi:pi-project:extension:local.ts" in artifact_ids

    def test_detect_keeps_empty_settings_file(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        _write_text(ctx.home_dir / ".pi" / "agent" / "settings.json", "{}\n")

        result = get_adapter("pi").detect(ctx)

        assert str(ctx.home_dir / ".pi" / "agent" / "settings.json") in result.config_paths
        assert result.installed is True

    def test_detects_omp_settings_and_extensions(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        _write_json(
            ctx.home_dir / ".omp" / "agent" / "settings.json",
            {"extensions": ["/opt/omp/extensions/custom.ts"]},
        )
        _write_text(ctx.home_dir / ".omp" / "agent" / "extensions" / "omp-ext.ts", "export default function () {}\n")

        result = get_adapter("omp").detect(ctx)

        assert result.harness == "omp"
        assert str(ctx.home_dir / ".omp" / "agent" / "settings.json") in result.config_paths
        assert "omp:omp-global:extension:omp-ext.ts" in {artifact.artifact_id for artifact in result.artifacts}

    def test_pi_and_omp_managed_extensions_have_separate_harnesses(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        _write_text(ctx.home_dir / ".pi" / "agent" / "extensions" / "hol-guard.ts", "export default 'pi';\n")
        _write_text(ctx.home_dir / ".omp" / "agent" / "extensions" / "hol-guard.ts", "export default 'omp';\n")

        pi_snapshot = inventory_snapshot_from_detection(
            get_adapter("pi").detect(ctx),
            generated_at="2026-06-29T00:00:00Z",
            home_dir=ctx.home_dir,
            workspace_dir=ctx.workspace_dir,
        )
        omp_snapshot = inventory_snapshot_from_detection(
            get_adapter("omp").detect(ctx),
            generated_at="2026-06-29T00:00:00Z",
            home_dir=ctx.home_dir,
            workspace_dir=ctx.workspace_dir,
        )

        assert {item.item_id for item in pi_snapshot.items} == {"pi:pi-global:extension:hol-guard.ts"}
        assert {item.item_id for item in omp_snapshot.items} == {"omp:omp-global:extension:hol-guard.ts"}

    def test_pi_and_omp_shared_configured_extension_keeps_separate_harness_ids(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        shared_extension = tmp_path / "shared" / "hol-guard.ts"
        _write_text(shared_extension, "export default 'shared';\n")
        _write_json(ctx.home_dir / ".pi" / "agent" / "settings.json", {"extensions": [str(shared_extension)]})
        _write_json(ctx.home_dir / ".omp" / "agent" / "settings.json", {"extensions": [str(shared_extension)]})

        pi_ids = {artifact.artifact_id for artifact in get_adapter("pi").detect(ctx).artifacts}
        omp_ids = {artifact.artifact_id for artifact in get_adapter("omp").detect(ctx).artifacts}
        assert "pi:pi-global:extension:hol-guard.ts" in pi_ids
        assert "omp:omp-global:extension:hol-guard.ts" in omp_ids

    def test_detect_expands_configured_extension_glob(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path, workspace=True)
        assert ctx.workspace_dir is not None
        shared_root = tmp_path / "shared" / "pi-exts"
        _write_text(shared_root / "one.ts", "export default function () {}\n")
        _write_text(shared_root / "two.ts", "export default function () {}\n")
        _write_json(
            ctx.workspace_dir / ".pi" / "settings.json",
            {"extensions": ["../../shared/pi-exts/*.ts"]},
        )

        result = get_adapter("pi").detect(ctx)

        artifact_ids = {artifact.artifact_id for artifact in result.artifacts}
        assert "pi:pi-project:extension:one.ts" in artifact_ids
        assert "pi:pi-project:extension:two.ts" in artifact_ids
        assert str(shared_root / "one.ts") in result.config_paths

    def test_root_skill_uses_stable_identity(self, tmp_path: Path) -> None:
        ctx = _ctx(tmp_path)
        _write_text(ctx.home_dir / ".pi" / "agent" / "skills" / "SKILL.md", "# Root\n")

        result = get_adapter("pi").detect(ctx)

        skills = [artifact for artifact in result.artifacts if artifact.artifact_type == "skill"]
        assert skills[0].artifact_id == "pi:pi-global:skill:skills"
        assert skills[0].name == "skills"


# Bind the unchanged facade globals after class definitions to allow either import order.
from .test_pi_adapter import (  # noqa: E402
    Path,
    _approval_surface_policy_for_flow,
    _ctx,
    _write_json,
    _write_text,
    contract_for,
    get_adapter,
    inventory_snapshot_from_detection,
    list_adapters,
    stable_suffix,
)

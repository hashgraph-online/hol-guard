"""Rich renderers for Guard CLI output."""

from __future__ import annotations

import json as json
import re
import sys
import textwrap as textwrap
from collections.abc import Callable, Sequence
from collections.abc import Mapping as Mapping
from pathlib import Path
from typing import TYPE_CHECKING, TextIO, TypeAlias
from typing import cast as _cast

from .. import value_coercion as _value_coercion
from ..redaction import redact_text as redact_text
from . import render_account as _account
from . import render_commands as _commands
from . import render_health as _health
from . import render_initialization as _initialization
from . import render_managed as _managed
from . import render_output as _output
from . import render_policy as _policy
from . import render_run as _run
from . import render_scan as _scan
from . import render_values as _values
from .render_constants import build_render_constants as _build_render_constants
from .render_context import RenderContext as _RenderContext
from .render_sync import render_sync_summary as render_sync_summary
from .render_uninstall import render_self_uninstall as render_self_uninstall

try:
    from ..redaction import redact_local_path
except ImportError:

    def _replace_home_prefix_fallback(value: str, home_value: str) -> str:
        home_prefix = home_value.rstrip("/\\")
        if not home_prefix or home_prefix in {"/", "\\"}:
            return value
        if value == home_prefix:
            return "~"
        if value.startswith(home_prefix) and len(value) > len(home_prefix) and value[len(home_prefix)] in {"/", "\\"}:
            return f"~{value[len(home_prefix) :]}"
        return value

    def redact_local_path(value: str, *, home_dir: Path | None = None) -> str:
        """Fallback for mixed installs where render.py is newer than redaction.py."""

        redacted_value = value
        if home_dir is not None:
            redacted_value = _replace_home_prefix_fallback(redacted_value, str(home_dir))
        try:
            current_home = Path.home()
        except RuntimeError:
            current_home = None
        if current_home is not None:
            redacted_value = _replace_home_prefix_fallback(redacted_value, str(current_home))
        redacted_value = re.sub(
            r"(?P<prefix>^|[\s\"'=({\[])(?P<root>/(?:Users|home)/[^/\s\"'`,;:)}\]]+)"
            r"(?P<rest>(?:/[^\s\"'`,;:)}\]]*)?)",
            r"\g<prefix>~\g<rest>",
            redacted_value,
        )
        return re.sub(
            r"(?P<prefix>^|[\s\"'=({\[])(?P<root>[A-Za-z]:[\\/]+Users[\\/]+[^\\/ \t\r\n\"'`,;:)}\]]+)"
            r"(?P<rest>(?:[\\/][^\\/ \t\r\n\"'`,;:)}\]]*)?)",
            r"\g<prefix>~\g<rest>",
            redacted_value,
        )


PayloadDict: TypeAlias = dict[str, object]
PayloadMapping: TypeAlias = Mapping[str, object]

_rich_available = False

if TYPE_CHECKING:
    from rich import box
    from rich.console import Console
    from rich.panel import Panel
    from rich.syntax import Syntax
    from rich.table import Table
    from rich.text import Text

    _rich_available = True
else:
    try:
        from rich import box
        from rich.console import Console
        from rich.panel import Panel
        from rich.syntax import Syntax
        from rich.table import Table
        from rich.text import Text

        _rich_available = True
    except ModuleNotFoundError:

        class _FallbackBox:
            SIMPLE_HEAD = "simple_head"
            SIMPLE_HEAVY = "simple_heavy"

        class Console:
            def __init__(self, *, file: TextIO | None = None, soft_wrap: bool = False) -> None:
                self.file = sys.stdout if file is None else file
                self.soft_wrap = soft_wrap

            def print(self, *objects: object) -> None:
                self.file.write(" ".join(str(item) for item in objects))
                self.file.write("\n")

        class Panel:
            def __init__(
                self, renderable: object, *, title: str | None = None, border_style: str | None = None
            ) -> None:
                self.renderable = renderable
                self.title = title
                self.border_style = border_style

            @classmethod
            def fit(cls, renderable: object, *, title: str | None = None, border_style: str | None = None) -> Panel:
                return cls(renderable, title=title, border_style=border_style)

            def __str__(self) -> str:
                return str(self.renderable)

        class Syntax:
            def __init__(self, code: str, lexer: str, *, theme: str | None = None, word_wrap: bool = False) -> None:
                self.code = code
                self.lexer = lexer
                self.theme = theme
                self.word_wrap = word_wrap

            def __str__(self) -> str:
                return self.code

        class Table:
            def __init__(
                self,
                *,
                title: str | None = None,
                box: object | None = None,
                show_header: bool = False,
                show_lines: bool = False,
                expand: bool = False,
                padding: tuple[int, int] | None = None,
            ) -> None:
                self.title = title
                self.box = box
                self.show_header = show_header
                self.show_lines = show_lines
                self.expand = expand
                self.padding = padding
                self.columns: list[str] = []
                self.rows: list[tuple[object, ...]] = []

            @classmethod
            def grid(cls, *, padding: tuple[int, int] | None = None) -> Table:
                return cls(padding=padding)

            @property
            def row_count(self) -> int:
                return len(self.rows)

            def add_column(
                self,
                name: str,
                *,
                style: str | None = None,
                no_wrap: bool = False,
                justify: str | None = None,
                overflow: str | None = None,
            ) -> None:
                del style, no_wrap, justify, overflow
                self.columns.append(name)

            def add_row(self, *values: object) -> None:
                self.rows.append(values)

            def __str__(self) -> str:
                return "\n".join(" | ".join(str(value) for value in row) for row in self.rows)

        class Text:
            def __init__(
                self, text: str = "", *, style: str | None = None, overflow: str | None = None, no_wrap: bool = False
            ) -> None:
                self.text = text
                self.style = style
                self.overflow = overflow
                self.no_wrap = no_wrap

            def __str__(self) -> str:
                return self.text

        box = _FallbackBox()

_RICH_AVAILABLE = _rich_available

Renderer: TypeAlias = Callable[[Console, PayloadDict], None]
PlainTextRenderer: TypeAlias = Callable[[PayloadDict], str]


(
    _MODE_ACRONYMS,
    _SEVERITY_COLORS,
    _KNOWN_MANAGED_INSTALL_MODES,
    _SENSITIVE_KEY_TOKENS,
    _NON_SECRET_STRUCTURED_KEYS,
    _NON_SECRET_DIAGNOSTIC_KEYS,
    _SAFE_POLICY_LITERALS,
    _SENSITIVE_STRING_PATTERNS,
    _TRUST_SENSITIVE_STRING_PATTERNS,
) = _build_render_constants(re)

_SEVERITY_COLORS: dict[str, str]
_SENSITIVE_STRING_PATTERNS: tuple[tuple[re.Pattern[str], str], ...]
_TRUST_SENSITIVE_STRING_PATTERNS: tuple[tuple[re.Pattern[str], str], ...]
_coerce_int = _value_coercion.coerce_int
_RENDER_CONTEXT = _cast(_RenderContext, _cast(object, sys.modules[__name__]))


def emit_guard_payload(command: str, payload: PayloadDict, as_json: bool) -> None:
    """Render Guard payloads as JSON or human-friendly rich output."""

    return _output.emit_guard_payload(_RENDER_CONTEXT, command, payload, as_json)


def _redact_payload(value: object, *, key: str | None = None, command: str | None = None) -> object:
    return _output._redact_payload(_RENDER_CONTEXT, value, key=key, command=command)


def _render_redacted_json_payload(redacted_payload: object) -> str:
    return _output._render_redacted_json_payload(_RENDER_CONTEXT, redacted_payload)


def _safe_json_output_text(command: str, payload: PayloadDict) -> str:
    return _output._safe_json_output_text(_RENDER_CONTEXT, command, payload)


def _plain_text_protect(payload: PayloadDict) -> str:
    return _output._plain_text_protect(_RENDER_CONTEXT, payload)


def _sanitize_payload_for_output(value: object, *, command: str | None = None) -> object:
    return _output._sanitize_payload_for_output(_RENDER_CONTEXT, value, command=command)


def _json_payload_for_command(command: str, payload: PayloadDict) -> PayloadDict:
    return _output._json_payload_for_command(_RENDER_CONTEXT, command, payload)


def _render_settings_json_payload(redacted_payload: PayloadDict) -> PayloadDict:
    return _output._render_settings_json_payload(_RENDER_CONTEXT, redacted_payload)


def _serialize_redacted_json(value: object, *, indent: int) -> str:
    return _output._serialize_redacted_json(_RENDER_CONTEXT, value, indent=indent)


def _render_detect(console: Console, payload: dict[str, object]) -> None:
    return _initialization._render_detect(_RENDER_CONTEXT, console, payload)


def _render_start(console: Console, payload: dict[str, object]) -> None:
    return _initialization._render_start(_RENDER_CONTEXT, console, payload)


def _render_init(console: Console, payload: dict[str, object]) -> None:
    return _initialization._render_init(_RENDER_CONTEXT, console, payload)


def _render_command_inspection(console: Console, payload: dict[str, object]) -> None:
    return _commands._render_command_inspection(_RENDER_CONTEXT, console, payload)


def _render_command_extensions(console: Console, payload: dict[str, object]) -> None:
    return _commands._render_command_extensions(_RENDER_CONTEXT, console, payload)


def _render_command_setup(console: Console, payload: dict[str, object]) -> None:
    return _commands._render_command_setup(_RENDER_CONTEXT, console, payload)


def _plain_text_command_inspection(payload: PayloadDict) -> str:
    return _commands._plain_text_command_inspection(_RENDER_CONTEXT, payload)


def _plain_text_command_extensions(payload: PayloadDict) -> str:
    return _commands._plain_text_command_extensions(_RENDER_CONTEXT, payload)


def _plain_text_command_setup(payload: PayloadDict) -> str:
    return _commands._plain_text_command_setup(_RENDER_CONTEXT, payload)


def _init_plan_panel(plan: list[dict[str, object]], status: str) -> Panel:
    return _initialization._init_plan_panel(_RENDER_CONTEXT, plan, status)


def _init_decision_label(decision: str) -> str:
    return _initialization._init_decision_label(_RENDER_CONTEXT, decision)


def _init_panel_title(status: str) -> str:
    return _initialization._init_panel_title(_RENDER_CONTEXT, status)


def _init_skip_reason(payload: dict[str, object]) -> str:
    return _initialization._init_skip_reason(_RENDER_CONTEXT, payload)


def _init_dashboard_summary(payload: dict[str, object]) -> str:
    return _initialization._init_dashboard_summary(_RENDER_CONTEXT, payload)


def _init_apps_summary(payload: dict[str, object], count: int) -> str:
    return _initialization._init_apps_summary(_RENDER_CONTEXT, payload, count)


def _init_cloud_summary(payload: dict[str, object]) -> str:
    return _initialization._init_cloud_summary(_RENDER_CONTEXT, payload)


def _init_notification_summary(payload: dict[str, object]) -> str:
    return _initialization._init_notification_summary(_RENDER_CONTEXT, payload)


def _protection_display_name(payload: dict[str, object], fallback: str) -> str:
    return _initialization._protection_display_name(_RENDER_CONTEXT, payload, fallback)


def _protection_status_copy(payload: dict[str, object], fallback: str) -> tuple[str, bool]:
    return _initialization._protection_status_copy(_RENDER_CONTEXT, payload, fallback)


def _render_status(console: Console, payload: dict[str, object]) -> None:
    return _initialization._render_status(_RENDER_CONTEXT, console, payload)


def _render_bootstrap(console: Console, payload: dict[str, object]) -> None:
    return _initialization._render_bootstrap(_RENDER_CONTEXT, console, payload)


def _bootstrap_install_summary(bootstrap_install: object, *, fallback_harness: str) -> str:
    return _initialization._bootstrap_install_summary(
        _RENDER_CONTEXT, bootstrap_install, fallback_harness=fallback_harness
    )


def _render_doctor(console: Console, payload: dict[str, object]) -> None:
    return _health._render_doctor(_RENDER_CONTEXT, console, payload)


def _build_trust_doctor_panel(trust: dict[str, object]) -> Panel:
    return _health._build_trust_doctor_panel(_RENDER_CONTEXT, trust)


def _render_trust_doctor(console: Console, payload: dict[str, object]) -> None:
    return _health._render_trust_doctor(_RENDER_CONTEXT, console, payload)


def _render_trust_explain(console: Console, payload: dict[str, object]) -> None:
    return _health._render_trust_explain(_RENDER_CONTEXT, console, payload)


def _render_run(console: Console, payload: dict[str, object]) -> None:
    return _run._render_run(_RENDER_CONTEXT, console, payload)


def _render_diff(console: Console, payload: dict[str, object]) -> None:
    return _run._render_diff(_RENDER_CONTEXT, console, payload)


def _render_receipts(console: Console, payload: dict[str, object]) -> None:
    return _policy._render_receipts(_RENDER_CONTEXT, console, payload)


def _render_inventory(console: Console, payload: dict[str, object]) -> None:
    return _policy._render_inventory(_RENDER_CONTEXT, console, payload)


def _render_policies(console: Console, payload: dict[str, object]) -> None:
    return _policy._render_policies(_RENDER_CONTEXT, console, payload)


def _render_advisories(console: Console, payload: dict[str, object]) -> None:
    return _policy._render_advisories(_RENDER_CONTEXT, console, payload)


def _build_advisory_table(items: list[dict[str, object]], *, title: str | None = None) -> Table:
    return _policy._build_advisory_table(_RENDER_CONTEXT, items, title=title)


def _render_events(console: Console, payload: dict[str, object]) -> None:
    return _policy._render_events(_RENDER_CONTEXT, console, payload)


def _render_approvals(console: Console, payload: dict[str, object]) -> None:
    return _policy._render_approvals(_RENDER_CONTEXT, console, payload)


def _render_managed_install(console: Console, payload: dict[str, object]) -> None:
    return _managed._render_managed_install(_RENDER_CONTEXT, console, payload)


def _render_apps(console: Console, payload: dict[str, object]) -> None:
    return _managed._render_apps(_RENDER_CONTEXT, console, payload)


def _render_supply_chain_risk_results(console: Console, supply_chain_risks: list[dict[str, object]]) -> None:
    return _scan._render_supply_chain_risk_results(_RENDER_CONTEXT, console, supply_chain_risks)


def _render_safe_decode_results(console: Console, safe_decode_risks: list[dict[str, object]]) -> None:
    return _scan._render_safe_decode_results(_RENDER_CONTEXT, console, safe_decode_risks)


def _render_sandbox_results(console: Console, sandbox_analysis: list[dict[str, object]]) -> None:
    return _scan._render_sandbox_results(_RENDER_CONTEXT, console, sandbox_analysis)


def _render_skill_scan_results(console: Console, skill_scan: list[dict[str, object]]) -> None:
    return _scan._render_skill_scan_results(_RENDER_CONTEXT, console, skill_scan)


def _managed_install_workspace_label(workspace: object) -> str:
    return _managed._managed_install_workspace_label(_RENDER_CONTEXT, workspace)


def _managed_install_config_label(manifest: dict[str, object]) -> str:
    return _managed._managed_install_config_label(_RENDER_CONTEXT, manifest)


def _render_single_managed_install(console: Console, managed_install: dict[str, object]) -> None:
    return _managed._render_single_managed_install(_RENDER_CONTEXT, console, managed_install)


def _managed_install_batch_summary(payload: dict[str, object], managed_installs: list[dict[str, object]]) -> Table:
    return _managed._managed_install_batch_summary(_RENDER_CONTEXT, payload, managed_installs)


def _managed_install_batch_table(managed_installs: list[dict[str, object]]) -> Table:
    return _managed._managed_install_batch_table(_RENDER_CONTEXT, managed_installs)


def _managed_install_batch_notes(managed_installs: list[dict[str, object]]) -> list[str]:
    return _managed._managed_install_batch_notes(_RENDER_CONTEXT, managed_installs)


def _notes_panel(notes: list[str]) -> Panel:
    return _managed._notes_panel(_RENDER_CONTEXT, notes)


def _render_decision(console: Console, payload: dict[str, object]) -> None:
    return _commands._render_decision(_RENDER_CONTEXT, console, payload)


def _render_login(console: Console, payload: dict[str, object]) -> None:
    return _account._render_login(_RENDER_CONTEXT, console, payload)


def _render_connect(console: Console, payload: dict[str, object]) -> None:
    return _account._render_connect(_RENDER_CONTEXT, console, payload)


def _render_dashboard(console: Console, payload: dict[str, object]) -> None:
    return _account._render_dashboard(_RENDER_CONTEXT, console, payload)


def _render_sync(console: Console, payload: dict[str, object]) -> None:
    return _account._render_sync(_RENDER_CONTEXT, console, payload)


def _managed_install_state_text(managed_install: dict[str, object]) -> str:
    return _managed._managed_install_state_text(_RENDER_CONTEXT, managed_install)


def _build_ecosystem_support_table(items: list[dict[str, object]]) -> Table:
    return _managed._build_ecosystem_support_table(_RENDER_CONTEXT, items)


def _managed_install_mode_text(mode: object) -> str | None:
    return _managed._managed_install_mode_text(_RENDER_CONTEXT, mode)


def _managed_install_notes(managed_install: dict[str, object], manifest: object) -> list[str]:
    return _managed._managed_install_notes(_RENDER_CONTEXT, managed_install, manifest)


def _add_update_version_rows(body: Table, version_check: object) -> None:
    return _account._add_update_version_rows(_RENDER_CONTEXT, body, version_check)


def _render_update(console: Console, payload: dict[str, object]) -> None:
    return _account._render_update(_RENDER_CONTEXT, console, payload)


def _connect_status_text(payload: dict[str, object]) -> str:
    return _account._connect_status_text(_RENDER_CONTEXT, payload)


def _connect_milestone_text(payload: dict[str, object]) -> str:
    return _account._connect_milestone_text(_RENDER_CONTEXT, payload)


def _connect_reason_text(payload: dict[str, object]) -> str:
    return _account._connect_reason_text(_RENDER_CONTEXT, payload)


def _connect_reason_requires_login(reason: str) -> bool:
    return _account._connect_reason_requires_login(_RENDER_CONTEXT, reason)


def _connect_reason_requires_paid_plan(reason: str) -> bool:
    return _account._connect_reason_requires_paid_plan(_RENDER_CONTEXT, reason)


def _connect_sync_note_text(payload: dict[str, object]) -> str | None:
    return _account._connect_sync_note_text(_RENDER_CONTEXT, payload)


def _render_hook(console: Console, payload: dict[str, object]) -> None:
    return _commands._render_hook(_RENDER_CONTEXT, console, payload)


def _cisco_status_text(status: str) -> Text:
    return _scan._cisco_status_text(_RENDER_CONTEXT, status)


def _render_cisco_evidence(console: Console, payload: dict[str, object]) -> None:
    return _scan._render_cisco_evidence(_RENDER_CONTEXT, console, payload)


def _build_consumer_summary_table(payload: dict[str, object]) -> Table:
    return _scan._build_consumer_summary_table(_RENDER_CONTEXT, payload)


def _render_consumer_evidence_panels(console: Console, payload: dict[str, object]) -> None:
    return _scan._render_consumer_evidence_panels(_RENDER_CONTEXT, console, payload)


def _render_scan(console: Console, payload: dict[str, object]) -> None:
    return _scan._render_scan(_RENDER_CONTEXT, console, payload)


def _render_deep_scan(console: Console, payload: dict[str, object]) -> None:
    return _scan._render_deep_scan(_RENDER_CONTEXT, console, payload)


def _render_explain(console: Console, payload: dict[str, object]) -> None:
    return _commands._render_explain(_RENDER_CONTEXT, console, payload)


def _render_preflight(console: Console, payload: dict[str, object]) -> None:
    return _commands._render_preflight(_RENDER_CONTEXT, console, payload)


def _render_protect(console: Console, payload: dict[str, object]) -> None:
    return _scan._render_protect(_RENDER_CONTEXT, console, payload)


def _render_fallback(console: Console, payload: dict[str, object]) -> None:
    return _output._render_fallback(_RENDER_CONTEXT, console, payload)


def _build_supply_chain_posture_panel(supply_chain: dict[str, object]) -> Panel:
    return _health._build_supply_chain_posture_panel(_RENDER_CONTEXT, supply_chain)


def _build_harness_table(detections: list[dict[str, object]]) -> Table:
    return _initialization._build_harness_table(_RENDER_CONTEXT, detections)


def _build_product_table(harnesses: list[dict[str, object]]) -> Table:
    return _initialization._build_product_table(_RENDER_CONTEXT, harnesses)


def _next_action_label(harness: dict[str, object]) -> str:
    return _initialization._next_action_label(_RENDER_CONTEXT, harness)


def _build_steps_panel(steps: Sequence[PayloadMapping]) -> Panel:
    return _initialization._build_steps_panel(_RENDER_CONTEXT, steps)


def _build_diagnostic_command_panel() -> Panel:
    return _initialization._build_diagnostic_command_panel(_RENDER_CONTEXT)


def _render_harness_detail(console: Console, detection: dict[str, object]) -> None:
    return _initialization._render_harness_detail(_RENDER_CONTEXT, console, detection)


def _build_artifact_table(artifacts: list[dict[str, object]]) -> Table:
    return _run._build_artifact_table(_RENDER_CONTEXT, artifacts)


def _build_artifact_result_table(artifacts: list[dict[str, object]]) -> Table:
    return _run._build_artifact_result_table(_RENDER_CONTEXT, artifacts)


def _build_run_artifact_table(artifacts: list[dict[str, str]]) -> Table:
    return _run._build_run_artifact_table(_RENDER_CONTEXT, artifacts)


def _run_title(*, blocked: bool, dry_run: bool) -> str:
    return _run._run_title(_RENDER_CONTEXT, blocked=blocked, dry_run=dry_run)


def _run_outcome_text(*, blocked: bool, dry_run: bool, launched: bool) -> str:
    return _run._run_outcome_text(_RENDER_CONTEXT, blocked=blocked, dry_run=dry_run, launched=launched)


def _build_run_steps(payload: dict[str, object], *, blocked: bool, dry_run: bool) -> list[dict[str, str]]:
    return _run._build_run_steps(_RENDER_CONTEXT, payload, blocked=blocked, dry_run=dry_run)


def _summarize_run_artifacts(artifacts: list[dict[str, object]]) -> list[dict[str, str]]:
    return _run._summarize_run_artifacts(_RENDER_CONTEXT, artifacts)


def _find_replaced_artifact_partner(
    artifacts: list[dict[str, object]],
    index: int,
    used_indexes: set[int],
) -> int | None:
    return _run._find_replaced_artifact_partner(_RENDER_CONTEXT, artifacts, index, used_indexes)


def _replacement_pair(
    first: dict[str, object],
    second: dict[str, object],
) -> tuple[dict[str, object], dict[str, object]]:
    return _run._replacement_pair(_RENDER_CONTEXT, first, second)


def _artifact_display_name(artifact: dict[str, object]) -> str:
    return _run._artifact_display_name(_RENDER_CONTEXT, artifact)


def _artifact_replacement_identity(artifact: dict[str, object]) -> tuple[tuple[str, str], ...]:
    return _run._artifact_replacement_identity(_RENDER_CONTEXT, artifact)


def _artifact_change_summary(artifact: dict[str, object]) -> str:
    return _run._artifact_change_summary(_RENDER_CONTEXT, artifact)


def _field_label(field: str) -> str:
    return _run._field_label(_RENDER_CONTEXT, field)


def _artifact_reason_text(artifact: dict[str, object]) -> str:
    return _run._artifact_reason_text(_RENDER_CONTEXT, artifact)


def _artifact_risk_text(*artifacts: dict[str, object]) -> str:
    return _run._artifact_risk_text(_RENDER_CONTEXT, *artifacts)


def _run_artifact_should_be_visible(artifact: dict[str, object]) -> bool:
    return _run._run_artifact_should_be_visible(_RENDER_CONTEXT, artifact)


def _artifact_needs_review(artifact: dict[str, object]) -> bool:
    return _run._artifact_needs_review(_RENDER_CONTEXT, artifact)


def _build_approval_table(items: list[dict[str, object]], *, title: str | None) -> Table:
    return _policy._build_approval_table(_RENDER_CONTEXT, items, title=title)


def _build_runtime_probe_panel(runtime_probe: dict[str, object]) -> Panel:
    return _health._build_runtime_probe_panel(_RENDER_CONTEXT, runtime_probe)


def _build_cloud_summary_panel(payload: dict[str, object]) -> Panel:
    return _health._build_cloud_summary_panel(_RENDER_CONTEXT, payload)


def _cloud_border_style(cloud_state: str) -> str:
    return _health._cloud_border_style(_RENDER_CONTEXT, cloud_state)


def _artifact_source_text(artifact: dict[str, object]) -> str:
    return _run._artifact_source_text(_RENDER_CONTEXT, artifact)


def _status_label(detection: dict[str, object]) -> str:
    return _values._status_label(_RENDER_CONTEXT, detection)


def _status_text(detection: dict[str, object]) -> Text:
    return _values._status_text(_RENDER_CONTEXT, detection)


def _warning_count(detection: dict[str, object]) -> int:
    return _values._warning_count(_RENDER_CONTEXT, detection)


def _bool_label(value: bool) -> Text:
    return _values._bool_label(_RENDER_CONTEXT, value)


def _action_text(action: str) -> Text:
    return _values._action_text(_RENDER_CONTEXT, action)


def _command_text(command: object) -> str:
    return _values._command_text(_RENDER_CONTEXT, command)


def _coerce_object_dict(value: object) -> PayloadDict:
    return _values._coerce_object_dict(_RENDER_CONTEXT, value)


def _coerce_dict_list(value: object) -> list[PayloadDict]:
    return _values._coerce_dict_list(_RENDER_CONTEXT, value)


def _coerce_string_list(value: object) -> list[str]:
    return _values._coerce_string_list(_RENDER_CONTEXT, value)


def _short_path(value: object) -> str:
    return _values._short_path(_RENDER_CONTEXT, value)


def _timestamp_parts(value: object) -> tuple[str, str]:
    return _values._timestamp_parts(_RENDER_CONTEXT, value)


def _clean_terminal_output(value: str) -> str:
    return _values._clean_terminal_output(_RENDER_CONTEXT, value)


_JSON_RENDERERS: dict[str, Callable[[PayloadDict], PayloadDict]] = {
    "settings": _render_settings_json_payload,
}


_PLAIN_TEXT_RENDERERS: dict[str, PlainTextRenderer] = {
    "command-extensions": _plain_text_command_extensions,
    "command-inspection": _plain_text_command_inspection,
    "command-setup": _plain_text_command_setup,
    "protect": _plain_text_protect,
}


_RENDERERS: dict[str, Renderer] = {
    "command-extensions": _render_command_extensions,
    "command-inspection": _render_command_inspection,
    "command-setup": _render_command_setup,
    "approvals": _render_approvals,
    "init": _render_init,
    "start": _render_start,
    "status": _render_status,
    "dashboard": _render_dashboard,
    "connect": _render_connect,
    "bootstrap": _render_bootstrap,
    "detect": _render_detect,
    "doctor": _render_doctor,
    "trust.doctor": _render_trust_doctor,
    "trust.explain": _render_trust_explain,
    "run": _render_run,
    "diff": _render_diff,
    "receipts": _render_receipts,
    "inventory": _render_inventory,
    "policies": _render_policies,
    "exceptions": _render_policies,
    "advisories": _render_advisories,
    "events": _render_events,
    "abom": _render_fallback,
    "install": _render_managed_install,
    "uninstall": _render_managed_install,
    "apps": _render_apps,
    "allow": _render_decision,
    "deny": _render_decision,
    "login": _render_login,
    "sync": _render_sync,
    "supply-chain-explain": _render_fallback,
    "supply-chain-scan": _render_fallback,
    "supply-chain-sync": _render_fallback,
    "update": _render_update,
    "hook": _render_hook,
    "protect": _render_protect,
    "preflight": _render_preflight,
    "scan": _render_scan,
    "deep-scan": _render_deep_scan,
    "explain": _render_explain,
}

"""Build the frozen synthetic cases using the original workload oracle façade."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scripts.native_slo_workloads import ExpectedResponse, QualificationCase


def build_cases(
    workspace: Path, *, system: str | None = None, runtime: Path | None = None
) -> tuple[QualificationCase, ...]:
    """Materialize a bounded corpus with shared immutable synthetic source files.

    The caller supplies a private, disposable workspace. Case IDs and output
    bytes are stable; absolute source paths are scoped to that workspace.
    """
    from scripts import native_slo_workloads as _api

    manifest = _api.corpus_manifest()
    sizes = _api.cast(dict[str, int], manifest["size_bytes"])
    routes = _api.cast(dict[str, dict[str, str]], manifest["harness_routes"])
    aliases = _api.cast(dict[str, dict[str, list[str]]], manifest["installed_event_aliases"])
    root = workspace.resolve() / "native-qualification"
    if root.is_symlink():
        raise ValueError("native_qualification_fixture_symlink")
    root.mkdir(parents=True, exist_ok=True)
    contents: dict[tuple[str, bool], tuple[str, str, Path]] = {}
    for size_class, size in sizes.items():
        for secret in (False, True):
            body = _api._content(size, secret)
            # The native source classifier admits .rs. A .txt file under this
            # neutral directory is intentionally not source-like and blocks
            # before scanning, which cannot qualify either content verdict.
            path = root / f"{'secret' if secret else 'benign'}-{size_class}.rs"
            # Do not follow a pre-existing fixture symlink, even in a caller's
            # purportedly private workspace.
            if path.is_symlink():
                raise ValueError("native_qualification_fixture_symlink")
            if path.exists():
                if path.stat().st_size != len(body) or path.read_bytes() != body:
                    raise ValueError("native_qualification_fixture_changed")
            else:
                with path.open("xb") as stream:
                    stream.write(body)
            contents[size_class, secret] = (body.decode("ascii"), _api.hashlib.sha256(body).hexdigest(), path)
    cases: list[QualificationCase] = []

    def add(
        harness: str,
        event: str,
        canonical: str,
        label: str,
        *,
        payload: Mapping[str, object],
        expected: ExpectedResponse,
        native: ExpectedResponse | None = None,
        setup: str = "normal",
        surface: str = "normalizer_only_not_installed",
        size_class: str = "small",
        content_bytes: int = 0,
        payload_kind: str = "inline",
        route: str = "native_resident",
        status: int = 200,
    ) -> None:
        encoded = _api.json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        cases.append(
            _api.QualificationCase(
                f"{harness}/{event}/{label}/{size_class}",
                harness,
                event,
                canonical,
                size_class,
                payload,
                expected,
                route,
                setup,
                surface,
                content_bytes,
                len(encoded),
                payload_kind,
                native,
                expected_http_status=status,
            )
        )

    def pre_payload(event: str, command: str) -> dict[str, object]:
        return {
            "hook_event_name": event,
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "guard_remaining_ms": _api._REMAINING_MS,
        }

    def post_payload(event: str, size_class: str, secret: bool, source: bool) -> tuple[dict[str, object], str]:
        text, digest, path = contents[size_class, secret]
        payload: dict[str, object] = {
            "hook_event_name": event,
            "tool_name": "Read",
            "guard_remaining_ms": _api._REMAINING_MS,
        }
        if source:
            payload["tool_input"] = {"file_path": str(path)}
            payload["guard_source_ref"] = {
                "version": 1,
                "path": str(path),
                "output_sha256": digest,
                "output_chars": len(text),
                "tool_input_path": str(path),
            }
        else:
            payload["tool_response"] = [{"type": "text", "text": text}]
        return payload, digest

    for harness, surfaces in sorted(routes.items()):
        pre_surface = surfaces["pre_tool_use"]
        if pre_surface.startswith("installed_"):
            events = aliases.get(harness, {}).get("PreToolUse", ["PreToolUse"])
            for event in events:
                vectors = [
                    ("benign", "pwd", "native_exact_safe_command"),
                    ("dangerous", "rm -rf /", "native_destructive_command"),
                    (
                        "review",
                        "git diff --output=/tmp/guard-qualification.diff README.md",
                        "native_command_review_required",
                    ),
                ]
                if event in {"beforeReadFile", "beforeWriteFile"}:
                    # These are actual file hooks, not shell samples wearing a
                    # different event name. Their intrinsic floor is review.
                    operation = "Read" if event == "beforeReadFile" else "Write"
                    reason = "native_file_read_review" if operation == "Read" else "native_file_write_review"
                    payload = {
                        "hook_event_name": event,
                        "tool_name": operation,
                        "tool_input": {"file_path": "README.md"},
                        "guard_remaining_ms": _api._REMAINING_MS,
                    }
                    for setup in ("normal", "watch"):
                        add(
                            harness,
                            event,
                            "PreToolUse",
                            setup,
                            payload=payload,
                            expected=_api._pre_expected(
                                harness,
                                "review" if setup == "normal" else "watch",
                                reason,
                                recording_only=setup == "watch",
                            ),
                            native=_api._native_pre("review", reason),
                            setup=setup,
                            surface=pre_surface,
                        )
                    continue
                if event == "beforeMCPExecution":
                    reason = "native_mcp_tool_review"
                    payload = {
                        "hook_event_name": event,
                        "tool_name": "mcp__qualification__inspect",
                        "tool_input": {"item": "fixture"},
                        "guard_remaining_ms": _api._REMAINING_MS,
                    }
                    for setup in ("normal", "watch"):
                        add(
                            harness,
                            event,
                            "PreToolUse",
                            setup,
                            payload=payload,
                            expected=_api._pre_expected(
                                harness,
                                "review" if setup == "normal" else "watch",
                                reason,
                                recording_only=setup == "watch",
                            ),
                            native=_api._native_pre("review", reason),
                            setup=setup,
                            surface=pre_surface,
                        )
                    continue
                for label, command, reason in vectors:
                    kind = "block" if label == "dangerous" else label
                    add(
                        harness,
                        event,
                        "PreToolUse",
                        label,
                        payload=pre_payload(event, command),
                        expected=_api._pre_expected(harness, kind, reason),
                        native=_api._native_pre(kind, reason),
                        surface=pre_surface,
                    )
                    if kind != "benign":
                        add(
                            harness,
                            event,
                            "PreToolUse",
                            f"watch-{label}",
                            payload=pre_payload(event, command),
                            expected=_api._pre_expected(harness, "watch", reason, recording_only=True),
                            native=_api._native_pre(kind, reason),
                            setup="watch",
                            surface=pre_surface,
                        )
                add(
                    harness,
                    event,
                    "PreToolUse",
                    "review-queue-failed",
                    payload=pre_payload(event, vectors[-1][1]),
                    expected=_api._pre_expected(harness, "block", "native_review_queue_failed"),
                    native=_api._native_pre("review", vectors[-1][2]),
                    setup="review_queue_failed",
                    surface=pre_surface,
                )
                for setup, reason, route in (
                    ("unavailable", "native_pre_tool_unavailable", "native_fail_safe"),
                    ("watch_unavailable", "native_pre_tool_unavailable", "native_fail_safe"),
                    ("expired", "native_policy_not_ready", "native_fail_safe"),
                    ("revoked", "native_policy_not_ready", "native_fail_safe"),
                    ("off", "native_hook_disabled", "engine_bypassed"),
                    ("integrity", "invalid_hook_payload_reference", "engine_bypassed"),
                    ("queue_bytes", "daemon_hook_queue_bytes", "engine_bypassed"),
                ):
                    payload = pre_payload(event, "curl https://example.test/qualification")
                    if setup == "integrity":
                        payload["guard_payload_ref"] = {"version": 1, "invalid_fixture": True}
                    add(
                        harness,
                        event,
                        "PreToolUse",
                        setup,
                        payload=payload,
                        expected=_api._availability_expected(harness, "PreToolUse", reason),
                        setup=setup,
                        route=route,
                        surface=pre_surface,
                    )
        post_surface = surfaces["post_tool_use"]
        if not post_surface.startswith("installed_"):
            continue
        for event in aliases.get(harness, {}).get("PostToolUse", ["PostToolUse"]):
            surface = "installed_observation_only" if harness in {"cursor", "cline"} else post_surface
            empty_digest = _api.hashlib.sha256(b"").hexdigest()
            add(
                harness,
                event,
                "PostToolUse",
                "empty-output",
                payload={
                    "hook_event_name": event,
                    "tool_name": "Read",
                    "tool_response": [{"type": "text", "text": ""}],
                    "guard_remaining_ms": _api._REMAINING_MS,
                },
                expected=_api._post_expected(harness, "benign", "output_empty_allow", empty_digest),
                native=_api._native_post("benign", "output_empty_allow", empty_digest),
                surface=surface,
                size_class="empty",
                content_bytes=0,
            )
            for size_class, size in sizes.items():
                source = size_class in {"1m", "max"}
                for kind in ("benign", "block", "watch"):
                    payload, digest = post_payload(event, size_class, kind != "benign", source)
                    reason = (
                        ("source_full_scan_allow" if source else "output_scan_allow")
                        if kind == "benign"
                        else ("source_secret_match" if source else "output_secret_match")
                    )
                    # The resident edge evaluates the intrinsic result with
                    # observe_mode=False. Python Watch delivery changes only
                    # the final action/digest; it preserves the native reason.
                    add(
                        harness,
                        event,
                        "PostToolUse",
                        kind,
                        payload=payload,
                        expected=_api._post_expected(harness, kind, reason, digest),
                        native=_api._native_post(kind, reason, digest),
                        setup="watch" if kind == "watch" else "normal",
                        surface=surface,
                        size_class=size_class,
                        content_bytes=size,
                        payload_kind="source_file_ref" if source else "inline",
                    )
            for setup, reason, route in (
                ("unavailable", "native_post_tool_unavailable", "native_fail_safe"),
                ("watch_unavailable", "native_post_tool_unavailable", "native_fail_safe"),
                ("off", "native_hook_disabled", "engine_bypassed"),
            ):
                payload, _ = post_payload(event, "1k", True, False)
                add(
                    harness,
                    event,
                    "PostToolUse",
                    setup,
                    payload=payload,
                    expected=_api._availability_expected(harness, "PostToolUse", reason),
                    setup=setup,
                    route=route,
                    surface=surface,
                    size_class="1k",
                    content_bytes=sizes["1k"],
                )

    # Keep source identity failures distinct from unavailable native evaluation.
    payload, digest = post_payload("PostToolUse", "1k", False, True)
    reference = _api.cast(dict[str, object], payload["guard_source_ref"])
    reference["output_sha256"] = "0" * 64
    add(
        "pi",
        "PostToolUse",
        "PostToolUse",
        "source-digest-mismatch",
        payload=payload,
        expected=_api._post_expected("pi", "block", "no_output_to_review"),
        native=_api._native_post("block", "no_output_to_review", digest),
        surface="installed_canonical_source_ref",
        size_class="1k",
        content_bytes=sizes["1k"],
        payload_kind="source_file_ref",
    )

    # Transport limits use HTTP status and engine bypass, never a semantic deny.
    for size_class in ("1m", "max"):
        payload, _ = post_payload("PostToolUse", size_class, False, False)
        add(
            "pi",
            "PostToolUse",
            "PostToolUse",
            f"inline-http-bound-{size_class}",
            payload=payload,
            expected=_api.ExpectedResponse(
                "transport_rejected", "not_delivered", "http_body_limit", {"error": "request_body_too_large"}
            ),
            route="engine_bypassed",
            status=413,
            surface="transport_boundary",
            size_class=size_class,
            content_bytes=sizes[size_class],
        )

    lifecycle = _api.cast(dict[str, list[str]], manifest["lifecycle_aliases"])
    for canonical, events in lifecycle.items():
        for event in events:
            for harness in ("grok", "claude-code"):
                add(
                    harness,
                    event,
                    canonical,
                    "unavailable",
                    payload={"hook_event_name": event, "guard_remaining_ms": _api._REMAINING_MS},
                    expected=_api._availability_expected(harness, canonical, "native_hook_event_unavailable"),
                    route="native_fail_safe",
                    setup="unavailable",
                    surface="lifecycle_observation_only",
                )
    for event in _api.cast(list[str], manifest["permission_aliases"]):
        add(
            "copilot",
            event,
            "PermissionRequest",
            "unavailable",
            payload={"hook_event_name": event, "guard_remaining_ms": _api._REMAINING_MS},
            expected=_api._availability_expected("copilot", "PermissionRequest", "native_hook_event_unavailable"),
            route="native_fail_safe",
            setup="unavailable",
            surface="permission_handoff",
        )

    for canonical, events in _api.cast(dict[str, list[str]], manifest["normalizer_only_aliases"]).items():
        for event in events:
            if canonical == "PreToolUse":
                add(
                    "claude-code",
                    event,
                    canonical,
                    "alias",
                    payload=pre_payload(event, "pwd"),
                    expected=_api._pre_expected("claude-code", "benign", "native_exact_safe_command"),
                    native=_api._native_pre("benign", "native_exact_safe_command"),
                )
            else:
                payload, digest = post_payload(event, "1k", False, False)
                add(
                    "claude-code",
                    event,
                    canonical,
                    "alias",
                    payload=payload,
                    expected=_api._post_expected("claude-code", "benign", "output_scan_allow", digest),
                    native=_api._native_post("benign", "output_scan_allow", digest),
                    size_class="1k",
                    content_bytes=sizes["1k"],
                )
    if len(cases) > _api._MAX_CASES or len({case.case_id for case in cases}) != len(cases):
        raise ValueError("native_qualification_case_bound_or_duplicate")
    if not _api.source_reference_supported(system=system, runtime=runtime):
        for index, case in enumerate(cases):
            if case.payload_kind != "source_file_ref":
                continue
            # The original artifact's refusal remains a separate denial
            # witness, never full-content coverage or a latency sample.
            watch = case.setup == "watch"
            kind = "watch" if watch else "block"
            reason = "no_output_to_review"
            reference = _api.cast(_api.Mapping[str, object], case.payload["guard_source_ref"])
            digest = str(reference["output_sha256"])
            cases[index] = _api.replace(
                case,
                expected=_api._post_expected(case.harness, kind, reason, digest if watch else None),
                native_expected=_api._native_post(kind, reason, digest),
                validation_scope="platform_source_reference_denial",
            )
    return tuple(cases)

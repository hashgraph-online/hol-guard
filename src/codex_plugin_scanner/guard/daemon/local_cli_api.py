"""Bounded daemon API for unlisted CLI observation and this-device grants."""

from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path
from typing import TYPE_CHECKING

from ..adapters.harness_mcp_discovery import (
    DiscoveredHarnessMcpServer,
    apply_source_labels,
    discover_harness_mcp_servers,
    discovered_server_for_observation,
    extra_env_for_mcp_launch,
    persist_discovered_harness_mcp_servers,
)
from ..approval_gate import (
    ApprovalGateError,
    consume_local_cli_trust_grant,
    input_from_mapping,
    require_local_cli_trust,
)
from ..local_cli_errors import LocalCliCatalogLimitError
from ..local_cli_trust import utc_now
from ..runtime.custom_extension_continuity import (
    record_local_custom_extension_mutation,
)
from ..runtime.local_cli_commands import (
    MAX_LOCAL_CLI_COMMANDS,
    LocalCliCommand,
    LocalCliCommandState,
    default_local_cli_commands,
    is_local_cli_command_id,
)
from ..runtime.local_cli_help import (
    discover_local_cli_commands,
    help_invocation_for_command,
)
from ..runtime.local_cli_identity import (
    LocalCliKind,
    UnlistedCliIdentity,
    is_local_cli_id,
    local_cli_recognition_candidates,
    recognize_operator_cli,
)
from ..runtime.local_mcp_probe import (
    McpProbeError,
    is_strict_package_mcp_launcher,
    looks_like_mcp_launch,
    mcp_launch_tokens,
    probe_stdio_mcp_server,
)
from ..runtime.local_mcp_stdio import McpCatalogResult
from ..runtime.local_skill_index import (
    LocalSkillRecord,
    approved_skill_roots,
    index_local_skills,
    inspect_indexed_skill,
    public_skill_page,
)
from ..runtime.mcp_protection import build_mcp_server_identity
from ..runtime.observed_mcp_tools import discover_observed_mcp_tools
from ..runtime.package_json_script_memory import (
    _package_item_available,
    operator_working_directory,
    public_local_cli_item,
    recognize_operator_package_scripts,
    refresh_package_script_catalogs,
)
from ..runtime.package_json_scripts import looks_like_package_script_paste
from ..runtime.skill_workflow_preflight import preflight_skill_dependencies
from .local_cli_api_contract import LOCAL_CLI_API_SCHEMA as _LOCAL_CLI_API_SCHEMA
from .local_cli_api_contract import LocalCliApiError
from .local_cli_continuity_api import decorate_local_cli_continuity
from .local_cli_mcp_store import bound_mcp_observation, stored_mcp_recognition
from .local_cli_registry_setup import registry_setup as reviewed_registry_setup
from .mcp_discovery_jobs import DiscoveryJobError, DiscoveryStageError, McpDiscoveryJobs
from .mcp_registry_undo import RegistrySetupUndo

if TYPE_CHECKING:
    from ..store import GuardStore

_VALID_STATES = frozenset({"allowed", "blocked", "unset"})
_DISCOVERY_TTL_SECONDS = 30.0


def _client_discovery_job_id(payload: dict[str, object]) -> str | None:
    value = payload.get("client_job_id")
    if value is None:
        return None
    if not isinstance(value, str) or len(value) != 32 or any(c not in "0123456789abcdef" for c in value):
        raise LocalCliApiError(400, "invalid_discovery_job")
    return value


class LocalCliApiService:
    def __init__(self, *, store: GuardStore) -> None:
        from ..runtime.codex_host_inventory import CodexHostInventoryCache

        self._store = store
        self._codex_host_inventory = CodexHostInventoryCache()
        self._discovery_cache: tuple[float, tuple[DiscoveredHarnessMcpServer, ...]] | None = None
        self._discovery_jobs = McpDiscoveryJobs()
        self._registry_setup_lock = threading.Lock()
        self._registry_setup_undo = RegistrySetupUndo(store)
        self._skill_index_lock = threading.Lock()
        self._skill_records: dict[str, LocalSkillRecord] = {}
        self._skill_issues: list[dict[str, str]] = []
        self._skill_index_revision = 0
        self._skill_selected_roots: tuple[str, ...] = ()
        self._skill_index_roots: tuple[str, ...] = ()
        self._skill_job_id: str | None = None
        self._skill_preflights: dict[str, tuple[float, dict[str, object]]] = {}

    def skills(self, payload: dict[str, object]) -> dict[str, object]:
        home = Path.home()
        roots = approved_skill_roots(home)
        operation = payload.get("operation", "list")
        if operation == "roots":
            return {
                "roots": [
                    {"root_id": key, "path": str(path), "available": path.is_dir()} for key, path in roots.items()
                ],
                "permissions_granted": False,
            }
        if operation == "scan":
            selected = payload.get("approved_root_ids")
            if (
                payload.get("confirm_metadata_read") is not True
                or not isinstance(selected, list)
                or not 1 <= len(selected) <= len(roots)
                or any(not isinstance(key, str) or key not in roots for key in selected)
                or len(set(selected)) != len(selected)
            ):
                raise LocalCliApiError(
                    400,
                    "invalid_skill_root_selection",
                    "Choose skill roots to read their metadata.",
                )
            selected_roots = {key: roots[key] for key in selected}
            selection = tuple(sorted(selected_roots))
            with self._skill_index_lock:
                if self._skill_job_id is not None:
                    try:
                        active = self._discovery_jobs.read(self._skill_job_id)
                    except DiscoveryJobError:
                        active = None
                    if active is not None and active["state"] in {"running", "cancelling"}:
                        if selection != self._skill_selected_roots:
                            raise LocalCliApiError(
                                409,
                                "skill_scan_in_progress",
                                "Finish or cancel the current skill scan first.",
                            )
                        return active

                def scan(cancel: threading.Event) -> None:
                    records, issues = index_local_skills(selected_roots, home=home, cancel=cancel)
                    if not cancel.is_set():
                        with self._skill_index_lock:
                            if not cancel.is_set():
                                self._skill_records = records
                                self._skill_issues = issues
                                self._skill_index_roots = selection
                                self._skill_index_revision += 1
                                self._skill_preflights.clear()

                try:
                    job = self._discovery_jobs.start(
                        "inventory:skills",
                        scan,
                        requested_job_id=_client_discovery_job_id(payload),
                    )
                except DiscoveryJobError as error:
                    raise LocalCliApiError(
                        503,
                        "skill_discovery_busy",
                        "Other inventories are refreshing. Try again shortly.",
                    ) from error
                self._skill_selected_roots = selection
                self._skill_job_id = str(job["job_id"])
                return job
        if operation in {"preflight", "preflight-result"}:
            skill_id = payload.get("skill_id")
            if (
                not isinstance(skill_id, str)
                or len(skill_id) != 64
                or any(c not in "0123456789abcdef" for c in skill_id)
            ):
                raise LocalCliApiError(400, "invalid_skill_identity")
            with self._skill_index_lock:
                record = self._skill_records.get(skill_id)
                index_revision = self._skill_index_revision
                cached = self._skill_preflights.get(skill_id)
            if record is None:
                raise LocalCliApiError(404, "skill_not_indexed")
            if operation == "preflight-result":
                if cached is None or time.monotonic() - cached[0] > 30:
                    raise LocalCliApiError(
                        409,
                        "workflow_preflight_expired",
                        "Prepare this workflow again with current evidence.",
                    )
                result = cached[1]
                try:
                    current_inspection = inspect_indexed_skill(record, home=home)
                except (OSError, ValueError) as error:
                    raise LocalCliApiError(
                        409,
                        "workflow_skill_changed",
                        "Skill files changed. Prepare the workflow again.",
                    ) from error
                if current_inspection != result.get("inspection"):
                    raise LocalCliApiError(
                        409,
                        "workflow_skill_changed",
                        "Skill files changed. Prepare the workflow again.",
                    )
                dependencies = record.metadata.get("dependencies")
                current = self._current_skill_requirements(dependencies)
                if result.get("authority_revision") != current.get("authority_revision") or result.get(
                    "requirements"
                ) != current.get("requirements"):
                    raise LocalCliApiError(
                        409,
                        "workflow_permissions_changed",
                        "Permissions changed. Prepare the workflow again.",
                    )
                return {
                    **result,
                    "native_publication": current["native_publication"],
                    "expires_in_seconds": max(0, int(30 - (time.monotonic() - cached[0]))),
                }
            if payload.get("confirm_directory_read") is not True:
                raise LocalCliApiError(
                    400,
                    "skill_inspection_consent_required",
                    "Confirm inspecting this skill directory's revision.",
                )

            def prepare(cancel: threading.Event) -> None:
                if cancel.is_set():
                    return
                inspected = inspect_indexed_skill(record, home=home)
                dependencies = record.metadata.get("dependencies")
                result = {
                    **self._current_skill_requirements(dependencies),
                    "skill_id": skill_id,
                    "inspection": inspected,
                    "expires_in_seconds": 30,
                }
                if not cancel.is_set():
                    with self._skill_index_lock:
                        if self._skill_index_revision == index_revision and not cancel.is_set():
                            self._skill_preflights[skill_id] = (time.monotonic(), result)

            try:
                return self._discovery_jobs.start(
                    f"skill:{skill_id}",
                    prepare,
                    requested_job_id=_client_discovery_job_id(payload),
                )
            except DiscoveryJobError as error:
                raise LocalCliApiError(
                    503,
                    "skill_discovery_busy",
                    "Other inventories are refreshing. Try again shortly.",
                ) from error
        if operation != "list":
            raise LocalCliApiError(400, "invalid_skill_operation")
        offset, search, revision = payload.get("offset", 0), payload.get("search", ""), payload.get("revision")
        if (
            type(offset) is not int
            or not 0 <= offset <= 1000
            or not isinstance(search, str)
            or len(search) > 128
            or (revision is not None and (type(revision) is not int or revision < 0))
        ):
            raise LocalCliApiError(400, "invalid_skill_page")
        with self._skill_index_lock:
            if revision is not None and revision != self._skill_index_revision:
                raise LocalCliApiError(409, "skill_index_changed", "Skill metadata changed. Reload the first page.")
            return {
                **public_skill_page(self._skill_records, offset=offset, search=search),
                "revision": self._skill_index_revision,
                "indexed_root_ids": list(self._skill_index_roots),
                "issues": self._skill_issues[:64],
                "issue_count": len(self._skill_issues),
                "complete": self._skill_index_revision > 0 and not self._skill_issues,
            }

    def _current_skill_requirements(self, dependencies: object) -> dict[str, object]:
        from ..native_policy_snapshot import local_cli_publication_status

        items = self._store.list_local_cli_items()
        revision = items[0].get("authority_revision") if items else self._store.read_local_cli_revision()
        if type(revision) is not int:
            raise LocalCliApiError(503, "workflow_authority_unavailable")
        result = preflight_skill_dependencies(
            dependencies if isinstance(dependencies, dict) else {},
            items,
            revision=revision,
        )
        result["native_publication"] = local_cli_publication_status(self._store.guard_home, revision)
        return result

    def refresh_job(self, payload: dict[str, object]) -> dict[str, object]:
        try:
            job_id = payload.get("job_id")
            if job_id is not None:
                if not isinstance(job_id, str) or len(job_id) != 32 or any(c not in "0123456789abcdef" for c in job_id):
                    raise LocalCliApiError(400, "invalid_discovery_job")
                return self._discovery_jobs.read(job_id, cancel=payload.get("cancel") is True)
            if payload.get("operation") == "codex-host-connections":
                return self._discovery_jobs.start(
                    "inventory:codex-host",
                    lambda cancel: self._codex_host_inventory.refresh(codex_home=Path.home() / ".codex", cancel=cancel),
                    reuse_seconds=0 if payload.get("force_refresh") is True else 30,
                    requested_job_id=_client_discovery_job_id(payload),
                )
            if payload.get("operation") == "configured-connections":

                def discover(cancel: threading.Event) -> None:
                    if cancel.is_set():
                        return
                    # Existing host adapters read configuration and persisted
                    # observations only. This path never starts a server.
                    self._observe_harness_mcp_servers(strict=True)
                    if not cancel.is_set():
                        try:
                            saturated = discover_observed_mcp_tools(self._store, seen_at=utc_now())
                        except LocalCliCatalogLimitError:
                            raise DiscoveryStageError("catalog_limit_reached") from None
                        except (OSError, RuntimeError, TypeError, ValueError, KeyError, UnicodeError, sqlite3.Error):
                            raise DiscoveryStageError("observed_provider_scan_failed") from None
                        if saturated:
                            raise DiscoveryStageError("catalog_limit_reached")

                return self._discovery_jobs.start(
                    "inventory:configured",
                    discover,
                    reuse_seconds=0 if payload.get("force_refresh") is True else 30,
                    requested_job_id=_client_discovery_job_id(payload),
                )
            cli_id = self._required_string(payload, "cli_id")
            if not is_local_cli_id(cli_id) or payload.get("confirm_process_start") is not True:
                raise LocalCliApiError(
                    400,
                    "discovery_process_consent_required",
                    "Confirm starting this configured server to list tools.",
                )
            item = next((item for item in self._store.list_local_cli_items() if item.get("cli_id") == cli_id), None)
            if item is None or item.get("surface") != "mcp":
                raise LocalCliApiError(404, "mcp_refresh_unavailable")

            def refresh(cancel: threading.Event) -> None:
                response = self.recognize({"cli_id": cli_id, "refresh": True}, cancel=cancel)
                if not cancel.is_set() and response.get("help_status") == "failed":
                    raise DiscoveryStageError(str(response.get("discovery_error", "discovery_failed")))

            return self._discovery_jobs.start(
                cli_id,
                refresh,
                requested_job_id=_client_discovery_job_id(payload),
            )
        except DiscoveryJobError as error:
            code = str(error)
            status = 404 if code == "discovery_job_unavailable" else 429 if code == "discovery_retry_backoff" else 503
            messages = {
                "discovery_job_unavailable": "This discovery is no longer available. Reload the current inventory.",
                "discovery_retry_backoff": "Discovery just failed. Wait ten seconds before trying again.",
                "discovery_busy": "Other connections are refreshing. Try again shortly.",
                "discovery_unavailable": "Guard is stopping. Reopen Guard to try discovery again.",
            }
            raise LocalCliApiError(status, code, messages.get(code, "Could not start discovery.")) from error

    def close_discovery(self) -> bool:
        return self._discovery_jobs.close()

    def list_items(self) -> dict[str, object]:
        # Listing must stay a read of persisted grants. Live MCP/package
        # discovery writes to the same store and can abort the HTTP response
        # when the daemon is under lock contention.
        return self._list_payload(self._listed_public_items())

    def provider_actions(self, payload: dict[str, object]) -> dict[str, object]:
        cli_id = self._required_string(payload, "cli_id")
        limit, offset, search = payload.get("limit", 100), payload.get("offset", 0), payload.get("search", "")
        token = payload.get("catalog_token")
        if (
            type(limit) is not int
            or not 1 <= limit <= 100
            or type(offset) is not int
            or not 0 <= offset <= 10_000
            or not isinstance(search, str)
            or len(search) > 128
            or (
                token is not None
                and (not isinstance(token, str) or len(token) != 64 or any(c not in "0123456789abcdef" for c in token))
            )
        ):
            raise LocalCliApiError(400, "invalid_provider_catalog_page")
        try:
            page = self._store.read_local_mcp_provider_actions(
                cli_id,
                limit=limit,
                offset=offset,
                search=search,
                expected_token=token,
            )
        except ValueError as error:
            if str(error) == "provider_catalog_changed":
                raise LocalCliApiError(
                    409,
                    "provider_catalog_changed",
                    "Inventory changed. Reload its first page; your draft choices are kept.",
                ) from error
            raise LocalCliApiError(404, "provider_connection_unavailable", str(error)) from error
        return {"schema_version": _LOCAL_CLI_API_SCHEMA, "cli_id": cli_id, **page}

    def provider_workflows(self, payload: dict[str, object]) -> dict[str, object]:
        cli_id = self._required_string(payload, "cli_id")
        offset = payload.get("offset", 0)
        if type(offset) is not int or not 0 <= offset <= 50:
            raise LocalCliApiError(400, "invalid_provider_workflow_page")
        try:
            page = self._store.read_local_mcp_workflows(cli_id, offset=offset)
        except ValueError as error:
            raise LocalCliApiError(404, "provider_connection_unavailable", str(error)) from error
        return {"schema_version": _LOCAL_CLI_API_SCHEMA, "cli_id": cli_id, **page}

    def registry_search(self, payload: dict[str, object]) -> dict[str, object]:
        query = payload.get("search")
        if not isinstance(query, str) or not 2 <= len(query.strip()) <= 80:
            raise LocalCliApiError(400, "invalid_registry_search", "Enter at least two characters.")
        from ..runtime.mcp_registry import search_mcp_registry

        try:
            result = search_mcp_registry(query)
        except ValueError as error:
            raise LocalCliApiError(503, str(error), "The public MCP registry is unavailable. Retry later.") from error
        return {"schema_version": _LOCAL_CLI_API_SCHEMA, **result}

    def registry_setup(self, payload: dict[str, object]) -> dict[str, object]:
        return reviewed_registry_setup(self._store, self._registry_setup_undo, self._registry_setup_lock, payload)

    def mcp_skills(self, payload: dict[str, object]) -> dict[str, object]:
        cli_id = self._required_string(payload, "cli_id")
        offset, search, revision = payload.get("offset", 0), payload.get("search", ""), payload.get("revision")
        if (
            type(offset) is not int
            or not 0 <= offset <= 1000
            or not isinstance(search, str)
            or len(search) > 128
            or (revision is not None and (type(revision) is not int or revision < 1))
        ):
            raise LocalCliApiError(400, "invalid_mcp_skill_page")
        try:
            page = self._store.read_local_mcp_skills(cli_id, offset=offset, search=search, expected_revision=revision)
        except ValueError as error:
            if str(error) == "mcp_skill_catalog_changed":
                raise LocalCliApiError(409, str(error), "Workflow metadata changed. Reload its first page.") from error
            raise LocalCliApiError(
                404, "mcp_skills_unavailable", "No verified workflow metadata is available."
            ) from error
        return {"cli_id": cli_id, **page}

    def discover_items(self) -> dict[str, object]:
        """Refresh package.json catalogs and app MCP servers, then return the list.

        GET listing stays a store read. This write path is for Add custom
        extension so project scripts reappear without blocking the overview.
        """
        # Connector history and configured launch discovery are independent.
        discovery_issue = None
        try:
            saturated = discover_observed_mcp_tools(self._store, seen_at=utc_now())
            if saturated:
                discovery_issue = "catalog_limit_reached"
        except (OSError, RuntimeError, TypeError, ValueError, KeyError, UnicodeError, sqlite3.Error):
            discovery_issue = "observed_provider_scan_failed"
        try:
            labels = self._observe_harness_mcp_servers(strict=True)
        except DiscoveryStageError:
            labels = {}
            if discovery_issue is None:
                discovery_issue = "configured_host_scan_failed"
        try:
            items = apply_source_labels(
                refresh_package_script_catalogs(self._store, home_dir=Path.home()),
                labels,
            )
        except (OSError, RuntimeError, TypeError, ValueError, KeyError, UnicodeError, sqlite3.Error):
            items = self._listed_public_items()
            if discovery_issue is None:
                discovery_issue = "package_catalog_refresh_failed"
        result = self._list_payload(items)
        if discovery_issue is not None:
            result["discovery_issue"] = discovery_issue
        return result

    def _listed_public_items(self) -> list[dict[str, object]]:
        stored = self._store.list_local_cli_items()
        configured = {
            (item.get("server_identity_hash"), item.get("server_command"), item.get("server_args_hash"))
            for item in stored
            if item.get("surface") == "mcp" and item.get("identity_hash") != item.get("server_identity_hash")
        }
        return [
            public_local_cli_item(item)
            for item in stored
            if _package_item_available(item)
            and not (
                item.get("surface") == "mcp"
                and isinstance(item.get("server_identity_hash"), str)
                and item.get("cli_id") == f"local-cli.mcp-{str(item.get('server_identity_hash'))[:8]}"
                and item.get("identity_hash") == item.get("server_identity_hash")
                and (item.get("server_identity_hash"), item.get("server_command"), item.get("server_args_hash"))
                in configured
            )
        ]

    def _list_payload(self, items: list[dict[str, object]]) -> dict[str, object]:
        from ..native_policy_snapshot import local_cli_publication_status

        revision = self._store.read_local_cli_revision()
        return {
            "schema_version": _LOCAL_CLI_API_SCHEMA,
            "revision": revision,
            "native_publication": local_cli_publication_status(self._store.guard_home, revision),
            "items": items,
            "host_inventory": self._codex_host_inventory.read(),
            "cloud": decorate_local_cli_continuity(self._store, items),
        }

    def recognize(self, payload: dict[str, object], *, cancel: threading.Event | None = None) -> dict[str, object]:
        home_dir = Path.home()
        live_command = None
        cli_id = payload.get("cli_id")
        stored_id = cli_id if isinstance(cli_id, str) and is_local_cli_id(cli_id) else None
        refresh_only = payload.get("refresh") is True
        if refresh_only and stored_id is None:
            raise LocalCliApiError(400, "invalid_local_cli", "Choose a connector to refresh.")
        command = "" if refresh_only else self._required_string(payload, "command")
        stored_mcp = stored_mcp_recognition(
            self._store,
            command,
            cli_id=stored_id,
            recognize_payload=self._recognize_payload,
            recognize_summary=_recognize_mcp_summary,
        )
        tokens = mcp_launch_tokens(command, cwd=home_dir, home_dir=home_dir)
        if stored_id is not None or (
            tokens is not None and looks_like_mcp_launch(tokens, command_text=command, cwd=home_dir, home_dir=home_dir)
        ):
            _ = self._observe_harness_mcp_servers()
            if stored_id is not None:
                live_command = self._live_mcp_launch_command(payload)
        if refresh_only and live_command is None:
            raise LocalCliApiError(
                400,
                "mcp_refresh_unavailable",
                "Guard cannot list tools from this connection directly yet. "
                "Refresh it in its host app, or supply its exact MCP launch command in Add custom extension.",
            )
        mcp_item = self._recognize_mcp(live_command or command, home_dir, cli_id=stored_id, cancel=cancel)
        if mcp_item is not None:
            return mcp_item
        if stored_mcp is not None:
            return stored_mcp
        operator_cwd = operator_working_directory(payload, home_dir=home_dir)
        package_scripts = recognize_operator_package_scripts(
            command,
            cwd=operator_cwd,
            home_dir=home_dir,
            store=self._store,
        )
        if package_scripts is not None:
            identity = package_scripts.identity
            self._store.record_local_cli_observation(
                identity,
                seen_at=utc_now(),
                source_path=identity.source_path,
                help_status="ok",
                surface="package-scripts",
            )
            self._store.replace_local_cli_commands(identity.cli_id, package_scripts.commands)
            return self._recognize_payload(identity.cli_id, identity.to_dict(), "ok", package_scripts.summary)
        identity, code, message = recognize_operator_cli(command, cwd=operator_cwd, home_dir=home_dir)
        if identity is None and looks_like_package_script_paste(command):
            raise LocalCliApiError(
                400,
                "missing_package_json",
                "Guard could not find package.json. Paste a project folder, package.json, or npm --prefix <dir> run.",
            )
        if identity is None:
            raise LocalCliApiError(400, code, message)
        commands, help_status, source_path = _discover_from_command(command, identity, operator_cwd, home_dir)
        self._store.record_local_cli_observation(
            identity,
            seen_at=utc_now(),
            source_path=source_path,
            help_status=help_status,
            surface="cli",
        )
        self._store.replace_local_cli_commands(identity.cli_id, commands)
        return self._recognize_payload(
            identity.cli_id,
            identity.to_dict(),
            help_status,
            _recognize_summary(identity.name, help_status, len(commands)),
        )

    def _recognize_mcp(
        self,
        command: str,
        home_dir: Path,
        *,
        cli_id: str | None = None,
        cancel: threading.Event | None = None,
    ) -> dict[str, object] | None:
        tokens = mcp_launch_tokens(command, cwd=home_dir, home_dir=home_dir)
        if tokens is None:
            return None
        servers = self._discovered_servers()
        launch_identity = build_mcp_server_identity(
            config_path="",
            command=tokens[0],
            args=tuple(tokens[1:]),
            transport="stdio",
        )
        stored_observation = self._store.find_local_mcp_observation(cli_id=cli_id) if cli_id else None
        stored_server_hash = (
            stored_observation.get("server_identity_hash") if isinstance(stored_observation, dict) else None
        )
        stored_source_label = stored_observation.get("source_label") if isinstance(stored_observation, dict) else None
        selected_server = discovered_server_for_observation(
            servers,
            cli_id=cli_id,
            server_command=launch_identity.command,
            args_hash=launch_identity.args_hash,
            server_identity_hash=stored_server_hash if isinstance(stored_server_hash, str) else None,
            source_label=stored_source_label if isinstance(stored_source_label, str) else None,
        )
        # A known connection remains MCP even when its script no longer exists.
        if selected_server is None and not looks_like_mcp_launch(
            tokens, command_text=command, cwd=home_dir, home_dir=home_dir
        ):
            return None
        extra_env = extra_env_for_mcp_launch(
            servers, command=command, cli_id=selected_server.identity.cli_id if selected_server else cli_id
        )
        provisional_id = (
            cli_id
            if cli_id and isinstance(stored_observation, dict)
            else selected_server.identity.cli_id
            if selected_server is not None
            else (cli_id or f"local-cli.mcp-{launch_identity.identity_hash[:8]}")
        )
        snapshot_before = next(
            (item for item in self._store.list_local_cli_items() if item.get("cli_id") == provisional_id),
            {},
        )
        catalog_before = snapshot_before.get("mcp_catalog")
        prior_revision = catalog_before.get("revision", 0) if isinstance(catalog_before, dict) else 0
        expected_catalog_revision = prior_revision if type(prior_revision) is int and prior_revision >= 0 else 0
        failure_code = "discovery_failed"
        try:
            probed = probe_stdio_mcp_server(
                command,
                cwd=home_dir,
                home_dir=home_dir,
                extra_env=extra_env,
                cancel=cancel,
                connection_identity_hash=selected_server.identity.identity_hash if selected_server else None,
                report_failure=selected_server is not None,
                guard_home=self._store.guard_home,
            )
        except McpProbeError as error:
            failure_code = error.code
            probed = None
        except (OSError, RuntimeError, TimeoutError, ValueError):
            probed = None
        if cancel is not None and cancel.is_set():
            raise LocalCliApiError(409, "discovery_cancelled")
        if probed is None:
            stored = stored_mcp_recognition(
                self._store,
                command,
                cli_id=cli_id,
                recognize_payload=self._recognize_payload,
                recognize_summary=_recognize_mcp_summary,
            )
            if stored is not None:
                item = stored.get("item")
                if isinstance(item, dict):
                    stored_id = item.get("cli_id")
                    identity_hash = item.get("identity_hash")
                    if isinstance(stored_id, str) and isinstance(identity_hash, str):
                        self._store.merge_local_cli_commands(
                            stored_id,
                            (),
                            limit=MAX_LOCAL_CLI_COMMANDS,
                            mcp_catalog=McpCatalogResult(reason="refresh_failed"),
                            identity_hash=identity_hash,
                            seen_at=utc_now(),
                        )
                        response = self._recognize_payload(
                            stored_id,
                            item,
                            "failed",
                            "Guard could not refresh this connector. "
                            "Known tools and choices were kept. Try listing again.",
                        )
                        response["discovery_error"] = failure_code
                        return response
                return stored
            if is_strict_package_mcp_launcher(tokens):
                launcher = Path(tokens[0]).name
                raise LocalCliApiError(
                    400,
                    "already_built_in",
                    (
                        f"{launcher} is already a built-in Guard extension. "
                        "Guard could not list MCP tools from that command."
                    ),
                )
            return None
        identity, server_hash, server_command, server_args_hash = bound_mcp_observation(
            self._store,
            selected_server.identity if selected_server is not None else probed.identity,
            selected_server.server_identity if selected_server is not None else probed.server_identity,
        )
        seen_at = utc_now()
        self._store.record_local_cli_observation(
            identity,
            seen_at=seen_at,
            source_path=None,
            help_status=probed.status,
            surface="mcp",
            server_identity_hash=server_hash,
            server_command=server_command,
            server_args_hash=server_args_hash,
        )
        catalog = probed.catalog
        self._commit_mcp_discovery(identity, probed.tools, catalog, seen_at, expected_catalog_revision)
        if catalog is not None and not catalog.complete:
            summary = (
                f"Guard found {len(catalog.tools)} tools, but discovery did not finish. "
                "Known tools and choices were kept. Try listing again."
            )
        else:
            summary = _recognize_mcp_summary(identity.name, probed.status, len(probed.tools))
        return self._recognize_payload(
            identity.cli_id,
            identity.to_dict(),
            probed.status,
            summary,
        )

    def _commit_mcp_discovery(
        self,
        identity: UnlistedCliIdentity,
        tools: tuple[LocalCliCommand, ...],
        catalog: McpCatalogResult | None,
        seen_at: str,
        expected_revision: int,
    ) -> None:
        from ..native_policy_snapshot import notify_native_policy_mutation

        notify_native_policy_mutation(self._store.guard_home)
        try:
            if catalog is not None and not catalog.complete:
                self._store.merge_local_cli_commands(
                    identity.cli_id,
                    tools,
                    limit=MAX_LOCAL_CLI_COMMANDS,
                    mcp_catalog=catalog,
                    identity_hash=identity.identity_hash,
                    seen_at=seen_at,
                    expected_catalog_revision=expected_revision,
                )
            else:
                self._store.replace_local_cli_commands(
                    identity.cli_id,
                    tools,
                    mcp_catalog=catalog,
                    identity_hash=identity.identity_hash,
                    seen_at=seen_at,
                    expected_catalog_revision=expected_revision,
                )
        except LocalCliCatalogLimitError as exc:
            raise LocalCliApiError(
                409,
                "catalog_limit_reached",
                "This connector has more tools than Guard can catalog safely. Existing choices were kept.",
            ) from exc
        except ValueError as exc:
            if str(exc) == "mcp_catalog_revision_conflict":
                raise LocalCliApiError(
                    409,
                    "catalog_revision_conflict",
                    "A newer discovery finished first. Your choices were kept; refresh the current inventory.",
                ) from exc
            raise
        finally:
            notify_native_policy_mutation(self._store.guard_home)

    def _observe_harness_mcp_servers(self, *, strict: bool = False) -> dict[str, str]:
        try:
            return persist_discovered_harness_mcp_servers(
                self._store,
                self._discovered_servers(strict=True) if strict else self._discovered_servers(),
                seen_at=utc_now(),
            )
        except (OSError, RuntimeError, TypeError, ValueError, KeyError, UnicodeError, sqlite3.Error):
            if strict:
                raise DiscoveryStageError("configured_host_scan_failed") from None
            return {}

    def _discovered_servers(self, *, strict: bool = False) -> tuple[DiscoveredHarnessMcpServer, ...]:
        now = time.monotonic()
        cached = self._discovery_cache
        if cached is not None and now - cached[0] < _DISCOVERY_TTL_SECONDS:
            return cached[1]
        try:
            codex_install = self._store.get_managed_install("codex")
            managed_workspace = (
                codex_install.get("workspace") if codex_install and codex_install.get("active") else None
            )
            workspace_dir = (
                Path(managed_workspace)
                if isinstance(managed_workspace, str) and Path(managed_workspace).is_absolute()
                else None
            )
            servers = discover_harness_mcp_servers(
                home_dir=Path.home(),
                guard_home=self._store.guard_home,
                workspace_dir=workspace_dir,
            )
        except (OSError, RuntimeError, TypeError, ValueError, KeyError, UnicodeError, sqlite3.Error):
            if strict:
                raise DiscoveryStageError("configured_host_scan_failed") from None
            return ()
        self._discovery_cache = (now, servers)
        return servers

    def _live_mcp_launch_command(self, payload: dict[str, object]) -> str | None:
        cli_id = payload.get("cli_id")
        if not isinstance(cli_id, str) or not is_local_cli_id(cli_id):
            return None
        existing = self._store.find_local_mcp_observation(cli_id=cli_id)
        server_command = existing.get("server_command") if isinstance(existing, dict) else None
        args_hash = existing.get("server_args_hash") if isinstance(existing, dict) else None
        server_hash = existing.get("server_identity_hash") if isinstance(existing, dict) else None
        source_label = existing.get("source_label") if isinstance(existing, dict) else None
        server = discovered_server_for_observation(
            self._discovered_servers(),
            cli_id=cli_id,
            server_command=server_command if isinstance(server_command, str) else None,
            args_hash=args_hash if isinstance(args_hash, str) else None,
            server_identity_hash=server_hash if isinstance(server_hash, str) else None,
            source_label=source_label if isinstance(source_label, str) else None,
        )
        return None if server is None else server.launch_command

    def _recognize_payload(
        self,
        cli_id: str,
        fallback: dict[str, object],
        help_status: str,
        summary: str,
    ) -> dict[str, object]:
        listed = next(
            (item for item in self._store.list_local_cli_items() if item.get("cli_id") == cli_id),
            None,
        )
        return {
            "schema_version": _LOCAL_CLI_API_SCHEMA,
            "revision": self._store.read_local_cli_revision(),
            "item": public_local_cli_item(listed or fallback),
            "help_status": help_status,
            "summary": summary,
        }

    def preview(self, payload: dict[str, object]) -> dict[str, object]:
        identity, state = self._mutation_from_payload(payload)
        self._provider_updates_from_payload(payload)
        current = self._store.read_local_cli_revision()
        expected = self._required_int(payload, "previous_revision")
        if expected != current:
            raise LocalCliApiError(409, "revision_conflict")
        summary = _preview_summary(identity.name, state)
        return {
            "schema_version": _LOCAL_CLI_API_SCHEMA,
            "previous_revision": current,
            "next_revision": current + 1,
            "cli_id": identity.cli_id,
            "identity_hash": identity.identity_hash,
            "state": state,
            "summary": summary,
        }

    def apply(self, payload: dict[str, object]) -> dict[str, object]:
        identity, state = self._mutation_from_payload(payload)
        provider_updates = self._provider_updates_from_payload(payload)
        expected = self._required_int(payload, "previous_revision")
        session_nonce = self._required_string(payload, "session_nonce")
        action = f"local-cli-{state}"
        subject = f"{identity.cli_id}:{identity.identity_hash}:{state}:{expected}"
        if provider_updates:
            from ..store_mcp_provider_permissions import provider_choices_digest

            subject += ":" + provider_choices_digest(provider_updates)
        try:
            grant = require_local_cli_trust(
                self._store.guard_home,
                approval_gate_input=input_from_mapping(payload),
                action=action,
                subject=subject,
                session_nonce=session_nonce,
            )
            consume_local_cli_trust_grant(
                self._store.guard_home,
                grant,
                action=action,
                subject=subject,
                session_nonce=session_nonce,
            )
        except ApprovalGateError as exc:
            raise LocalCliApiError(exc.status, exc.code, str(exc)) from exc
        command_states = self._command_states_from_payload(payload)
        from ..native_policy_snapshot import local_cli_publication_status, notify_native_policy_mutation

        # Retire acknowledged authority before writing. The final notification
        # also rejects publications raced with a commit or rollback.
        notify_native_policy_mutation(self._store.guard_home)
        try:
            revision = record_local_custom_extension_mutation(
                self._store,
                identity=identity,
                state=state,
                expected_revision=expected,
                command_states=command_states,
                now=utc_now(),
                provider_updates=provider_updates,
            )
        except ValueError as exc:
            if str(exc) == "local_cli_revision_conflict":
                raise LocalCliApiError(409, "revision_conflict") from exc
            if str(exc) == "provider_action_revision_conflict":
                raise LocalCliApiError(409, "provider_action_revision_conflict") from exc
            raise LocalCliApiError(400, "invalid_local_cli_mutation", str(exc)) from exc
        finally:
            notify_native_policy_mutation(self._store.guard_home)
        return {
            "schema_version": _LOCAL_CLI_API_SCHEMA,
            "status": "applied",
            "revision": revision,
            "native_publication": local_cli_publication_status(self._store.guard_home, revision),
            "cli_id": identity.cli_id,
            "state": state,
        }

    @staticmethod
    def _provider_updates_from_payload(payload: dict[str, object]) -> tuple[tuple[str, str, int], ...]:
        import re

        raw = payload.get("provider_actions", [])
        if not isinstance(raw, list) or len(raw) > 100:
            raise LocalCliApiError(400, "invalid_provider_actions")
        updates: list[tuple[str, str, int]] = []
        for entry in raw:
            if not isinstance(entry, dict) or set(entry) != {"tool_slug", "state", "revision"}:
                raise LocalCliApiError(400, "invalid_provider_actions")
            slug, state, revision = entry["tool_slug"], entry["state"], entry["revision"]
            if (
                not isinstance(slug, str)
                or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", slug)
                or state not in ("review", "block")
                or type(revision) is not int
                or revision < 1
            ):
                raise LocalCliApiError(400, "invalid_provider_actions")
            updates.append((slug, str(state), revision))
        if len({slug for slug, _, _ in updates}) != len(updates):
            raise LocalCliApiError(400, "invalid_provider_actions")
        return tuple(updates)

    def _mutation_from_payload(self, payload: dict[str, object]) -> tuple[UnlistedCliIdentity, str]:
        cli_id = self._required_string(payload, "cli_id")
        identity_hash = self._required_string(payload, "identity_hash")
        name = self._required_string(payload, "name")
        kind = self._required_string(payload, "kind")
        state = self._required_string(payload, "state")
        if not is_local_cli_id(cli_id):
            raise LocalCliApiError(400, "invalid_cli_id")
        if len(identity_hash) != 64 or any(character not in "0123456789abcdef" for character in identity_hash):
            raise LocalCliApiError(400, "invalid_identity_hash")
        typed_kind = _cli_kind(kind)
        if typed_kind is None:
            raise LocalCliApiError(400, "invalid_cli_kind")
        if state not in _VALID_STATES:
            raise LocalCliApiError(400, "invalid_cli_state")
        example_label = payload.get("example_label")
        interpreter_name = payload.get("interpreter_name")
        if example_label is not None and not isinstance(example_label, str):
            raise LocalCliApiError(400, "invalid_example_label")
        if interpreter_name is not None and not isinstance(interpreter_name, str):
            raise LocalCliApiError(400, "invalid_interpreter_name")
        identity = UnlistedCliIdentity(
            cli_id=cli_id,
            name=name[:120],
            kind=typed_kind,
            identity_hash=identity_hash,
            example_label=(example_label or name)[:160],
            interpreter_name=interpreter_name,
        )
        return identity, state

    def _command_states_from_payload(self, payload: dict[str, object]) -> dict[str, LocalCliCommandState]:
        raw = payload.get("commands")
        if raw is None:
            return {}
        if not isinstance(raw, list) or len(raw) > MAX_LOCAL_CLI_COMMANDS:
            raise LocalCliApiError(400, "invalid_commands")
        states: dict[str, LocalCliCommandState] = {}
        for entry in raw:
            if not isinstance(entry, dict):
                raise LocalCliApiError(400, "invalid_commands")
            command_id = entry.get("command_id")
            state = entry.get("state")
            if not isinstance(command_id, str) or not is_local_cli_command_id(command_id):
                raise LocalCliApiError(400, "invalid_command_id")
            if state != "inherit" and state != "allow" and state != "review" and state != "block":
                raise LocalCliApiError(400, "invalid_command_state")
            states[command_id] = state
        return states

    def _required_string(self, payload: dict[str, object], key: str) -> str:
        value = payload.get(key)
        if not isinstance(value, str) or not value.strip():
            raise LocalCliApiError(400, f"missing_{key}")
        return value.strip()

    def _required_int(self, payload: dict[str, object], key: str) -> int:
        value = payload.get(key)
        if type(value) is not int:
            raise LocalCliApiError(400, f"missing_{key}")
        return value


def _preview_summary(name: str, state: str) -> str:
    if state == "allowed":
        return (
            f"Add {name} as a custom extension. Recommended commands stay on Guard's usual review. "
            "Allow or block applies only to the commands you set."
        )
    if state == "blocked":
        return f"Keep {name} as a custom extension and block every command from this file."
    return f"Remove the {name} custom extension from this device."


def _recognize_mcp_summary(name: str, help_status: str, tool_count: int) -> str:
    if help_status == "ok":
        return (
            f"Guard listed {tool_count} tools from this MCP server. "
            "Recommended keeps the usual review. Allow or block each tool like a built-in."
        )
    if help_status == "empty":
        return (
            f"{name} did not list tools. You can still allow or block this server, or set Recommended for other tools."
        )
    return (
        f"Guard could not list tools from {name}. You can still add the server. "
        "List tools again, or continue and keep tools on Recommended."
    )


def _recognize_summary(name: str, help_status: str, command_count: int) -> str:
    if help_status == "ok":
        return (
            f"Guard read {command_count} commands from {name} --help. "
            "Recommended keeps the usual review. Allow or block each command like a built-in tool."
        )
    if help_status == "empty":
        return (
            f"{name} did not list subcommands. You can still allow or block this file, "
            "or set Recommended for other commands."
        )
    return (
        f"Guard could not read {name} --help. You can still add the tool. "
        "Commands stay on Recommended until --help works."
    )


def _discover_from_command(
    command: str,
    identity: UnlistedCliIdentity,
    cwd: Path,
    home_dir: Path,
) -> tuple[tuple[LocalCliCommand, ...], str, str | None]:
    source_path: str | None = None
    for candidate in local_cli_recognition_candidates(command, cwd=cwd, home_dir=home_dir):
        invocation = help_invocation_for_command(candidate, cwd=cwd, home_dir=home_dir)
        if invocation is None:
            continue
        matched, argv = invocation
        if matched.cli_id != identity.cli_id:
            continue
        tool_path = next(iter(argv), None)
        if tool_path is None:
            continue
        source_path = argv[1] if matched.kind == "script" and len(argv) >= 2 else tool_path
        commands, help_status = discover_local_cli_commands(matched, argv)
        return commands, help_status, source_path
    return default_local_cli_commands(identity.name), "failed", source_path


def _cli_kind(value: str) -> LocalCliKind | None:
    if value == "executable":
        return "executable"
    if value == "script":
        return "script"
    return None

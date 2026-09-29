"""Connection-bound proposed provider dependencies; no activation or authority."""

from __future__ import annotations

import json
import sqlite3
from hashlib import sha256

from .runtime.composio_workflows import ComposioWorkflowProposal


def write_workflow_proposals(
    connection: sqlite3.Connection,
    cli_id: str,
    identity_hash: str,
    proposals: tuple[ComposioWorkflowProposal, ...],
    *,
    seen_at: str,
) -> None:
    if len(proposals) > 50:
        raise ValueError("provider_workflow_capacity")
    for proposal in proposals:
        raw = json.dumps(
            {
                "primary": proposal.primary,
                "supporting": proposal.supporting,
                "guidance_present": proposal.guidance_present,
            },
            separators=(",", ":"),
            sort_keys=True,
        )
        digest = sha256((identity_hash + "\n" + raw).encode()).hexdigest()
        connection.execute(
            """insert into local_mcp_workflow_proposal values (?, ?, ?, ?, ?)
               on conflict(cli_id, identity_hash, proposal_id) do update set seen_at = excluded.seen_at""",
            (cli_id, identity_hash, digest, raw, seen_at),
        )
    # Retention only discards advisory history, never grants or action/schema evidence.
    connection.execute(
        """delete from local_mcp_workflow_proposal where cli_id = ? and proposal_id not in (
           select proposal_id from local_mcp_workflow_proposal where cli_id = ? and identity_hash = ?
           order by seen_at desc, proposal_id limit 50)""",
        (cli_id, cli_id, identity_hash),
    )


def read_workflow_proposals(connection: sqlite3.Connection, cli_id: str, *, offset: int = 0) -> dict[str, object]:
    if type(offset) is not int or not 0 <= offset <= 50:
        raise ValueError("invalid_provider_workflow_page")
    observation = connection.execute(
        "select identity_hash from local_cli_observation where cli_id = ? and surface = 'mcp'",
        (cli_id,),
    ).fetchone()
    if observation is None:
        raise ValueError("provider_connection_unavailable")
    identity_hash = observation[0]
    rows = connection.execute(
        """select proposal_id, proposal_json, seen_at from local_mcp_workflow_proposal
           where cli_id = ? and identity_hash = ? order by seen_at desc, proposal_id limit 11 offset ?""",
        (cli_id, identity_hash, offset),
    ).fetchall()
    page = [(proposal_id, json.loads(raw), seen_at) for proposal_id, raw, seen_at in rows[:10]]
    slugs = tuple(
        dict.fromkeys(slug for _, metadata, _ in page for role in ("primary", "supporting") for slug in metadata[role])
    )
    actions: dict[str, tuple[object, object, object]] = {}
    # One bounded authority snapshot for the whole page; even SQLite's older
    # 999-variable limit covers the parser's maximum 10 x 50 action IDs.
    if slugs:
        placeholders = ",".join("?" for _ in slugs)
        action_rows = connection.execute(
            f"""select a.tool_slug, a.full_schema, a.revision, g.state from local_mcp_provider_action a
                left join local_mcp_provider_grant g on g.cli_id = a.cli_id
                and g.identity_hash = a.identity_hash and g.tool_slug = a.tool_slug
                where a.cli_id = ? and a.identity_hash = ? and a.provider = 'composio'
                and a.tool_slug in ({placeholders})""",
            (cli_id, identity_hash, *slugs),
        ).fetchall()
        actions = {row[0]: (row[1], row[2], row[3]) for row in action_rows}
    proposals: list[dict[str, object]] = []
    for proposal_id, metadata, seen_at in page:
        requirements: list[dict[str, object]] = []
        for role in ("primary", "supporting"):
            for slug in metadata[role]:
                row = actions.get(slug)
                requirements.append(
                    {
                        "tool_slug": slug,
                        "role": role,
                        "state": "unresolved" if row is None else "saved-deny" if row[2] == "block" else "ask",
                        "schema_observed": row is not None and bool(row[0]),
                        "action_revision": row[1] if row else None,
                    }
                )
        proposals.append(
            {
                "proposal_id": proposal_id,
                "source": "composio-search-guidance",
                "guidance_present": metadata["guidance_present"],
                "seen_at": seen_at,
                "requirements": requirements,
                "requirements_complete": False,
                "permissions_granted": False,
                "account_binding": "unverified",
            }
        )
    return {"proposals": proposals, "next_offset": offset + 10 if len(rows) > 10 else None}

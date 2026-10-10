"""Current external classification and reviewed or introducing-author authority."""

from __future__ import annotations

import re
import urllib.parse
from typing import Any

from extension_claim_provenance import ClaimProvenanceError, resolve_initial_contribution


def external_contribution(client: Any, extension_id: str, ref: str) -> bool:
    runtime_id = extension_id if extension_id.startswith("command.") else f"command.mcp-{extension_id[4:]}"
    binding = client.file_json(f"contracts/extensions/trust/{runtime_id}.v1.json", ref, missing_ok=True)
    return binding == {
        "schemaVersion": "guard.extension-trust-binding.v1", "extension": runtime_id, "trustClass": "external",
    }


def accepted_claimant_ids(
    client: Any, extension_id: str, ref: str, listing: dict[str, Any] | None,
    *, validate_listing: Any, contribution_paths: Any,
) -> tuple[str, ...]:
    """Explicit reviewed IDs override automatic introducing-author authority.

    An explicit empty array revokes automatic claims; an absent field needs no
    extra listing PR. Credit fields alone cannot grant claim authority.
    """
    # Revalidate current classification. Older introducing merges may predate
    # per-extension bindings; they still establish authorship, not current trust.
    if not re.fullmatch(r"[a-f0-9]{40}", ref) and not external_contribution(client, extension_id, ref):
        return ()
    if listing is not None:
        ids = validate_listing(listing, extension_id)
        if "maintainerGithubIds" in listing:
            return ids
    paths = [path for path in contribution_paths(extension_id) if client.file_exists(path, ref)]
    if not paths:
        return ()
    try:
        for path in paths:
            if path.startswith("contributions/command-sources/"):
                source = client.file_json(path, ref)
                if (not isinstance(source, dict) or source.get("schema") != "guard.command-extension-source.v1"
                        or not isinstance(source.get("extension"), dict)
                        or source["extension"].get("extension_id") != extension_id):
                    raise ClaimProvenanceError("Authored command source identity differs")
        sha = ref
        if not re.fullmatch(r"[a-f0-9]{40}", sha):
            commit = client._request(f"{client.base_url}/commits/{urllib.parse.quote(ref, safe='')}")
            sha = commit.get("sha") if isinstance(commit, dict) else None
        return (resolve_initial_contribution(client, paths, sha).github_id,)
    except ClaimProvenanceError as error:
        print(f"{extension_id}: automatic claim authority needs review: {error}")
        return ()

from scripts.ci.generate_release_notes import render_notes


def test_deferred_stable_release_notes_use_verified_github_asset_install() -> None:
    notes = render_notes(
        [],
        version="3.20.0",
        channel="stable",
        repo="hashgraph-online/hol-guard",
        tag="v3.20.0",
        previous_tag=None,
        source_sha="a" * 40,
        pypi_deferred=True,
    )

    assert "pending quota availability" in notes
    assert "https://github.com/hashgraph-online/hol-guard/releases/tag/v3.20.0" in notes
    assert 'uv tool install "./hol_guard-3.20.0-py3-none-any.whl[cisco]"' in notes
    assert 'uv tool install "hol-guard[cisco]==3.20.0"' not in notes

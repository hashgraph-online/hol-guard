"""Provider credentials and fixture paths never reach exported Gauntlet evidence."""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest import mock

from ci.gauntlet.input_evidence import fixture_path_aliases, redact_value


def test_a_forwarded_provider_credential_never_reaches_exported_evidence():
    """The harness CLI's own login is in the environment its tool children inherit.

    Any command the model runs can print it - ``env`` and ``printenv`` outright,
    a build that echoes its environment by accident - and the transcript that
    captures it is packed into the public evidence bundle. Path and canary
    redaction does not cover a credential, so the value is replaced by name.
    """
    from ci.gauntlet.case_helpers import add_credential_redactions

    replacements = {"/fixture/home": "{{home}}"}
    login = {"ANTHROPIC_API_KEY": "sk-ant-not-a-real-key", "CLAUDE_CODE_OAUTH_TOKEN": ""}
    add_credential_redactions(replacements, login)
    transcript = [{"output": "PATH=/usr/bin\nANTHROPIC_API_KEY=sk-ant-not-a-real-key\n"}]
    redacted = redact_value(transcript, replacements)
    assert "sk-ant-not-a-real-key" not in str(redacted)
    assert redacted[0]["output"].endswith("ANTHROPIC_API_KEY=<anthropic_api_key-redacted>\n")
    # An unset credential has no value to hide, and an empty replacement key
    # would rewrite every position in every exported string.
    assert "" not in replacements


def test_a_credential_handed_on_in_an_encoding_is_redacted_too():
    """Replacing the literal value leaves every reversible spelling of it readable.

    A model that pipes its environment through ``base64``, a client that logs a
    percent-encoded header, a tool that hex-escapes what it sends: each writes
    bytes the bundle's reader can turn straight back into a live key.
    """
    import base64
    from urllib.parse import quote

    from ci.gauntlet.case_helpers import add_credential_redactions

    key = "sk-ant-not-a-real-key"
    replacements = {}
    add_credential_redactions(replacements, {"ANTHROPIC_API_KEY": key})
    raw = key.encode("utf-8")
    spellings = (
        key,
        base64.b64encode(raw).decode("ascii"),
        base64.b64encode(raw).decode("ascii").rstrip("="),
        base64.urlsafe_b64encode(raw).decode("ascii"),
        raw.hex(),
        raw.hex().upper(),
        quote(key, safe=""),
    )
    transcript = [{"output": "\n".join(spellings)}]
    redacted = str(redact_value(transcript, replacements))
    for spelling in spellings:
        assert spelling not in redacted, spelling
    assert "<anthropic_api_key-redacted>" in redacted


def test_a_credential_base64ed_mid_stream_and_wrapped_is_redacted():
    """``env | base64`` is how a key really reaches a transcript, and it is neither aligned nor flat.

    The key sits at whatever byte offset the dump puts it at, so its encoding
    depends on the bytes around it, and ``base64`` breaks the result every 76
    columns. Matching one unbroken, three-byte-aligned spelling leaves nearly
    all of the key decodable in the published bundle.
    """
    import base64

    from ci.gauntlet.case_helpers import add_credential_redactions

    key = "sk-ant-api03-" + "aB3dE6gH9jK2mN5p" * 7
    replacements = {}
    add_credential_redactions(replacements, {"ANTHROPIC_API_KEY": key})
    raw = key.encode("utf-8")
    for prefix in (b"PATH=/usr/bin\nANTHROPIC_API_KEY=", b"x\nANTHROPIC_API_KEY=", b"xy\nANTHROPIC_API_KEY="):
        stream = prefix + raw + b"\nHOME=/fixture/home\n"
        wrapped = base64.encodebytes(stream).decode("ascii")
        assert "\n" in wrapped.strip(), "the fixture stream is long enough to wrap"
        # The groups made entirely of key bytes, as this stream really encodes
        # them: nothing in them comes from a neighbour, so all of them must go.
        flat = base64.b64encode(stream).decode("ascii")
        offset = len(prefix)
        interior = flat[-(-offset // 3) * 4 : ((offset + len(raw)) // 3) * 4]
        assert len(interior) > 76 and interior in "".join(wrapped.split())
        redacted = redact_value([{"output": wrapped}], replacements)[0]["output"]
        assert interior not in "".join(redacted.split()), prefix
        assert "<anthropic_api_key-redacted>" in redacted


def test_a_credential_piped_through_base64_with_a_trailing_newline_is_redacted():
    """``echo $KEY | base64`` encodes the key plus the newline ``echo`` added.

    That trailing byte changes the final group, so neither the padded nor the
    unpadded spelling of the key alone appears anywhere in the output.
    """
    import base64

    from ci.gauntlet.case_helpers import add_credential_redactions

    key = "sk-ant-api03-" + "aB3dE6gH9jK2mN5p" * 7
    replacements = {}
    add_credential_redactions(replacements, {"ANTHROPIC_API_KEY": key})
    raw = key.encode("utf-8")
    flat = base64.b64encode(raw + b"\n").decode("ascii")
    assert base64.b64encode(raw).decode("ascii") not in flat, "the fixture key exercises the shifted tail"
    redacted = redact_value([{"output": flat}], replacements)[0]["output"]
    whole = flat[: (len(raw) // 3) * 4]
    assert whole not in redacted
    assert "<anthropic_api_key-redacted>" in redacted


def test_a_credential_named_in_a_property_name_is_redacted() -> None:
    """A tool that keys its report by the value reports the key in a property name.

    ``jq`` grouping a report by token, a cache keyed by credential and an
    environment map inverted for lookup all put the secret on the left of the
    colon. A redaction that rewrites only values hands the public bundle a
    readable key, so the mapping is rewritten on both sides.
    """
    from ci.gauntlet.case_helpers import add_credential_redactions

    key = "sk-ant-api03-" + "aB3dE6gH9jK2mN5p" * 7
    replacements: dict = {}
    add_credential_redactions(replacements, {"ANTHROPIC_API_KEY": key})
    redacted = redact_value({"tokens": {key: {"source": key}}}, replacements)
    assert key not in json.dumps(redacted)
    assert redacted == {"tokens": {"<anthropic_api_key-redacted>": {"source": "<anthropic_api_key-redacted>"}}}


def test_a_fixture_path_in_a_property_name_is_aliased() -> None:
    """A per-file report names the file in its property name, and the alias belongs there too."""
    workspace = Path("/fixture/home/project")
    replacements = fixture_path_aliases({str(workspace): "{{workspace}}"})
    report = {str(workspace / "src/app.ts"): {"errors": 0}}
    redacted = redact_value(report, replacements)
    assert str(workspace) not in json.dumps(redacted)
    assert redacted == {"{{workspace}}/src/app.ts": {"errors": 0}}


def test_a_seeded_login_file_withholds_the_credential_variable() -> None:
    """A credential the CLI does not need is one the model's commands cannot print.

    Redaction hides a key the transcript already captured; withholding it keeps
    the key out of the tool children altogether, so no spelling of the dump -
    encoded, split or reported by a tool - can carry it into the bundle. The
    operator who authenticates by key alone has no login file, and the variable
    is still forwarded for them.
    """
    from ci.gauntlet.harnesses import adapter, credential_environment

    spec = adapter("claude-code")
    names = [name for name in spec.credential_env if name]
    assert names, "the claude-code adapter forwards at least one credential variable"
    with mock.patch.dict(os.environ, {name: "sk-ant-not-a-real-key" for name in names}, clear=False):
        assert credential_environment(spec, login_seeded=True) == {}
        forwarded = credential_environment(spec, login_seeded=False)
    assert sorted(forwarded) == sorted(names)


def test_an_unreadable_login_copy_is_not_a_login(tmp_path: Path) -> None:
    """A login the CLI cannot read leaves the key to forward, not to withhold.

    Withholding the variable is right only where the fixture HOME can
    authenticate without it. An empty or truncated copy authenticates nothing,
    and treating it as a login would fail every case of that run on the CLI's
    own sign-in rather than on anything Guard decided.
    """
    from ci.gauntlet.harnesses import CredentialSeed, adapter

    spec = adapter("claude-code")
    relative = spec.credential_files[0]
    logins = (
        (b'{"claudeAiOauth": {"accessToken": "not-a-real-token"}}', True),
        (b"", False),
        (b"{", False),
        (b"{}", False),
    )
    for payload, usable in logins:
        source, fixture = tmp_path / payload.hex() / "source", tmp_path / payload.hex() / "fixture"
        (source / relative).parent.mkdir(mode=0o700, parents=True)
        (source / relative).write_bytes(payload)
        fixture.mkdir(mode=0o700, parents=True)
        seed = CredentialSeed(spec, source, fixture)
        assert seed.login_usable is usable, payload

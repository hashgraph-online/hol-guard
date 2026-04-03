"""Tests for spec-aligned safe autofixes."""

import json

from codex_plugin_scanner.lint_fixes import apply_safe_autofixes


def test_apply_safe_autofixes_preserves_codex_relative_paths(tmp_path):
    plugin_manifest = tmp_path / ".codex-plugin"
    plugin_manifest.mkdir()
    (plugin_manifest / "plugin.json").write_text(
        json.dumps(
            {
                "name": "demo-plugin",
                "version": "1.0.0",
                "description": "demo",
                "skills": "skills",
                "apps": ["apps/demo.app.json"],
                "interface": {
                    "displayName": "Demo Plugin",
                    "shortDescription": "demo",
                    "longDescription": "demo",
                    "developerName": "HOL",
                    "category": "Developer Tools",
                    "capabilities": ["Read"],
                    "websiteURL": "https://example.com",
                    "privacyPolicyURL": "https://example.com/privacy",
                    "termsOfServiceURL": "https://example.com/terms",
                    "composerIcon": "assets/icon.svg",
                    "logo": "./assets/logo.svg",
                    "screenshots": ["assets/screenshot.svg"],
                },
            }
        ),
        encoding="utf-8",
    )

    marketplace_dir = tmp_path / ".agents" / "plugins"
    marketplace_dir.mkdir(parents=True)
    (marketplace_dir / "marketplace.json").write_text(
        json.dumps(
            {
                "name": "demo-marketplace",
                "plugins": [
                    {
                        "source": {
                            "source": "https://github.com/hashgraph-online/example-plugin",
                            "path": "plugins/demo",
                        },
                        "policy": {"installation": "manual", "authentication": "none"},
                        "category": "Developer Tools",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    changes = apply_safe_autofixes(tmp_path)

    manifest_payload = json.loads((plugin_manifest / "plugin.json").read_text(encoding="utf-8"))
    marketplace_payload = json.loads((marketplace_dir / "marketplace.json").read_text(encoding="utf-8"))

    assert changes
    assert manifest_payload["skills"] == "./skills"
    assert manifest_payload["apps"] == ["./apps/demo.app.json"]
    assert manifest_payload["interface"]["composerIcon"] == "./assets/icon.svg"
    assert manifest_payload["interface"]["logo"] == "./assets/logo.svg"
    assert manifest_payload["interface"]["screenshots"] == ["./assets/screenshot.svg"]
    assert marketplace_payload["plugins"][0]["source"]["path"] == "./plugins/demo"

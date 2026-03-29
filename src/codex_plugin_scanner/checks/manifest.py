"""Manifest validation checks (31 points)."""

from __future__ import annotations

import json
import re
from pathlib import Path

from ..models import CheckResult, Finding, Severity

SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")
KEBAB_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
RECOMMENDED_FIELDS = ("author", "homepage", "repository", "license", "keywords")
INTERFACE_METADATA_FIELDS = ("type", "displayName", "shortDescription", "longDescription", "developerName", "category")
INTERFACE_URL_FIELDS = ("websiteURL", "privacyPolicyURL", "termsOfServiceURL")
INTERFACE_ASSET_FIELDS = ("composerIcon", "logo")
HEX_COLOR_RE = re.compile(r"^#[0-9A-Fa-f]{6}$")


def load_manifest(plugin_dir: Path) -> dict | None:
    path = plugin_dir / ".codex-plugin" / "plugin.json"
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def _manifest_finding(
    rule_id: str,
    title: str,
    description: str,
    remediation: str,
    *,
    severity: Severity = Severity.MEDIUM,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=severity,
        category="manifest-validation",
        title=title,
        description=description,
        remediation=remediation,
        file_path=".codex-plugin/plugin.json",
    )


def _is_safe_relative_path(plugin_dir: Path, value: str) -> bool:
    candidate = Path(value)
    if candidate.is_absolute():
        return False
    resolved = (plugin_dir / candidate).resolve()
    try:
        resolved.relative_to(plugin_dir.resolve())
    except ValueError:
        return False
    return True


def _load_interface(manifest: dict | None) -> dict | None:
    if manifest is None:
        return None
    interface = manifest.get("interface")
    if interface is None:
        return None
    if isinstance(interface, dict):
        return interface
    return {}


def check_plugin_json_exists(plugin_dir: Path) -> CheckResult:
    exists = (plugin_dir / ".codex-plugin" / "plugin.json").exists()
    findings = ()
    if not exists:
        findings = (
            _manifest_finding(
                "PLUGIN_JSON_MISSING",
                "plugin.json is missing",
                "Codex plugins must declare .codex-plugin/plugin.json.",
                "Add .codex-plugin/plugin.json with the documented plugin fields.",
            ),
        )
    return CheckResult(
        name="plugin.json exists",
        passed=exists,
        points=4 if exists else 0,
        max_points=4,
        message="plugin.json found" if exists else "plugin.json not found at .codex-plugin/plugin.json",
        findings=findings,
    )


def check_valid_json(plugin_dir: Path) -> CheckResult:
    path = plugin_dir / ".codex-plugin" / "plugin.json"
    try:
        json.loads(path.read_text(encoding="utf-8"))
        return CheckResult(name="Valid JSON", passed=True, points=4, max_points=4, message="plugin.json is valid JSON")
    except Exception:
        return CheckResult(
            name="Valid JSON",
            passed=False,
            points=0,
            max_points=4,
            message="plugin.json is not valid JSON",
            findings=(
                _manifest_finding(
                    "PLUGIN_JSON_INVALID",
                    "plugin.json is invalid JSON",
                    "The plugin manifest could not be parsed.",
                    "Fix the JSON syntax in .codex-plugin/plugin.json.",
                ),
            ),
        )


def check_required_fields(plugin_dir: Path) -> CheckResult:
    manifest = load_manifest(plugin_dir)
    if manifest is None:
        return CheckResult(
            name="Required fields present",
            passed=False,
            points=0,
            max_points=5,
            message="Cannot parse plugin.json",
            findings=(
                _manifest_finding(
                    "PLUGIN_JSON_REQUIRED_FIELDS_UNCHECKED",
                    "Required fields could not be validated",
                    "Required manifest fields cannot be validated until plugin.json parses cleanly.",
                    "Fix the manifest format and include name, version, and description.",
                ),
            ),
        )
    required = ["name", "version", "description"]
    missing = [field for field in required if not manifest.get(field) or not isinstance(manifest.get(field), str)]
    if not missing:
        return CheckResult(
            name="Required fields present",
            passed=True,
            points=5,
            max_points=5,
            message="All required fields (name, version, description) are present.",
        )
    findings = tuple(
        _manifest_finding(
            f"PLUGIN_JSON_MISSING_{field.upper()}",
            f'Manifest field "{field}" is missing',
            f'The manifest does not define a valid string for "{field}".',
            f'Add a non-empty string value for "{field}" in plugin.json.',
        )
        for field in missing
    )
    return CheckResult(
        name="Required fields present",
        passed=False,
        points=0,
        max_points=5,
        message=f"Missing required fields: {', '.join(missing)}",
        findings=findings,
    )


def check_semver(plugin_dir: Path) -> CheckResult:
    manifest = load_manifest(plugin_dir)
    if manifest is None:
        return CheckResult(
            name="Version follows semver",
            passed=False,
            points=0,
            max_points=3,
            message="Cannot parse plugin.json",
        )
    version = str(manifest.get("version", ""))
    if version and SEMVER_RE.match(version):
        return CheckResult(
            name="Version follows semver",
            passed=True,
            points=3,
            max_points=3,
            message=f'Version "{version}" follows semver.',
        )
    return CheckResult(
        name="Version follows semver",
        passed=False,
        points=0,
        max_points=3,
        message=f'Version "{version}" does not follow semver (expected X.Y.Z).',
        findings=(
            _manifest_finding(
                "PLUGIN_JSON_BAD_SEMVER",
                "Manifest version is not semver",
                f'The version "{version}" does not match the documented semver format.',
                "Use a version like 1.2.3 in plugin.json.",
                severity=Severity.LOW,
            ),
        ),
    )


def check_kebab_case(plugin_dir: Path) -> CheckResult:
    manifest = load_manifest(plugin_dir)
    if manifest is None:
        return CheckResult(
            name="Name is kebab-case",
            passed=False,
            points=0,
            max_points=2,
            message="Cannot parse plugin.json",
        )
    name = str(manifest.get("name", ""))
    if name and KEBAB_RE.match(name):
        return CheckResult(
            name="Name is kebab-case",
            passed=True,
            points=2,
            max_points=2,
            message=f'Name "{name}" is kebab-case.',
        )
    return CheckResult(
        name="Name is kebab-case",
        passed=False,
        points=0,
        max_points=2,
        message=f'Name "{name}" should be kebab-case.',
        findings=(
            _manifest_finding(
                "PLUGIN_JSON_BAD_NAME",
                "Manifest name is not kebab-case",
                f'The plugin name "{name}" does not follow the recommended kebab-case style.',
                "Rename the plugin to use lowercase words separated by hyphens.",
                severity=Severity.LOW,
            ),
        ),
    )


def check_recommended_metadata(plugin_dir: Path) -> CheckResult:
    manifest = load_manifest(plugin_dir)
    if manifest is None:
        return CheckResult(
            name="Recommended metadata present",
            passed=False,
            points=0,
            max_points=4,
            message="Cannot parse plugin.json",
        )

    missing: list[str] = []
    for field in RECOMMENDED_FIELDS:
        value = manifest.get(field)
        if field == "author":
            if not isinstance(value, dict) or not isinstance(value.get("name"), str) or not value.get("name"):
                missing.append(field)
            continue
        if field == "keywords":
            if not isinstance(value, list) or not value or not all(isinstance(item, str) and item for item in value):
                missing.append(field)
            continue
        if not isinstance(value, str) or not value:
            missing.append(field)

    if not missing:
        return CheckResult(
            name="Recommended metadata present",
            passed=True,
            points=4,
            max_points=4,
            message="Recommended plugin metadata is present.",
        )

    findings = tuple(
        _manifest_finding(
            f"PLUGIN_JSON_RECOMMENDED_{field.upper()}",
            f'Recommended field "{field}" is missing',
            f'The manifest is missing the documented recommended field "{field}".',
            f'Add "{field}" to strengthen the plugin manifest metadata.',
            severity=Severity.INFO,
        )
        for field in missing
    )
    return CheckResult(
        name="Recommended metadata present",
        passed=False,
        points=0,
        max_points=4,
        message=f"Missing recommended metadata: {', '.join(missing)}",
        findings=findings,
    )


def check_interface_metadata(plugin_dir: Path) -> CheckResult:
    manifest = load_manifest(plugin_dir)
    interface = _load_interface(manifest)
    if interface is None:
        return CheckResult(
            name="Interface metadata complete if declared",
            passed=True,
            points=0,
            max_points=0,
            message="No interface metadata declared, check not applicable.",
            applicable=False,
        )

    if not interface:
        return CheckResult(
            name="Interface metadata complete if declared",
            passed=False,
            points=0,
            max_points=3,
            message="Manifest interface must be a JSON object.",
            findings=(
                _manifest_finding(
                    "PLUGIN_JSON_INTERFACE_INVALID",
                    "Manifest interface is not a JSON object",
                    'The "interface" field must be an object when it is declared.',
                    'Replace "interface" with a JSON object that contains the documented publishable metadata.',
                ),
            ),
        )

    missing = [
        field
        for field in INTERFACE_METADATA_FIELDS
        if not isinstance(interface.get(field), str) or not interface.get(field, "").strip()
    ]

    capabilities = interface.get("capabilities")
    if (
        not isinstance(capabilities, list)
        or not capabilities
        or not all(isinstance(item, str) and item.strip() for item in capabilities)
    ):
        missing.append("capabilities")

    default_prompt = interface.get("defaultPrompt")
    if default_prompt is not None:
        valid_string_prompt = isinstance(default_prompt, str) and default_prompt.strip()
        valid_list_prompt = (
            isinstance(default_prompt, list)
            and default_prompt
            and all(isinstance(item, str) and item.strip() for item in default_prompt)
        )
        if not valid_string_prompt and not valid_list_prompt:
            missing.append("defaultPrompt")

    brand_color = interface.get("brandColor")
    if brand_color is not None and (not isinstance(brand_color, str) or not HEX_COLOR_RE.match(brand_color)):
        missing.append("brandColor")

    if not missing:
        return CheckResult(
            name="Interface metadata complete if declared",
            passed=True,
            points=3,
            max_points=3,
            message="Interface metadata contains the expected publishable fields.",
        )

    findings = tuple(
        _manifest_finding(
            f"PLUGIN_JSON_INTERFACE_{field.upper()}",
            f'Interface field "{field}" is missing or invalid',
            f'The interface object is missing a valid "{field}" value.',
            f'Add a valid "{field}" field to the interface metadata.',
            severity=Severity.INFO,
        )
        for field in missing
    )
    return CheckResult(
        name="Interface metadata complete if declared",
        passed=False,
        points=0,
        max_points=3,
        message=f"Interface metadata is missing or invalid: {', '.join(missing)}",
        findings=findings,
    )


def _is_https_url(value: object) -> bool:
    return isinstance(value, str) and value.startswith("https://")


def _interface_asset_paths(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    return []


def check_interface_assets(plugin_dir: Path) -> CheckResult:
    manifest = load_manifest(plugin_dir)
    interface = _load_interface(manifest)
    if interface is None:
        return CheckResult(
            name="Interface links and assets valid if declared",
            passed=True,
            points=0,
            max_points=0,
            message="No interface metadata declared, check not applicable.",
            applicable=False,
        )

    if not interface:
        return CheckResult(
            name="Interface links and assets valid if declared",
            passed=False,
            points=0,
            max_points=3,
            message="Manifest interface must be a JSON object.",
            findings=(
                _manifest_finding(
                    "PLUGIN_JSON_INTERFACE_INVALID",
                    "Manifest interface is not a JSON object",
                    'The "interface" field must be an object when it is declared.',
                    'Replace "interface" with a JSON object that contains valid URLs and asset paths.',
                ),
            ),
        )

    issues: list[str] = []
    for field in INTERFACE_URL_FIELDS:
        if not _is_https_url(interface.get(field)):
            issues.append(field)

    for field in INTERFACE_ASSET_FIELDS:
        value = interface.get(field)
        if (
            not isinstance(value, str)
            or not _is_safe_relative_path(plugin_dir, value)
            or not (plugin_dir / value).exists()
        ):
            issues.append(field)

    screenshots = _interface_asset_paths(interface.get("screenshots"))
    if not screenshots:
        issues.append("screenshots")
    else:
        for screenshot in screenshots:
            if not _is_safe_relative_path(plugin_dir, screenshot) or not (plugin_dir / screenshot).exists():
                issues.append("screenshots")
                break

    if not issues:
        return CheckResult(
            name="Interface links and assets valid if declared",
            passed=True,
            points=3,
            max_points=3,
            message="Interface URLs use HTTPS and referenced assets exist within the plugin directory.",
        )

    findings = tuple(
        _manifest_finding(
            f"PLUGIN_JSON_INTERFACE_ASSET_{field.upper()}",
            f'Interface asset or URL "{field}" is invalid',
            f'The interface field "{field}" must use HTTPS or point to a safe in-repo asset.',
            f'Update "{field}" to use HTTPS or an existing relative asset path.',
            severity=Severity.INFO,
        )
        for field in issues
    )
    return CheckResult(
        name="Interface links and assets valid if declared",
        passed=False,
        points=0,
        max_points=3,
        message=f"Interface links or assets are invalid: {', '.join(issues)}",
        findings=findings,
    )


def check_declared_paths_safe(plugin_dir: Path) -> CheckResult:
    manifest = load_manifest(plugin_dir)
    if manifest is None:
        return CheckResult(
            name="Declared paths are safe",
            passed=False,
            points=0,
            max_points=3,
            message="Cannot parse plugin.json",
        )

    unsafe: list[str] = []
    skills_path = manifest.get("skills")
    if isinstance(skills_path, str) and not _is_safe_relative_path(plugin_dir, skills_path):
        unsafe.append(f"skills={skills_path}")

    apps = manifest.get("apps")
    if isinstance(apps, list):
        for app in apps:
            if isinstance(app, str) and not _is_safe_relative_path(plugin_dir, app):
                unsafe.append(f"apps={app}")

    if not unsafe:
        return CheckResult(
            name="Declared paths are safe",
            passed=True,
            points=3,
            max_points=3,
            message="Declared manifest paths stay within the plugin directory.",
        )

    findings = tuple(
        _manifest_finding(
            "PLUGIN_JSON_UNSAFE_PATH",
            "Manifest declares an unsafe path",
            f'The manifest path "{entry}" resolves outside the plugin directory or is absolute.',
            "Use only relative paths that stay within the plugin repository.",
        )
        for entry in unsafe
    )
    return CheckResult(
        name="Declared paths are safe",
        passed=False,
        points=0,
        max_points=3,
        message=f"Unsafe manifest paths detected: {', '.join(unsafe)}",
        findings=findings,
    )


def run_manifest_checks(plugin_dir: Path) -> tuple[CheckResult, ...]:
    return (
        check_plugin_json_exists(plugin_dir),
        check_valid_json(plugin_dir),
        check_required_fields(plugin_dir),
        check_semver(plugin_dir),
        check_kebab_case(plugin_dir),
        check_recommended_metadata(plugin_dir),
        check_interface_metadata(plugin_dir),
        check_interface_assets(plugin_dir),
        check_declared_paths_safe(plugin_dir),
    )

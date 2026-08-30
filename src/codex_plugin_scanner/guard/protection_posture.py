"""Machine-wide protection posture and dual-write to legacy mode/level."""

from __future__ import annotations

from .models import GuardAction, GuardMode

VALID_PROTECTION_POSTURES = frozenset({"protected", "extra_careful", "watch"})
DEFAULT_PROTECTION_POSTURE = "protected"
DEFAULT_WATCH_AUTO_REVERT_HOURS = 24
MAX_WATCH_AUTO_REVERT_HOURS = 168
HIGH_CONFIDENCE_LABELS = frozenset({"strong"})
ALWAYS_STOP_RISK_CLASSES = frozenset({"guard_bypass", "encoded_exfiltration"})
HIGH_CONFIDENCE_STOP_RISK_CLASSES = frozenset({"credential_exfiltration", "data_flow_exfiltration"})

POSTURE_COPY: dict[str, dict[str, str]] = {
    "protected": {
        "label": "Protected",
        "help": (
            "Stops theft, wipes, and Guard bypass. Asks once about new tools or "
            "first-time secret access, then remembers."
        ),
    },
    "extra_careful": {
        "label": "Extra careful",
        "help": (
            "Same as Protected, and also asks the first time this project talks to a new site or installs a new tool."
        ),
    },
    "watch": {
        "label": "Watch",
        "help": ("Records what Guard would have stopped, but does not stop anything. Use only while debugging."),
    },
}

POSTURE_RISK_ACTIONS: dict[str, dict[str, GuardAction]] = {
    "protected": {
        "local_secret_read": "require-reapproval",
        "credential_exfiltration": "require-reapproval",
        "data_flow_exfiltration": "require-reapproval",
        "destructive_shell": "require-reapproval",
        "encoded_execution": "require-reapproval",
        "network_egress": "allow",
        "prompt_injection": "require-reapproval",
        "mcp_dangerous_tool": "require-reapproval",
        "malicious_skill": "require-reapproval",
        "package_script": "require-reapproval",
        "persistence": "require-reapproval",
        "guard_bypass": "block",
        "cloud_advisory": "allow",
        "encoded_exfiltration": "block",
    },
    "extra_careful": {
        "local_secret_read": "require-reapproval",
        "credential_exfiltration": "require-reapproval",
        "data_flow_exfiltration": "require-reapproval",
        "destructive_shell": "require-reapproval",
        "encoded_execution": "require-reapproval",
        "network_egress": "require-reapproval",
        "prompt_injection": "require-reapproval",
        "mcp_dangerous_tool": "require-reapproval",
        "malicious_skill": "require-reapproval",
        "package_script": "require-reapproval",
        "persistence": "require-reapproval",
        "guard_bypass": "block",
        "cloud_advisory": "require-reapproval",
        "encoded_exfiltration": "block",
    },
}


def normalize_protection_posture(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip().replace("-", "_").lower()
    if normalized in VALID_PROTECTION_POSTURES:
        return normalized
    return None


def coerce_protection_posture(value: object) -> str:
    posture = normalize_protection_posture(value)
    if posture is None:
        raise ValueError("Invalid Guard protection posture.")
    return posture


def coerce_loaded_protection_posture(value: object) -> str | None:
    return normalize_protection_posture(value)


def coerce_watch_auto_revert_hours(value: object, default: int = DEFAULT_WATCH_AUTO_REVERT_HOURS) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        return default
    if value < 0 or value > MAX_WATCH_AUTO_REVERT_HOURS:
        return default
    return value


def derive_protection_posture(mode: object, security_level: object) -> str:
    if mode == "observe":
        return "watch"
    if security_level == "strict":
        return "extra_careful"
    if security_level == "paranoid":
        return "extra_careful"
    return DEFAULT_PROTECTION_POSTURE


def dual_write_from_posture(
    posture: str,
    *,
    current_security_level: str | None = None,
) -> tuple[GuardMode, str | None]:
    if posture == "watch":
        return "observe", current_security_level
    if posture == "extra_careful":
        return "enforce", "strict"
    return "enforce", "balanced"


def resolve_posture_defaults(posture: str) -> dict[str, GuardAction] | None:
    return POSTURE_RISK_ACTIONS.get(posture)


def is_high_confidence(confidence: object) -> bool:
    if not isinstance(confidence, str):
        return False
    return confidence.strip().lower() in HIGH_CONFIDENCE_LABELS


def apply_posture_confidence(
    *,
    posture: str,
    explicit: bool,
    risk_class: str,
    action: GuardAction,
    confidence: object = None,
    persistence_writes_launch_agent: bool = False,
    injection_disables_guard: bool = False,
    skill_is_known_bad: bool = False,
) -> GuardAction:
    if not explicit or posture not in {"protected", "extra_careful"}:
        return action
    if risk_class in ALWAYS_STOP_RISK_CLASSES:
        return "block"
    if risk_class in HIGH_CONFIDENCE_STOP_RISK_CLASSES and is_high_confidence(confidence):
        return "block"
    if risk_class == "prompt_injection" and injection_disables_guard and is_high_confidence(confidence):
        return "block"
    if risk_class == "persistence" and persistence_writes_launch_agent:
        return "block"
    if risk_class == "malicious_skill" and skill_is_known_bad:
        return "block"
    return action


def posture_label(posture: str) -> str:
    copy = POSTURE_COPY.get(posture)
    return copy["label"] if copy is not None else posture


def posture_help(posture: str) -> str:
    copy = POSTURE_COPY.get(posture)
    return copy["help"] if copy is not None else ""


def protection_is_off(*, posture: str, mode: str) -> bool:
    return posture == "watch" or mode == "observe"


def recording_only_from_config_text(text: str) -> bool:
    """Parse top-level Guard config text for watch/observe recording-only mode."""

    mode = ""
    posture = ""
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("["):
            continue
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key == "mode":
            mode = value
        elif key == "protection_posture":
            posture = value
    return protection_is_off(posture=posture, mode=mode)


def protection_status_fields(*, posture: str, mode: str) -> dict[str, object]:
    off = protection_is_off(posture=posture, mode=mode)
    return {
        "protection": posture,
        "protection_label": posture_label(posture),
        "protection_help": posture_help(posture),
        "protection_off": off,
    }

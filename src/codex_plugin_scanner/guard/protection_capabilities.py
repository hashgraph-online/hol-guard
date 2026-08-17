"""Per-harness protection capability contract used by Settings honesty copy."""

from __future__ import annotations

from dataclasses import dataclass

from .adapters.contracts import HARNESS_CONTRACTS, display_name_for


@dataclass(frozen=True, slots=True)
class HarnessProtectionCapability:
    harness: str
    can_pre_block: bool
    can_ask_inline: bool
    has_native_remember: bool
    fail_open_on_hook_failure: bool
    can_pre_block_limited: bool = False

    def to_dict(self) -> dict[str, object]:
        display_name = display_name_for(self.harness)
        return {
            "harness": self.harness,
            "display_name": display_name,
            "can_pre_block": self.can_pre_block,
            "can_ask_inline": self.can_ask_inline,
            "has_native_remember": self.has_native_remember,
            "fail_open_on_hook_failure": self.fail_open_on_hook_failure,
            "can_pre_block_limited": self.can_pre_block_limited,
            "honesty_sentence": honesty_sentence(self, display_name),
            "limited": self.fail_open_on_hook_failure or self.can_pre_block_limited,
        }


def honesty_sentence(capability: HarnessProtectionCapability, display_name: str) -> str:
    if capability.can_ask_inline and capability.has_native_remember:
        return f"{display_name} uses this app's prompt when it can."
    if capability.can_ask_inline:
        return f"{display_name} asks in chat, then remembers."
    if capability.fail_open_on_hook_failure:
        limited = f"Limited in {display_name}. This app cannot ask in chat."
        return f"{limited} If Guard is down, this app continues."
    if capability.can_pre_block_limited:
        return f"Limited in {display_name}. Guard stops what it can see and opens Guard for the rest."
    return f"{display_name} stops the action and opens Guard. This app cannot ask in chat."


HARNESS_PROTECTION_CAPABILITIES: tuple[HarnessProtectionCapability, ...] = (
    HarnessProtectionCapability("codex", True, True, False, False),
    HarnessProtectionCapability("claude-code", True, True, False, False),
    HarnessProtectionCapability("opencode", True, True, True, False),
    HarnessProtectionCapability("copilot", True, True, False, False),
    HarnessProtectionCapability("cursor", True, True, True, False),
    HarnessProtectionCapability("cline", True, False, False, False),
    HarnessProtectionCapability("gemini", True, False, False, False, True),
    HarnessProtectionCapability("hermes", True, False, False, False),
    HarnessProtectionCapability("openclaw", True, False, False, False),
    HarnessProtectionCapability("antigravity", True, False, False, False, True),
    HarnessProtectionCapability("kimi", True, False, False, True),
    HarnessProtectionCapability("grok", True, False, False, True),
    HarnessProtectionCapability("pi", True, False, False, True),
    HarnessProtectionCapability("omp", True, False, False, True),
    HarnessProtectionCapability("zcode", True, False, False, True),
)

_CAPABILITY_BY_HARNESS = {item.harness: item for item in HARNESS_PROTECTION_CAPABILITIES}


def capability_for(harness: str) -> HarnessProtectionCapability | None:
    return _CAPABILITY_BY_HARNESS.get(harness)


def protection_capability_payloads() -> list[dict[str, object]]:
    known = {contract.harness for contract in HARNESS_CONTRACTS}
    return [item.to_dict() for item in HARNESS_PROTECTION_CAPABILITIES if item.harness in known]

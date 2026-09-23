"""
Tool Registry — Step 12.
Every tool has a metadata record describing its risk and access requirements.
"""

from dataclasses import dataclass
from typing import List

RISK_LOW      = "LOW"
RISK_MEDIUM   = "MEDIUM"
RISK_HIGH     = "HIGH"
RISK_CRITICAL = "CRITICAL"

# Emergency revocation kill-switch — Step 7 (emergency revocation)
# Set to True to instantly disable ALL tool execution across the agent.
REVOKED = False


def revoke_all():
    """Activate emergency revocation — blocks every tool call immediately."""
    global REVOKED
    REVOKED = True
    print("[EMERGENCY REVOCATION] All agent tool access has been revoked.")


def restore_access():
    """Restore access after emergency revocation."""
    global REVOKED
    REVOKED = False
    print("[ACCESS RESTORED] Agent tool access re-enabled.")


@dataclass
class ToolMeta:
    name: str
    risk: str
    requires_approval: bool
    allowed_roles: List[str]
    side_effect: bool           # Writes / sends / executes something
    can_exfiltrate: bool        # Result can leave the system
    untrusted_content: bool     # Tool result may contain attacker-controlled content (Step 5)
    description: str


REGISTRY: dict[str, ToolMeta] = {
    "search_employee": ToolMeta(
        name="search_employee",
        risk=RISK_LOW,
        requires_approval=False,
        allowed_roles=["employee", "manager", "admin"],
        side_effect=False,
        can_exfiltrate=False,
        untrusted_content=False,
        description="Read-only employee directory lookup",
    ),
    "read_file": ToolMeta(
        name="read_file",
        risk=RISK_MEDIUM,
        requires_approval=False,
        allowed_roles=["employee", "manager", "admin"],
        side_effect=False,
        can_exfiltrate=False,
        untrusted_content=True,   # File content is attacker-controllable
        description="Read files from the internal data store",
    ),
    "create_file": ToolMeta(
        name="create_file",
        risk=RISK_MEDIUM,
        requires_approval=False,
        allowed_roles=["employee", "manager", "admin"],
        side_effect=True,
        can_exfiltrate=False,
        untrusted_content=False,
        description="Write files to the sandbox",
    ),
    "send_email": ToolMeta(
        name="send_email",
        risk=RISK_HIGH,
        requires_approval=True,
        allowed_roles=["manager", "admin"],
        side_effect=True,
        can_exfiltrate=True,
        untrusted_content=False,
        description="Send email — persistent, can exfiltrate data",
    ),
    "execute_command": ToolMeta(
        name="execute_command",
        risk=RISK_CRITICAL,
        requires_approval=True,
        allowed_roles=["admin"],
        side_effect=True,
        can_exfiltrate=True,
        untrusted_content=False,
        description="Execute shell command — highest risk",
    ),
}


def get_tool_meta(tool_name: str) -> ToolMeta | None:
    return REGISTRY.get(tool_name)


def is_registered(tool_name: str) -> bool:
    return tool_name in REGISTRY

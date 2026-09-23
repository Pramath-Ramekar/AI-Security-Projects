"""
Policy Engine — Step 13.
Every tool request passes through here before execution.
Checks: emergency revocation → registry → role → risk level.
"""

from dataclasses import dataclass
import security.tool_registry as _reg
from security.tool_registry import get_tool_meta, is_registered, RISK_CRITICAL, RISK_HIGH


@dataclass
class PolicyDecision:
    allowed: bool
    requires_approval: bool
    reason: str
    tool_name: str
    risk: str = "UNKNOWN"


def evaluate(tool_name: str, arguments: dict, user_role: str = "employee") -> PolicyDecision:
    """
    Evaluate whether a tool call is permitted for the given role.
    Returns a PolicyDecision — always check .allowed before executing.
    """

    # 0. Emergency revocation kill-switch (Step 7)
    if _reg.REVOKED:
        return PolicyDecision(
            allowed=False,
            requires_approval=False,
            reason="EMERGENCY REVOCATION ACTIVE — all tool access is disabled",
            tool_name=tool_name,
        )

    # 1. Registry check
    if not is_registered(tool_name):
        return PolicyDecision(
            allowed=False,
            requires_approval=False,
            reason=f"Tool '{tool_name}' is not in the registry",
            tool_name=tool_name,
        )

    meta = get_tool_meta(tool_name)

    # 2. Role check
    if user_role not in meta.allowed_roles:
        return PolicyDecision(
            allowed=False,
            requires_approval=False,
            reason=(
                f"Role '{user_role}' is not permitted to use '{tool_name}'. "
                f"Allowed roles: {meta.allowed_roles}"
            ),
            tool_name=tool_name,
            risk=meta.risk,
        )

    # 3. HIGH / CRITICAL always require human approval regardless of role
    if meta.risk in (RISK_CRITICAL, RISK_HIGH):
        return PolicyDecision(
            allowed=True,
            requires_approval=True,
            reason=f"Tool '{tool_name}' is {meta.risk} risk — human approval required",
            tool_name=tool_name,
            risk=meta.risk,
        )

    return PolicyDecision(
        allowed=True,
        requires_approval=meta.requires_approval,
        reason="Permitted",
        tool_name=tool_name,
        risk=meta.risk,
    )

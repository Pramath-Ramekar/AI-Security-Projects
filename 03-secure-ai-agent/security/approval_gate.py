"""
Human Approval Gate — Step 15.
High-risk tool calls pause for human review before executing.
"""

from dataclasses import dataclass
from typing import Optional


@dataclass
class ApprovalRequest:
    tool_name: str
    arguments: dict
    risk: str
    reason: str


@dataclass
class ApprovalResult:
    approved: bool
    reviewer: str
    notes: str = ""


def request_approval(tool_name: str, arguments: dict, risk: str, reason: str) -> ApprovalResult:
    """
    Display the pending tool call to a human and wait for approval.
    In production this would integrate with Slack, email, or a UI.
    For the lab, this is a simple CLI prompt.
    """
    print("\n" + "!" * 60)
    print("  APPROVAL REQUIRED")
    print("!" * 60)
    print(f"  Tool:   {tool_name}")
    print(f"  Risk:   {risk}")
    print(f"  Reason: {reason}")
    print(f"  Arguments:")
    for k, v in arguments.items():
        val_str = str(v)
        if len(val_str) > 100:
            val_str = val_str[:100] + "..."
        print(f"    {k}: {val_str}")
    print("!" * 60)

    while True:
        choice = input("  Approve? [y/n]: ").strip().lower()
        if choice in ("y", "yes"):
            notes = input("  Notes (optional): ").strip()
            return ApprovalResult(approved=True, reviewer="human_operator", notes=notes)
        elif choice in ("n", "no"):
            notes = input("  Reason for denial (optional): ").strip()
            return ApprovalResult(approved=False, reviewer="human_operator", notes=notes)
        else:
            print("  Please enter 'y' or 'n'.")


def auto_deny(tool_name: str, arguments: dict) -> ApprovalResult:
    """Used in non-interactive/test mode — automatically denies high-risk actions."""
    return ApprovalResult(
        approved=False,
        reviewer="auto_policy",
        notes=f"Auto-denied in non-interactive mode: {tool_name}",
    )

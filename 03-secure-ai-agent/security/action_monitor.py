"""
Action Monitor — Step 17.
Detects dangerous tool-chain patterns within a single agent session.
Individual tools may be low-risk; their combination can be critical.
"""

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class ToolEvent:
    tool_name: str
    arguments: dict
    result_summary: str = ""


@dataclass
class ChainVerdict:
    blocked: bool
    pattern_name: str
    reason: str


class ActionMonitor:
    def __init__(self):
        self.history: List[ToolEvent] = []

    def record(self, tool_name: str, arguments: dict, result_summary: str = ""):
        self.history.append(ToolEvent(tool_name, arguments, result_summary))

    def evaluate_chain(self, next_tool: str, next_args: dict) -> ChainVerdict:
        """
        Look at the current tool call in context of previous calls.
        Returns a ChainVerdict — blocked=True means the chain is dangerous.
        """
        tools_used = [e.tool_name for e in self.history]

        # Pattern: read any file → send external email
        if next_tool == "send_email":
            to = next_args.get("to", "")
            if "read_file" in tools_used and not to.endswith("@aegis.internal"):
                return ChainVerdict(
                    blocked=True,
                    pattern_name="READ_THEN_EXFIL",
                    reason=(
                        f"Chain detected: file was read earlier this session, "
                        f"and now an email is being sent to external address '{to}'. "
                        "This pattern matches data exfiltration."
                    ),
                )

        # Pattern: search employees → send email with large body
        if next_tool == "send_email":
            body = next_args.get("body", "")
            if "search_employee" in tools_used and len(body) > 500:
                return ChainVerdict(
                    blocked=True,
                    pattern_name="SEARCH_THEN_DUMP",
                    reason=(
                        "Chain detected: employee data was searched, then a large email body "
                        "was composed — possible bulk data dump."
                    ),
                )

        # Pattern: read file → create file (exfil via file copy to sandbox)
        if next_tool == "create_file" and "read_file" in tools_used:
            if len(self.history) >= 2:
                return ChainVerdict(
                    blocked=False,
                    pattern_name="READ_THEN_WRITE",
                    reason="File read followed by file create — allowed but logged.",
                )

        # Pattern: any tool → execute_command after reading sensitive data
        if next_tool == "execute_command":
            sensitive_reads = [
                e for e in self.history
                if e.tool_name == "read_file"
                and ("employee" in e.arguments.get("filename", "") or
                     "roadmap" in e.arguments.get("filename", ""))
            ]
            if sensitive_reads:
                return ChainVerdict(
                    blocked=True,
                    pattern_name="SENSITIVE_READ_THEN_EXEC",
                    reason="Sensitive file was read earlier; executing a command now is blocked.",
                )

        return ChainVerdict(blocked=False, pattern_name="NONE", reason="OK")

    def reset(self):
        self.history.clear()

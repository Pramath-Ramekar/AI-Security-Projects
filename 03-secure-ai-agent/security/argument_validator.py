"""
Argument Validator — Step 14.
Validates LLM-generated tool arguments before execution.
Never trust the model's output as safe input.
"""

import os
import re

DATA_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data"))
SANDBOX_ROOT = os.path.join(DATA_ROOT, "sandbox")

# External domains that are never allowed as email recipients
BLOCKED_EXTERNAL_DOMAINS = {
    "external.com", "evil.com", "rival.com", "attacker.com",
    "offsite.net", "leak.io",
}

DANGEROUS_COMMAND_PATTERNS = [
    r"\.\.[/\\]",          # path traversal
    r"rm\s+-rf",           # recursive delete (unix)
    r"del\s+/[sq]",        # recursive delete (windows)
    r"format\s+[a-zA-Z]:", # disk format
    r"shutdown",
    r"net\s+user",         # user management
    r"reg\s+",             # registry edits
    r"wget\s+|curl\s+",    # downloads
    r"powershell",
    r"cmd\.exe",
    r"&\s*&|\|\s*\|",      # command chaining
]


def validate_read_file(filename: str) -> tuple[bool, str]:
    """Ensure filename stays within DATA_ROOT and does not traverse."""
    if not filename:
        return False, "Filename cannot be empty"

    resolved = os.path.abspath(os.path.join(DATA_ROOT, filename))

    if not resolved.startswith(DATA_ROOT):
        return False, f"Path traversal detected: '{filename}' resolves outside data root"

    # Block direct access to employee DB from a file read (should use search tool)
    if "employee_db" in filename and "employees.json" in filename:
        return False, "Direct access to employee database is not permitted via read_file. Use search_employee."

    return True, "OK"


def validate_create_file(filename: str, content: str) -> tuple[bool, str]:
    """Ensure create_file targets only the sandbox."""
    if not filename:
        return False, "Filename cannot be empty"

    resolved = os.path.abspath(os.path.join(SANDBOX_ROOT, filename))

    if not resolved.startswith(SANDBOX_ROOT):
        return False, f"Path traversal detected: '{filename}' resolves outside sandbox"

    if len(content) > 1_000_000:
        return False, "Content exceeds 1MB limit"

    return True, "OK"


def validate_send_email(to: str, subject: str, body: str) -> tuple[bool, str]:
    """Validate email recipients and content."""
    if not to or "@" not in to:
        return False, f"Invalid recipient: '{to}'"

    domain = to.split("@")[-1].lower()

    if domain in BLOCKED_EXTERNAL_DOMAINS:
        return False, f"Recipient domain '{domain}' is not permitted"

    if not to.endswith("@aegis.internal") and domain not in ("aegis.internal",):
        return False, f"External recipients require explicit admin approval. '{to}' is not an internal address."

    if len(body) > 50_000:
        return False, "Email body exceeds maximum allowed length (possible data dump)"

    return True, "OK"


def validate_execute_command(command: str) -> tuple[bool, str]:
    """Validate shell command against dangerous pattern allowlist."""
    if not command or not command.strip():
        return False, "Command cannot be empty"

    command_lower = command.lower()

    for pattern in DANGEROUS_COMMAND_PATTERNS:
        if re.search(pattern, command_lower):
            return False, f"Dangerous pattern detected in command: '{pattern}'"

    # Only allow simple safe commands
    ALLOWED_COMMANDS = ("dir", "ls", "echo", "type", "cat", "pwd", "whoami")
    first_word = command_lower.strip().split()[0]
    if first_word not in ALLOWED_COMMANDS:
        return False, f"Command '{first_word}' is not in the allowlist: {ALLOWED_COMMANDS}"

    return True, "OK"


def validate(tool_name: str, arguments: dict) -> tuple[bool, str]:
    """Dispatch validation by tool name."""
    validators = {
        "read_file": lambda a: validate_read_file(a.get("filename", "")),
        "create_file": lambda a: validate_create_file(a.get("filename", ""), a.get("content", "")),
        "send_email": lambda a: validate_send_email(a.get("to", ""), a.get("subject", ""), a.get("body", "")),
        "execute_command": lambda a: validate_execute_command(a.get("command", "")),
        "search_employee": lambda a: (True, "OK"),  # no dangerous arguments possible
    }

    validator = validators.get(tool_name)
    if not validator:
        return False, f"No validator found for tool '{tool_name}'"

    return validator(arguments)

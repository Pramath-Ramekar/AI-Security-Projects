import subprocess
import os
import shlex

SANDBOX_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data", "sandbox"))

# VULNERABLE version: minimal restrictions
def execute_command(command: str) -> dict:
    """Execute a shell command. VULNERABLE: no allowlist, minimal sandboxing."""
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=10,
            cwd=SANDBOX_DIR,
        )
        return {
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode,
        }
    except subprocess.TimeoutExpired:
        return {"error": "Command timed out after 10 seconds"}
    except Exception as e:
        return {"error": str(e)}

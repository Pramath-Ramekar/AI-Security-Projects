import os

DATA_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data"))

def read_file(filename: str) -> dict:
    """Read a file from the data store. filename is relative to data/."""
    # VULNERABLE: no path validation — allows traversal
    target = os.path.join(DATA_ROOT, filename)
    resolved = os.path.abspath(target)

    if not os.path.exists(resolved):
        return {"error": f"File not found: {filename}"}

    if os.path.isdir(resolved):
        entries = os.listdir(resolved)
        return {"type": "directory", "entries": entries}

    with open(resolved, "r", errors="replace") as f:
        content = f.read()

    return {"filename": filename, "content": content, "size": len(content)}


def create_file(filename: str, content: str) -> dict:
    """Create a file in the sandbox. filename is relative to data/sandbox/."""
    # VULNERABLE: no path validation
    sandbox = os.path.join(DATA_ROOT, "sandbox")
    target = os.path.abspath(os.path.join(sandbox, filename))

    os.makedirs(os.path.dirname(target), exist_ok=True)
    with open(target, "w") as f:
        f.write(content)

    return {"created": filename, "size": len(content)}

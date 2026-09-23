from tools.search import search_employee
from tools.file_reader import read_file, create_file
from tools.email import send_email, list_sent
from tools.sandbox import execute_command

TOOL_MAP = {
    "search_employee": search_employee,
    "read_file": read_file,
    "create_file": create_file,
    "send_email": send_email,
    "execute_command": execute_command,
}

TOOL_SCHEMAS = [
    {
        "name": "search_employee",
        "description": "Search the internal employee directory by name, role, or department.",
        "parameters": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Name, role, department, or employee ID to search for."}
            },
            "required": ["query"],
        },
    },
    {
        "name": "read_file",
        "description": "Read a file from the internal data store. Filename is relative to the data directory.",
        "parameters": {
            "type": "object",
            "properties": {
                "filename": {"type": "string", "description": "Relative path to the file, e.g. 'documents/report.txt'"}
            },
            "required": ["filename"],
        },
    },
    {
        "name": "create_file",
        "description": "Create or overwrite a file in the sandbox area.",
        "parameters": {
            "type": "object",
            "properties": {
                "filename": {"type": "string", "description": "Filename relative to sandbox, e.g. 'output.txt'"},
                "content": {"type": "string", "description": "Content to write."},
            },
            "required": ["filename", "content"],
        },
    },
    {
        "name": "send_email",
        "description": "Send an email on behalf of the user.",
        "parameters": {
            "type": "object",
            "properties": {
                "to": {"type": "string", "description": "Recipient email address."},
                "subject": {"type": "string", "description": "Email subject."},
                "body": {"type": "string", "description": "Email body text."},
            },
            "required": ["to", "subject", "body"],
        },
    },
    {
        "name": "execute_command",
        "description": "Execute a shell command in the sandbox directory.",
        "parameters": {
            "type": "object",
            "properties": {
                "command": {"type": "string", "description": "Shell command to run."}
            },
            "required": ["command"],
        },
    },
]

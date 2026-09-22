from typing import Dict, List, Optional

USERS: Dict[str, Dict] = {
    "alice":   {"role": "employee",  "department": "hr",          "display_name": "Alice Chen"},
    "bob":     {"role": "engineer",  "department": "engineering",  "display_name": "Bob Kumar"},
    "charlie": {"role": "finance",   "department": "finance",      "display_name": "Charlie Osei"},
    "diana":   {"role": "admin",     "department": "security",     "display_name": "Diana Reyes"},
    "eve":     {"role": "employee",  "department": "hr",           "display_name": "Eve Nakamura"},
    "mallory": {"role": "engineer",  "department": "engineering",  "display_name": "Mallory Petrov"},
}

ROLE_PERMISSIONS: Dict[str, List[str]] = {
    "employee": ["hr"],
    "engineer": ["hr", "engineering"],
    "finance":  ["hr", "finance"],
    "admin":    ["hr", "engineering", "finance", "security", "secrets"],
}

# Maps role → ChromaDB metadata field used for access filtering
ROLE_ACCESS_FIELD: Dict[str, str] = {
    "employee": "access_employee",
    "engineer": "access_engineer",
    "finance":  "access_finance",
    "admin":    "access_admin",
}


def get_user_role(username: str) -> Optional[str]:
    user = USERS.get(username.lower())
    return user["role"] if user else None


def get_user_info(username: str) -> Optional[Dict]:
    return USERS.get(username.lower())


def check_access(username: str, department: str) -> bool:
    role = get_user_role(username)
    if role is None:
        return False
    return department in ROLE_PERMISSIONS.get(role, [])


def get_user_chromadb_filter(username: str) -> Optional[Dict]:
    role = get_user_role(username)
    if role is None:
        return None
    field = ROLE_ACCESS_FIELD.get(role)
    if field is None:
        return None
    return {field: {"$eq": True}}

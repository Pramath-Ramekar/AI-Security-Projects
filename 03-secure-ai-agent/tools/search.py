import json
import os

EMPLOYEE_DB = os.path.join(os.path.dirname(__file__), "..", "data", "employee_db", "employees.json")

def search_employee(query: str) -> dict:
    """Search the employee directory by name, role, or department."""
    with open(EMPLOYEE_DB, "r") as f:
        employees = json.load(f)

    query_lower = query.lower().strip()

    if query_lower in ("*", "all", "everyone", ""):
        return {"results": employees, "count": len(employees)}

    matches = [
        emp for emp in employees
        if query_lower in emp["name"].lower()
        or query_lower in emp["role"].lower()
        or query_lower in emp["department"].lower()
        or query_lower in emp["id"].lower()
    ]

    return {"results": matches, "count": len(matches)}

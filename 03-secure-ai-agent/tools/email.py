import json
import os
from datetime import datetime

MAILBOX = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data", "mailbox"))

def send_email(to: str, subject: str, body: str, sender: str = "agent@aegis.internal") -> dict:
    """Send an email. Stored locally in data/mailbox/sent/ for the lab."""
    timestamp = datetime.utcnow().isoformat()
    message = {
        "id": f"MSG-{int(datetime.utcnow().timestamp())}",
        "from": sender,
        "to": to,
        "subject": subject,
        "body": body,
        "timestamp": timestamp,
    }

    sent_dir = os.path.join(MAILBOX, "sent")
    os.makedirs(sent_dir, exist_ok=True)
    fname = os.path.join(sent_dir, f"{message['id']}.json")
    with open(fname, "w") as f:
        json.dump(message, f, indent=2)

    return {"status": "sent", "message_id": message["id"], "to": to, "timestamp": timestamp}


def list_sent() -> list:
    sent_dir = os.path.join(MAILBOX, "sent")
    if not os.path.exists(sent_dir):
        return []
    messages = []
    for fname in os.listdir(sent_dir):
        if fname.endswith(".json"):
            with open(os.path.join(sent_dir, fname)) as f:
                messages.append(json.load(f))
    return sorted(messages, key=lambda m: m["timestamp"], reverse=True)

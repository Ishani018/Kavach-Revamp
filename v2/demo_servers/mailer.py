"""Demo MCP server: sends email. Nothing leaves the machine: messages are appended to a local outbox file."""
import json
import os
import time

from kavach2.gateway.miniserver import MiniServer

server = MiniServer("mailer")
OUTBOX = os.environ.get("KAVACH_DEMO_OUTBOX", os.path.join(os.path.dirname(os.path.abspath(__file__)), "outbox.jsonl"))


@server.tool("Send an email.", {"to": {"type": "string"}, "subject": {"type": "string"}, "body": {"type": "string"}},
             ["to", "subject", "body"], read_only=False)
def send_email(to: str, subject: str, body: str):
    with open(OUTBOX, "a", encoding="utf-8") as f:
        f.write(json.dumps({"time": time.strftime("%Y-%m-%d %H:%M:%S"), "to": to, "subject": subject, "body": body}) + "\n")
    return f"Email sent to {to}."


@server.tool("List emails that were sent.", {}, [], read_only=True)
def list_sent():
    if not os.path.exists(OUTBOX):
        return "No emails sent."
    with open(OUTBOX, encoding="utf-8") as f:
        return "".join(f) or "No emails sent."


if __name__ == "__main__":
    server.run()

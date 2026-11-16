#!/usr/bin/env python3
"""VS Code agent hook (UserPromptSubmit): tells the Kavach gateway what the user typed.

The gateway only sees tool traffic. With this hook it also knows the user's own words, so a value the
user typed is recognised as theirs. The hook never blocks: if the gateway is not running it does nothing.
Standard library only. Reads the hook event as JSON on stdin.
"""
import json
import os
import sys
import urllib.request

URL_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "kavach-dashboard-url.txt")


def main() -> None:
    try:
        event = json.load(sys.stdin)
        prompt = event.get("prompt")
        if event.get("hook_event_name") == "UserPromptSubmit" and isinstance(prompt, str) and prompt.strip():
            with open(os.environ.get("KAVACH_DASHBOARD_URL_FILE", URL_FILE), encoding="utf-8") as f:
                base, token = f.read().strip().split("/?t=")
            request = urllib.request.Request(base + "/api/prompt", data=json.dumps({"text": prompt}).encode(),
                                             headers={"X-Kavach-Token": token, "Content-Type": "application/json"})
            urllib.request.urlopen(request, timeout=3).read()
    except Exception:
        pass  # never get in the user's way
    print(json.dumps({"continue": True}))


if __name__ == "__main__":
    main()

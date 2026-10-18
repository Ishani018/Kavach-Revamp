"""Groq as an AI evidence provider (KAVACH_AI=live, KAVACH_AI_PROVIDER=groq).

Groq serves open models through an OpenAI-compatible chat API; this calls it
with httpx (already a dependency), reading the key from GROQ_API_KEY. The
same task instructions and schemas as the Claude provider are used. The
request asks for schema-constrained JSON; for models without that mode it
retries once in plain JSON mode with the schema in the prompt. Either way
kavach/ai/schema.py validates the answer locally before it is used.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, Optional

import httpx

from .evidence import Task
from .tasks import PREAMBLE, api_schema

log = logging.getLogger("kavach.ai.groq")


class GroqProvider:
    url = "https://api.groq.com/openai/v1/chat/completions"

    def __init__(self, model: str, timeout: float) -> None:
        key = os.environ.get("GROQ_API_KEY", "").strip()
        if not key:
            raise RuntimeError("GROQ_API_KEY is not set")
        self.model = model
        self._client = httpx.Client(timeout=timeout, headers={"Authorization": f"Bearer {key}"})

    def complete(self, task: Task, payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        schema = api_schema(task.schema)
        messages = [
            {"role": "system", "content": PREAMBLE + task.instructions},
            {"role": "user", "content": json.dumps(payload, sort_keys=True, ensure_ascii=False)},
        ]
        strict = {"type": "json_schema",
                  "json_schema": {"name": task.name.replace(".", "_"), "schema": schema, "strict": True}}
        reply = self._post(messages, strict)
        if reply == "unsupported":
            plain = [dict(messages[0], content=messages[0]["content"]
                          + "\nThe JSON must match this schema: " + json.dumps(schema)), messages[1]]
            reply = self._post(plain, {"type": "json_object"})
        return reply if isinstance(reply, dict) else None

    def _post(self, messages, response_format):
        body = {"model": self.model, "temperature": 0, "messages": messages, "response_format": response_format}
        try:
            r = self._client.post(self.url, json=body)
        except httpx.HTTPError as exc:
            log.warning("Groq request failed (%s); no evidence", type(exc).__name__)
            return None
        if r.status_code == 400 and response_format["type"] == "json_schema":
            return "unsupported"
        if r.status_code != 200:
            log.warning("Groq returned HTTP %s; no evidence", r.status_code)
            return None
        try:
            choice = r.json()["choices"][0]
            if choice.get("finish_reason") not in (None, "stop"):
                return None
            data = json.loads(choice["message"]["content"])
        except (ValueError, KeyError, IndexError, TypeError):
            return None
        return data if isinstance(data, dict) else None

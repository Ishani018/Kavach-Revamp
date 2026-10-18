"""Claude as an AI evidence provider (only loaded when KAVACH_AI=live)."""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, Optional

from .evidence import Task
from .tasks import PREAMBLE as _PREAMBLE, api_schema  # noqa: F401  (api_schema re-exported)

log = logging.getLogger("kavach.ai.anthropic")

class AnthropicProvider:
    def __init__(self, model: str, timeout: float) -> None:
        import anthropic  # optional dependency (requirements-ai.txt), only needed for live mode

        self._sdk = anthropic
        self.model = model
        # Kavach owns the time budget and fails closed; no SDK-level retries.
        self._client = anthropic.Anthropic(timeout=timeout, max_retries=0)

    def complete(self, task: Task, payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        anthropic = self._sdk
        try:
            response = self._client.beta.messages.create(
                model=self.model,
                max_tokens=4000,
                betas=["server-side-fallback-2026-07-01"],
                fallbacks="default",
                system=_PREAMBLE + task.instructions,
                output_config={
                    "effort": "low",
                    "format": {"type": "json_schema", "schema": api_schema(task.schema)},
                },
                messages=[{
                    "role": "user",
                    "content": json.dumps(payload, sort_keys=True, ensure_ascii=False),
                }],
            )
        except anthropic.RateLimitError:
            log.warning("AI evidence rate limited; no evidence")
            return None
        except anthropic.APIStatusError as exc:
            log.warning("AI evidence API error %s; no evidence", exc.status_code)
            return None
        except anthropic.APIConnectionError:
            log.warning("AI evidence connection failed; no evidence")
            return None

        if response.stop_reason in ("refusal", "max_tokens"):
            return None
        text = next((b.text for b in response.content if b.type == "text"), None)
        if text is None:
            return None
        try:
            data = json.loads(text)
        except ValueError:
            return None
        return data if isinstance(data, dict) else None

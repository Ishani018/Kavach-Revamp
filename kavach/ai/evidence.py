"""The AI evidence broker: one place where ministers ask a model a question."""

from __future__ import annotations

import concurrent.futures as _cf
import hashlib
import json
import logging
import os
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Optional, Protocol

from .schema import SchemaError, validate

log = logging.getLogger("kavach.ai")

DEFAULT_MODEL = "claude-opus-5-5"
PROVIDERS = ("anthropic", "groq")
DEFAULT_MODELS = {"anthropic": DEFAULT_MODEL, "groq": "openai/gpt-oss-120b"}
MODES = ("off", "live", "replay")


@dataclass(frozen=True)
class Task:
    """A fixed question type. Bump `version` whenever instructions or schema
    change, so recorded answers to the old question are never reused."""

    name: str
    version: int
    instructions: str
    schema: Dict[str, Any]


@dataclass(frozen=True)
class Answer:
    data: Dict[str, Any]
    source: str      # "live" | "cache" | "replay"
    key: str         # content hash of the question

    def provenance(self) -> Dict[str, str]:
        """For decision diagnostics: enough to find the recorded answer again."""
        return {"ai_source": self.source, "ai_key": self.key[:16]}


class Provider(Protocol):
    model: str

    def complete(self, task: Task, payload: Dict[str, Any]) -> Optional[Dict[str, Any]]: ...


@dataclass
class _Stats:
    asked: int = 0
    answered: int = 0
    failed: int = 0
    by_source: Dict[str, int] = field(default_factory=dict)


class AIEvidence:
    def __init__(self, mode: str = "off", provider: Optional[Provider] = None,
                 record_path: Optional[Path] = None, timeout: float = 4.0,
                 model: str = DEFAULT_MODEL, intent_checks: bool = False) -> None:
        if mode not in MODES:
            raise ValueError(f"KAVACH_AI must be one of {MODES}")
        if mode == "live" and provider is None:
            raise ValueError("live AI evidence needs a provider")
        self.mode = mode
        self.provider = provider
        self.model = provider.model if provider is not None else model
        self.timeout = timeout
        # Per-action "does this fit the user's task?" checks (NAVIGATOR POL-011).
        # Separate opt-in: they add a model question to most consequential calls.
        self.intent_checks = intent_checks and mode != "off"
        self.record_path = Path(record_path) if record_path else None
        self.stats = _Stats()
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()
        self._pool = _cf.ThreadPoolExecutor(max_workers=4, thread_name_prefix="kavach-ai")
        self._recorded: set = set()
        if self.record_path is not None and self.record_path.is_file():
            self._load_record(into_cache=(mode == "replay"))

    @property
    def enabled(self) -> bool:
        return self.mode != "off"

    def key(self, task: Task, payload: Dict[str, Any]) -> str:
        canonical = json.dumps(
            {"task": task.name, "version": task.version, "model": self.model, "payload": payload},
            sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str,
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def ask(self, task: Task, payload: Dict[str, Any]) -> Optional[Answer]:
        """The validated answer, or None (off, unrecorded, timed out, refused,
        invalid, or failed). Callers must treat None exactly like 'AI off'."""
        if not self.enabled:
            return None
        key = self.key(task, payload)
        with self._lock:
            self.stats.asked += 1
            cached = self._cache.get(key)
        if cached is not None:
            return self._answered(cached, "replay" if self.mode == "replay" else "cache", key)
        if self.mode == "replay":
            return self._failed()

        future = self._pool.submit(self.provider.complete, task, payload)
        try:
            data = future.result(timeout=self.timeout)
        except _cf.TimeoutError:
            log.warning("AI task %s timed out after %.1fs; no evidence", task.name, self.timeout)
            return self._failed()
        except Exception as exc:
            log.warning("AI task %s failed (%s); no evidence", task.name, type(exc).__name__)
            return self._failed()
        if data is None:
            return self._failed()
        try:
            validate(data, task.schema)
        except SchemaError as exc:
            log.warning("AI task %s returned an invalid answer (%s); no evidence", task.name, exc)
            return self._failed()

        with self._lock:
            self._cache[key] = data
            self._append_record(task, key, data)
        return self._answered(data, "live", key)

    # ---- internals --------------------------------------------------------

    def _answered(self, data: Dict[str, Any], source: str, key: str) -> Answer:
        with self._lock:
            self.stats.answered += 1
            self.stats.by_source[source] = self.stats.by_source.get(source, 0) + 1
        return Answer(data=json.loads(json.dumps(data)), source=source, key=key)

    def _failed(self) -> None:
        with self._lock:
            self.stats.failed += 1
        return None

    def _append_record(self, task: Task, key: str, data: Dict[str, Any]) -> None:
        # Only the question's hash and the answer are written, never the payload
        # (it can hold commands or masked secret context).
        if self.record_path is None or key in self._recorded:
            return
        self._recorded.add(key)
        line = json.dumps({"key": key, "task": task.name, "version": task.version, "model": self.model,
                           "answer": data},
                          sort_keys=True, ensure_ascii=False) + "\n"
        self.record_path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.record_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(fd, line.encode("utf-8"))
        finally:
            os.close(fd)

    def _load_record(self, into_cache: bool) -> None:
        for line in self.record_path.read_text(encoding="utf-8").splitlines():
            try:
                row = json.loads(line)
            except ValueError:
                continue
            if isinstance(row, dict) and isinstance(row.get("key"), str) and isinstance(row.get("answer"), dict):
                self._recorded.add(row["key"])
                if into_cache:
                    self._cache[row["key"]] = row["answer"]


def from_env(provider_factory: Optional[Callable[[str, float], Provider]] = None) -> AIEvidence:
    """Build from KAVACH_AI* environment variables. Live mode with no usable
    provider (SDK missing, no credentials) falls back to off, loudly."""
    mode = os.environ.get("KAVACH_AI", "off").strip().lower() or "off"
    record = os.environ.get("KAVACH_AI_RECORD") or None
    provider_name = os.environ.get("KAVACH_AI_PROVIDER", "anthropic").strip().lower() or "anthropic"
    if provider_name not in PROVIDERS:
        log.error("KAVACH_AI_PROVIDER=%r is not one of %s; AI evidence is off", provider_name, PROVIDERS)
        return AIEvidence("off")
    model = os.environ.get("KAVACH_AI_MODEL", "").strip() or DEFAULT_MODELS[provider_name]
    try:
        timeout = float(os.environ.get("KAVACH_AI_TIMEOUT", "4"))
    except ValueError:
        timeout = 4.0
    intent = os.environ.get("KAVACH_AI_INTENT", "off").strip().lower() in ("1", "on", "true", "yes")
    if mode not in MODES:
        log.error("KAVACH_AI=%r is not one of %s; AI evidence is off", mode, MODES)
        return AIEvidence("off")
    if mode != "live":
        return AIEvidence(mode, record_path=Path(record) if record else None, timeout=timeout, model=model,
                          intent_checks=intent)
    try:
        if provider_factory is None and provider_name == "groq":
            from .groq_provider import GroqProvider
            provider_factory = GroqProvider
        elif provider_factory is None:
            from .anthropic_provider import AnthropicProvider
            provider_factory = AnthropicProvider
        provider = provider_factory(model, timeout)
    except Exception as exc:
        log.error("KAVACH_AI=live but no AI provider could start (%s); AI evidence is off", type(exc).__name__)
        return AIEvidence("off")
    return AIEvidence("live", provider=provider, record_path=Path(record) if record else None, timeout=timeout,
                      intent_checks=intent)

"""A small JSON-schema checker for the schemas in kavach/ai/tasks.py.

Structured outputs already constrain the model server-side; this re-checks
locally so a provider bug, a replayed record or a test fake cannot slip an
off-schema answer past Kavach. It supports exactly the keywords the task
schemas use and rejects schemas that use anything else."""

from __future__ import annotations

from typing import Any, Dict

_SUPPORTED = {"type", "properties", "required", "additionalProperties", "items", "enum", "maxItems",
              "maxLength", "minimum", "maximum", "description"}
_TYPES = {
    "object": dict, "array": list, "string": str, "boolean": bool,
    "integer": int, "number": (int, float),
}


class SchemaError(ValueError):
    pass


def validate(value: Any, schema: Dict[str, Any], path: str = "$") -> None:
    unknown = set(schema) - _SUPPORTED
    if unknown:
        raise SchemaError(f"{path}: unsupported schema keyword(s) {sorted(unknown)}")
    expected = schema.get("type")
    if expected is not None:
        py = _TYPES[expected]
        if isinstance(value, bool) and expected in ("integer", "number"):
            raise SchemaError(f"{path}: expected {expected}, got boolean")
        if not isinstance(value, py):
            raise SchemaError(f"{path}: expected {expected}")
    if "enum" in schema and value not in schema["enum"]:
        raise SchemaError(f"{path}: value not in enum")
    if isinstance(value, str) and "maxLength" in schema and len(value) > schema["maxLength"]:
        raise SchemaError(f"{path}: longer than {schema['maxLength']}")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            raise SchemaError(f"{path}: below minimum")
        if "maximum" in schema and value > schema["maximum"]:
            raise SchemaError(f"{path}: above maximum")
    if isinstance(value, list):
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            raise SchemaError(f"{path}: more than {schema['maxItems']} items")
        for i, item in enumerate(value):
            validate(item, schema.get("items", {}), f"{path}[{i}]")
    if isinstance(value, dict):
        props = schema.get("properties", {})
        for name in schema.get("required", []):
            if name not in value:
                raise SchemaError(f"{path}: missing {name!r}")
        if schema.get("additionalProperties") is False:
            extra = set(value) - set(props)
            if extra:
                raise SchemaError(f"{path}: unexpected {sorted(extra)}")
        for name, item in value.items():
            if name in props:
                validate(item, props[name], f"{path}.{name}")

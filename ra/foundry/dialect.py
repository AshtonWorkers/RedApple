"""Groom dialect loading and schema validation (RA-FND-002).

The validator name must identify a §11 assertion. Today the only normative
heap-diff assertion is ``heap_diff.class_stable`` (RA-GRM-002).
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, Optional

from .errors import DialectDefect
from .models import Dialect

SECTION_11_VALIDATORS = {
    "heap_diff.class_stable": "RA-GRM-002",
}

DEFAULT_SCHEMA_PATH = (
    Path(__file__).resolve().parents[2] / "schemas" / "groom-dialect.schema.json"
)


def _type_name(value: Any) -> str:
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return "null"


def _type_matches(value: Any, expected: str) -> bool:
    if expected == "object":
        return isinstance(value, dict)
    if expected == "array":
        return isinstance(value, list)
    if expected == "string":
        return isinstance(value, str)
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if expected == "null":
        return value is None
    return True


def _fail(path: str, message: str) -> None:
    raise DialectDefect(f"{path}: {message}")


def _validate(instance: Any, schema: Dict[str, Any], path: str = "$") -> None:
    if "enum" in schema and instance not in schema["enum"]:
        _fail(path, f"value {instance!r} not in enum {schema['enum']!r}")

    expected_type = schema.get("type")
    if expected_type is not None and not _type_matches(instance, expected_type):
        _fail(
            path,
            f"expected type {expected_type}, got {_type_name(instance)}",
        )

    if expected_type == "object" or (isinstance(instance, dict) and "properties" in schema):
        if not isinstance(instance, dict):
            _fail(path, f"expected object, got {_type_name(instance)}")
        for required in schema.get("required", []):
            if required not in instance:
                _fail(f"{path}.{required}", "missing required property")
        properties = schema.get("properties", {})
        additional = schema.get("additionalProperties", True)
        for key, value in instance.items():
            child_path = f"{path}.{key}"
            if key in properties:
                _validate(value, properties[key], child_path)
            elif additional is False:
                _fail(child_path, "additional property not allowed")
            elif isinstance(additional, dict):
                _validate(value, additional, child_path)

    if expected_type == "array" or (isinstance(instance, list) and "items" in schema):
        if not isinstance(instance, list):
            _fail(path, f"expected array, got {_type_name(instance)}")
        min_items = schema.get("minItems")
        max_items = schema.get("maxItems")
        if min_items is not None and len(instance) < min_items:
            _fail(path, f"array has {len(instance)} items, minItems {min_items}")
        if max_items is not None and len(instance) > max_items:
            _fail(path, f"array has {len(instance)} items, maxItems {max_items}")
        item_schema = schema.get("items")
        if item_schema is not None:
            for index, item in enumerate(instance):
                _validate(item, item_schema, f"{path}[{index}]")

    if isinstance(instance, str):
        min_length = schema.get("minLength")
        if min_length is not None and len(instance) < min_length:
            _fail(path, f"string shorter than minLength {min_length}")
        pattern = schema.get("pattern")
        if pattern is not None and re.search(pattern, instance) is None:
            _fail(path, f"string {instance!r} does not match pattern {pattern!r}")

    if isinstance(instance, (int, float)) and not isinstance(instance, bool):
        minimum = schema.get("minimum")
        if minimum is not None and instance < minimum:
            _fail(path, f"number {instance} below minimum {minimum}")


def load_schema(schema_path: Optional[Path] = None) -> Dict[str, Any]:
    """Load the groom dialect JSON schema."""
    path = schema_path or DEFAULT_SCHEMA_PATH
    return json.loads(path.read_text(encoding="utf-8"))


def validate_dialect(
    data: Dict[str, Any], schema_path: Optional[Path] = None
) -> Dialect:
    """Validate dialect data against the schema and §11 validator rule."""
    schema = load_schema(schema_path)
    _validate(data, schema)

    validator = str(data["validator"])
    requirement = SECTION_11_VALIDATORS.get(validator)
    if requirement is None:
        _fail(
            "$.validator",
            f"validator {validator!r} does not name a §11 assertion",
        )

    return Dialect(
        format=str(data["format"]),
        data=dict(data),
        validator=validator,
        validator_requirement=requirement,
    )


def load_dialect_file(
    path: Path, schema_path: Optional[Path] = None
) -> Dialect:
    """Read and validate a dialect JSON file."""
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise DialectDefect(f"{path}: dialect must be a JSON object")
    return validate_dialect(data, schema_path=schema_path)

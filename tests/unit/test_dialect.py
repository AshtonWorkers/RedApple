"""Groom dialect validation tests (RA-FND-002)."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from ra.foundry import DialectDefect, load_dialect_file, validate_dialect
from ra.foundry.dialect import _type_matches, _type_name, _validate, load_schema

from .helpers import VALID_DIALECT, write_harness


class DialectTest(unittest.TestCase):
    def test_valid_dialect_loads(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            spec = write_harness(Path(tmp))
            dialect = load_dialect_file(spec.dialect_path)
            self.assertEqual(dialect.format, "heif")
            self.assertEqual(dialect.validator, "heap_diff.class_stable")
            self.assertEqual(dialect.validator_requirement, "RA-GRM-002")
            self.assertEqual(dialect.data["victim_class"], "kalloc_2048")

    def test_validator_must_name_section_11_assertion(self) -> None:
        schema = {
            "type": "object",
            "required": ["format", "validator"],
            "properties": {
                "format": {"type": "string"},
                "validator": {"type": "string"},
            },
        }
        with tempfile.TemporaryDirectory() as tmp:
            schema_path = Path(tmp) / "schema.json"
            schema_path.write_text(json.dumps(schema), encoding="utf-8")
            with self.assertRaises(DialectDefect):
                validate_dialect(
                    {"format": "heif", "validator": "not.section11"},
                    schema_path=schema_path,
                )

    def test_schema_violations(self) -> None:
        cases = []
        missing = dict(VALID_DIALECT)
        del missing["post"]
        cases.append(missing)
        additional = dict(VALID_DIALECT, unexpected=True)
        cases.append(additional)
        bad_box = dict(VALID_DIALECT, pre_seed=[{"box": "BAD"}])
        cases.append(bad_box)
        too_many = dict(VALID_DIALECT, pre_seed=[{"box": "meta", "count": 65}])
        cases.append(too_many)
        bad_pad = dict(VALID_DIALECT, victim_pad="spray")
        cases.append(bad_pad)
        bad_class = dict(VALID_DIALECT, victim_class="kalloc_x")
        cases.append(bad_class)
        bad_post = dict(VALID_DIALECT, post={})
        cases.append(bad_post)
        for index, data in enumerate(cases):
            with self.subTest(index=index), tempfile.TemporaryDirectory() as tmp:
                spec = write_harness(Path(tmp), harness_id=f"bad{index}", dialect=data)
                with self.assertRaises(DialectDefect):
                    load_dialect_file(spec.dialect_path)

    def test_load_schema_rejects_non_object(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            schema_path = Path(tmp) / "schema.json"
            schema_path.write_text("[]", encoding="utf-8")
            with self.assertRaises(DialectDefect):
                load_schema(schema_path)

    def test_load_dialect_file_rejects_non_object(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "dialect.json"
            path.write_text("[]", encoding="utf-8")
            with self.assertRaises(DialectDefect):
                load_dialect_file(path)

    def test_validate_schema_features(self) -> None:
        schema = {
            "type": "object",
            "required": ["kind", "items", "name", "count"],
            "properties": {
                "kind": {"enum": ["a", "b"]},
                "items": {"type": "array", "minItems": 1, "maxItems": 2, "items": {"type": "integer", "minimum": 1}},
                "name": {"type": "string", "minLength": 2, "pattern": "^a"},
                "count": {"type": "number", "minimum": 0, "maximum": 10},
                "extra": {"type": "string"},
            },
            "additionalProperties": {"type": "string"},
        }
        _validate({"kind": "a", "items": [1], "name": "ab", "count": 1, "extra": "ok", "other": "x"}, schema)
        bad_cases = [
            {"kind": "c", "items": [1], "name": "ab", "count": 1},
            {"kind": "a", "items": [], "name": "ab", "count": 1},
            {"kind": "a", "items": [1, 2, 3], "name": "ab", "count": 1},
            {"kind": "a", "items": [0], "name": "ab", "count": 1},
            {"kind": "a", "items": [1], "name": "a", "count": 1},
            {"kind": "a", "items": [1], "name": "ba", "count": 1},
            {"kind": "a", "items": [1], "name": "ab", "count": 11},
            {"kind": "a", "items": [1], "name": "ab", "count": 1, "other": 2},
        ]
        for data in bad_cases:
            with self.subTest(data=data), self.assertRaises(DialectDefect):
                _validate(data, schema)

    def test_validate_schema_array_without_items(self) -> None:
        _validate([1, "x"], {"type": "array"})

    def test_type_helpers(self) -> None:
        self.assertEqual(_type_name(None), "null")
        self.assertEqual(_type_name(True), "boolean")
        self.assertEqual(_type_name(1), "integer")
        self.assertEqual(_type_name(1.5), "number")
        self.assertEqual(_type_name("x"), "string")
        self.assertEqual(_type_name([]), "array")
        self.assertEqual(_type_name({}), "object")
        self.assertTrue(_type_matches(1, "integer"))
        self.assertFalse(_type_matches(True, "integer"))
        self.assertTrue(_type_matches(1, "number"))
        self.assertFalse(_type_matches(True, "number"))
        self.assertTrue(_type_matches(None, "null"))
        self.assertTrue(_type_matches(True, "boolean"))
        self.assertFalse(_type_matches(1, "boolean"))
        self.assertTrue(_type_matches("x", "string"))
        self.assertFalse(_type_matches(1, "string"))
        self.assertTrue(_type_matches([], "array"))
        self.assertFalse(_type_matches({}, "array"))
        self.assertTrue(_type_matches({}, "object"))
        self.assertFalse(_type_matches([], "object"))
        self.assertTrue(_type_matches(object(), "unknown"))
        with self.assertRaises(DialectDefect):
            _validate("x", {"type": "integer"})


if __name__ == "__main__":
    unittest.main()

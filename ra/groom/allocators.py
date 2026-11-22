"""Allocator model loading for RA-GRM-001 provenance-carrying models."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..errors import FormatFail

DEFAULT_MODELS_PATH = Path(__file__).with_name("models.json")
_SIZE_CLASS_RE = re.compile(r"^kalloc_[0-9]+$")


@dataclass(frozen=True)
class AllocatorModel:
    """One allocator model with provenance and machine-readable classes."""

    name: str
    provenance: str
    classes_kb: tuple[int, ...] = ()
    cages: tuple[str, ...] = ()
    notes: str = ""

    def size_classes(self) -> tuple[str, ...]:
        """Allocator size-class labels in kilobyte order."""
        return tuple(f"kalloc_{kb}" for kb in self.classes_kb)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "provenance": self.provenance,
            "classes_kb": list(self.classes_kb),
            "size_classes": list(self.size_classes()),
            "cages": list(self.cages),
            "notes": self.notes,
        }


@dataclass(frozen=True)
class AllocatorModelSet:
    """Validated set of allocator models loaded from ``models.json``."""

    format: str
    models: tuple[AllocatorModel, ...]
    source_path: str | None = None

    def get(self, name: str) -> AllocatorModel:
        """Return one named model or raise ``FormatFail``."""
        for model in self.models:
            if model.name == name:
                return model
        raise FormatFail(f"unknown allocator model {name!r}")

    def libpas(self) -> AllocatorModel:
        """Return the libpas size-class model."""
        return self.get("libpas_size_classes")

    def all_size_classes(self) -> tuple[str, ...]:
        """All allocator size classes across models, deduplicated in order."""
        seen: list[str] = []
        for model in self.models:
            for size_class in model.size_classes():
                if size_class not in seen:
                    seen.append(size_class)
        return tuple(seen)

    def is_known_size_class(self, size_class: str) -> bool:
        """Return whether a size class is declared by any model."""
        return size_class in set(self.all_size_classes())

    def provenance_for(
        self,
        size_class: str,
        cage: str = "",
        isoheap: str = "",
        structure_id: str = "",
    ) -> dict[str, str]:
        """Return provenance entries for the models a candidate relies on."""
        provenance: dict[str, str] = {}
        for model in self.models:
            used = False
            if model.name == "libpas_size_classes" and size_class in model.size_classes() or model.name == "gigacage" and cage and cage in model.cages or model.name == "isoheap" and isoheap or model.name == "structure_id" and structure_id:
                used = True
            if used:
                provenance[model.name] = model.provenance
        if not provenance:
            provenance["libpas_size_classes"] = self.libpas().provenance
        return provenance

    def to_dict(self) -> dict[str, Any]:
        return {
            "format": self.format,
            "source_path": self.source_path,
            "models": [model.to_dict() for model in self.models],
        }


def load_allocator_models(path: str | Path | None = None) -> AllocatorModelSet:
    """Load and validate ``models.json`` allocator models."""
    model_path = Path(path) if path is not None else DEFAULT_MODELS_PATH
    try:
        raw = json.loads(model_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise FormatFail(f"allocator models not found: {model_path}") from exc
    except json.JSONDecodeError as exc:
        raise FormatFail(f"allocator models JSON invalid: {exc}") from exc
    if not isinstance(raw, dict):
        raise FormatFail("allocator models must be a JSON object")
    fmt = raw.get("format")
    models_raw = raw.get("models")
    if fmt != "heif" or not isinstance(models_raw, dict):
        raise FormatFail("allocator models must use format 'heif' with a models object")
    models: list[AllocatorModel] = []
    for name, item in models_raw.items():
        if not isinstance(name, str) or not isinstance(item, dict):
            raise FormatFail("allocator model entries must be objects")
        provenance = item.get("provenance")
        if not isinstance(provenance, str) or not provenance:
            raise FormatFail(f"allocator model {name!r} missing provenance")
        classes_kb = _int_tuple(item.get("classes_kb", []), f"{name}.classes_kb")
        cages = _str_tuple(item.get("cages", []), f"{name}.cages")
        notes = item.get("notes", "")
        models.append(
            AllocatorModel(
                name=name,
                provenance=provenance,
                classes_kb=classes_kb,
                cages=cages,
                notes=str(notes),
            )
        )
    if not models:
        raise FormatFail("allocator models must not be empty")
    return AllocatorModelSet(format=str(fmt), models=tuple(models), source_path=str(model_path))


def size_class_for_kb(size_kb: int, models: AllocatorModelSet) -> str:
    """Choose the smallest libpas size class that can hold ``size_kb`` KiB."""
    if size_kb <= 0:
        raise FormatFail("size_kb must be positive")
    classes = models.libpas().classes_kb
    for kb in classes:
        if kb >= size_kb:
            return f"kalloc_{kb}"
    return f"kalloc_{classes[-1]}"


def adjacent_size_classes(size_class: str, models: AllocatorModelSet) -> tuple[str, str]:
    """Return previous and next libpas size classes around ``size_class``."""
    classes = models.libpas().size_classes()
    if size_class not in classes:
        raise FormatFail(f"size class {size_class!r} is not a libpas class")
    idx = classes.index(size_class)
    prev_class = classes[idx - 1] if idx > 0 else classes[idx]
    next_class = classes[idx + 1] if idx + 1 < len(classes) else classes[idx]
    return prev_class, next_class


def is_valid_size_class(size_class: str) -> bool:
    """Return whether a label has the allocator size-class shape."""
    return _SIZE_CLASS_RE.match(size_class) is not None


def _int_tuple(value: Any, label: str) -> tuple[int, ...]:
    if not isinstance(value, list):
        raise FormatFail(f"{label} must be a list")
    out: list[int] = []
    for item in value:
        if isinstance(item, bool) or not isinstance(item, int) or item <= 0:
            raise FormatFail(f"{label} must contain positive integers")
        out.append(item)
    return tuple(out)


def _str_tuple(value: Any, label: str) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise FormatFail(f"{label} must be a list")
    out: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item:
            raise FormatFail(f"{label} must contain non-empty strings")
        out.append(item)
    return tuple(out)

"""TOML configuration validated against Appendix F (RA-CFG-001)."""

from __future__ import annotations

import os
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..errors import FormatFail

MAX_SPEND_USD = 40
DEFAULT_MODEL = "deepseek-v4.1-flash"
_USD_MICRO = 1_000_000


class ConfigError(FormatFail):
    """Configuration validation failure."""

    code = "CONFIG_INVALID"


@dataclass(frozen=True)
class StationConfig:
    """Station envelope configuration."""

    external_mount: str
    max_vm_images: int = 2


@dataclass(frozen=True)
class BudgetConfig:
    """Nightly budget configuration; money is integer USD here, micro-USD at spend time."""

    spend_usd: int = MAX_SPEND_USD
    crashes_per_device: int = 400

    @property
    def spend_usd_micro(self) -> int:
        """Budget cap in integer micro-USD (I4)."""
        return self.spend_usd * _USD_MICRO


@dataclass(frozen=True)
class ModelConfig:
    """PRESS model routing configuration."""

    primary: str = DEFAULT_MODEL
    local_only: bool = False


@dataclass(frozen=True)
class IosLaneConfig:
    """iOS lane defaults."""

    tier: str = "C"
    signing_cadence_days: int = 6


@dataclass(frozen=True)
class RedAppleConfig:
    """Validated RED APPLE configuration."""

    station: StationConfig
    budget: BudgetConfig
    model: ModelConfig
    ios_lane: IosLaneConfig
    path: Path | None = None

    def budget_payload(self) -> dict[str, object]:
        """Budget JSON payload for the run table; no floats on the money path."""
        return {
            "spend_usd_micro": self.budget.spend_usd_micro,
            "crashes_per_device": self.budget.crashes_per_device,
            "max_vm_images": self.station.max_vm_images,
            "model": self.model.primary,
            "local_only": self.model.local_only,
        }


def _err(path: str, message: str) -> ConfigError:
    return ConfigError(f"{path}: {message}")


def _expect_keys(mapping: Mapping[str, Any], allowed: Mapping[str, Any], path: str) -> None:
    unknown = sorted(set(mapping) - set(allowed))
    if unknown:
        raise _err(path, f"unknown keys: {', '.join(unknown)}")


def _get_int(
    mapping: Mapping[str, Any], key: str, default: int, path: str, *, minimum: int = 0
) -> int:
    value = mapping.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int):
        raise _err(f"{path}.{key}", "must be an integer")
    if value < minimum:
        raise _err(f"{path}.{key}", f"must be >= {minimum}")
    return value


def _get_bool(mapping: Mapping[str, Any], key: str, default: bool, path: str) -> bool:
    value = mapping.get(key, default)
    if not isinstance(value, bool):
        raise _err(f"{path}.{key}", "must be a boolean")
    return value


def _get_str(mapping: Mapping[str, Any], key: str, default: str | None, path: str) -> str:
    value = mapping.get(key, default)
    if not isinstance(value, str) or not value:
        raise _err(f"{path}.{key}", "must be a non-empty string")
    return value


def parse_config(data: Mapping[str, Any], *, path: Path | None = None) -> RedAppleConfig:
    """Validate a decoded TOML document against Appendix F."""
    if not isinstance(data, Mapping):
        raise ConfigError("config root must be a table")
    allowed_root = {"station", "budget", "model", "lane"}
    _expect_keys(data, {key: None for key in allowed_root}, "config")

    station_raw = data.get("station", {})
    if not isinstance(station_raw, Mapping):
        raise _err("station", "must be a table")
    _expect_keys(station_raw, {"external_mount": None, "max_vm_images": None}, "station")
    if "external_mount" not in station_raw:
        raise _err("station.external_mount", "is required")
    external_mount = _get_str(station_raw, "external_mount", None, "station")
    if not Path(external_mount).is_absolute():
        raise _err("station.external_mount", "must be an absolute path")
    max_vm_images = _get_int(station_raw, "max_vm_images", 2, "station", minimum=1)
    if max_vm_images > 2:
        raise _err("station.max_vm_images", "must be <= 2 (RA-STN-002)")

    budget_raw = data.get("budget", {})
    if not isinstance(budget_raw, Mapping):
        raise _err("budget", "must be a table")
    _expect_keys(budget_raw, {"spend_usd": None, "crashes_per_device": None}, "budget")
    spend_usd = _get_int(budget_raw, "spend_usd", MAX_SPEND_USD, "budget", minimum=1)
    if spend_usd > MAX_SPEND_USD:
        raise _err("budget.spend_usd", f"exceeds nightly cap {MAX_SPEND_USD}")
    crashes_per_device = _get_int(budget_raw, "crashes_per_device", 400, "budget", minimum=1)

    model_raw = data.get("model", {})
    if not isinstance(model_raw, Mapping):
        raise _err("model", "must be a table")
    _expect_keys(model_raw, {"primary": None, "local_only": None}, "model")
    primary = _get_str(model_raw, "primary", DEFAULT_MODEL, "model")
    local_only = _get_bool(model_raw, "local_only", False, "model")

    lane_raw = data.get("lane", {})
    if not isinstance(lane_raw, Mapping):
        raise _err("lane", "must be a table")
    _expect_keys(lane_raw, {"ios": None}, "lane")
    ios_raw = lane_raw.get("ios", {})
    if not isinstance(ios_raw, Mapping):
        raise _err("lane.ios", "must be a table")
    _expect_keys(ios_raw, {"tier": None, "signing_cadence_days": None}, "lane.ios")
    tier = _get_str(ios_raw, "tier", "C", "lane.ios")
    if tier not in {"A", "B", "C"}:
        raise _err("lane.ios.tier", "must be A, B, or C")
    signing_cadence_days = _get_int(ios_raw, "signing_cadence_days", 6, "lane.ios", minimum=1)

    return RedAppleConfig(
        station=StationConfig(external_mount=external_mount, max_vm_images=max_vm_images),
        budget=BudgetConfig(spend_usd=spend_usd, crashes_per_device=crashes_per_device),
        model=ModelConfig(primary=primary, local_only=local_only),
        ios_lane=IosLaneConfig(tier=tier, signing_cadence_days=signing_cadence_days),
        path=path,
    )


def load_config(path: str | Path | None = None) -> RedAppleConfig:
    """Load and validate ``redapple.toml`` (or the given path)."""
    config_path = (
        Path(path) if path is not None else Path(os.environ.get("REDAPPLE_CONFIG", "redapple.toml"))
    )
    if not config_path.exists():
        raise ConfigError(f"config not found: {config_path}")
    try:
        data = tomllib.loads(config_path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"invalid TOML in {config_path}: {exc}") from exc
    return parse_config(data, path=config_path)


def budget_usd_micro(config: RedAppleConfig) -> int:
    """Configured budget cap in integer micro-USD."""
    return config.budget.spend_usd_micro


def validate_budget_usd(value: int, config: RedAppleConfig) -> int:
    """Validate a CLI dollar budget and return micro-USD; refuses above cap."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError("budget must be an integer number of USD")
    if value < 1:
        raise ConfigError("budget must be >= 1 USD")
    cap_usd = min(config.budget.spend_usd, MAX_SPEND_USD)
    if value > cap_usd:
        raise ConfigError(f"budget {value} USD exceeds cap {cap_usd} USD")
    return value * _USD_MICRO

"""Centralized, env-overridable configuration for Graviton (Hard Rule 7D)."""
from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import tempfile


def _env_int(name: str, default: int, *, min_val: int = 0) -> int:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        val = int(raw)
    except ValueError as exc:
        raise ValueError(f"Invalid integer for {name}: {raw!r}") from exc
    if val < min_val:
        raise ValueError(f"{name} must be >= {min_val}, got {val}")
    return val


def _env_float(name: str, default: float, *, min_val: float = 0.0) -> float:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        val = float(raw)
    except ValueError as exc:
        raise ValueError(f"Invalid float for {name}: {raw!r}") from exc
    if val < min_val:
        raise ValueError(f"{name} must be >= {min_val}, got {val}")
    return val


@dataclass(frozen=True)
class GravitonConfig:
    """Validated runtime configuration with env overrides (no hard-coded secrets or user paths)."""

    state_dir: Path
    key_dir: Path | None
    max_frame_bytes: int
    read_timeout_s: float
    idle_timeout_s: float
    max_connections: int
    lock_timeout_s: float
    sync_interval_s: float
    envelope_ttl_s: int
    max_envelopes_per_user: int
    max_storage_bytes_per_user: int
    rotation_cutoff_offset: int
    rotation_grace_epochs: int
    max_clock_skew_ms: int
    max_arrival_delay_ms: int


def load_config() -> GravitonConfig:
    env_state = os.environ.get("TRACK4_STATE_DIR") or os.environ.get("GRAVITON_HOME")
    state_dir = Path(env_state) if env_state else (Path(tempfile.gettempdir()) / "graviton_state")
    env_key = os.environ.get("TRACK4_KEY_DIR")
    key_dir = Path(env_key) if env_key else None

    return GravitonConfig(
        state_dir=state_dir,
        key_dir=key_dir,
        max_frame_bytes=_env_int("GRAVITON_MAX_FRAME_BYTES", 1_048_576, min_val=1024),
        read_timeout_s=_env_float("GRAVITON_READ_TIMEOUT_S", 5.0, min_val=0.1),
        idle_timeout_s=_env_float("GRAVITON_IDLE_TIMEOUT_S", 30.0, min_val=0.5),
        max_connections=_env_int("GRAVITON_MAX_CONNECTIONS", 64, min_val=1),
        lock_timeout_s=_env_float("GRAVITON_LOCK_TIMEOUT_S", 4.0, min_val=0.1),
        sync_interval_s=_env_float("GRAVITON_SYNC_INTERVAL_S", 1.0, min_val=0.05),
        envelope_ttl_s=_env_int("GRAVITON_ENVELOPE_TTL_S", 3600, min_val=1),
        max_envelopes_per_user=_env_int("GRAVITON_MAX_ENVELOPES_PER_USER", 500, min_val=1),
        max_storage_bytes_per_user=_env_int("GRAVITON_MAX_STORAGE_BYTES_PER_USER", 10_485_760, min_val=1024),
        rotation_cutoff_offset=_env_int("GRAVITON_ROTATION_CUTOFF_OFFSET", 2, min_val=1),
        rotation_grace_epochs=_env_int("GRAVITON_ROTATION_GRACE_EPOCHS", 0, min_val=0),
        max_clock_skew_ms=_env_int("GRAVITON_MAX_CLOCK_SKEW_MS", 5_000, min_val=0),
        max_arrival_delay_ms=_env_int("GRAVITON_MAX_ARRIVAL_DELAY_MS", 10_000, min_val=0),
    )

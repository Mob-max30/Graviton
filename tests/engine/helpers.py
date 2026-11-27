"""Reusable helper for spawning real daemon subprocesses on ephemeral ports."""
from __future__ import annotations

import base64
import json
from pathlib import Path
import subprocess
import sys
import time

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


class DaemonProcess:
    """Manages a real OS daemon subprocess and polls its ready file."""

    def __init__(self, args: list[str], ready_file: Path, *, timeout: float = 10.0) -> None:
        self.ready_file = ready_file
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "graviton", *args],
            cwd=str(REPO_ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                out, err = self.proc.communicate(timeout=2)
                raise RuntimeError(f"Daemon exited early ({self.proc.returncode}): {out}\n{err}")
            if ready_file.is_file():
                try:
                    info = json.loads(ready_file.read_text(encoding="utf-8"))
                    if "port" in info:
                        self.host: str = info["host"]
                        self.port: int = int(info["port"])
                        self.node_id: str = info.get("node_id", "")
                        self.node_pk: bytes = (
                            base64.b64decode(info["node_pk_b64"]) if "node_pk_b64" in info else b""
                        )
                        return
                except Exception:
                    pass
            time.sleep(0.05)
        self.kill()
        raise TimeoutError(f"Daemon did not become ready within {timeout}s")

    def stop(self, timeout: float = 5.0) -> tuple[str, str]:
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                return self.proc.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        return self.proc.communicate(timeout=2)

    def kill(self) -> None:
        if self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait(timeout=5)

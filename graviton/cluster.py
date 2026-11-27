"""Real multi-process cluster launcher and lifecycle manager."""
from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

from graviton.daemon.node import init_node_daemon
from graviton.net.client import NodeClient
from graviton.storage import atomic_write_text, ensure_state_dir

CLUSTER_FILENAME = "cluster.json"


def _wait_for_ready(proc: subprocess.Popen, ready_file: Path, timeout: float = 10.0) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            out, err = proc.communicate(timeout=2)
            raise RuntimeError(f"Node exited early ({proc.returncode}): {out}\n{err}")
        if ready_file.is_file():
            try:
                info = json.loads(ready_file.read_text(encoding="utf-8"))
                if "port" in info:
                    return info
            except Exception:
                pass
        time.sleep(0.05)
    proc.kill()
    raise TimeoutError(f"Node did not become ready within {timeout}s")


def cluster_up(
    cluster_dir: str | Path,
    node_count: int,
    feed_id: str,
    admin_public_key: bytes,
    *,
    sync_interval_s: float = 0.2,
    initial_entries: list[bytes] | None = None,
) -> dict:
    """Start N real node OS processes on ephemeral ports and write cluster.json."""
    if node_count < 1:
        raise ValueError("node_count must be >= 1")
    root = Path(cluster_dir)
    ensure_state_dir(root)
    nodes_meta: list[dict] = []

    hub_host = ""
    hub_port = 0

    for idx in range(node_count):
        node_id = f"node_{idx}"
        node_dir = root / node_id
        ready_file = root / f"{node_id}.ready.json"
        ready_file.unlink(missing_ok=True)
        _, node_pk, _ = init_node_daemon(node_dir, node_id, feed_id, admin_public_key)

        cmd = [
            sys.executable,
            "-m",
            "graviton",
            "node",
            "run",
            "--dir",
            str(node_dir),
            "--listen",
            "127.0.0.1:0",
            "--ready-file",
            str(ready_file),
        ]
        if idx > 0:
            cmd.extend(["--upstream", f"{hub_host}:{hub_port}", "--sync-interval", str(sync_interval_s)])

        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            info = _wait_for_ready(proc, ready_file)
        except Exception:
            for prev in nodes_meta:
                try:
                    os.kill(prev["pid"], signal.SIGTERM)
                except OSError:
                    pass
            raise

        if idx == 0:
            hub_host, hub_port = info["host"], int(info["port"])
            if initial_entries:
                with NodeClient(hub_host, hub_port, expected_node_pk=node_pk) as cli:
                    cli.feed_push(initial_entries)

        nodes_meta.append(
            {
                "node_id": node_id,
                "pid": proc.pid,
                "host": info["host"],
                "port": int(info["port"]),
                "dir": str(node_dir),
                "node_pk_b64": base64.b64encode(node_pk).decode("ascii"),
            }
        )

    cluster_info = {
        "version": 1,
        "feed_id": feed_id,
        "sync_interval_s": sync_interval_s,
        "nodes": nodes_meta,
    }
    atomic_write_text(root / CLUSTER_FILENAME, json.dumps(cluster_info, indent=2))
    return cluster_info


def cluster_status(cluster_dir: str | Path) -> list[dict]:
    root = Path(cluster_dir)
    info = json.loads((root / CLUSTER_FILENAME).read_text(encoding="utf-8"))
    out = []
    for n in info["nodes"]:
        pk = base64.b64decode(n["node_pk_b64"])
        try:
            with NodeClient(n["host"], int(n["port"]), expected_node_pk=pk, timeout=2.0) as cli:
                assert cli.hello is not None
                out.append(
                    {
                        "node_id": n["node_id"],
                        "pid": n["pid"],
                        "host": n["host"],
                        "port": n["port"],
                        "epoch": cli.hello.node_epoch,
                        "alive": True,
                    }
                )
        except Exception:
            out.append(
                {
                    "node_id": n["node_id"],
                    "pid": n["pid"],
                    "host": n["host"],
                    "port": n["port"],
                    "epoch": None,
                    "alive": False,
                }
            )
    return out


def cluster_down(cluster_dir: str | Path) -> int:
    root = Path(cluster_dir)
    cpath = root / CLUSTER_FILENAME
    if not cpath.is_file():
        return 0
    info = json.loads(cpath.read_text(encoding="utf-8"))
    stopped = 0
    for n in info["nodes"]:
        pid = int(n["pid"])
        try:
            if os.name == "nt":
                subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"], capture_output=True, check=False)
            else:
                os.kill(pid, signal.SIGTERM)
            stopped += 1
        except OSError:
            pass
    return stopped

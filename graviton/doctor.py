"""Environment self-check (`graviton doctor`)."""
from __future__ import annotations

import os
from pathlib import Path
import socket
import sqlite3
import sys

from graviton.admin import graviton_home
from graviton.crypto.aead import aead_available
from graviton.storage import ensure_state_dir


def run_doctor(*, home_dir: Path | None = None) -> list[dict]:
    checks: list[dict] = []

    # 1. Python version
    py_ok = sys.version_info >= (3, 12)
    checks.append(
        {
            "name": "python",
            "ok": py_ok,
            "detail": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
            "action": "Upgrade to Python 3.12+" if not py_ok else "OK",
        }
    )

    # 2. pqcrypto import
    try:
        from pqcrypto.kem import ml_kem_768  # noqa: F401
        from pqcrypto.sign import ml_dsa_65  # noqa: F401

        pq_ok = True
        pq_detail = "ML-KEM-768 and ML-DSA-65 available"
    except Exception as exc:
        pq_ok = False
        pq_detail = str(exc)
    checks.append(
        {
            "name": "pqcrypto",
            "ok": pq_ok,
            "detail": pq_detail,
            "action": "Install with: pip install pqcrypto==0.4.0" if not pq_ok else "OK",
        }
    )

    # 3. AEAD availability
    aead_ok = aead_available()
    checks.append(
        {
            "name": "aead_extra",
            "ok": aead_ok,
            "detail": "cryptography AES-256-GCM + scrypt available" if aead_ok else "not installed (core-only mode)",
            "action": "Optional for core; install for CLI/E2EE with: pip install '.[app]'" if not aead_ok else "OK",
        }
    )

    # 4. SQLite version and DELETE ... RETURNING
    try:
        conn = sqlite3.connect(":memory:")
        conn.execute("CREATE TABLE t (id INTEGER PRIMARY KEY)")
        conn.execute("INSERT INTO t VALUES (1)")
        row = conn.execute("DELETE FROM t WHERE id = 1 RETURNING id").fetchone()
        conn.close()
        ret_ok = row is not None and row[0] == 1
        sql_detail = f"sqlite {sqlite3.sqlite_version}, RETURNING={'yes' if ret_ok else 'no'}"
    except Exception as exc:
        ret_ok = False
        sql_detail = f"sqlite {sqlite3.sqlite_version}: {exc}"
    checks.append(
        {
            "name": "sqlite_returning",
            "ok": ret_ok,
            "detail": sql_detail,
            "action": "Upgrade SQLite >= 3.35" if not ret_ok else "OK",
        }
    )

    # 5. State directory permissions
    target_home = home_dir or graviton_home()
    try:
        ensure_state_dir(target_home)
        probe = target_home / ".doctor_probe"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        dir_ok = True
        dir_detail = f"writable ({target_home})"
    except Exception as exc:
        dir_ok = False
        dir_detail = f"{target_home}: {exc}"
    checks.append(
        {
            "name": "state_dir",
            "ok": dir_ok,
            "detail": dir_detail,
            "action": "Set GRAVITON_HOME to a writable directory" if not dir_ok else "OK",
        }
    )

    # 6. Loopback port bind availability
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("127.0.0.1", 0))
        _, port = s.getsockname()
        s.close()
        port_ok = True
        port_detail = f"ephemeral loopback bind succeeded (port {port})"
    except Exception as exc:
        port_ok = False
        port_detail = str(exc)
    checks.append(
        {
            "name": "loopback_port",
            "ok": port_ok,
            "detail": port_detail,
            "action": "Check local firewall or socket permissions" if not port_ok else "OK",
        }
    )

    return checks

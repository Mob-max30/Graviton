"""One JSON request per process. Team code owns all application behavior."""
import json
import os
import sys
from typing import Any, Dict

from team_app import dispatch
from trustledger.core.service import DispatchError
from trustledger.core.store import IntegrityError

DEFAULT_MAX_INPUT_BYTES = 1024 * 1024  # 1 MiB


def _max_input_bytes() -> int:
    raw = os.environ.get("TRACK4_MAX_INPUT_BYTES")
    if raw:
        try:
            val = int(raw)
            if val > 0:
                return val
        except ValueError:
            pass
    return DEFAULT_MAX_INPUT_BYTES


def _emit(payload: Dict[str, Any]) -> int:
    sys.stdout.write(json.dumps(payload, allow_nan=False) + "\n")
    return 0


def main() -> int:
    max_bytes = _max_input_bytes()
    try:
        raw_input = sys.stdin.read(max_bytes + 1)
    except (OSError, UnicodeDecodeError):
        print("Request failed; inspect team application locally.", file=sys.stderr)
        return 1

    if len(raw_input.encode("utf-8", errors="replace")) > max_bytes:
        return _emit({"error": "input_too_large"})

    try:
        request = json.loads(raw_input)
    except (json.JSONDecodeError, ValueError):
        return _emit({"error": "invalid_json"})

    if not isinstance(request, dict):
        return _emit({"error": "invalid_request_type"})

    try:
        response = dispatch(request)
        if not isinstance(response, dict):
            raise ValueError("Response must be an object")
        encoded = json.dumps(response, allow_nan=False)
    except DispatchError:
        return _emit({"error": "invalid_request"})
    except IntegrityError:
        return _emit({"error": "integrity_violation"})
    except Exception:
        # Do not print request data or exception details that could contain secrets.
        print("Request failed; inspect team application locally.", file=sys.stderr)
        return 1

    sys.stdout.write(encoded + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

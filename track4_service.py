"""One JSON request per process. Team code owns all application behavior."""
import json
import sys
from team_app import dispatch

MAX_INPUT_BYTES = 1_048_576
MAX_OUTPUT_BYTES = 65_536


def _emit(obj: dict) -> int:
    encoded = json.dumps(obj, allow_nan=False, separators=(",", ":"))
    if len(encoded.encode("utf-8")) >= MAX_OUTPUT_BYTES:
        encoded = json.dumps({"error": "response_too_large"}, allow_nan=False, separators=(",", ":"))
    sys.stdout.write(encoded + "\n")
    return 0


def main() -> int:
    try:
        raw = sys.stdin.read(MAX_INPUT_BYTES + 1)
        if len(raw.encode("utf-8")) > MAX_INPUT_BYTES:
            return _emit({"error": "payload_too_large"})
        if not raw or not raw.strip():
            return _emit({"error": "empty_request"})
        request = json.loads(raw)
        if not isinstance(request, dict):
            return _emit({"error": "invalid_request"})
    except Exception:
        # Do not print request data or exception details that could contain secrets.
        return _emit({"error": "invalid_json"})

    try:
        response = dispatch(request)
        if not isinstance(response, dict):
            raise ValueError("Response must be an object")
        return _emit(response)
    except Exception:
        # Do not print request data or exception details that could contain secrets.
        print("Request failed; inspect team application locally.", file=sys.stderr)
        return _emit({"error": "internal_error"})


if __name__ == "__main__":
    raise SystemExit(main())

"""One JSON request per process. Team code owns all application behavior."""
import json
import sys
from team_app import dispatch


def main():
    try:
        raw = sys.stdin.read()
        if not raw or not raw.strip():
            sys.stdout.write(json.dumps({"error": "empty_request"}, allow_nan=False) + "\n")
            return 0
        request = json.loads(raw)
        if not isinstance(request, dict):
            sys.stdout.write(json.dumps({"error": "invalid_request"}, allow_nan=False) + "\n")
            return 0
    except Exception:
        # Do not print request data or exception details that could contain secrets.
        sys.stdout.write(json.dumps({"error": "invalid_json"}, allow_nan=False) + "\n")
        return 0

    try:
        response = dispatch(request)
        if not isinstance(response, dict):
            raise ValueError("Response must be an object")
        encoded = json.dumps(response, allow_nan=False)
    except Exception:
        # Do not print request data or exception details that could contain secrets.
        print("Request failed; inspect team application locally.", file=sys.stderr)
        sys.stdout.write(json.dumps({"error": "internal_error"}, allow_nan=False) + "\n")
        return 1

    sys.stdout.write(encoded + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

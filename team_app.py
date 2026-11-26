"""Entry point stub for team application dispatch."""
from typing import Any, Dict

from trustledger.core.service import dispatch as core_dispatch


def dispatch(request: Dict[str, Any]) -> Dict[str, Any]:
    """Route requests to the judged core service."""
    return core_dispatch(request)

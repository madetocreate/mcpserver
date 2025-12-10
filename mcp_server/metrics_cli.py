import json
from typing import Any
from .observability import InMemoryMetrics


def format_metrics(metrics: InMemoryMetrics) -> str:
    snapshot = metrics.snapshot()
    return json.dumps(snapshot, indent=2, sort_keys=True)


if __name__ == "__main__":
    import sys
    print("This module is meant to be used from inside the MCP server, not as a standalone CLI.", file=sys.stderr)

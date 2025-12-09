from __future__ import annotations

import asyncio
import json
import sys
from typing import Any, Dict

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client


MCP_URL = "http://127.0.0.1:9000/mcp"


async def main() -> None:
    if len(sys.argv) < 3:
        print("Usage: python scripts/call_tool.py <tool_name> '<json-args>'")
        raise SystemExit(1)

    tool_name = sys.argv[1]
    raw_args = sys.argv[2]

    try:
        params: Dict[str, Any] = json.loads(raw_args)
    except Exception as exc:
        print("Failed to parse JSON arguments")
        print(repr(exc))
        raise SystemExit(1)

    async with streamablehttp_client(MCP_URL) as (read_stream, write_stream, _):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            try:
                result = await session.call_tool(tool_name, params)
                print("Tool call result:")
                print(result)
            except Exception as exc:
                print("Tool call failed:")
                print(repr(exc))


if __name__ == "__main__":
    asyncio.run(main())

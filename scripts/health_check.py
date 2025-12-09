from __future__ import annotations

import asyncio
from typing import Any

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client


MCP_URL = "http://127.0.0.1:9000/mcp"


async def main() -> None:
    print(f"Connecting to MCP server at {MCP_URL}...")
    async with streamablehttp_client(MCP_URL) as (read_stream, write_stream, _):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()

            print("Fetching tool list...")
            tools = await session.list_tools()
            print(f"Found {len(tools.tools)} tools:")
            for tool in tools.tools:
                print(f" - {tool.name}")

            print("Calling memory.search for health check...")
            try:
                result = await session.call_tool(
                    "memory.search",
                    {
                        "tenant_id": "default",
                        "query": "health-check",
                        "limit": 1,
                        "actor": "health-check",
                        "actor_role": "Orchestrator",
                    },
                )
                print("memory.search OK")
                print(result)
            except Exception as exc:
                print("memory.search FAILED")
                print(repr(exc))


if __name__ == "__main__":
    asyncio.run(main())

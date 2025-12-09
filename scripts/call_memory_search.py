from __future__ import annotations

import asyncio

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client


MCP_URL = "http://127.0.0.1:8000/mcp"


async def main() -> None:
    async with streamablehttp_client(MCP_URL) as (read_stream, write_stream, _):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            try:
                result = await session.call_tool(
                    "memory.search",
                    {
                        "tenant_id": "dev-tenant",
                        "query": "test",
                        "limit": 5,
                        "actor": "cli-debug",
                        "actor_role": "Orchestrator",
                    },
                )
                print("Tool call result:")
                print(result)
            except Exception as exc:
                print("Tool call failed:")
                print(repr(exc))


if __name__ == "__main__":
    asyncio.run(main())

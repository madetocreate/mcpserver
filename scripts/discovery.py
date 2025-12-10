from __future__ import annotations

import asyncio
from typing import Any, Dict

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

MCP_URL = "http://127.0.0.1:9000/mcp"


async def main() -> None:
    async with streamablehttp_client(MCP_URL) as (read_stream, write_stream, _):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            try:
                result: Dict[str, Any] = await session.call_tool(
                    "observability.discovery",
                    {
                        "tenant_id": "default",
                        "actor": "discovery-cli",
                        "actor_role": "Orchestrator",
                    },
                )
                print("Discovery result:")
                print(result)
            except Exception as exc:
                print("Discovery failed:")
                print(repr(exc))


if __name__ == "__main__":
    asyncio.run(main())


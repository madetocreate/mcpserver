from __future__ import annotations

import asyncio

from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client


MCP_URL = "http://127.0.0.1:9000/mcp"


async def main() -> None:
    async with streamablehttp_client(MCP_URL) as (read_stream, write_stream, _):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            tools_result = await session.list_tools()
            print("Available tools:")
            for tool in tools_result.tools:
                print(f"- {tool.name}: {tool.description}")


if __name__ == "__main__":
    asyncio.run(main())

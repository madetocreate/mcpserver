from __future__ import annotations

import pytest
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client


MCP_URL = "http://127.0.0.1:9000/mcp"


@pytest.mark.asyncio
async def test_memory_search_smoke() -> None:
    async with streamablehttp_client(MCP_URL) as (read_stream, write_stream, _):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            result = await session.call_tool(
                "memory.search",
                {
                    "tenant_id": "default",
                    "query": "pytest",
                    "limit": 1,
                    "actor": "pytest",
                    "actor_role": "Orchestrator",
                },
            )
            assert result.isError is False

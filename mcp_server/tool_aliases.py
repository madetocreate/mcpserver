from __future__ import annotations

from typing import Any, Awaitable, Callable, Dict, Optional

from mcp.server.fastmcp import FastMCP

InvokeBackendTool = Callable[..., Awaitable[Dict[str, Any]]]

def register_dot_alias_tools(mcp: FastMCP, invoke_backend_tool: InvokeBackendTool) -> None:
    """
    Register dot-notation alias tools (e.g., memory.search, memory.write).
    
    Note: invoke_backend_tool signature is _invoke_backend_tool which doesn't accept
    actor/actor_role parameters (they come from config). These kwargs are ignored.
    """
    @mcp.tool(name="memory.search", description="Search tenant memories.")
    async def memory_search(
        tenant_id: str,
        query: str,
        limit: int = 20,
        include_archived: bool = False,
        ctx: Any = None,
    ) -> Dict[str, Any]:
        payload = {"query": query, "limit": limit, "include_archived": include_archived}
        return await invoke_backend_tool(
            ctx=ctx,
            tool_name="memory_search",
            service="memory",
            method="POST",
            path="/search",
            tenant_id=tenant_id,
            payload_data=payload,
            timeout=15.0,
        )

    @mcp.tool(name="memory.write", description="Write a memory item.")
    async def memory_write(
        tenant_id: str,
        content: str,
        kind: str = "note",
        tags: Optional[list[str]] = None,
        user_approved: bool = False,
        ctx: Any = None,
    ) -> Dict[str, Any]:
        payload = {"content": content, "kind": kind, "tags": tags or [], "user_approved": user_approved}
        return await invoke_backend_tool(
            ctx=ctx,
            tool_name="memory_write",
            service="memory",
            method="POST",
            path="/write",
            tenant_id=tenant_id,
            payload_data=payload,
            timeout=15.0,
        )


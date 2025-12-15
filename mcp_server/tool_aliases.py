from __future__ import annotations

from typing import Any, Awaitable, Callable, Dict, Optional

from mcp.server.fastmcp import FastMCP

InvokeBackendTool = Callable[..., Awaitable[Dict[str, Any]]]

def register_dot_alias_tools(mcp: FastMCP, invoke_backend_tool: InvokeBackendTool) -> None:
    @mcp.tool(name="memory.search", description="Search tenant memories.")
    async def memory_search(
        tenant_id: str,
        query: str,
        limit: int = 20,
        include_archived: bool = False,
        actor: str = "orchestrator",
        actor_role: str = "Orchestrator",
        ctx: Any = None,
    ) -> Dict[str, Any]:
        payload = {"query": query, "limit": limit, "include_archived": include_archived}
        return await invoke_backend_tool(
            ctx=ctx,
            tool_name="memory.search",
            service="memory",
            method="POST",
            path="/search",
            tenant_id=tenant_id,
            actor=actor,
            actor_role=actor_role,
            payload_data=payload,
            timeout=15.0,
        )

    @mcp.tool(name="memory.write", description="Write a memory item.")
    async def memory_write(
        tenant_id: str,
        content: str,
        kind: str = "note",
        tags: Optional[list[str]] = None,
        actor: str = "orchestrator",
        actor_role: str = "Orchestrator",
        ctx: Any = None,
    ) -> Dict[str, Any]:
        payload = {"content": content, "kind": kind, "tags": tags or [], "actor": actor, "actor_role": actor_role}
        return await invoke_backend_tool(
            ctx=ctx,
            tool_name="memory.write",
            service="memory",
            method="POST",
            path="/write",
            tenant_id=tenant_id,
            actor=actor,
            actor_role=actor_role,
            payload_data=payload,
            timeout=15.0,
        )


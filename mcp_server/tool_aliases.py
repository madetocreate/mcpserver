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

    async def _workflow(tool_name: str, service: str, tenant_id: str, message: str, thread_id: Optional[str], actor: str, actor_role: str, ctx: Any) -> Dict[str, Any]:
        payload = {"tenant_id": tenant_id, "message": message, "thread_id": thread_id}
        return await invoke_backend_tool(
            ctx=ctx,
            tool_name=tool_name,
            service=service,
            method="POST",
            path="/workflow",
            tenant_id=tenant_id,
            actor=actor,
            actor_role=actor_role,
            payload_data=payload,
            timeout=60.0,
        )

    @mcp.tool(name="support.workflow", description="Run support workflow.")
    async def support_workflow(tenant_id: str, message: str, thread_id: Optional[str] = None, actor: str = "orchestrator", actor_role: str = "Orchestrator", ctx: Any = None) -> Dict[str, Any]:
        return await _workflow("support.workflow", "support", tenant_id, message, thread_id, actor, actor_role, ctx)

    @mcp.tool(name="marketing.workflow", description="Run marketing workflow.")
    async def marketing_workflow(tenant_id: str, message: str, thread_id: Optional[str] = None, actor: str = "orchestrator", actor_role: str = "Orchestrator", ctx: Any = None) -> Dict[str, Any]:
        return await _workflow("marketing.workflow", "marketing", tenant_id, message, thread_id, actor, actor_role, ctx)

    @mcp.tool(name="website.workflow", description="Run website workflow.")
    async def website_workflow(tenant_id: str, message: str, thread_id: Optional[str] = None, actor: str = "orchestrator", actor_role: str = "Orchestrator", ctx: Any = None) -> Dict[str, Any]:
        return await _workflow("website.workflow", "website", tenant_id, message, thread_id, actor, actor_role, ctx)

    @mcp.tool(name="backoffice.workflow", description="Run backoffice workflow.")
    async def backoffice_workflow(tenant_id: str, message: str, thread_id: Optional[str] = None, actor: str = "orchestrator", actor_role: str = "Orchestrator", ctx: Any = None) -> Dict[str, Any]:
        return await _workflow("backoffice.workflow", "backoffice", tenant_id, message, thread_id, actor, actor_role, ctx)

    @mcp.tool(name="onboarding.workflow", description="Run onboarding workflow.")
    async def onboarding_workflow(
        tenant_id: str,
        session_id: str,
        message: str,
        confirm_fetch: Optional[bool] = None,
        actor: str = "orchestrator",
        actor_role: str = "Orchestrator",
        ctx: Any = None,
    ) -> Dict[str, Any]:
        payload = {"tenant_id": tenant_id, "session_id": session_id, "message": message, "confirm_fetch": confirm_fetch}
        return await invoke_backend_tool(
            ctx=ctx,
            tool_name="onboarding.workflow",
            service="onboarding",
            method="POST",
            path="/workflow",
            tenant_id=tenant_id,
            actor=actor,
            actor_role=actor_role,
            payload_data=payload,
            timeout=60.0,
        )

from __future__ import annotations

import os
import asyncio
import logging
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx
from mcp.server.fastmcp import Context, FastMCP
from mcp.server.session import ServerSession

from .config import load_config


CONFIG_PATH = Path(
    os.getenv(
        "MCP_SERVER_CONFIG",
        str(Path(__file__).resolve().parent.parent / "config" / "server.yaml"),
    )
)
CONFIG = load_config(Path(CONFIG_PATH))


class RateLimitError(Exception):
    pass


class PermissionError(Exception):
    pass


class BackendError(Exception):
    pass


class RateLimiter:
    def __init__(self, config: Dict[str, Any]) -> None:
        rl_cfg = config.get("rate_limits", {})
        self.default_per_minute = int(rl_cfg.get("default_per_minute", 60))
        self.per_tool = rl_cfg.get("per_tool", {})
        self._buckets: Dict[str, Dict[str, Any]] = {}
        self._lock = asyncio.Lock()

    async def check(self, tenant_id: str, tool_name: str) -> None:
        key = f"{tenant_id}:{tool_name}"
        limit = int(self.per_tool.get(tool_name, self.default_per_minute))
        now = datetime.now(timezone.utc)
        window = now.replace(second=0, microsecond=0)
        async with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None or bucket["window"] != window:
                bucket = {"window": window, "count": 0}
                self._buckets[key] = bucket
            if bucket["count"] >= limit:
                raise RateLimitError(f"Rate limit exceeded for {tool_name}")
            bucket["count"] += 1


class PermissionChecker:
    def __init__(self, config: Dict[str, Any]) -> None:
        security_cfg = config.get("security", {})
        self.tools = security_cfg.get("tools", {})

    def ensure_allowed(self, tool_name: str, actor_role: str) -> Dict[str, Any]:
        tool_cfg = self.tools.get(tool_name)
        if tool_cfg is None:
            return {}
        allowed = tool_cfg.get("allowed_roles", [])
        if allowed and actor_role not in allowed:
            raise PermissionError(
                f"Role '{actor_role}' is not allowed to call {tool_name}"
            )
        return tool_cfg


class BackendClient:
    def __init__(self, http_client: httpx.AsyncClient, config: Dict[str, Any]) -> None:
        self.http_client = http_client
        self.config = config

    def _base_url(self, tenant_id: str, service: str) -> str:
        tenants = self.config.get("tenants", {})
        tenant = tenants.get(tenant_id) or tenants.get("default")
        if tenant is None:
            raise BackendError(f"Unknown tenant '{tenant_id}'")
        services = tenant.get("services", {})
        base = services.get(service)
        if base is None:
            raise BackendError(f"Service '{service}' not configured for tenant '{tenant_id}'")
        return str(base).rstrip("/")

    async def request(
        self,
        tenant_id: str,
        service: str,
        method: str,
        path: str,
        payload: Optional[Dict[str, Any]] = None,
        timeout: float = 10.0,
        retries: int = 2,
    ) -> Dict[str, Any]:
        base = self._base_url(tenant_id, service)
        url = f"{base}/{path.lstrip('/')}"
        last_exc: Optional[Exception] = None
        for attempt in range(retries + 1):
            try:
                response = await self.http_client.request(
                    method=method.upper(),
                    url=url,
                    json=payload,
                    timeout=timeout,
                )
                status = response.status_code
                if status == 429:
                    raise BackendError("Upstream rate limit")
                if status >= 500:
                    raise BackendError(f"Upstream {service} error {status}")
                response.raise_for_status()
                data = response.json()
                if isinstance(data, dict):
                    return data
                return {"result": data}
            except Exception as exc:
                last_exc = exc
                if attempt >= retries:
                    break
                backoff = 0.3 * (2**attempt)
                await asyncio.sleep(backoff)
        message = str(last_exc) if last_exc else "Unknown backend error"
        raise BackendError(message)


def setup_logger(config: Dict[str, Any]) -> logging.Logger:
    logger = logging.getLogger("mcp_server")
    if logger.handlers:
        return logger
    server_cfg = config.get("server", {})
    level_name = str(server_cfg.get("log_level", "INFO")).upper()
    level = getattr(logging, level_name, logging.INFO)
    logger.setLevel(level)
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        '{"ts":"%(asctime)s","level":"%(levelname)s","tool":"%(tool)s","tenant":"%(tenant)s","actor":"%(actor)s","msg":"%(message)s"}'
    )
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.propagate = False
    return logger


@dataclass
class AppContext:
    config: Dict[str, Any]
    backend: BackendClient
    rate_limiter: RateLimiter
    permissions: PermissionChecker
    logger: logging.Logger


TypedContext = Context[ServerSession, AppContext]


@asynccontextmanager
async def lifespan(server: FastMCP) -> AsyncIterator[AppContext]:
    logger = setup_logger(CONFIG)
    http_client = httpx.AsyncClient()
    backend = BackendClient(http_client=http_client, config=CONFIG)
    rate_limiter = RateLimiter(CONFIG)
    permissions = PermissionChecker(CONFIG)
    app_ctx = AppContext(
        config=CONFIG,
        backend=backend,
        rate_limiter=rate_limiter,
        permissions=permissions,
        logger=logger,
    )
    try:
        yield app_ctx
    finally:
        await http_client.aclose()


server_cfg = CONFIG.get("server", {})

_server_host = os.getenv("MCP_SERVER_HOST", server_cfg.get("host", "127.0.0.1"))
_server_port = int(os.getenv("MCP_SERVER_PORT", server_cfg.get("port", 9000)))

mcp = FastMCP(
    server_cfg.get("name", "simple-gpt-mcp"),
    lifespan=lifespan,
    json_response=True,
    host=_server_host,
    port=_server_port,
)


async def _call_backend_tool(
    ctx: TypedContext,
    tool_name: str,
    service: str,
    method: str,
    path: str,
    tenant_id: str,
    actor: str,
    actor_role: str,
    payload: Dict[str, Any],
    timeout: float = 10.0,
) -> Dict[str, Any]:
    app = ctx.request_context.lifespan_context
    await app.rate_limiter.check(tenant_id, tool_name)
    tool_cfg = app.permissions.ensure_allowed(tool_name, actor_role)
    requires_approval = bool(tool_cfg.get("user_approval_required")) if tool_cfg else False
    user_approved = bool(payload.get("user_approved", False))
    if requires_approval and not user_approved:
        raise PermissionError(
            f"Tool {tool_name} requires user approval but 'user_approved' was false."
        )
    start = time.perf_counter()
    try:
        result = await app.backend.request(
            tenant_id=tenant_id,
            service=service,
            method=method,
            path=path,
            payload=payload,
            timeout=timeout,
        )
        duration_ms = (time.perf_counter() - start) * 1000.0
        result["_meta"] = {
            "tool": tool_name,
            "duration_ms": duration_ms,
        }
        app.logger.info(
            "ok",
            extra={
                "tool": tool_name,
                "tenant": tenant_id,
                "actor": actor,
            },
        )
        return result
    except Exception as exc:
        app.logger.error(
            str(exc),
            extra={
                "tool": tool_name,
                "tenant": tenant_id,
                "actor": actor,
            },
        )
        raise


@mcp.tool(
    name="memory.search",
    description="Search tenant-specific long-term memory for relevant items.",
)
async def memory_search(
    tenant_id: str,
    query: str,
    limit: int = 20,
    include_archived: bool = False,
    actor: str = "orchestrator",
    actor_role: str = "Orchestrator",
    ctx: TypedContext | None = None,
) -> Dict[str, Any]:
    if ctx is None:
        raise RuntimeError("Context is required")
    payload: Dict[str, Any] = {
        "tenant_id": tenant_id,
        "query": query,
        "limit": limit,
        "include_archived": include_archived,
        "actor": actor,
        "actor_role": actor_role,
    }
    return await _call_backend_tool(
        ctx=ctx,
        tool_name="memory.search",
        service="memory",
        method="POST",
        path="/search",
        tenant_id=tenant_id,
        actor=actor,
        actor_role=actor_role,
        payload=payload,
        timeout=10.0,
    )


@mcp.tool(
    name="memory.write",
    description="Persist a new memory item for the tenant.",
)
async def memory_write(
    tenant_id: str,
    content: str,
    kind: str = "note",
    tags: Optional[List[str]] = None,
    correlation_id: Optional[str] = None,
    actor: str = "orchestrator",
    actor_role: str = "Orchestrator",
    ctx: TypedContext | None = None,
) -> Dict[str, Any]:
    if ctx is None:
        raise RuntimeError("Context is required")
    payload: Dict[str, Any] = {
        "tenant_id": tenant_id,
        "content": content,
        "kind": kind,
        "tags": tags or [],
        "correlation_id": correlation_id,
        "actor": actor,
        "actor_role": actor_role,
    }
    return await _call_backend_tool(
        ctx=ctx,
        tool_name="memory.write",
        service="memory",
        method="POST",
        path="/write",
        tenant_id=tenant_id,
        actor=actor,
        actor_role=actor_role,
        payload=payload,
        timeout=10.0,
    )


@mcp.tool(
    name="memory.delete",
    description="Delete or soft-delete a memory item.",
)
async def memory_delete(
    tenant_id: str,
    memory_id: str,
    soft_delete: bool = True,
    user_approved: bool = False,
    actor: str = "orchestrator",
    actor_role: str = "Orchestrator",
    ctx: TypedContext | None = None,
) -> Dict[str, Any]:
    if ctx is None:
        raise RuntimeError("Context is required")
    payload: Dict[str, Any] = {
        "tenant_id": tenant_id,
        "memory_id": memory_id,
        "soft_delete": soft_delete,
        "user_approved": user_approved,
        "actor": actor,
        "actor_role": actor_role,
    }
    return await _call_backend_tool(
        ctx=ctx,
        tool_name="memory.delete",
        service="memory",
        method="POST",
        path="/delete",
        tenant_id=tenant_id,
        actor=actor,
        actor_role=actor_role,
        payload=payload,
        timeout=10.0,
    )


@mcp.tool(
    name="memory.archive",
    description="Archive a memory item so it no longer appears in default search.",
)
async def memory_archive(
    tenant_id: str,
    memory_id: str,
    user_approved: bool = False,
    actor: str = "orchestrator",
    actor_role: str = "Orchestrator",
    ctx: TypedContext | None = None,
) -> Dict[str, Any]:
    if ctx is None:
        raise RuntimeError("Context is required")
    payload: Dict[str, Any] = {
        "tenant_id": tenant_id,
        "memory_id": memory_id,
        "user_approved": user_approved,
        "actor": actor,
        "actor_role": actor_role,
    }
    return await _call_backend_tool(
        ctx=ctx,
        tool_name="memory.archive",
        service="memory",
        method="POST",
        path="/archive",
        tenant_id=tenant_id,
        actor=actor,
        actor_role=actor_role,
        payload=payload,
        timeout=10.0,
    )


@mcp.tool(
    name="memory.telemetry",
    description="Return aggregate telemetry on memory usage and tool calls.",
)
async def memory_telemetry(
    tenant_id: str,
    window_minutes: int = 60,
    actor: str = "orchestrator",
    actor_role: str = "Orchestrator",
    ctx: TypedContext | None = None,
) -> Dict[str, Any]:
    if ctx is None:
        raise RuntimeError("Context is required")
    payload: Dict[str, Any] = {
        "tenant_id": tenant_id,
        "window_minutes": window_minutes,
        "actor": actor,
        "actor_role": actor_role,
    }
    return await _call_backend_tool(
        ctx=ctx,
        tool_name="memory.telemetry",
        service="memory",
        method="GET",
        path="/telemetry",
        tenant_id=tenant_id,
        actor=actor,
        actor_role=actor_role,
        payload=payload,
        timeout=5.0,
    )


@mcp.tool(
    name="crm.lookup_customer",
    description="Lookup a single customer record by identifier.",
)
async def crm_lookup_customer(
    tenant_id: str,
    customer_id: str,
    actor: str = "orchestrator",
    actor_role: str = "CRM-Supervisor",
    ctx: TypedContext | None = None,
) -> Dict[str, Any]:
    if ctx is None:
        raise RuntimeError("Context is required")
    payload: Dict[str, Any] = {
        "tenant_id": tenant_id,
        "customer_id": customer_id,
        "actor": actor,
        "actor_role": actor_role,
    }
    return await _call_backend_tool(
        ctx=ctx,
        tool_name="crm.lookup_customer",
        service="crm",
        method="GET",
        path="/lookup_customer",
        tenant_id=tenant_id,
        actor=actor,
        actor_role=actor_role,
        payload=payload,
        timeout=5.0,
    )


@mcp.tool(
    name="crm.search_customers",
    description="Search customers by free-text query or filters.",
)
async def crm_search_customers(
    tenant_id: str,
    query: str,
    limit: int = 20,
    actor: str = "orchestrator",
    actor_role: str = "CRM-Supervisor",
    ctx: TypedContext | None = None,
) -> Dict[str, Any]:
    if ctx is None:
        raise RuntimeError("Context is required")
    payload: Dict[str, Any] = {
        "tenant_id": tenant_id,
        "query": query,
        "limit": limit,
        "actor": actor,
        "actor_role": actor_role,
    }
    return await _call_backend_tool(
        ctx=ctx,
        tool_name="crm.search_customers",
        service="crm",
        method="POST",
        path="/search_customers",
        tenant_id=tenant_id,
        actor=actor,
        actor_role=actor_role,
        payload=payload,
        timeout=10.0,
    )


@mcp.tool(
    name="crm.create_note",
    description="Attach a note to a CRM customer record.",
)
async def crm_create_note(
    tenant_id: str,
    customer_id: str,
    text: str,
    actor: str = "orchestrator",
    actor_role: str = "CRM-Supervisor",
    ctx: TypedContext | None = None,
) -> Dict[str, Any]:
    if ctx is None:
        raise RuntimeError("Context is required")
    payload: Dict[str, Any] = {
        "tenant_id": tenant_id,
        "customer_id": customer_id,
        "text": text,
        "actor": actor,
        "actor_role": actor_role,
    }
    return await _call_backend_tool(
        ctx=ctx,
        tool_name="crm.create_note",
        service="crm",
        method="POST",
        path="/create_note",
        tenant_id=tenant_id,
        actor=actor,
        actor_role=actor_role,
        payload=payload,
        timeout=10.0,
    )


@mcp.tool(
    name="crm.update_pipeline",
    description="Update the pipeline stage or value for an opportunity.",
)
async def crm_update_pipeline(
    tenant_id: str,
    opportunity_id: str,
    stage: str,
    value: Optional[float] = None,
    user_approved: bool = False,
    actor: str = "orchestrator",
    actor_role: str = "CRM-Supervisor",
    ctx: TypedContext | None = None,
) -> Dict[str, Any]:
    if ctx is None:
        raise RuntimeError("Context is required")
    payload: Dict[str, Any] = {
        "tenant_id": tenant_id,
        "opportunity_id": opportunity_id,
        "stage": stage,
        "value": value,
        "user_approved": user_approved,
        "actor": actor,
        "actor_role": actor_role,
    }
    return await _call_backend_tool(
        ctx=ctx,
        tool_name="crm.update_pipeline",
        service="crm",
        method="POST",
        path="/update_pipeline",
        tenant_id=tenant_id,
        actor=actor,
        actor_role=actor_role,
        payload=payload,
        timeout=10.0,
    )


@mcp.tool(
    name="automation.trigger",
    description="Trigger an automation workflow with a payload.",
)
async def automation_trigger(
    tenant_id: str,
    workflow_id: str,
    input_payload: Optional[Dict[str, Any]] = None,
    user_approved: bool = False,
    actor: str = "orchestrator",
    actor_role: str = "Automation-Supervisor",
    ctx: TypedContext | None = None,
) -> Dict[str, Any]:
    if ctx is None:
        raise RuntimeError("Context is required")
    payload: Dict[str, Any] = {
        "tenant_id": tenant_id,
        "workflow_id": workflow_id,
        "input": input_payload or {},
        "user_approved": user_approved,
        "actor": actor,
        "actor_role": actor_role,
    }
    return await _call_backend_tool(
        ctx=ctx,
        tool_name="automation.trigger",
        service="automation",
        method="POST",
        path="/trigger",
        tenant_id=tenant_id,
        actor=actor,
        actor_role=actor_role,
        payload=payload,
        timeout=20.0,
    )


@mcp.tool(
    name="automation.validate",
    description="Validate whether a workflow can run with the given payload.",
)
async def automation_validate(
    tenant_id: str,
    workflow_id: str,
    input_payload: Optional[Dict[str, Any]] = None,
    actor: str = "orchestrator",
    actor_role: str = "Automation-Supervisor",
    ctx: TypedContext | None = None,
) -> Dict[str, Any]:
    if ctx is None:
        raise RuntimeError("Context is required")
    payload: Dict[str, Any] = {
        "tenant_id": tenant_id,
        "workflow_id": workflow_id,
        "input": input_payload or {},
        "actor": actor,
        "actor_role": actor_role,
    }
    return await _call_backend_tool(
        ctx=ctx,
        tool_name="automation.validate",
        service="automation",
        method="POST",
        path="/validate",
        tenant_id=tenant_id,
        actor=actor,
        actor_role=actor_role,
        payload=payload,
        timeout=10.0,
    )


@mcp.tool(
    name="automation.run_flow",
    description="Start a long-running automation flow.",
)
async def automation_run_flow(
    tenant_id: str,
    flow_key: str,
    mode: str = "async",
    input_payload: Optional[Dict[str, Any]] = None,
    user_approved: bool = False,
    actor: str = "orchestrator",
    actor_role: str = "Automation-Supervisor",
    ctx: TypedContext | None = None,
) -> Dict[str, Any]:
    if ctx is None:
        raise RuntimeError("Context is required")
    payload: Dict[str, Any] = {
        "tenant_id": tenant_id,
        "flow_key": flow_key,
        "mode": mode,
        "input": input_payload or {},
        "user_approved": user_approved,
        "actor": actor,
        "actor_role": actor_role,
    }
    return await _call_backend_tool(
        ctx=ctx,
        tool_name="automation.run_flow",
        service="automation",
        method="POST",
        path="/run_flow",
        tenant_id=tenant_id,
        actor=actor,
        actor_role=actor_role,
        payload=payload,
        timeout=30.0,
    )


@mcp.tool(
    name="automation.list_workflows",
    description="List available automation workflows for the tenant.",
)
async def automation_list_workflows(
    tenant_id: str,
    query: Optional[str] = None,
    tag: Optional[str] = None,
    actor: str = "orchestrator",
    actor_role: str = "Automation-Supervisor",
    ctx: TypedContext | None = None,
) -> Dict[str, Any]:
    if ctx is None:
        raise RuntimeError("Context is required")
    payload: Dict[str, Any] = {
        "tenant_id": tenant_id,
        "query": query,
        "tag": tag,
        "actor": actor,
        "actor_role": actor_role,
    }
    return await _call_backend_tool(
        ctx=ctx,
        tool_name="automation.list_workflows",
        service="automation",
        method="GET",
        path="/workflows",
        tenant_id=tenant_id,
        actor=actor,
        actor_role=actor_role,
        payload=payload,
        timeout=10.0,
    )


@mcp.tool(
    name="inbox.get_thread",
    description="Load a full inbox thread including messages and metadata.",
)
async def inbox_get_thread(
    tenant_id: str,
    thread_id: str,
    actor: str = "orchestrator",
    actor_role: str = "Inbox-Supervisor",
    ctx: TypedContext | None = None,
) -> Dict[str, Any]:
    if ctx is None:
        raise RuntimeError("Context is required")
    payload: Dict[str, Any] = {
        "tenant_id": tenant_id,
        "thread_id": thread_id,
        "actor": actor,
        "actor_role": actor_role,
    }
    return await _call_backend_tool(
        ctx=ctx,
        tool_name="inbox.get_thread",
        service="inbox",
        method="GET",
        path="/thread",
        tenant_id=tenant_id,
        actor=actor,
        actor_role=actor_role,
        payload=payload,
        timeout=10.0,
    )


@mcp.tool(
    name="inbox.reply",
    description="Reply to an existing inbox thread.",
)
async def inbox_reply(
    tenant_id: str,
    thread_id: str,
    body: str,
    draft: bool = False,
    user_approved: bool = False,
    actor: str = "orchestrator",
    actor_role: str = "Inbox-Supervisor",
    ctx: TypedContext | None = None,
) -> Dict[str, Any]:
    if ctx is None:
        raise RuntimeError("Context is required")
    payload: Dict[str, Any] = {
        "tenant_id": tenant_id,
        "thread_id": thread_id,
        "body": body,
        "draft": draft,
        "user_approved": user_approved,
        "actor": actor,
        "actor_role": actor_role,
    }
    return await _call_backend_tool(
        ctx=ctx,
        tool_name="inbox.reply",
        service="inbox",
        method="POST",
        path="/reply",
        tenant_id=tenant_id,
        actor=actor,
        actor_role=actor_role,
        payload=payload,
        timeout=15.0,
    )


@mcp.tool(
    name="inbox.list",
    description="List inbox threads for a folder.",
)
async def inbox_list(
    tenant_id: str,
    folder: str = "inbox",
    limit: int = 20,
    actor: str = "orchestrator",
    actor_role: str = "Inbox-Supervisor",
    ctx: TypedContext | None = None,
) -> Dict[str, Any]:
    if ctx is None:
        raise RuntimeError("Context is required")
    payload: Dict[str, Any] = {
        "tenant_id": tenant_id,
        "folder": folder,
        "limit": limit,
        "actor": actor,
        "actor_role": actor_role,
    }
    return await _call_backend_tool(
        ctx=ctx,
        tool_name="inbox.list",
        service="inbox",
        method="GET",
        path="/list",
        tenant_id=tenant_id,
        actor=actor,
        actor_role=actor_role,
        payload=payload,
        timeout=10.0,
    )


@mcp.tool(
    name="inbox.send_message",
    description="Send a new inbox message.",
)
async def inbox_send_message(
    tenant_id: str,
    to: str,
    subject: str,
    body: str,
    cc: Optional[List[str]] = None,
    bcc: Optional[List[str]] = None,
    user_approved: bool = False,
    actor: str = "orchestrator",
    actor_role: str = "Inbox-Supervisor",
    ctx: TypedContext | None = None,
) -> Dict[str, Any]:
    if ctx is None:
        raise RuntimeError("Context is required")
    payload: Dict[str, Any] = {
        "tenant_id": tenant_id,
        "to": to,
        "subject": subject,
        "body": body,
        "cc": cc or [],
        "bcc": bcc or [],
        "user_approved": user_approved,
        "actor": actor,
        "actor_role": actor_role,
    }
    return await _call_backend_tool(
        ctx=ctx,
        tool_name="inbox.send_message",
        service="inbox",
        method="POST",
        path="/send",
        tenant_id=tenant_id,
        actor=actor,
        actor_role=actor_role,
        payload=payload,
        timeout=20.0,
    )


@mcp.tool(
    name="file.search_local",
    description="Search local or indexed files by query.",
)
async def file_search_local(
    tenant_id: str,
    query: str,
    max_results: int = 20,
    actor: str = "orchestrator",
    actor_role: str = "User-Agent",
    ctx: TypedContext | None = None,
) -> Dict[str, Any]:
    if ctx is None:
        raise RuntimeError("Context is required")
    payload: Dict[str, Any] = {
        "tenant_id": tenant_id,
        "query": query,
        "max_results": max_results,
        "actor": actor,
        "actor_role": actor_role,
    }
    return await _call_backend_tool(
        ctx=ctx,
        tool_name="file.search_local",
        service="files",
        method="POST",
        path="/search",
        tenant_id=tenant_id,
        actor=actor,
        actor_role=actor_role,
        payload=payload,
        timeout=10.0,
    )


@mcp.tool(
    name="file.preview",
    description="Get a textual preview for a file.",
)
async def file_preview(
    tenant_id: str,
    file_id: str,
    actor: str = "orchestrator",
    actor_role: str = "User-Agent",
    ctx: TypedContext | None = None,
) -> Dict[str, Any]:
    if ctx is None:
        raise RuntimeError("Context is required")
    payload: Dict[str, Any] = {
        "tenant_id": tenant_id,
        "file_id": file_id,
        "actor": actor,
        "actor_role": actor_role,
    }
    return await _call_backend_tool(
        ctx=ctx,
        tool_name="file.preview",
        service="files",
        method="GET",
        path="/preview",
        tenant_id=tenant_id,
        actor=actor,
        actor_role=actor_role,
        payload=payload,
        timeout=10.0,
    )


@mcp.tool(
    name="file.metadata",
    description="Get structured metadata for a file.",
)
async def file_metadata(
    tenant_id: str,
    file_id: str,
    actor: str = "orchestrator",
    actor_role: str = "User-Agent",
    ctx: TypedContext | None = None,
) -> Dict[str, Any]:
    if ctx is None:
        raise RuntimeError("Context is required")
    payload: Dict[str, Any] = {
        "tenant_id": tenant_id,
        "file_id": file_id,
        "actor": actor,
        "actor_role": actor_role,
    }
    return await _call_backend_tool(
        ctx=ctx,
        tool_name="file.metadata",
        service="files",
        method="GET",
        path="/metadata",
        tenant_id=tenant_id,
        actor=actor,
        actor_role=actor_role,
        payload=payload,
        timeout=10.0,
    )

@mcp.tool(
    name="support.workflow",
    description="Run the support workflow agent to handle a support request.",
)
async def support_workflow(
    tenant_id: str,
    message: str,
    actor: str = "orchestrator",
    actor_role: str = "Orchestrator",
    ctx: TypedContext | None = None,
) -> Dict[str, Any]:
    if ctx is None:
        raise RuntimeError("Context is required")
    payload: Dict[str, Any] = {
        "tenant_id": tenant_id,
        "message": message,
        "actor": actor,
        "actor_role": actor_role,
    }
    return await _call_backend_tool(
        ctx=ctx,
        tool_name="support.workflow",
        service="support",
        method="POST",
        path="/workflow",
        tenant_id=tenant_id,
        actor=actor,
        actor_role=actor_role,
        payload=payload,
        timeout=30.0,
    )


@mcp.tool(
    name="marketing.workflow",
    description="Run the marketing workflow agent to handle marketing requests.",
)
async def marketing_workflow(
    tenant_id: str,
    message: str,
    thread_id: Optional[str] = None,
    actor: str = "orchestrator",
    actor_role: str = "Orchestrator",
    ctx: TypedContext | None = None,
) -> Dict[str, Any]:
    if ctx is None:
        raise RuntimeError("Context is required")
    payload: Dict[str, Any] = {
        "tenant_id": tenant_id,
        "message": message,
        "thread_id": thread_id,
        "actor": actor,
        "actor_role": actor_role,
    }
    return await _call_backend_tool(
        ctx=ctx,
        tool_name="marketing.workflow",
        service="marketing",
        method="POST",
        path="/workflow",
        tenant_id=tenant_id,
        actor=actor,
        actor_role=actor_role,
        payload=payload,
        timeout=30.0,
    )


@mcp.tool(
    name="website.workflow",
    description="Run the website workflow agent to handle website widget conversations.",
)
async def website_workflow(
    tenant_id: str,
    message: str,
    thread_id: Optional[str] = None,
    actor: str = "orchestrator",
    actor_role: str = "Orchestrator",
    ctx: TypedContext | None = None,
) -> Dict[str, Any]:
    if ctx is None:
        raise RuntimeError("Context is required")
    payload: Dict[str, Any] = {
        "tenant_id": tenant_id,
        "message": message,
        "thread_id": thread_id,
        "actor": actor,
        "actor_role": actor_role,
    }
    return await _call_backend_tool(
        ctx=ctx,
        tool_name="website.workflow",
        service="website",
        method="POST",
        path="/workflow",
        tenant_id=tenant_id,
        actor=actor,
        actor_role=actor_role,
        payload=payload,
        timeout=30.0,
    )


@mcp.tool(
    name="backoffice.workflow",
    description="Run the backoffice workflow agent to handle internal operations requests.",
)
async def backoffice_workflow(
    tenant_id: str,
    message: str,
    thread_id: Optional[str] = None,
    actor: str = "orchestrator",
    actor_role: str = "Orchestrator",
    ctx: TypedContext | None = None,
) -> Dict[str, Any]:
    if ctx is None:
        raise RuntimeError("Context is required")
    payload: Dict[str, Any] = {
        "tenant_id": tenant_id,
        "message": message,
        "thread_id": thread_id,
        "actor": actor,
        "actor_role": actor_role,
    }
    return await _call_backend_tool(
        ctx=ctx,
        tool_name="backoffice.workflow",
        service="backoffice",
        method="POST",
        path="/workflow",
        tenant_id=tenant_id,
        actor=actor,
        actor_role=actor_role,
        payload=payload,
        timeout=30.0,
    )

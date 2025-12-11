from __future__ import annotations

import os
import asyncio
import logging
import time
import json
import uuid
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
from .observability import AuditLogger, InMemoryMetrics
from .rate_limits import AdvancedRateLimiter, RateLimitError


CONFIG_PATH = Path(
    os.getenv(
        "MCP_SERVER_CONFIG",
        str(Path(__file__).resolve().parent.parent / "config" / "server.yaml"),
    )
)
CONFIG = load_config(Path(CONFIG_PATH))


class MCPError(Exception):
    """Base exception for all MCP server errors."""
    pass


class MCPClientError(MCPError):
    """Client-side errors (4xx) - user input issues."""
    pass


class MCPServerError(MCPError):
    """Server-side errors (5xx) - internal issues."""
    pass


class PermissionError(MCPClientError):
    """Permission/authorization errors."""
    pass


class BackendError(MCPServerError):
    """Backend service errors."""
    pass




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
    
    # Use a custom formatter that handles missing fields gracefully
    class StructuredFormatter(logging.Formatter):
        """Custom formatter that handles missing structured fields gracefully."""
        
        def format(self, record: logging.LogRecord) -> str:
            # Ensure all structured fields exist with defaults
            if not hasattr(record, "tool"):
                record.tool = ""
            if not hasattr(record, "tenant"):
                record.tenant = ""
            if not hasattr(record, "actor"):
                record.actor = ""
            if not hasattr(record, "correlation_id"):
                record.correlation_id = ""
            if not hasattr(record, "duration_ms"):
                record.duration_ms = ""
            return super().format(record)
    
    handler.setFormatter(StructuredFormatter(
        '{"ts":"%(asctime)s","level":"%(levelname)s","tool":"%(tool)s","tenant":"%(tenant)s","actor":"%(actor)s",'
        '"correlation_id":"%(correlation_id)s","duration_ms":"%(duration_ms)s","msg":"%(message)s"}'
    ))
    logger.addHandler(handler)
    logger.propagate = False
    return logger


@dataclass
class AppContext:
    config: Dict[str, Any]
    backend: BackendClient
    rate_limiter: AdvancedRateLimiter
    permissions: PermissionChecker
    logger: logging.Logger
    audit: AuditLogger
    metrics: InMemoryMetrics


TypedContext = Context[ServerSession, AppContext]


@asynccontextmanager
async def lifespan(server: FastMCP) -> AsyncIterator[AppContext]:
    logger = setup_logger(CONFIG)
    
    
    # Configure HTTP client with connection pooling and timeouts
    server_cfg = CONFIG.get("server", {})
    http_limits = server_cfg.get("http_limits", {})
    http_client = httpx.AsyncClient(
        limits=httpx.Limits(
            max_connections=int(http_limits.get("max_connections", 100)),
            max_keepalive_connections=int(http_limits.get("max_keepalive_connections", 20)),
        ),
        timeout=httpx.Timeout(
            connect=float(http_limits.get("connect_timeout", 5.0)),
            read=float(http_limits.get("read_timeout", 30.0)),
            write=float(http_limits.get("write_timeout", 10.0)),
            pool=float(http_limits.get("pool_timeout", 5.0)),
        ),
        follow_redirects=True,
    )
    
    backend = BackendClient(http_client=http_client, config=CONFIG)
    rate_limiter = AdvancedRateLimiter(CONFIG.get("rate_limits", {}))
    logs_dir = Path(__file__).resolve().parent.parent / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    audit_path = logs_dir / "audit.log"
    audit = AuditLogger(path=str(audit_path))
    metrics = InMemoryMetrics()
    app_ctx = AppContext(
        config=CONFIG,
        backend=backend,
        rate_limiter=rate_limiter,
        permissions=PermissionChecker(CONFIG),
        logger=logger,
        audit=audit,
        metrics=metrics,
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
    # Note: stateless_http=True should work, but testing shows session_id not returned
    # FastMCP might need session_id in query params for stateless mode to work correctly
    stateless_http=True,  # Enable stateless HTTP mode for OpenAI Agent Builder compatibility
)


# Static list of all registered tools for HTTP discovery
_ALL_TOOLS = [
    "memory.search", "memory.write", "memory.delete", "memory.archive", "memory.telemetry",
    "crm.lookup_customer", "crm.search_customers", "crm.create_note", "crm.update_pipeline",
    "automation.trigger", "automation.validate", "automation.run_flow", "automation.list_workflows",
    "inbox.get_thread", "inbox.reply", "inbox.list", "inbox.send_message",
    "file.search_local", "file.preview", "file.metadata",
    "support.supervisor", "marketing.supervisor", "website.supervisor", "backoffice.supervisor",
    "memory.supervisor", "crm.supervisor", "automation.supervisor", "inbox.supervisor",
    "file.supervisor", "communications.supervisor",
    "observability.metrics", "observability.health", "observability.discovery",
]


# Note: FastMCP doesn't expose its internal ASGI app easily for adding custom routes.
# The discovery endpoint /mcp/discovery is available via:
# 1. MCP protocol: Call the observability.discovery tool via /mcp endpoint
# 2. HTTP GET: Use curl/scripts to call observability.discovery tool through MCP protocol


def _generate_correlation_id() -> str:
    """Generate a unique correlation ID for request tracing."""
    return str(uuid.uuid4())


def _require_context(ctx: TypedContext | None) -> TypedContext:
    """Ensure context is provided, raise if None."""
    if ctx is None:
        raise RuntimeError("Context is required")
    return ctx


def _build_base_payload(
    tenant_id: str,
    actor: str,
    actor_role: str,
    **extra: Any,
) -> Dict[str, Any]:
    """Build base payload with common fields and optional extras."""
    payload: Dict[str, Any] = {
        "tenant_id": tenant_id,
        "actor": actor,
        "actor_role": actor_role,
        **extra,
    }
    return payload


async def _invoke_backend_tool(
    ctx: TypedContext | None,
    tool_name: str,
    service: str,
    method: str,
    path: str,
    tenant_id: str,
    actor: str,
    actor_role: str,
    payload_data: Dict[str, Any],
    timeout: float = 10.0,
) -> Dict[str, Any]:
    """Helper function to invoke backend tool with standardized error handling."""
    ctx = _require_context(ctx)
    payload = _build_base_payload(tenant_id, actor, actor_role, **payload_data)
    return await _call_backend_tool(
        ctx=ctx,
        tool_name=tool_name,
        service=service,
        method=method,
        path=path,
        tenant_id=tenant_id,
        actor=actor,
        actor_role=actor_role,
        payload=payload,
        timeout=timeout,
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
    
    # Generate correlation ID if not present
    correlation_id = payload.get("correlation_id") or _generate_correlation_id()
    if "correlation_id" not in payload:
        payload["correlation_id"] = correlation_id
    
    # Calculate payload size for audit logging
    payload_size = len(json.dumps(payload, ensure_ascii=False))
    
    start = time.perf_counter()
    error_code: Optional[str] = None
    status = "ok"
    
    try:
        app.rate_limiter.check(tenant_id, tool_name, actor)
        tool_cfg = app.permissions.ensure_allowed(tool_name, actor_role)
        requires_approval = bool(tool_cfg.get("user_approval_required")) if tool_cfg else False
        user_approved = bool(payload.get("user_approved", False))
        if requires_approval and not user_approved:
            error_code = "APPROVAL_REQUIRED"
            raise PermissionError(
                f"Tool {tool_name} requires user approval but 'user_approved' was false."
            )
        
        result = await app.backend.request(
            tenant_id=tenant_id,
            service=service,
            method=method,
            path=path,
            payload=payload,
            timeout=timeout,
        )
        duration_ms = (time.perf_counter() - start) * 1000.0
        app.metrics.record(tool_name, duration_ms, error=False)
        
        # Add metadata to response
        result["_meta"] = {
            "tool": tool_name,
            "duration_ms": duration_ms,
            "correlation_id": correlation_id,
        }
        
        # Audit logging
        app.audit.log_call(
            tool=tool_name,
            tenant=tenant_id,
            actor=actor,
            role=actor_role,
            status=status,
            duration_ms=duration_ms,
            error_code=None,
            correlation_id=correlation_id,
            payload_size=payload_size,
        )
        
        app.logger.info(
            "Tool call succeeded",
            extra={
                "tool": tool_name,
                "tenant": tenant_id,
                "actor": actor,
                "correlation_id": correlation_id,
                "duration_ms": duration_ms,
            },
        )
        return result
        
    except RateLimitError as exc:
        duration_ms = (time.perf_counter() - start) * 1000.0
        error_code = "RATE_LIMIT_EXCEEDED"
        status = "rate_limited"
        app.metrics.record(tool_name, duration_ms, error=True)
        
        app.audit.log_call(
            tool=tool_name,
            tenant=tenant_id,
            actor=actor,
            role=actor_role,
            status=status,
            duration_ms=duration_ms,
            error_code=error_code,
            correlation_id=correlation_id,
            payload_size=payload_size,
        )
        
        app.logger.warning(
            f"Rate limit exceeded: {exc}",
            extra={
                "tool": tool_name,
                "tenant": tenant_id,
                "actor": actor,
                "correlation_id": correlation_id,
                "reset_in_seconds": exc.reset_in_seconds,
            },
        )
        raise
        
    except PermissionError as exc:
        duration_ms = (time.perf_counter() - start) * 1000.0
        error_code = error_code or "PERMISSION_DENIED"
        status = "permission_denied"
        app.metrics.record(tool_name, duration_ms, error=True)
        
        app.audit.log_call(
            tool=tool_name,
            tenant=tenant_id,
            actor=actor,
            role=actor_role,
            status=status,
            duration_ms=duration_ms,
            error_code=error_code,
            correlation_id=correlation_id,
            payload_size=payload_size,
        )
        
        app.logger.warning(
            f"Permission denied: {exc}",
            extra={
                "tool": tool_name,
                "tenant": tenant_id,
                "actor": actor,
                "correlation_id": correlation_id,
            },
        )
        raise
        
    except BackendError as exc:
        duration_ms = (time.perf_counter() - start) * 1000.0
        error_code = "BACKEND_ERROR"
        status = "backend_error"
        app.metrics.record(tool_name, duration_ms, error=True)
        
        app.audit.log_call(
            tool=tool_name,
            tenant=tenant_id,
            actor=actor,
            role=actor_role,
            status=status,
            duration_ms=duration_ms,
            error_code=error_code,
            correlation_id=correlation_id,
            payload_size=payload_size,
        )
        
        app.logger.error(
            f"Backend error: {exc}",
            extra={
                "tool": tool_name,
                "tenant": tenant_id,
                "actor": actor,
                "correlation_id": correlation_id,
                "service": service,
            },
        )
        raise
        
    except Exception as exc:
        duration_ms = (time.perf_counter() - start) * 1000.0
        error_code = "INTERNAL_ERROR"
        status = "error"
        app.metrics.record(tool_name, duration_ms, error=True)
        
        app.audit.log_call(
            tool=tool_name,
            tenant=tenant_id,
            actor=actor,
            role=actor_role,
            status=status,
            duration_ms=duration_ms,
            error_code=error_code,
            correlation_id=correlation_id,
            payload_size=payload_size,
        )
        
        app.logger.error(
            f"Unexpected error: {exc}",
            extra={
                "tool": tool_name,
                "tenant": tenant_id,
                "actor": actor,
                "correlation_id": correlation_id,
                "error_type": type(exc).__name__,
            },
            exc_info=True,
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
    return await _invoke_backend_tool(
        ctx=ctx,
        tool_name="memory.search",
        service="memory",
        method="POST",
        path="/search",
        tenant_id=tenant_id,
        actor=actor,
        actor_role=actor_role,
        payload_data={"query": query, "limit": limit, "include_archived": include_archived},
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
    payload_data: Dict[str, Any] = {
        "content": content,
        "kind": kind,
        "tags": tags or [],
    }
    if correlation_id:
        payload_data["correlation_id"] = correlation_id
    return await _invoke_backend_tool(
        ctx=ctx,
        tool_name="memory.write",
        service="memory",
        method="POST",
        path="/write",
        tenant_id=tenant_id,
        actor=actor,
        actor_role=actor_role,
        payload_data=payload_data,
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
    return await _invoke_backend_tool(
        ctx=ctx,
        tool_name="memory.delete",
        service="memory",
        method="POST",
        path="/delete",
        tenant_id=tenant_id,
        actor=actor,
        actor_role=actor_role,
        payload_data={"memory_id": memory_id, "soft_delete": soft_delete, "user_approved": user_approved},
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
    return await _invoke_backend_tool(
        ctx=ctx,
        tool_name="memory.archive",
        service="memory",
        method="POST",
        path="/archive",
        tenant_id=tenant_id,
        actor=actor,
        actor_role=actor_role,
        payload_data={"memory_id": memory_id, "user_approved": user_approved},
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
    return await _invoke_backend_tool(
        ctx=ctx,
        tool_name="memory.telemetry",
        service="memory",
        method="GET",
        path="/telemetry",
        tenant_id=tenant_id,
        actor=actor,
        actor_role=actor_role,
        payload_data={"window_minutes": window_minutes},
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
    return await _invoke_backend_tool(
        ctx=ctx,
        tool_name="crm.lookup_customer",
        service="crm",
        method="GET",
        path="/lookup_customer",
        tenant_id=tenant_id,
        actor=actor,
        actor_role=actor_role,
        payload_data={"customer_id": customer_id},
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
    return await _invoke_backend_tool(
        ctx=ctx,
        tool_name="crm.search_customers",
        service="crm",
        method="POST",
        path="/search_customers",
        tenant_id=tenant_id,
        actor=actor,
        actor_role=actor_role,
        payload_data={"query": query, "limit": limit},
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
    return await _invoke_backend_tool(
        ctx=ctx,
        tool_name="crm.create_note",
        service="crm",
        method="POST",
        path="/create_note",
        tenant_id=tenant_id,
        actor=actor,
        actor_role=actor_role,
        payload_data={"customer_id": customer_id, "text": text},
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
    payload_data: Dict[str, Any] = {
        "opportunity_id": opportunity_id,
        "stage": stage,
        "user_approved": user_approved,
    }
    if value is not None:
        payload_data["value"] = value
    return await _invoke_backend_tool(
        ctx=ctx,
        tool_name="crm.update_pipeline",
        service="crm",
        method="POST",
        path="/update_pipeline",
        tenant_id=tenant_id,
        actor=actor,
        actor_role=actor_role,
        payload_data=payload_data,
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
    return await _invoke_backend_tool(
        ctx=ctx,
        tool_name="automation.trigger",
        service="automation",
        method="POST",
        path="/trigger",
        tenant_id=tenant_id,
        actor=actor,
        actor_role=actor_role,
        payload_data={"workflow_id": workflow_id, "input": input_payload or {}, "user_approved": user_approved},
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
    return await _invoke_backend_tool(
        ctx=ctx,
        tool_name="automation.validate",
        service="automation",
        method="POST",
        path="/validate",
        tenant_id=tenant_id,
        actor=actor,
        actor_role=actor_role,
        payload_data={"workflow_id": workflow_id, "input": input_payload or {}},
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
    return await _invoke_backend_tool(
        ctx=ctx,
        tool_name="automation.run_flow",
        service="automation",
        method="POST",
        path="/run_flow",
        tenant_id=tenant_id,
        actor=actor,
        actor_role=actor_role,
        payload_data={"flow_key": flow_key, "mode": mode, "input": input_payload or {}, "user_approved": user_approved},
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
    payload_data: Dict[str, Any] = {}
    if query:
        payload_data["query"] = query
    if tag:
        payload_data["tag"] = tag
    return await _invoke_backend_tool(
        ctx=ctx,
        tool_name="automation.list_workflows",
        service="automation",
        method="GET",
        path="/workflows",
        tenant_id=tenant_id,
        actor=actor,
        actor_role=actor_role,
        payload_data=payload_data,
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
    return await _invoke_backend_tool(
        ctx=ctx,
        tool_name="inbox.get_thread",
        service="inbox",
        method="GET",
        path="/thread",
        tenant_id=tenant_id,
        actor=actor,
        actor_role=actor_role,
        payload_data={"thread_id": thread_id},
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
    return await _invoke_backend_tool(
        ctx=ctx,
        tool_name="inbox.reply",
        service="inbox",
        method="POST",
        path="/reply",
        tenant_id=tenant_id,
        actor=actor,
        actor_role=actor_role,
        payload_data={"thread_id": thread_id, "body": body, "draft": draft, "user_approved": user_approved},
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
    return await _invoke_backend_tool(
        ctx=ctx,
        tool_name="inbox.list",
        service="inbox",
        method="GET",
        path="/list",
        tenant_id=tenant_id,
        actor=actor,
        actor_role=actor_role,
        payload_data={"folder": folder, "limit": limit},
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
    return await _invoke_backend_tool(
        ctx=ctx,
        tool_name="inbox.send_message",
        service="inbox",
        method="POST",
        path="/send",
        tenant_id=tenant_id,
        actor=actor,
        actor_role=actor_role,
        payload_data={"to": to, "subject": subject, "body": body, "cc": cc or [], "bcc": bcc or [], "user_approved": user_approved},
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
    return await _invoke_backend_tool(
        ctx=ctx,
        tool_name="file.search_local",
        service="files",
        method="POST",
        path="/search",
        tenant_id=tenant_id,
        actor=actor,
        actor_role=actor_role,
        payload_data={"query": query, "max_results": max_results},
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
    return await _invoke_backend_tool(
        ctx=ctx,
        tool_name="file.preview",
        service="files",
        method="GET",
        path="/preview",
        tenant_id=tenant_id,
        actor=actor,
        actor_role=actor_role,
        payload_data={"file_id": file_id},
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
    return await _invoke_backend_tool(
        ctx=ctx,
        tool_name="file.metadata",
        service="files",
        method="GET",
        path="/metadata",
        tenant_id=tenant_id,
        actor=actor,
        actor_role=actor_role,
        payload_data={"file_id": file_id},
        timeout=10.0,
    )


@mcp.tool(
    name="support.supervisor",
    description="Run the support workflow agent to handle a support request.",
)
async def support_workflow(
    tenant_id: str,
    message: str,
    actor: str = "orchestrator",
    actor_role: str = "Orchestrator",
    ctx: TypedContext | None = None,
) -> Dict[str, Any]:
    return await _invoke_backend_tool(
        ctx=ctx,
        tool_name="support.supervisor",
        service="support",
        method="POST",
        path="/workflow",
        tenant_id=tenant_id,
        actor=actor,
        actor_role=actor_role,
        payload_data={"message": message},
        timeout=30.0,
    )


@mcp.tool(
    name="marketing.supervisor",
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
    payload_data: Dict[str, Any] = {"message": message}
    if thread_id:
        payload_data["thread_id"] = thread_id
    return await _invoke_backend_tool(
        ctx=ctx,
        tool_name="marketing.supervisor",
        service="marketing",
        method="POST",
        path="/workflow",
        tenant_id=tenant_id,
        actor=actor,
        actor_role=actor_role,
        payload_data=payload_data,
        timeout=30.0,
    )


@mcp.tool(
    name="website.supervisor",
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
    payload_data: Dict[str, Any] = {"message": message}
    if thread_id:
        payload_data["thread_id"] = thread_id
    return await _invoke_backend_tool(
        ctx=ctx,
        tool_name="website.supervisor",
        service="website",
        method="POST",
        path="/workflow",
        tenant_id=tenant_id,
        actor=actor,
        actor_role=actor_role,
        payload_data=payload_data,
        timeout=30.0,
    )


@mcp.tool(
    name="backoffice.supervisor",
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
    payload_data: Dict[str, Any] = {"message": message}
    if thread_id:
        payload_data["thread_id"] = thread_id
    return await _invoke_backend_tool(
        ctx=ctx,
        tool_name="backoffice.supervisor",
        service="backoffice",
        method="POST",
        path="/workflow",
        tenant_id=tenant_id,
        actor=actor,
        actor_role=actor_role,
        payload_data=payload_data,
        timeout=30.0,
    )



@mcp.tool(
    name="observability.metrics",
    description="Return in-memory counters and average latency per MCP tool.",
)
async def observability_metrics(
    tenant_id: str,
    actor: str = "orchestrator",
    actor_role: str = "Orchestrator",
    ctx: TypedContext | None = None,
) -> Dict[str, Any]:
    ctx = _require_context(ctx)
    app = ctx.request_context.lifespan_context
    app.rate_limiter.check(tenant_id, "observability.metrics", actor)
    app.permissions.ensure_allowed("observability.metrics", actor_role)
    snapshot = app.metrics.snapshot()
    return {
        "tenant_id": tenant_id,
        "metrics": snapshot,
    }


@mcp.tool(
    name="observability.health",
    description="Return basic configuration and status information about the MCP server.",
)
async def observability_health(
    tenant_id: str,
    include_config: bool = True,
    actor: str = "orchestrator",
    actor_role: str = "Orchestrator",
    ctx: TypedContext | None = None,
) -> Dict[str, Any]:
    ctx = _require_context(ctx)
    app = ctx.request_context.lifespan_context
    app.rate_limiter.check(tenant_id, "observability.health", actor)
    app.permissions.ensure_allowed("observability.health", actor_role)
    server_cfg = app.config.get("server", {})
    tenants_cfg = app.config.get("tenants", {})
    now = datetime.now(timezone.utc).isoformat()
    data: Dict[str, Any] = {
        "tenant_id": tenant_id,
        "time": now,
        "server": {
            "host": server_cfg.get("host"),
            "port": server_cfg.get("port"),
            "name": server_cfg.get("name", "simple-gpt-mcp"),
            "log_level": server_cfg.get("log_level", "INFO"),
        },
        "tenants": sorted(list(tenants_cfg.keys())),
    }
    if include_config:
        data["server_config"] = server_cfg
    return data

@mcp.tool(
    name="observability.discovery",
    description="List all available MCP tools and their parameters.",
)
async def observability_discovery(
    tenant_id: str,
    actor: str = "orchestrator",
    actor_role: str = "Orchestrator",
    ctx: TypedContext | None = None,
) -> Dict[str, Any]:
    ctx = _require_context(ctx)
    app = ctx.request_context.lifespan_context
    app.rate_limiter.check(tenant_id, "observability.discovery", actor)
    app.permissions.ensure_allowed("observability.discovery", actor_role)

    # Get tools via MCP server session
    session = ctx.request_context.session
    tools_list = []
    
    try:
        # Use the session to list tools - this is the proper MCP way
        tools_result = await session.list_tools()
        for tool in tools_result.tools:
            tool_data: Dict[str, Any] = {
                "name": tool.name,
                "description": tool.description or "",
            }
            # Extract input schema if available
            if hasattr(tool, "inputSchema") and tool.inputSchema:
                tool_data["inputSchema"] = tool.inputSchema.model_dump() if hasattr(tool.inputSchema, "model_dump") else tool.inputSchema
            elif hasattr(tool, "parameters") and tool.parameters:
                tool_data["parameters"] = tool.parameters
            tools_list.append(tool_data)
    except Exception:
        # Fallback: try to access tools from mcp object
        tools_dict: Dict[str, Any] = {}
        if hasattr(mcp, "_router") and hasattr(mcp._router, "_tools"):
            tools_dict = mcp._router._tools
        elif hasattr(mcp, "_tools"):
            tools_dict = mcp._tools
        elif hasattr(mcp, "tools"):
            tools_dict = mcp.tools
        
        for tool_name, tool_info in tools_dict.items():
            tool_data: Dict[str, Any] = {
                "name": tool_name,
                "description": getattr(tool_info, "description", "") or "",
            }
            if hasattr(tool_info, "parameters") and tool_info.parameters:
                tool_data["parameters"] = tool_info.parameters
            tools_list.append(tool_data)

    tools_list = sorted(tools_list, key=lambda x: x["name"])

    return {
        "tenant_id": tenant_id,
        "tool_count": len(tools_list),
        "tools": tools_list,
        "transport": "streamable-http",
        "endpoint": "/mcp",
    }


@mcp.tool(
    name="memory.supervisor",
    description="Run the memory workflow agent to handle memory-related requests.",
)
async def memory_supervisor(
    tenant_id: str,
    message: str,
    actor: str = "orchestrator",
    actor_role: str = "Orchestrator",
    ctx: TypedContext | None = None,
) -> Dict[str, Any]:
    return await _invoke_backend_tool(
        ctx=ctx,
        tool_name="memory.supervisor",
        service="memory",
        method="POST",
        path="/workflow",
        tenant_id=tenant_id,
        actor=actor,
        actor_role=actor_role,
        payload_data={"message": message},
        timeout=30.0,
    )


@mcp.tool(
    name="crm.supervisor",
    description="Run the CRM workflow agent to handle CRM-related requests.",
)
async def crm_supervisor(
    tenant_id: str,
    message: str,
    actor: str = "orchestrator",
    actor_role: str = "Orchestrator",
    ctx: TypedContext | None = None,
) -> Dict[str, Any]:
    return await _invoke_backend_tool(
        ctx=ctx,
        tool_name="crm.supervisor",
        service="crm",
        method="POST",
        path="/workflow",
        tenant_id=tenant_id,
        actor=actor,
        actor_role=actor_role,
        payload_data={"message": message},
        timeout=30.0,
    )


@mcp.tool(
    name="automation.supervisor",
    description="Run the automation workflow agent to orchestrate automation flows.",
)
async def automation_supervisor(
    tenant_id: str,
    message: str,
    actor: str = "orchestrator",
    actor_role: str = "Orchestrator",
    ctx: TypedContext | None = None,
) -> Dict[str, Any]:
    return await _invoke_backend_tool(
        ctx=ctx,
        tool_name="automation.supervisor",
        service="automation",
        method="POST",
        path="/workflow",
        tenant_id=tenant_id,
        actor=actor,
        actor_role=actor_role,
        payload_data={"message": message},
        timeout=30.0,
    )


@mcp.tool(
    name="inbox.supervisor",
    description="Run the inbox workflow agent to coordinate multi-channel inbox operations.",
)
async def inbox_supervisor(
    tenant_id: str,
    message: str,
    actor: str = "orchestrator",
    actor_role: str = "Orchestrator",
    ctx: TypedContext | None = None,
) -> Dict[str, Any]:
    return await _invoke_backend_tool(
        ctx=ctx,
        tool_name="inbox.supervisor",
        service="inbox",
        method="POST",
        path="/workflow",
        tenant_id=tenant_id,
        actor=actor,
        actor_role=actor_role,
        payload_data={"message": message},
        timeout=30.0,
    )


@mcp.tool(
    name="file.supervisor",
    description="Run the file workflow agent to coordinate file search and preview operations.",
)
async def file_supervisor(
    tenant_id: str,
    message: str,
    actor: str = "orchestrator",
    actor_role: str = "Orchestrator",
    ctx: TypedContext | None = None,
) -> Dict[str, Any]:
    return await _invoke_backend_tool(
        ctx=ctx,
        tool_name="file.supervisor",
        service="files",
        method="POST",
        path="/workflow",
        tenant_id=tenant_id,
        actor=actor,
        actor_role=actor_role,
        payload_data={"message": message},
        timeout=30.0,
    )


@mcp.tool(
    name="communications.supervisor",
    description="Run the communications workflow agent to route and coordinate messages across channels.",
)
async def communications_supervisor(
    tenant_id: str,
    message: str,
    preferred_channel: Optional[str] = None,
    actor: str = "orchestrator",
    actor_role: str = "Orchestrator",
    ctx: TypedContext | None = None,
) -> Dict[str, Any]:
    payload_data: Dict[str, Any] = {"message": message}
    if preferred_channel:
        payload_data["preferred_channel"] = preferred_channel
    return await _invoke_backend_tool(
        ctx=ctx,
        tool_name="communications.supervisor",
        service="communications",
        method="POST",
        path="/workflow",
        tenant_id=tenant_id,
        actor=actor,
        actor_role=actor_role,
        payload_data=payload_data,
        timeout=30.0,
    )

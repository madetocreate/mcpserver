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
from .cost_policy import has_cost_approval, is_high_cost_tool
from .observability import AuditLogger, InMemoryMetrics
from .rate_limits import AdvancedRateLimiter, RateLimitError
from .trace_context import (
    create_context,
    get_propagation_headers,
    get_current_context,
    set_current_context,
    TRACEPARENT_HEADER,
    CORRELATION_ID_HEADER,
)


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


class CircuitBreakerError(MCPServerError):
    """Circuit breaker is open - service temporarily unavailable."""
    def __init__(self, service: str, reset_after: float):
        self.service = service
        self.reset_after = reset_after
        super().__init__(f"Circuit breaker open for {service}, retry after {reset_after:.1f}s")


class CircuitBreaker:
    """
    Circuit Breaker pattern implementation for backend service calls.
    
    States:
    - CLOSED: Normal operation, requests pass through
    - OPEN: Service is failing, requests are rejected immediately
    - HALF_OPEN: Testing if service has recovered
    
    Best Practice 2025: Prevents cascading failures and allows services to recover.
    """
    
    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: float = 30.0,
        half_open_max_calls: int = 3,
    ):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.half_open_max_calls = half_open_max_calls
        
        # State per service
        self._failures: Dict[str, int] = {}
        self._last_failure_time: Dict[str, float] = {}
        self._state: Dict[str, str] = {}  # "closed", "open", "half_open"
        self._half_open_calls: Dict[str, int] = {}
    
    def _get_state(self, service: str) -> str:
        """Get current circuit state for a service."""
        state = self._state.get(service, "closed")
        
        if state == "open":
            # Check if recovery timeout has passed
            last_failure = self._last_failure_time.get(service, 0)
            if time.time() - last_failure >= self.recovery_timeout:
                self._state[service] = "half_open"
                self._half_open_calls[service] = 0
                return "half_open"
        
        return state
    
    def can_execute(self, service: str) -> bool:
        """Check if a request can be executed for this service."""
        state = self._get_state(service)
        
        if state == "closed":
            return True
        elif state == "half_open":
            # Allow limited calls in half-open state
            calls = self._half_open_calls.get(service, 0)
            return calls < self.half_open_max_calls
        else:  # open
            return False
    
    def get_reset_time(self, service: str) -> float:
        """Get seconds until circuit might reset."""
        last_failure = self._last_failure_time.get(service, 0)
        elapsed = time.time() - last_failure
        return max(0, self.recovery_timeout - elapsed)
    
    def record_success(self, service: str) -> None:
        """Record a successful call."""
        state = self._get_state(service)
        
        if state == "half_open":
            # Success in half-open: close the circuit
            self._state[service] = "closed"
            self._failures[service] = 0
            self._half_open_calls[service] = 0
        elif state == "closed":
            # Reset failure count on success
            self._failures[service] = 0
    
    def record_failure(self, service: str) -> None:
        """Record a failed call."""
        state = self._get_state(service)
        
        if state == "half_open":
            # Failure in half-open: open the circuit again
            self._state[service] = "open"
            self._last_failure_time[service] = time.time()
            self._half_open_calls[service] = 0
        else:
            # Increment failure count
            failures = self._failures.get(service, 0) + 1
            self._failures[service] = failures
            self._last_failure_time[service] = time.time()
            
            # Open circuit if threshold reached
            if failures >= self.failure_threshold:
                self._state[service] = "open"
    
    def before_call(self, service: str) -> None:
        """Called before making a request. Raises if circuit is open."""
        if not self.can_execute(service):
            reset_time = self.get_reset_time(service)
            raise CircuitBreakerError(service, reset_time)
        
        state = self._get_state(service)
        if state == "half_open":
            self._half_open_calls[service] = self._half_open_calls.get(service, 0) + 1
    
    def get_status(self) -> Dict[str, Any]:
        """Get status of all circuits for observability."""
        status = {}
        for service in set(self._state.keys()) | set(self._failures.keys()):
            status[service] = {
                "state": self._get_state(service),
                "failures": self._failures.get(service, 0),
                "reset_in": self.get_reset_time(service) if self._get_state(service) == "open" else 0,
            }
        return status




class PermissionChecker:
    def __init__(self, config: Dict[str, Any]) -> None:
        security_cfg = config.get("security", {})
        self.tools = security_cfg.get("tools", {})
        self.default_allowed_roles = security_cfg.get("default_allowed_roles", [])

    def ensure_allowed(self, tool_name: str, actor_role: str) -> Dict[str, Any]:
        """
        Check if actor_role is allowed to call tool_name.
        
        Rules:
        1. If tool has explicit allowed_roles, actor_role must be in that list
        2. If tool has no allowed_roles, check default_allowed_roles
        3. If default_allowed_roles is set and actor_role is not in it, deny access
        """
        tool_cfg = self.tools.get(tool_name) or {}
        allowed = tool_cfg.get("allowed_roles")
        
        # Rule 1: Tool has explicit allowed_roles
        if allowed:
            if actor_role not in allowed:
                raise PermissionError(
                    f"Role '{actor_role}' is not allowed to call {tool_name}. "
                    f"Allowed roles: {allowed}"
                )
        # Rule 2 & 3: No explicit allowed_roles, check default
        elif self.default_allowed_roles:
            if actor_role not in self.default_allowed_roles:
                raise PermissionError(
                    f"Role '{actor_role}' is not allowed to call {tool_name}. "
                    f"Default allowed roles: {self.default_allowed_roles}"
                )
        
        return tool_cfg


class BackendClient:
    def __init__(
        self,
        http_client: httpx.AsyncClient,
        config: Dict[str, Any],
        circuit_breaker: Optional[CircuitBreaker] = None,
    ) -> None:
        self.http_client = http_client
        self.config = config
        # Security: Internal API key for backend requests
        # P0 Fix: Support both BACKEND_INTERNAL_API_KEY and INTERNAL_API_KEY (fallback)
        self.internal_api_key = (
            os.getenv("BACKEND_INTERNAL_API_KEY") or os.getenv("INTERNAL_API_KEY") or ""
        ).strip()
        # Circuit breaker for resilience
        self.circuit_breaker = circuit_breaker or CircuitBreaker()

    def _base_url(self, tenant_id: str, service: str) -> str:
        tenants = self.config.get("tenants", {})
        tenant = tenants.get(tenant_id) or tenants.get("default")
        if tenant is None:
            raise BackendError(f"Unknown tenant '{tenant_id}'")
        services = tenant.get("services", {})
        svc_cfg = services.get(service)
        if svc_cfg is None:
            raise BackendError(f'Service "{service}" not configured for tenant "{tenant_id}"')
        if isinstance(svc_cfg, dict):
            base = svc_cfg.get("base_url") or svc_cfg.get("url")
        else:
            base = svc_cfg
        if base is None:
            raise BackendError(f'Service "{service}" missing base_url for tenant "{tenant_id}"')
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
        # Circuit breaker check
        circuit_key = f"{tenant_id}:{service}"
        self.circuit_breaker.before_call(circuit_key)
        
        base = self._base_url(tenant_id, service)
        url = f"{base}/{path.lstrip('/')}"
        
        # Security: Set internal API key header if configured
        headers: Dict[str, str] = {}
        if self.internal_api_key:
            headers["x-internal-api-key"] = self.internal_api_key
        
        # W3C Trace Context: Propagate trace headers to downstream services
        trace_headers = get_propagation_headers()
        headers.update(trace_headers)
        
        last_exc: Optional[Exception] = None
        for attempt in range(retries + 1):
            try:
                response = await self.http_client.request(
                    method=method.upper(),
                    url=url,
                    json=payload,
                    headers=headers,
                    timeout=timeout,
                )
                status = response.status_code
                if status == 429:
                    raise BackendError("Upstream rate limit")
                if status >= 500:
                    raise BackendError(f"Upstream {service} error {status}")
                response.raise_for_status()
                data = response.json()
                
                # Success: record in circuit breaker
                self.circuit_breaker.record_success(circuit_key)
                
                if isinstance(data, dict):
                    return data
                return {"result": data}
            except CircuitBreakerError:
                # Re-raise circuit breaker errors without recording as failure
                raise
            except Exception as exc:
                last_exc = exc
                if attempt >= retries:
                    break
                backoff = 0.3 * (2**attempt)
                await asyncio.sleep(backoff)
        
        # All retries failed: record failure in circuit breaker
        self.circuit_breaker.record_failure(circuit_key)
        
        message = str(last_exc) if last_exc else "Unknown backend error"
        raise BackendError(message)
    
    def get_circuit_status(self) -> Dict[str, Any]:
        """Get circuit breaker status for observability."""
        return self.circuit_breaker.get_status()


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
    circuit_breaker: CircuitBreaker


TypedContext = Context[ServerSession, AppContext]


@asynccontextmanager
async def lifespan(server: FastMCP) -> AsyncIterator[AppContext]:
    logger = setup_logger(CONFIG)
    
    
    # Configure HTTP client with connection pooling and timeouts
    server_cfg = CONFIG.get("server", {})
    http_limits = server_cfg.get("http_limits", {})
    # Security: follow_redirects=False für interne Service Calls
    # Redirects sind für interne Backend-Calls meist unnötig und können SSRF-Risiken erhöhen
    # Wenn Redirects nötig sind: nur same-origin und explizit erlauben
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
        follow_redirects=False,  # Security: Keine automatischen Redirects für interne Calls
    )
    
    # Circuit breaker configuration from config or defaults
    circuit_cfg = CONFIG.get("circuit_breaker", {})
    circuit_breaker = CircuitBreaker(
        failure_threshold=int(circuit_cfg.get("failure_threshold", 5)),
        recovery_timeout=float(circuit_cfg.get("recovery_timeout", 30.0)),
        half_open_max_calls=int(circuit_cfg.get("half_open_max_calls", 3)),
    )
    
    backend = BackendClient(http_client=http_client, config=CONFIG, circuit_breaker=circuit_breaker)
    # P0 Fix: Warn if internal API key is missing (MCP->Backend calls may fail)
    if not backend.internal_api_key:
        logger.warning(
            "Internal API key missing (BACKEND_INTERNAL_API_KEY or INTERNAL_API_KEY not set). "
            "MCP->Backend calls may fail with 401/403."
        )
    rate_limiter = AdvancedRateLimiter(CONFIG.get("rate_limits", {}))
    logs_dir = Path(__file__).resolve().parent.parent / "logs"
    logs_dir.mkdir(parents=True, exist_ok=True)
    audit_path = logs_dir / "audit.log"
    audit = AuditLogger(path=str(audit_path))
    metrics = InMemoryMetrics()
    
    # P0 Fix: Share metrics instance with FastAPI app for /metrics endpoint
    try:
        from .http_app import set_shared_metrics
        set_shared_metrics(metrics)
    except Exception as e:
        logger.warning(f"Failed to set shared metrics: {e}")
    
    app_ctx = AppContext(
        config=CONFIG,
        backend=backend,
        rate_limiter=rate_limiter,
        permissions=PermissionChecker(CONFIG),
        logger=logger,
        audit=audit,
        metrics=metrics,
        circuit_breaker=circuit_breaker,
    )
    try:
        yield app_ctx
    finally:
        await http_client.aclose()


server_cfg = CONFIG.get("server", {})

# Security: Default bind auf 127.0.0.1 (nicht 0.0.0.0) - nur localhost, nicht alle Interfaces
# Für Production hinter Reverse-Proxy: MCP_SERVER_HOST=0.0.0.0 explizit setzen
_server_host = os.getenv("MCP_SERVER_HOST", server_cfg.get("host", "127.0.0.1"))
_server_port = int(os.getenv("MCP_SERVER_PORT", server_cfg.get("port", 9000)))

# Security: In Production muss MCP_SERVER_TOKEN gesetzt sein
from .env_utils import is_production_env

mcp_token = os.getenv("MCP_SERVER_TOKEN", "").strip()
if is_production_env() and not mcp_token:
    raise RuntimeError(
        "MCP_SERVER_TOKEN is required in production. "
        "Set MCP_SERVER_TOKEN environment variable before starting the MCP server."
    )

# FastMCP Server - keep it simple for maximum compatibility
# Removed stateless_http and json_response initially to match minimal server approach
# These can be re-added later if needed, but start with defaults
mcp = FastMCP(
    server_cfg.get("name", "simple-gpt-mcp"),
    lifespan=lifespan,
    host=_server_host,
    port=_server_port,
)


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
    """
    Build base payload with common fields and optional extras.
    
    Security: actor/actor_role werden NACH extra gesetzt, damit extra diese Werte nicht überschreiben kann.
    """
    # Security: Entferne actor/actor_role aus extra falls vorhanden (Client-Input ignorieren)
    extra_clean = {k: v for k, v in extra.items() if k not in ("actor", "actor_role")}
    
    # Security: actor/actor_role werden immer zuletzt gesetzt, damit extra sie nicht überschreiben kann
    payload: Dict[str, Any] = {
        "tenant_id": tenant_id,
        **extra_clean,
        "actor": actor,  # Gesetzt nach extra, kann nicht überschrieben werden
        "actor_role": actor_role,  # Gesetzt nach extra, kann nicht überschrieben werden
    }
    return payload


async def _invoke_backend_tool(
    ctx: TypedContext | None,
    tool_name: str,
    service: str,
    method: str,
    path: str,
    tenant_id: str,
    payload_data: Dict[str, Any],
    timeout: float = 10.0,
) -> Dict[str, Any]:
    """
    Helper function to invoke backend tool with standardized error handling.
    
    Security: actor/actor_role kommen aus Config, nicht aus Client-Input.
    Client-kontrollierte Werte werden ignoriert, um Privilege-Escalation zu verhindern.
    """
    ctx = _require_context(ctx)
    
    # Security: actor/actor_role immer aus Config, nie aus Client-Input
    server_cfg = CONFIG.get("server", {})
    security_cfg = CONFIG.get("security", {})
    safe_actor = server_cfg.get("default_actor") or security_cfg.get("default_actor") or "mcp-server"
    safe_actor_role = server_cfg.get("default_actor_role") or security_cfg.get("default_actor_role") or "Agent"
    
    # Entferne actor/actor_role aus payload_data falls vorhanden (Client-Input ignorieren)
    payload_data_clean = {k: v for k, v in payload_data.items() if k not in ("actor", "actor_role")}
    
    payload = _build_base_payload(tenant_id, safe_actor, safe_actor_role, **payload_data_clean)
    return await _call_backend_tool(
        ctx=ctx,
        tool_name=tool_name,
        service=service,
        method=method,
        path=path,
        tenant_id=tenant_id,
        actor=safe_actor,
        actor_role=safe_actor_role,
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
    
    # Get correlation ID from headers, payload, or generate new
    # Priority: headers > payload > generate
    correlation_id = None
    try:
        # Try to get from request headers (if available in context)
        # Note: FastMCP context may not expose headers directly, so we check payload first
        correlation_id = payload.get("correlation_id")
    except Exception:
        pass
    
    # If not in payload, try to get from trace context
    if not correlation_id:
        try:
            from .trace_context import get_current_context
            trace_ctx = get_current_context()
            if trace_ctx:
                correlation_id = trace_ctx.get("correlation_id")
        except Exception:
            pass
    
    # Generate if still not present
    if not correlation_id:
        correlation_id = _generate_correlation_id()
    
    # Ensure correlation_id is in payload for backend propagation
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
        
        # Security: Remove user_approved from payload (LLM cannot control approval)
        # Approval must come from trusted context (Header or server-config), not from tool args
        payload.pop("user_approved", None)
        
        # User approval check (for destructive actions)
        # Security: Approval must come from trusted context (HTTP Header Token), NOT from payload/tool args
        requires_approval = bool(tool_cfg.get("user_approval_required")) if tool_cfg else False
        if requires_approval:
            # Defense-in-Depth: Verify approval token from HTTP headers
            # Token is set by RequestContextMiddleware in http_app.py
            approval_token = None
            approval_tenant_id = None
            approval_user_id = None
            
            # Try to get approval token from request context (set by middleware)
            try:
                # Access request state from FastAPI middleware
                # ctx.request_context may contain the FastAPI request object
                request = getattr(ctx.request_context, "request", None)
                if request and hasattr(request, "state"):
                    approval_token = getattr(request.state, "approval_token", None)
                    approval_tenant_id = getattr(request.state, "tenant_id", None)
                    approval_user_id = getattr(request.state, "user_id", None)
            except Exception as e:
                logger.debug(f"Could not access request state for approval token: {e}")
            
            # Fallback: Check for internal call marker (for server-to-server calls)
            internal_call = payload.get("_internal_call", False)
            
            if approval_token:
                # Verify approval token
                from .approval import verify_approval_token
                
                ok, reason, claims = verify_approval_token(
                    token=approval_token,
                    expected_tool=tool_name,
                    tenant_id=approval_tenant_id or tenant_id,
                    user_id=approval_user_id or actor,
                )
                
                if not ok:
                    error_code = reason.upper()
                    raise PermissionError(
                        f"Tool {tool_name} requires user approval. "
                        f"Approval token verification failed: {reason}"
                    )
                
                # Token verified: mark approval granted in trace context
                try:
                    from .trace_context import get_current_context
                    trace_ctx = get_current_context()
                    if trace_ctx:
                        trace_ctx["approval_granted"] = True
                        trace_ctx["approval_id"] = claims.approval_id if claims else None
                except Exception:
                    pass
                
                logger.info(
                    f"[Approval] Token verified for tool {tool_name}: "
                    f"approval_id={claims.approval_id if claims else 'unknown'}"
                )
            elif internal_call:
                # Internal call: allow (for server-to-server calls)
                logger.debug(f"[Approval] Internal call allowed for tool {tool_name}")
            else:
                # No approval token and not internal call: deny
                error_code = "APPROVAL_REQUIRED"
                raise PermissionError(
                    f"Tool {tool_name} requires user approval. "
                    "Approval must come from trusted HTTP header (X-Aklow-Approval-Token), "
                    "not from tool arguments."
                )
        
        # High-cost gate (for expensive operations like image/video/audio generation)
        if is_high_cost_tool(tool_name, tool_cfg):
            if not has_cost_approval(payload):
                error_code = "COST_APPROVAL_REQUIRED"
                raise PermissionError(
                    f"Tool '{tool_name}' is high-cost and requires explicit approval "
                    f"(cost_approved=true or user_approved=true)."
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
    name="memory_search",
    description="Search tenant-specific long-term memory for relevant items.",
)
async def memory_search(
    tenant_id: str,
    query: str,
    limit: int = 20,
    include_archived: bool = False,
    ctx: TypedContext | None = None,
) -> Dict[str, Any]:
    return await _invoke_backend_tool(
        ctx=ctx,
        tool_name="memory_search",
        service="memory",
        method="POST",
        path="/search",
        tenant_id=tenant_id,
        payload_data={"query": query, "limit": limit, "include_archived": include_archived},
        timeout=10.0,
    )


@mcp.tool(
    name="memory_write",
    description="Persist a new memory item for the tenant.",
)
async def memory_write(
    tenant_id: str,
    content: str,
    kind: str = "note",
    type: Optional[str] = None,
    tags: Optional[List[str]] = None,
    correlation_id: Optional[str] = None,
    user_approved: bool = False,
    ctx: TypedContext | None = None,
) -> Dict[str, Any]:
    """
    Persist a new memory item for the tenant.
    
    Parameters:
    - kind: MemoryKind (fact|preference|instruction|summary|note) - Memory-Klasse
    - type: MemoryItemType (conversation_message|email|document|...) - Item-Typ/Herkunft, optional, default: "custom"
    
    Security: actor/actor_role entfernt - kommen aus Config, nicht aus Client-Input.
    Note: user_approved parameter added for approval flow compatibility.
    """
    payload_data: Dict[str, Any] = {
        "content": content,
        "kind": kind,
        "tags": tags or [],
        "user_approved": user_approved,
    }
    if type:
        payload_data["type"] = type
    if correlation_id:
        payload_data["correlation_id"] = correlation_id
    return await _invoke_backend_tool(
        ctx=ctx,
        tool_name="memory_write",
        service="memory",
        method="POST",
        path="/write",
        tenant_id=tenant_id,
        payload_data=payload_data,
        timeout=10.0,
    )


@mcp.tool(
    name="memory_delete",
    description="Delete or soft-delete a memory item.",
)
async def memory_delete(
    tenant_id: str,
    memory_id: str,
    soft_delete: bool = True,
    user_approved: bool = False,
    ctx: TypedContext | None = None,
) -> Dict[str, Any]:
    """
    Security: actor/actor_role entfernt - kommen aus Config, nicht aus Client-Input.
    """
    return await _invoke_backend_tool(
        ctx=ctx,
        tool_name="memory_delete",
        service="memory",
        method="POST",
        path="/delete",
        tenant_id=tenant_id,
        payload_data={"memory_id": memory_id, "soft_delete": soft_delete, "user_approved": user_approved},
        timeout=10.0,
    )


@mcp.tool(
    name="memory_archive",
    description="Archive a memory item so it no longer appears in default search.",
)
async def memory_archive(
    tenant_id: str,
    memory_id: str,
    user_approved: bool = False,
    ctx: TypedContext | None = None,
) -> Dict[str, Any]:
    return await _invoke_backend_tool(
        ctx=ctx,
        tool_name="memory_archive",
        service="memory",
        method="POST",
        path="/archive",
        tenant_id=tenant_id,
        payload_data={"memory_id": memory_id, "user_approved": user_approved},
        timeout=10.0,
    )


@mcp.tool(
    name="memory_telemetry",
    description="Return aggregate telemetry on memory usage and tool calls.",
)
async def memory_telemetry(
    tenant_id: str,
    window_minutes: int = 60,
    ctx: TypedContext | None = None,
) -> Dict[str, Any]:
    return await _invoke_backend_tool(
        ctx=ctx,
        tool_name="memory_telemetry",
        service="memory",
        method="GET",
        path="/telemetry",
        tenant_id=tenant_id,
        payload_data={"window_minutes": window_minutes},
        timeout=5.0,
    )


@mcp.tool(
    name="crm_lookup_customer",
    description="Lookup a single customer record by identifier.",
)
async def crm_lookup_customer(
    tenant_id: str,
    customer_id: str,
    ctx: TypedContext | None = None,
) -> Dict[str, Any]:
    return await _invoke_backend_tool(
        ctx=ctx,
        tool_name="crm_lookup_customer",
        service="crm",
        method="POST",
        path="/lookup_customer",
        tenant_id=tenant_id,
        payload_data={"customer_id": customer_id},
        timeout=5.0,
    )


@mcp.tool(
    name="crm_search_customers",
    description="Search customers by free-text query or filters.",
)
async def crm_search_customers(
    tenant_id: str,
    query: str,
    limit: int = 20,
    ctx: TypedContext | None = None,
) -> Dict[str, Any]:
    return await _invoke_backend_tool(
        ctx=ctx,
        tool_name="crm_search_customers",
        service="crm",
        method="POST",
        path="/search_customers",
        tenant_id=tenant_id,
        payload_data={"query": query, "limit": limit},
        timeout=10.0,
    )


@mcp.tool(
    name="crm_create_note",
    description="Attach a note to a CRM customer record.",
)
async def crm_create_note(
    tenant_id: str,
    customer_id: str,
    text: str,
    user_approved: bool = False,
    ctx: TypedContext | None = None,
) -> Dict[str, Any]:
    return await _invoke_backend_tool(
        ctx=ctx,
        tool_name="crm_create_note",
        service="crm",
        method="POST",
        path="/create_note",
        tenant_id=tenant_id,
        payload_data={"customer_id": customer_id, "text": text, "user_approved": user_approved},
        timeout=10.0,
    )


@mcp.tool(
    name="crm_update_pipeline",
    description="Update the pipeline stage or value for an opportunity.",
)
async def crm_update_pipeline(
    tenant_id: str,
    opportunity_id: str,
    stage: str,
    value: Optional[float] = None,
    user_approved: bool = False,
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
        tool_name="crm_update_pipeline",
        service="crm",
        method="POST",
        path="/update_pipeline",
        tenant_id=tenant_id,
        payload_data=payload_data,
        timeout=10.0,
    )



@mcp.tool(
    name="crm_link_entities",
    description="Create an association between two CRM entities.",
)
async def crm_link_entities(
    tenant_id: str,
    from_type: str,
    from_id: str,
    to_type: str,
    to_id: str,
    association_type: str = "related",
    user_approved: bool = False,
    ctx: TypedContext | None = None,
) -> Dict[str, Any]:
    return await _invoke_backend_tool(
        ctx=ctx,
        tool_name="crm_link_entities",
        service="crm",
        method="POST",
        path="/link_entities",
        tenant_id=tenant_id,
        payload_data={
            "from_type": from_type,
            "from_id": from_id,
            "to_type": to_type,
            "to_id": to_id,
            "association_type": association_type,
            "user_approved": user_approved,
        },
        timeout=10.0,
    )


@mcp.tool(
    name="crm_list_associations",
    description="List associations for a CRM entity.",
)
async def crm_list_associations(
    tenant_id: str,
    entity_type: str,
    entity_id: str,
    limit: int = 100,
    ctx: TypedContext | None = None,
) -> Dict[str, Any]:
    return await _invoke_backend_tool(
        ctx=ctx,
        tool_name="crm_list_associations",
        service="crm",
        method="POST",
        path="/list_associations",
        tenant_id=tenant_id,
        payload_data={"entity_type": entity_type, "entity_id": entity_id, "limit": limit},
        timeout=10.0,
    )


@mcp.tool(
    name="crm_get_timeline",
    description="Fetch a CRM timeline (activities + linked memory) for an entity.",
)
async def crm_get_timeline(
    tenant_id: str,
    entity_type: str,
    entity_id: str,
    limit: int = 50,
    ctx: TypedContext | None = None,
) -> Dict[str, Any]:
    return await _invoke_backend_tool(
        ctx=ctx,
        tool_name="crm_get_timeline",
        service="crm",
        method="POST",
        path="/timeline",
        tenant_id=tenant_id,
        payload_data={"entity_type": entity_type, "entity_id": entity_id, "limit": limit},
        timeout=10.0,
    )


@mcp.tool(
    name="crm_define_pipeline",
    description="Create a pipeline and stages for an object type.",
)
async def crm_define_pipeline(
    tenant_id: str,
    object_type: str,
    name: str,
    stages: List[Dict[str, Any]],
    is_default: bool = False,
    user_approved: bool = False,
    ctx: TypedContext | None = None,
) -> Dict[str, Any]:
    return await _invoke_backend_tool(
        ctx=ctx,
        tool_name="crm_define_pipeline",
        service="crm",
        method="POST",
        path="/define_pipeline",
        tenant_id=tenant_id,
        payload_data={
            "object_type": object_type,
            "name": name,
            "stages": stages,
            "is_default": is_default,
            "user_approved": user_approved,
        },
        timeout=10.0,
    )


@mcp.tool(
    name="crm_list_pipelines",
    description="List pipelines (and stages) for an object type.",
)
async def crm_list_pipelines(
    tenant_id: str,
    object_type: Optional[str] = None,
    ctx: TypedContext | None = None,
) -> Dict[str, Any]:
    return await _invoke_backend_tool(
        ctx=ctx,
        tool_name="crm_list_pipelines",
        service="crm",
        method="POST",
        path="/list_pipelines",
        tenant_id=tenant_id,
        payload_data={"object_type": object_type},
        timeout=10.0,
    )



@mcp.tool(
    name="crm_upsert_contact",
    description="Create or update a CRM contact (idempotent by email).",
)
async def crm_upsert_contact(
    tenant_id: str,
    email: str,
    first_name: Optional[str] = None,
    last_name: Optional[str] = None,
    phone: Optional[str] = None,
    company_name: Optional[str] = None,
    user_approved: bool = False,
    ctx: TypedContext | None = None,
) -> Dict[str, Any]:
    return await _invoke_backend_tool(
        ctx=ctx,
        tool_name="crm_upsert_contact",
        service="crm",
        method="POST",
        path="/upsert_contact",
        tenant_id=tenant_id,
        payload_data={
            "email": email,
            "first_name": first_name,
            "last_name": last_name,
            "phone": phone,
            "company_name": company_name,
            "user_approved": user_approved,
        },
        timeout=10.0,
    )


@mcp.tool(
    name="crm_upsert_company",
    description="Create or update a CRM company (idempotent by domain or name).",
)
async def crm_upsert_company(
    tenant_id: str,
    name: str,
    domain: Optional[str] = None,
    industry: Optional[str] = None,
    company_size: Optional[str] = None,
    lifecycle_stage: Optional[str] = None,
    user_approved: bool = False,
    ctx: TypedContext | None = None,
) -> Dict[str, Any]:
    return await _invoke_backend_tool(
        ctx=ctx,
        tool_name="crm_upsert_company",
        service="crm",
        method="POST",
        path="/upsert_company",
        tenant_id=tenant_id,
        payload_data={
            "name": name,
            "domain": domain,
            "industry": industry,
            "company_size": company_size,
            "lifecycle_stage": lifecycle_stage,
            "user_approved": user_approved,
        },
        timeout=10.0,
    )


@mcp.tool(
    name="crm_create_deal",
    description="Create a CRM deal/opportunity.",
)
async def crm_create_deal(
    tenant_id: str,
    name: str,
    amount: Optional[float] = None,
    currency: str = "EUR",
    pipeline: Optional[str] = None,
    stage: Optional[str] = None,
    status: str = "open",
    company_id: Optional[str] = None,
    primary_contact_id: Optional[str] = None,
    expected_close_date: Optional[str] = None,
    user_approved: bool = False,
    ctx: TypedContext | None = None,
) -> Dict[str, Any]:
    return await _invoke_backend_tool(
        ctx=ctx,
        tool_name="crm_create_deal",
        service="crm",
        method="POST",
        path="/create_deal",
        tenant_id=tenant_id,
        payload_data={
            "name": name,
            "amount": amount,
            "currency": currency,
            "pipeline": pipeline,
            "stage": stage,
            "status": status,
            "company_id": company_id,
            "primary_contact_id": primary_contact_id,
            "expected_close_date": expected_close_date,
            "user_approved": user_approved,
        },
        timeout=10.0,
    )


@mcp.tool(
    name="crm_merge_contacts",
    description="Merge one contact into another.",
)
async def crm_merge_contacts(
    tenant_id: str,
    source_contact_id: str,
    target_contact_id: str,
    reason: Optional[str] = None,
    user_approved: bool = False,
    ctx: TypedContext | None = None,
) -> Dict[str, Any]:
    return await _invoke_backend_tool(
        ctx=ctx,
        tool_name="crm_merge_contacts",
        service="crm",
        method="POST",
        path="/merge_contacts",
        tenant_id=tenant_id,
        payload_data={
            "source_contact_id": source_contact_id,
            "target_contact_id": target_contact_id,
            "reason": reason,
            "user_approved": user_approved,
        },
        timeout=10.0,
    )



@mcp.tool(
    name="crm_audit_query",
    description="Query CRM audit log entries.",
)
async def crm_audit_query(
    tenant_id: str,
    entity_type: Optional[str] = None,
    entity_id: Optional[str] = None,
    action: Optional[str] = None,
    limit: int = 100,
    ctx: TypedContext | None = None,
) -> Dict[str, Any]:
    return await _invoke_backend_tool(
        ctx=ctx,
        tool_name="crm_audit_query",
        service="crm",
        method="POST",
        path="/audit_query",
        tenant_id=tenant_id,
        payload_data={"entity_type": entity_type, "entity_id": entity_id, "action": action, "limit": limit},
        timeout=10.0,
    )


@mcp.tool(
    name="crm_events_pull",
    description="Pull pending CRM events from the outbox.",
)
async def crm_events_pull(
    tenant_id: str,
    limit: int = 50,
    ctx: TypedContext | None = None,
) -> Dict[str, Any]:
    return await _invoke_backend_tool(
        ctx=ctx,
        tool_name="crm_events_pull",
        service="crm",
        method="POST",
        path="/events_pull",
        tenant_id=tenant_id,
        payload_data={"limit": limit},
        timeout=10.0,
    )


@mcp.tool(
    name="crm_events_ack",
    description="Acknowledge a CRM outbox event as processed.",
)
async def crm_events_ack(
    tenant_id: str,
    event_id: str,
    status: str = "processed",
    ctx: TypedContext | None = None,
) -> Dict[str, Any]:
    return await _invoke_backend_tool(
        ctx=ctx,
        tool_name="crm_events_ack",
        service="crm",
        method="POST",
        path="/events_ack",
        tenant_id=tenant_id,
        payload_data={"event_id": event_id, "status": status},
        timeout=10.0,
    )



@mcp.tool(
    name="crm_create_task",
    description="Create a CRM task on an entity.",
)
async def crm_create_task(
    tenant_id: str,
    entity_type: str,
    entity_id: str,
    subject: str,
    description: str = "",
    due_at: str | None = None,
    user_approved: bool = False,
    ctx: TypedContext | None = None,
) -> Dict[str, Any]:
    return await _invoke_backend_tool(
        ctx=ctx,
        tool_name="crm_create_task",
        service="crm",
        method="POST",
        path="/create_task",
        tenant_id=tenant_id,
        payload_data={
            "entity_type": entity_type,
            "entity_id": entity_id,
            "subject": subject,
            "description": description,
            "due_at": due_at,
            "user_approved": user_approved,
        },
        timeout=10.0,
    )


@mcp.tool(
    name="crm_complete_task",
    description="Complete a CRM task.",
)
async def crm_complete_task(
    tenant_id: str,
    task_id: str,
    user_approved: bool = False,
    ctx: TypedContext | None = None,
) -> Dict[str, Any]:
    return await _invoke_backend_tool(
        ctx=ctx,
        tool_name="crm_complete_task",
        service="crm",
        method="POST",
        path="/complete_task",
        tenant_id=tenant_id,
        payload_data={"task_id": task_id, "user_approved": user_approved},
        timeout=10.0,
    )


@mcp.tool(
    name="crm_log_call",
    description="Log a CRM call and link it into memory.",
)
async def crm_log_call(
    tenant_id: str,
    entity_type: str,
    entity_id: str,
    subject: str,
    summary: str,
    duration_seconds: int | None = None,
    occurred_at: str | None = None,
    user_approved: bool = False,
    ctx: TypedContext | None = None,
) -> Dict[str, Any]:
    return await _invoke_backend_tool(
        ctx=ctx,
        tool_name="crm_log_call",
        service="crm",
        method="POST",
        path="/log_call",
        tenant_id=tenant_id,
        payload_data={
            "entity_type": entity_type,
            "entity_id": entity_id,
            "subject": subject,
            "summary": summary,
            "duration_seconds": duration_seconds,
            "occurred_at": occurred_at,
            "user_approved": user_approved,
        },
        timeout=10.0,
    )


@mcp.tool(
    name="crm_log_meeting",
    description="Log a CRM meeting and link it into memory.",
)
async def crm_log_meeting(
    tenant_id: str,
    entity_type: str,
    entity_id: str,
    subject: str,
    summary: str,
    start_at: str | None = None,
    end_at: str | None = None,
    user_approved: bool = False,
    ctx: TypedContext | None = None,
) -> Dict[str, Any]:
    return await _invoke_backend_tool(
        ctx=ctx,
        tool_name="crm_log_meeting",
        service="crm",
        method="POST",
        path="/log_meeting",
        tenant_id=tenant_id,
        payload_data={
            "entity_type": entity_type,
            "entity_id": entity_id,
            "subject": subject,
            "summary": summary,
            "start_at": start_at,
            "end_at": end_at,
            "user_approved": user_approved,
        },
        timeout=10.0,
    )



@mcp.tool(
    name="crm_define_property",
    description="Define a custom CRM property for an object type.",
)
async def crm_define_property(
    tenant_id: str,
    object_type: str,
    name: str,
    label: str | None = None,
    data_type: str = "string",
    field_type: str | None = None,
    options: list[dict[str, Any]] | None = None,
    required: bool = False,
    unique_property: bool = False,
    archived: bool = False,
    description: str | None = None,
    user_approved: bool = False,
    ctx: TypedContext | None = None,
) -> Dict[str, Any]:
    return await _invoke_backend_tool(
        ctx=ctx,
        tool_name="crm_define_property",
        service="crm",
        method="POST",
        path="/define_property",
        tenant_id=tenant_id,
        payload_data={
            "object_type": object_type,
            "name": name,
            "label": label,
            "data_type": data_type,
            "field_type": field_type,
            "options": options,
            "required": required,
            "unique_property": unique_property,
            "archived": archived,
            "description": description,
            "user_approved": user_approved,
        },
        timeout=10.0,
    )


@mcp.tool(
    name="crm_list_properties",
    description="List property definitions for an object type.",
)
async def crm_list_properties(
    tenant_id: str,
    object_type: str,
    ctx: TypedContext | None = None,
) -> Dict[str, Any]:
    return await _invoke_backend_tool(
        ctx=ctx,
        tool_name="crm_list_properties",
        service="crm",
        method="POST",
        path="/list_properties",
        tenant_id=tenant_id,
        payload_data={"object_type": object_type},
        timeout=10.0,
    )


@mcp.tool(
    name="crm_set_property",
    description="Set a property value on a CRM record.",
)
async def crm_set_property(
    tenant_id: str,
    object_type: str,
    record_id: str,
    property_name: str,
    value: Any = None,
    user_approved: bool = False,
    ctx: TypedContext | None = None,
) -> Dict[str, Any]:
    return await _invoke_backend_tool(
        ctx=ctx,
        tool_name="crm_set_property",
        service="crm",
        method="POST",
        path="/set_property",
        tenant_id=tenant_id,
        payload_data={
            "object_type": object_type,
            "record_id": record_id,
            "property_name": property_name,
            "value": value,
            "user_approved": user_approved,
        },
        timeout=10.0,
    )


@mcp.tool(
    name="crm_get_property",
    description="Get a property value from a CRM record.",
)
async def crm_get_property(
    tenant_id: str,
    object_type: str,
    record_id: str,
    property_name: str,
    ctx: TypedContext | None = None,
) -> Dict[str, Any]:
    return await _invoke_backend_tool(
        ctx=ctx,
        tool_name="crm_get_property",
        service="crm",
        method="POST",
        path="/get_property",
        tenant_id=tenant_id,
        payload_data={"object_type": object_type, "record_id": record_id, "property_name": property_name},
        timeout=10.0,
    )



@mcp.tool(
    name="crm_search_advanced",
    description="Advanced CRM search with filters, sort and pagination.",
)
async def crm_search_advanced(
    tenant_id: str,
    object_type: str,
    filters: List[Dict[str, Any]],
    limit: int = 20,
    offset: int = 0,
    sort_by: str = "updated_at",
    sort_dir: str = "DESC",
    ctx: TypedContext | None = None,
) -> Dict[str, Any]:
    return await _invoke_backend_tool(
        ctx=ctx,
        tool_name="crm_search_advanced",
        service="crm",
        method="POST",
        path="/search_advanced",
        tenant_id=tenant_id,
        payload_data={"object_type": object_type, "filters": filters, "limit": limit, "offset": offset, "sort_by": sort_by, "sort_dir": sort_dir},
        timeout=10.0,
    )


@mcp.tool(
    name="crm_create_segment",
    description="Create or update a CRM segment (list).",
)
async def crm_create_segment(
    tenant_id: str,
    object_type: str,
    name: str,
    definition: Dict[str, Any],
    is_dynamic: bool = True,
    user_approved: bool = False,
    ctx: TypedContext | None = None,
) -> Dict[str, Any]:
    return await _invoke_backend_tool(
        ctx=ctx,
        tool_name="crm_create_segment",
        service="crm",
        method="POST",
        path="/create_segment",
        tenant_id=tenant_id,
        payload_data={"object_type": object_type, "name": name, "definition": definition, "is_dynamic": is_dynamic, "user_approved": user_approved},
        timeout=10.0,
    )


@mcp.tool(
    name="crm_list_segments",
    description="List CRM segments (lists).",
)
async def crm_list_segments(
    tenant_id: str,
    object_type: Optional[str] = None,
    ctx: TypedContext | None = None,
) -> Dict[str, Any]:
    return await _invoke_backend_tool(
        ctx=ctx,
        tool_name="crm_list_segments",
        service="crm",
        method="POST",
        path="/list_segments",
        tenant_id=tenant_id,
        payload_data={"object_type": object_type},
        timeout=10.0,
    )


@mcp.tool(
    name="crm_segment_members",
    description="Get record IDs for a segment (dynamic compute or static membership).",
)
async def crm_segment_members(
    tenant_id: str,
    segment_id: str,
    limit: int = 50,
    offset: int = 0,
    ctx: TypedContext | None = None,
) -> Dict[str, Any]:
    return await _invoke_backend_tool(
        ctx=ctx,
        tool_name="crm_segment_members",
        service="crm",
        method="POST",
        path="/segment_members",
        tenant_id=tenant_id,
        payload_data={"segment_id": segment_id, "limit": limit, "offset": offset},
        timeout=10.0,
    )



@mcp.tool(
    name="crm_webhook_create",
    description="Create or update a CRM webhook subscription.",
)
async def crm_webhook_create(
    tenant_id: str,
    name: str,
    endpoint_url: str,
    secret: str | None = None,
    event_types: list[str] | None = None,
    user_approved: bool = False,
    ctx: TypedContext | None = None,
) -> Dict[str, Any]:
    return await _invoke_backend_tool(
        ctx=ctx,
        tool_name="crm_webhook_create",
        service="crm",
        method="POST",
        path="/webhook_create",
        tenant_id=tenant_id,
        payload_data={"name": name, "endpoint_url": endpoint_url, "secret": secret, "event_types": event_types, "user_approved": user_approved},
        timeout=10.0,
    )


@mcp.tool(
    name="crm_webhook_list",
    description="List CRM webhook subscriptions.",
)
async def crm_webhook_list(
    tenant_id: str,
    ctx: TypedContext | None = None,
) -> Dict[str, Any]:
    return await _invoke_backend_tool(
        ctx=ctx,
        tool_name="crm_webhook_list",
        service="crm",
        method="POST",
        path="/webhook_list",
        tenant_id=tenant_id,
        payload_data={},
        timeout=10.0,
    )


@mcp.tool(
    name="crm_webhook_disable",
    description="Disable a CRM webhook subscription.",
)
async def crm_webhook_disable(
    tenant_id: str,
    subscription_id: str,
    user_approved: bool = False,
    ctx: TypedContext | None = None,
) -> Dict[str, Any]:
    return await _invoke_backend_tool(
        ctx=ctx,
        tool_name="crm_webhook_disable",
        service="crm",
        method="POST",
        path="/webhook_disable",
        tenant_id=tenant_id,
        payload_data={"subscription_id": subscription_id, "user_approved": user_approved},
        timeout=10.0,
    )


@mcp.tool(
    name="crm_webhook_dispatch",
    description="Dispatch pending CRM outbox events to webhook subscriptions.",
)
async def crm_webhook_dispatch(
    tenant_id: str,
    limit: int = 50,
    ctx: TypedContext | None = None,
) -> Dict[str, Any]:
    return await _invoke_backend_tool(
        ctx=ctx,
        tool_name="crm_webhook_dispatch",
        service="crm",
        method="POST",
        path="/webhook_dispatch",
        tenant_id=tenant_id,
        payload_data={"limit": limit},
        timeout=30.0,
    )


@mcp.tool(
    name="crm_define_object_type",
    description="Define a custom CRM object type.",
)
async def crm_define_object_type(
    tenant_id: str,
    object_type: str,
    label: str,
    plural_label: str,
    description: str | None = None,
    archived: bool = False,
    user_approved: bool = False,
    ctx: TypedContext | None = None,
) -> Dict[str, Any]:
    return await _invoke_backend_tool(
        ctx=ctx,
        tool_name="crm_define_object_type",
        service="crm",
        method="POST",
        path="/define_object_type",
        tenant_id=tenant_id,
        payload_data={"object_type": object_type, "label": label, "plural_label": plural_label, "description": description, "archived": archived, "user_approved": user_approved},
        timeout=10.0,
    )


@mcp.tool(
    name="crm_create_object_record",
    description="Create a record for a custom object type.",
)
async def crm_create_object_record(
    tenant_id: str,
    object_type: str,
    properties: Dict[str, Any],
    user_approved: bool = False,
    ctx: TypedContext | None = None,
) -> Dict[str, Any]:
    return await _invoke_backend_tool(
        ctx=ctx,
        tool_name="crm_create_object_record",
        service="crm",
        method="POST",
        path="/create_object_record",
        tenant_id=tenant_id,
        payload_data={"object_type": object_type, "properties": properties, "user_approved": user_approved},
        timeout=10.0,
    )


@mcp.tool(
    name="crm_get_object_record",
    description="Get a record for a custom object type.",
)
async def crm_get_object_record(
    tenant_id: str,
    record_id: str,
    ctx: TypedContext | None = None,
) -> Dict[str, Any]:
    return await _invoke_backend_tool(
        ctx=ctx,
        tool_name="crm_get_object_record",
        service="crm",
        method="POST",
        path="/get_object_record",
        tenant_id=tenant_id,
        payload_data={"record_id": record_id},
        timeout=10.0,
    )


@mcp.tool(
    name="crm_update_object_record",
    description="Update a record for a custom object type.",
)
async def crm_update_object_record(
    tenant_id: str,
    record_id: str,
    patch: Dict[str, Any],
    user_approved: bool = False,
    ctx: TypedContext | None = None,
) -> Dict[str, Any]:
    return await _invoke_backend_tool(
        ctx=ctx,
        tool_name="crm_update_object_record",
        service="crm",
        method="POST",
        path="/update_object_record",
        tenant_id=tenant_id,
        payload_data={"record_id": record_id, "patch": patch, "user_approved": user_approved},
        timeout=10.0,
    )


@mcp.tool(
    name="observability_metrics",
    description="Return in-memory counters and average latency per MCP tool.",
)
async def observability_metrics(
    tenant_id: str,
    ctx: TypedContext | None = None,
) -> Dict[str, Any]:
    ctx = _require_context(ctx)
    app = ctx.request_context.lifespan_context
    
    # Security: Get actor/actor_role from config, not from client input
    server_cfg = CONFIG.get("server", {})
    security_cfg = CONFIG.get("security", {})
    actor = server_cfg.get("default_actor") or security_cfg.get("default_actor") or "mcp-server"
    actor_role = server_cfg.get("default_actor_role") or security_cfg.get("default_actor_role") or "Agent"
    
    app.rate_limiter.check(tenant_id, "observability_metrics", actor)
    app.permissions.ensure_allowed("observability_metrics", actor_role)
    snapshot = app.metrics.snapshot()
    return {
        "tenant_id": tenant_id,
        "metrics": snapshot,
    }


@mcp.tool(
    name="observability_circuit_breaker",
    description="Return circuit breaker status for all backend services.",
)
async def observability_circuit_breaker(
    tenant_id: str,
    ctx: TypedContext | None = None,
) -> Dict[str, Any]:
    """
    Return circuit breaker status for observability.
    
    Shows:
    - State per service (closed, open, half_open)
    - Failure count
    - Time until reset (if open)
    """
    ctx = _require_context(ctx)
    app = ctx.request_context.lifespan_context
    
    # Security: Get actor/actor_role from config, not from client input
    server_cfg = CONFIG.get("server", {})
    security_cfg = CONFIG.get("security", {})
    actor = server_cfg.get("default_actor") or security_cfg.get("default_actor") or "mcp-server"
    actor_role = server_cfg.get("default_actor_role") or security_cfg.get("default_actor_role") or "Agent"
    
    app.rate_limiter.check(tenant_id, "observability_circuit_breaker", actor)
    app.permissions.ensure_allowed("observability_circuit_breaker", actor_role)
    
    circuit_status = app.circuit_breaker.get_status()
    
    return {
        "tenant_id": tenant_id,
        "circuit_breaker": circuit_status,
        "config": {
            "failure_threshold": app.circuit_breaker.failure_threshold,
            "recovery_timeout": app.circuit_breaker.recovery_timeout,
            "half_open_max_calls": app.circuit_breaker.half_open_max_calls,
        },
    }


@mcp.tool(
    name="observability_health",
    description="Return basic configuration and status information about the MCP server.",
)
async def observability_health(
    tenant_id: str,
    include_config: bool = True,
    ctx: TypedContext | None = None,
) -> Dict[str, Any]:
    ctx = _require_context(ctx)
    app = ctx.request_context.lifespan_context
    
    # Security: Get actor/actor_role from config, not from client input
    server_cfg = CONFIG.get("server", {})
    security_cfg = CONFIG.get("security", {})
    actor = server_cfg.get("default_actor") or security_cfg.get("default_actor") or "mcp-server"
    actor_role = server_cfg.get("default_actor_role") or security_cfg.get("default_actor_role") or "Agent"
    
    app.rate_limiter.check(tenant_id, "observability_health", actor)
    app.permissions.ensure_allowed("observability_health", actor_role)
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
    name="observability_discovery",
    description="List all available MCP tools and their parameters.",
)
async def observability_discovery(
    tenant_id: str,
    ctx: TypedContext | None = None,
) -> Dict[str, Any]:
    ctx = _require_context(ctx)
    app = ctx.request_context.lifespan_context
    
    # Security: Get actor/actor_role from config, not from client input
    server_cfg = CONFIG.get("server", {})
    security_cfg = CONFIG.get("security", {})
    actor = server_cfg.get("default_actor") or security_cfg.get("default_actor") or "mcp-server"
    actor_role = server_cfg.get("default_actor_role") or security_cfg.get("default_actor_role") or "Agent"
    
    app.rate_limiter.check(tenant_id, "observability_discovery", actor)
    app.permissions.ensure_allowed("observability_discovery", actor_role)

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
    name="observability.metrics",
    description="Alias for observability_metrics (dot notation).",
)
async def observability_metrics_dot(
    tenant_id: str,
    ctx: TypedContext | None = None,
) -> Dict[str, Any]:
    return await observability_metrics(tenant_id=tenant_id, ctx=ctx)

@mcp.tool(
    name="observability.health",
    description="Alias for observability_health (dot notation).",
)
async def observability_health_dot(
    tenant_id: str,
    ctx: TypedContext | None = None,
) -> Dict[str, Any]:
    return await observability_health(tenant_id=tenant_id, ctx=ctx)

@mcp.tool(
    name="observability.discovery",
    description="Alias for observability_discovery (dot notation).",
)
async def observability_discovery_dot(
    tenant_id: str,
    ctx: TypedContext | None = None,
) -> Dict[str, Any]:
    return await observability_discovery(tenant_id=tenant_id, ctx=ctx)


from mcp_server.website_fetch_tools import register_website_fetch_tools

def _env_flag(name: str, default: str) -> bool:
    v = os.getenv(name, default).strip().lower()
    return v not in {"0", "false", "no", "off", ""}

def _tool_profile() -> str:
    return os.getenv("MCP_TOOL_PROFILE", "core").strip().lower()

def _core_allowlist() -> set[str]:
    return {
        "website.fetch",
        "memory_search",
        "memory_write",
        "memory_telemetry",
        "observability_discovery",
        "observability_health",
        "observability_metrics",
        "crm_lookup_customer",
        "crm_search_customers",
        "crm_get_timeline",
        "crm_list_properties",
        "crm_list_pipelines",
        "crm_list_associations",
    }

def _apply_tool_allowlist() -> None:
    profile = _tool_profile()
    if profile == "full":
        return
    allow = _core_allowlist()
    tool_manager = getattr(mcp, "_tool_manager", None)
    tools = getattr(tool_manager, "_tools", None) if tool_manager is not None else None
    if not isinstance(tools, dict):
        return
    for name in list(tools.keys()):
        if name not in allow:
            tools.pop(name, None)

register_website_fetch_tools(mcp)

if _env_flag("MCP_ENABLE_DOT_ALIASES", "0"):
    from mcp_server.tool_aliases import register_dot_alias_tools
    register_dot_alias_tools(mcp, _invoke_backend_tool)

# Real Estate tools removed - no longer needed

_apply_tool_allowlist()

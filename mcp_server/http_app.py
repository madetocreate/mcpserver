"""
Saubere FastAPI/ASGI-Struktur für MCP Server.

Ersetzt uvicorn.Config Monkey-Patch durch:
- FastAPI App mit Middleware
- Bearer Token Auth Middleware
- Origin Allowlist Middleware
- MCP mount unter /mcp
- Healthcheck unter /health
"""
from __future__ import annotations

import os
import logging
from typing import Any, Callable, Optional

from fastapi import FastAPI, Request, Response, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from .server import mcp, server_cfg, CONFIG
from .env_utils import is_production_env

# Import FastMCP to check for ASGI app access methods
try:
    from mcp.server.fastmcp import FastMCP
except ImportError:
    FastMCP = None

logger = logging.getLogger("mcp_server.http_app")


def _normalize_origin(origin: str) -> str:
    """Normalize origin for comparison (remove protocol, lowercase, extract host:port)."""
    origin_lower = origin.lower().strip()
    # Remove protocol
    for proto in ["https://", "http://"]:
        if origin_lower.startswith(proto):
            origin_lower = origin_lower[len(proto):]
    # Extract host:port (remove path)
    host_port = origin_lower.split("/")[0]
    return host_port


def _parse_allowed_origins(origins_str: str) -> list[str]:
    """Parse comma-separated origins and normalize them."""
    if not origins_str or not origins_str.strip():
        return []
    origins = [o.strip() for o in origins_str.split(",") if o.strip()]
    return [_normalize_origin(o) for o in origins]


class BearerTokenAuthMiddleware(BaseHTTPMiddleware):
    """Middleware für Bearer Token Authentication."""
    
    def __init__(self, app: ASGIApp, expected_token: str | None = None, require_in_production: bool = True):
        super().__init__(app)
        self.expected_token = expected_token or os.getenv("MCP_SERVER_TOKEN", "").strip()
        self.require_in_production = require_in_production
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Skip auth for /health and /mcp/discovery
        path = request.url.path
        if path in ("/health", "/mcp/discovery"):
            return await call_next(request)
        
        # Only check auth for /mcp endpoints
        if not path.startswith("/mcp"):
            return await call_next(request)
        
        # In production: Token ist Pflicht
        if is_production_env() and not self.expected_token:
            logger.error("[Auth] MCP_SERVER_TOKEN not set in production")
            return JSONResponse(
                {"error": "server_error", "message": "MCP_SERVER_TOKEN not configured"},
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        
        if self.expected_token:
            auth_header = request.headers.get("authorization", "")
            if not auth_header.startswith("Bearer "):
                logger.warning(f"[Auth] Missing or invalid Authorization header for {request.method} {path}")
                return JSONResponse(
                    {"error": "unauthorized", "message": "Missing or invalid Authorization header"},
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    headers={"WWW-Authenticate": "Bearer"},
                )
            
            token = auth_header[7:]  # Remove "Bearer "
            # Security: Use timing-safe comparison to prevent timing attacks
            import hmac
            if not hmac.compare_digest(token, self.expected_token):
                logger.warning(f"[Auth] Invalid token for {request.method} {path}")
                return JSONResponse(
                    {"error": "unauthorized", "message": "Invalid token"},
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    headers={"WWW-Authenticate": "Bearer"},
                )
            
            logger.debug(f"[Auth] Token authenticated for {request.method} {path}")
        
        return await call_next(request)


class OriginAllowlistMiddleware(BaseHTTPMiddleware):
    """Middleware für Origin-Check (DNS rebinding Schutz)."""
    
    def __init__(
        self,
        app: ASGIApp,
        allowed_origins: list[str] | None = None,
        require_origin: bool | None = None,
    ):
        super().__init__(app)
        # Parse from ENV if not provided
        if allowed_origins is None:
            origins_str = os.getenv("MCP_ALLOWED_ORIGINS", "").strip()
            self.allowed_origins = _parse_allowed_origins(origins_str) if origins_str else []
        else:
            self.allowed_origins = allowed_origins
        
        # require_origin: default true in production, false in dev
        if require_origin is None:
            self.require_origin = is_production_env()
        else:
            self.require_origin = require_origin
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Skip origin check for /health and /mcp/discovery
        path = request.url.path
        if path in ("/health", "/mcp/discovery"):
            return await call_next(request)
        
        # Only check origin for /mcp endpoints
        if not path.startswith("/mcp"):
            return await call_next(request)
        
        # If no allowlist configured, skip check
        if not self.allowed_origins:
            return await call_next(request)
        
        origin_header = request.headers.get("origin") or request.headers.get("Origin", "")
        
        if origin_header:
            # Origin header present: validate against allowlist
            origin_normalized = _normalize_origin(origin_header)
            if origin_normalized not in self.allowed_origins:
                logger.warning(f"[Origin] Origin {origin_header} not in allowlist for {request.method} {path}")
                return JSONResponse(
                    {"error": "forbidden", "message": "Origin not allowed"},
                    status_code=status.HTTP_403_FORBIDDEN,
                )
        # Security: If Origin header is missing, allow request (server-to-server traffic)
        # Origin checks are primarily for browser protection, not server-to-server
        # Only reject if require_origin is explicitly set AND we're in a browser context
        # (which we can't reliably detect, so we allow missing Origin)
        
        return await call_next(request)


class RequestContextMiddleware(BaseHTTPMiddleware):
    """
    Middleware für Request Context (Tenant ID, User ID, Approval Token, Correlation ID).
    
    Parst Headers und setzt sie in request.state für spätere Verwendung.
    NIEMALS Token/Secrets in Logs dumpen (nur JTI/Approval ID truncated).
    """
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Parse headers and set in request.state
        request.state.tenant_id = request.headers.get("x-aklow-tenant-id", "").strip()
        request.state.user_id = request.headers.get("x-aklow-user-id", "").strip()
        request.state.tool_name = request.headers.get("x-aklow-tool-name", "").strip()
        request.state.approval_token = request.headers.get("x-aklow-approval-token", "").strip()
        request.state.correlation_id = (
            request.headers.get("x-correlation-id") or 
            request.headers.get("x-request-id") or 
            ""
        ).strip()
        
        # NEVER log full tokens
        if request.state.approval_token:
            logger.debug(
                f"[Context] Request with approval token: "
                f"tenant={request.state.tenant_id}, user={request.state.user_id}, "
                f"tool={request.state.tool_name}, correlation_id={request.state.correlation_id}"
            )
        
        return await call_next(request)


def _list_tool_names() -> list[str]:
    """
    Dynamically list all registered tool names from the MCP server.
    
    FastMCP stores tools in different places depending on version.
    We check the known locations in a safe order.
    """
    tools_dict: dict[str, Any] = {}
    
    if hasattr(mcp, "_tool_manager") and hasattr(mcp._tool_manager, "_tools"):
        tools_dict = mcp._tool_manager._tools
    elif hasattr(mcp, "_router") and hasattr(mcp._router, "_tools"):
        tools_dict = mcp._router._tools
    elif hasattr(mcp, "_tools"):
        tools_dict = mcp._tools
    elif hasattr(mcp, "tools"):
        tools_dict = mcp.tools
    
    if isinstance(tools_dict, dict):
        return sorted(list(tools_dict.keys()))
    return []


def _compute_tools_hash(tool_names: list[str]) -> str:
    """
    Berechnet SHA256 Hash der sortierten Tool-Namen.
    
    Args:
        tool_names: Liste der Tool-Namen
        
    Returns:
        SHA256 Hash als Hex-String
    """
    import hashlib
    
    # Sortiere Tool-Namen und join mit \n
    sorted_names = sorted(tool_names)
    content = "\n".join(sorted_names)
    
    # Berechne SHA256
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def create_app() -> FastAPI:
    """
    Erstellt die FastAPI-App mit Middleware und MCP-Mount.
    
    Returns:
        FastAPI-App mit:
        - Bearer Token Auth Middleware
        - Origin Allowlist Middleware
        - MCP mount unter /mcp
        - Healthcheck unter /health
        - Discovery endpoint unter /mcp/discovery
    """
    app = FastAPI(
        title="Simple GPT MCP Server",
        description="MCP Tool Gateway for Memory, CRM, and other backend services",
        version="1.0.0",
    )
    
    # Add Bearer Token Auth Middleware
    app.add_middleware(BearerTokenAuthMiddleware)
    
    # Add Origin Allowlist Middleware
    app.add_middleware(OriginAllowlistMiddleware)
    
    # Add Request Context Middleware (parses tenant_id, user_id, approval_token headers)
    app.add_middleware(RequestContextMiddleware)
    
    # Healthcheck endpoint (public, no auth)
    @app.get("/health")
    async def health() -> dict[str, Any]:
        """Healthcheck endpoint."""
        return {"ok": True, "status": "healthy"}
    
    # Metrics endpoint (public, no auth)
    @app.get("/metrics")
    async def metrics(request: Request) -> Response:
        """Prometheus-compatible metrics endpoint."""
        from fastapi.responses import Response
        from .observability import InMemoryMetrics, get_shared_metrics
        
        try:
            # P0 Fix: Use shared metrics instance instead of creating new instance
            # The shared instance is created in server.py lifespan and set via set_shared_metrics()
            metrics_instance = get_shared_metrics()
            
            # If no shared instance, create new (should not happen in production after startup)
            if metrics_instance is None:
                logger.warning("No shared metrics instance found, creating new instance (metrics will be empty)")
                metrics_instance = InMemoryMetrics()
            
            snapshot = metrics_instance.snapshot()
            
            # Format as Prometheus metrics
            lines = []
            lines.append("# HELP mcp_server_healthy MCP server health status")
            lines.append("# TYPE mcp_server_healthy gauge")
            lines.append("mcp_server_healthy 1")
            
            # Tool metrics
            for tool_name, tool_metrics in snapshot.items():
                # Sanitize tool name for Prometheus (replace dots/colons with underscores)
                safe_name = tool_name.replace(".", "_").replace(":", "_").replace("-", "_")
                
                lines.append(f"# HELP mcp_tool_calls_total Total number of tool calls")
                lines.append(f"# TYPE mcp_tool_calls_total counter")
                lines.append(f'mcp_tool_calls_total{{tool="{tool_name}"}} {tool_metrics["calls"]}')
                
                lines.append(f"# HELP mcp_tool_errors_total Total number of tool errors")
                lines.append(f"# TYPE mcp_tool_errors_total counter")
                lines.append(f'mcp_tool_errors_total{{tool="{tool_name}"}} {tool_metrics["errors"]}')
                
                lines.append(f"# HELP mcp_tool_avg_latency_ms Average tool latency in milliseconds")
                lines.append(f"# TYPE mcp_tool_avg_latency_ms gauge")
                lines.append(f'mcp_tool_avg_latency_ms{{tool="{tool_name}"}} {tool_metrics["avg_latency_ms"]}')
            
            content = "\n".join(lines) + "\n"
            return Response(content=content, media_type="text/plain; version=0.0.4")
        except Exception as e:
            logger.error(f"Failed to get metrics: {e}", exc_info=True)
            return Response(
                content=f"# Error generating metrics\n# {str(e)}\n",
                media_type="text/plain",
                status_code=500,
            )
    
    # Discovery endpoint (public, no auth)
    @app.get("/mcp/discovery")
    async def discovery() -> dict[str, Any]:
        """Discovery endpoint - lists available tools."""
        import os
        import logging
        
        logger = logging.getLogger(__name__)
        tool_names = _list_tool_names()
        tools_hash = _compute_tools_hash(tool_names)
        
        # Optional: Prüfe PINNED_TOOLS_HASH
        pinned_hash = os.environ.get("PINNED_TOOLS_HASH", "").strip()
        hash_mismatch = False
        if pinned_hash:
            if tools_hash != pinned_hash:
                hash_mismatch = True
                logger.warning(
                    f"Tools hash mismatch: expected {pinned_hash}, got {tools_hash}. "
                    f"Tool set may have changed unexpectedly."
                )
        
        response = {
            "version": "1.0",
            "server": server_cfg.get("name", "simple-gpt-mcp"),
            "transport": "streamable-http",
            "endpoint": "/mcp",
            "tools": [{"name": name} for name in tool_names],
            "tool_count": len(tool_names),
            "tools_hash": tools_hash,
            "note": "For detailed tool information, use the MCP protocol endpoint /mcp or call observability.discovery tool",
        }
        
        if pinned_hash:
            response["pinned_hash"] = pinned_hash
            response["hash_mismatch"] = hash_mismatch
        
        return response
    
    # Mount MCP ASGI app under /mcp
    # FastMCP's streamable-http transport creates an ASGI app internally
    # We need to get it and mount it under /mcp
    # Since FastMCP.run() starts uvicorn internally, we need to access the ASGI app before calling run()
    
    try:
        # Try to get or create FastMCP's ASGI app for streamable-http transport
        # FastMCP should expose the ASGI app via internal structure
        mcp_asgi = None
        
        # Method 1: Check if FastMCP has a public method to get ASGI app
        if hasattr(mcp, "get_asgi_app"):
            try:
                mcp_asgi = mcp.get_asgi_app()
            except Exception as e:
                logger.debug(f"[Mount] mcp.get_asgi_app() failed: {e}")
        
        # Method 2: Try to initialize transport and get ASGI app
        if not mcp_asgi:
            try:
                # FastMCP might need transport to be initialized first
                # Try to access or create the transport
                if hasattr(mcp, "_transport") and mcp._transport is not None:
                    transport = mcp._transport
                    if hasattr(transport, "_app"):
                        mcp_asgi = transport._app
                    elif hasattr(transport, "app"):
                        mcp_asgi = transport.app
                    elif hasattr(transport, "asgi_app"):
                        mcp_asgi = transport.asgi_app
            except Exception as e:
                logger.debug(f"[Mount] Failed to get ASGI app from transport: {e}")
        
        # Method 3: Try direct access to ASGI app
        if not mcp_asgi:
            if hasattr(mcp, "_app"):
                mcp_asgi = mcp._app
            elif hasattr(mcp, "asgi_app"):
                mcp_asgi = mcp.asgi_app
            elif hasattr(mcp, "_asgi_app"):
                mcp_asgi = mcp._asgi_app
        
        if mcp_asgi:
            # Create path-rewriting wrapper to remove /mcp prefix
            async def mcp_asgi_wrapper(scope: dict[str, Any], receive: Callable, send: Callable) -> None:
                """
                ASGI wrapper that forwards requests to FastMCP.
                
                Removes /mcp prefix and forwards to FastMCP's streamable-http handler.
                """
                # Rewrite path: remove /mcp prefix for FastMCP
                if scope["type"] == "http":
                    original_path = scope.get("path", "")
                    if original_path.startswith("/mcp"):
                        new_path = original_path[len("/mcp"):] or "/"
                        scope = dict(scope)
                        scope["path"] = new_path
                    
                    # FastMCP streamable-http may require Accept header for GET requests
                    if scope.get("method") == "GET" and new_path == "/":
                        headers = list(scope.get("headers", []))
                        has_accept = any(name == b"accept" for name, _ in headers)
                        if not has_accept:
                            # Add Accept header for FastMCP compatibility
                            headers.append((b"accept", b"application/json, text/event-stream"))
                            scope["headers"] = headers
                
                # Forward to FastMCP's ASGI app
                await mcp_asgi(scope, receive, send)
            
            # Mount the wrapper
            from starlette.routing import Mount
            app.mount("/mcp", mcp_asgi_wrapper)
            logger.info("[Mount] Successfully mounted FastMCP ASGI app under /mcp")
        
    except Exception as e:
        logger.error(f"[Mount] Failed to mount MCP app: {e}", exc_info=True)
        # Fallback route
        @app.api_route("/mcp/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
        async def mcp_error_fallback(path: str) -> dict[str, Any]:
            return {
                "error": "mount_failed",
                "message": f"MCP app mounting failed: {e}",
            }
    
    return app


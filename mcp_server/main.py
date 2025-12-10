from __future__ import annotations

import signal
import sys
from typing import Any

from starlette.responses import JSONResponse

from .server import mcp, _ALL_TOOLS, server_cfg


def main() -> None:
    try:
        # Patch uvicorn.Config to wrap the app with discovery endpoint
        # FastMCP uses uvicorn.Config/Server internally
        import uvicorn
        
        original_config_init = uvicorn.Config.__init__
        
        def patched_config_init(self: Any, app: Any, *args: Any, **kwargs: Any) -> None:
            """Wrap uvicorn.Config.__init__ to inject discovery endpoint and fix host headers."""
            # Wrap the ASGI app before passing to Config
            original_asgi_app = app
            
            async def wrapped_asgi_app(scope: Any, receive: Any, send: Any) -> None:
                """ASGI app wrapper that intercepts /mcp/discovery and fixes host headers for ngrok."""
                if scope["type"] == "http":
                    path = scope.get("path", "")
                    query_string = scope.get("query_string", b"")
                    method = scope.get("method", "")
                    
                    # Fix host header for ngrok - replace with localhost to prevent "421 Misdirected Request"
                    # This allows ngrok forwarding to work correctly
                    headers = list(scope.get("headers", []))
                    accept_header = None
                    
                    for i, (name, value) in enumerate(headers):
                        if name == b"host":
                            # Replace ngrok host with localhost to pass Starlette's host validation
                            # Store original host in a custom header for reference
                            headers[i] = (b"host", b"localhost:9000")
                            headers.append((b"x-original-host", value))
                        elif name == b"accept":
                            accept_header = value.decode("utf-8", errors="ignore")
                    
                    # If no host header found, add one
                    if not any(name == b"host" for name, _ in headers):
                        headers.append((b"host", b"localhost:9000"))
                    
                    # Update scope with modified headers
                    scope = dict(scope)
                    scope["headers"] = headers
                    
                    # Handle /mcp/messages endpoint for Agent Builder
                    # Agent Builder sends: POST /mcp/messages/?session_id=XXX
                    # FastMCP streamable-http expects: POST /mcp (creates session), then GET /mcp?session_id=XXX
                    # But OpenAI Agent Builder seems to use a different pattern
                    # Let's try: if POST /mcp/messages with session_id, convert to GET /mcp?session_id
                    # Actually wait - POST with body should go to POST /mcp, but session_id handling is tricky
                    if path.startswith("/mcp/messages") and method == "POST":
                        # Extract session_id from query string
                        session_id = None
                        if query_string:
                            query_str = query_string.decode("utf-8", errors="ignore")
                            for param in query_str.split("&"):
                                if param.startswith("session_id="):
                                    session_id = param.split("=", 1)[1]
                                    break
                        
                        # FastMCP streamable-http: POST creates session, GET retrieves
                        # But Agent Builder sends POST with session_id already set
                        # This suggests it expects to send messages via POST
                        # Try redirecting to POST /mcp with session_id in query
                        # But if that doesn't work (405), maybe we need GET instead?
                        new_scope = dict(scope)
                        new_scope["path"] = "/mcp"
                        # Keep query string - FastMCP might handle POST with session_id
                        new_scope["query_string"] = query_string
                        await original_asgi_app(new_scope, receive, send)
                        return
                    
                    # Preserve query_string for all other requests
                    scope["query_string"] = query_string
                    
                    if path == "/mcp/discovery" and method == "GET":
                        response = JSONResponse({
                            "version": "1.0",
                            "server": server_cfg.get("name", "simple-gpt-mcp"),
                            "transport": "sse",
                            "endpoint": "/sse",
                            "tools": sorted([{"name": name} for name in _ALL_TOOLS], key=lambda x: x["name"]),
                            "tool_count": len(_ALL_TOOLS),
                            "note": "For detailed tool information, use the MCP protocol endpoint /sse or call observability.discovery tool",
                        })
                        await response(scope, receive, send)
                        return
                    
                # Forward all other requests to original app with fixed host header
                await original_asgi_app(scope, receive, send)
            
            # Call original Config.__init__ with wrapped app
            # Remove allowed_hosts from kwargs if present (uvicorn.Config doesn't accept it directly)
            kwargs.pop("allowed_hosts", None)
            kwargs.setdefault("server_header", False)
            original_config_init(self, wrapped_asgi_app, *args, **kwargs)
            # Set allowed_hosts after initialization to accept all hosts for ngrok
            if hasattr(self, "allowed_hosts"):
                self.allowed_hosts = ["*"]
            # Also try to disable host checking via app settings
            if hasattr(self, "app") and hasattr(self.app, "state"):
                # Try to disable host checking in Starlette app
                pass
        
        # Patch Config before running
        uvicorn.Config.__init__ = patched_config_init
        
        try:
            # Using streamable-http transport - supports both GET and POST
            # Agent Builder sends GET /mcp and POST /mcp/messages
            # We handle redirects in the ASGI wrapper
            mcp.run(transport="streamable-http")
        finally:
            # Restore original Config.__init__
            uvicorn.Config.__init__ = original_config_init
    except KeyboardInterrupt:
        print("\nServer shutdown requested...")
        sys.exit(0)


if __name__ == "__main__":
    main()

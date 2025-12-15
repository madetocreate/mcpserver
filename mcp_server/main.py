"""
Main entry point for the MCP server.

Simplified wrapper that only handles:
- Logging for debugging
- /mcp/discovery endpoint for HTTP discovery

All MCP protocol handling is delegated to FastMCP - no protocol-level manipulation.
"""
from __future__ import annotations

import sys
from typing import Any, Dict

from starlette.responses import JSONResponse

from .server import mcp, server_cfg


def _list_tool_names() -> list[str]:
    """
    Dynamically list all registered tool names from the MCP server.
    
    Returns:
        Sorted list of tool names
    """
    tools_dict: Dict[str, Any] = {}
    
    # Try different ways to access tools from mcp object
    if hasattr(mcp, "_router") and hasattr(mcp._router, "_tools"):
        tools_dict = mcp._router._tools
    elif hasattr(mcp, "_tools"):
        tools_dict = mcp._tools
    elif hasattr(mcp, "tools"):
        tools_dict = mcp.tools
    
    return sorted(list(tools_dict.keys()))


def main() -> None:
    """Start the MCP server with minimal wrapper for discovery endpoint only."""
    try:
        import uvicorn
        
        original_config_init = uvicorn.Config.__init__
        
        def patched_config_init(self: Any, app: Any, *args: Any, **kwargs: Any) -> None:
            """Wrap uvicorn.Config to add /mcp/discovery endpoint and logging."""
            original_asgi_app = app
            
            async def wrapped_asgi_app(scope: Any, receive: Any, send: Any) -> None:
                """Minimal ASGI wrapper: only logging, /mcp/discovery, and minimal Accept header fix."""
                if scope["type"] == "http":
                    path = scope.get("path", "")
                    method = scope.get("method", "")
                    
                    # Enhanced logging for /mcp requests
                    if path.startswith("/mcp"):
                        import logging
                        logger = logging.getLogger("mcp_server.wrapper")
                        query_str = scope.get("query_string", b"").decode("utf-8", errors="ignore")
                        
                        # Log all headers for debugging
                        headers_dict = {k.decode("utf-8", errors="ignore"): v.decode("utf-8", errors="ignore") 
                                       for k, v in scope.get("headers", [])}
                        logger.info(f"[ASGI] {method} {path}?{query_str}")
                        if "accept" in headers_dict:
                            logger.info(f"[ASGI] Accept header: {headers_dict['accept']}")
                        else:
                            logger.info(f"[ASGI] No Accept header present")
                    
                    # Handle /mcp/discovery endpoint (custom endpoint, not part of MCP protocol)
                    if path == "/mcp/discovery" and method == "GET":
                        tool_names = _list_tool_names()
                        response = JSONResponse({
                            "version": "1.0",
                            "server": server_cfg.get("name", "simple-gpt-mcp"),
                            "transport": "streamable-http",
                            "endpoint": "/mcp",
                            "tools": [{"name": name} for name in tool_names],
                            "tool_count": len(tool_names),
                            "note": "For detailed tool information, use the MCP protocol endpoint /mcp or call observability.discovery tool",
                        })
                        await response(scope, receive, send)
                        return
                    
                    # Minimal fix: FastMCP streamable-http requires Accept header for GET /mcp
                    # Try both text/event-stream and application/json, text/event-stream
                    if path == "/mcp" and method == "GET":
                        headers = list(scope.get("headers", []))
                        has_accept = any(name == b"accept" for name, _ in headers)
                        if not has_accept:
                            import logging
                            logger = logging.getLogger("mcp_server.wrapper")
                            # FastMCP may require both application/json and text/event-stream
                            # Try the more complete Accept header first
                            headers.append((b"accept", b"application/json, text/event-stream"))
                            scope = dict(scope)
                            scope["headers"] = headers
                            logger.info(f"[ASGI] Added Accept header: application/json, text/event-stream")
                
                # Forward all requests to FastMCP (minimal modification only when necessary)
                await original_asgi_app(scope, receive, send)
            
            # Clean up kwargs and call original Config
            kwargs.pop("allowed_hosts", None)
            kwargs.setdefault("server_header", False)
            original_config_init(self, wrapped_asgi_app, *args, **kwargs)
            # Set allowed_hosts to accept all hosts (since we use 0.0.0.0 in server.py)
            if hasattr(self, "allowed_hosts"):
                self.allowed_hosts = ["*"]
        
        # Patch Config before running
        uvicorn.Config.__init__ = patched_config_init
        
        try:
            # Use standard streamable-http transport - let FastMCP handle all protocol details
            print(f"Starting MCP server on http://0.0.0.0:9000/mcp")
            print(f"Discovery endpoint: http://0.0.0.0:9000/mcp/discovery")
            mcp.run(transport="streamable-http")
        finally:
            # Restore original Config.__init__
            uvicorn.Config.__init__ = original_config_init
    except KeyboardInterrupt:
        print("\nServer shutdown requested...")
        sys.exit(0)


if __name__ == "__main__":
    main()

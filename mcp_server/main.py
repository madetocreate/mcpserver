"""
Main entry point for the MCP server.

Saubere ASGI-Struktur ohne Monkey-Patches:
- FastAPI App mit Middleware (Auth + Origin)
- MCP mount unter /mcp
- Healthcheck unter /health
"""
from __future__ import annotations

import os
import sys

import uvicorn

from .http_app import create_app
from .server import server_cfg


def main() -> None:
    """Start the MCP server using clean FastAPI/ASGI structure."""
    try:
        # Get host/port from ENV or config
        host = os.getenv("MCP_SERVER_HOST", os.getenv("MCP_HOST", server_cfg.get("host", "127.0.0.1")))
        port = int(os.getenv("MCP_SERVER_PORT", os.getenv("MCP_PORT", str(server_cfg.get("port", 9000)))))
        
        # Create FastAPI app with middleware and MCP mount
        app = create_app()
        
        print(f"Starting MCP server on http://{host}:{port}")
        print(f"MCP endpoint: http://{host}:{port}/mcp")
        print(f"Discovery endpoint: http://{host}:{port}/mcp/discovery")
        print(f"Healthcheck: http://{host}:{port}/health")
        
        # Start uvicorn with the FastAPI app
        uvicorn.run(
            app,
            host=host,
            port=port,
            log_level=server_cfg.get("log_level", "INFO").lower(),
            server_header=False,  # Security: Don't expose server version
        )
    except KeyboardInterrupt:
        print("\nServer shutdown requested...")
        sys.exit(0)
    except Exception as e:
        print(f"Failed to start MCP server: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

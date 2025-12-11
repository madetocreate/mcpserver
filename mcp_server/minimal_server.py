"""
Minimal MCP Server zum Testen der Agent Builder Verbindung.

Dieser Server ist absichtlich einfach gehalten, um die Basis-Verbindung
zu validieren, bevor die komplexe Wrapper-Logik zum Einsatz kommt.
"""
import sys

from mcp.server.fastmcp import FastMCP

# 1. MCP-Server – ohne stateless_http / json_response für den Anfang
# host="0.0.0.0" sorgt dafür, dass uvicorn alle Hosts akzeptiert (ngrok inkl.)
mcp = FastMCP(
    "SimpleGPT-Minimal",
    host="0.0.0.0",
    port=9000,
)

# 2. Ein einfaches Test-Tool
@mcp.tool()
def ping() -> str:
    """Simple connectivity test tool."""
    return "pong"

@mcp.tool()
def echo(message: str) -> str:
    """Echo back the message."""
    return f"Echo: {message}"

if __name__ == "__main__":
    # 3. Standard-Streamable-HTTP-Server, keine Wrapper, keine mount_path-Tricks
    print("Starting minimal MCP server on http://0.0.0.0:9000/mcp")
    print("Test with ngrok: ngrok http 9000")
    print("Then configure Agent Builder with: https://<ngrok-url>/mcp")
    try:
        mcp.run(transport="streamable-http")
    except KeyboardInterrupt:
        print("\nServer shutdown requested...")
        sys.exit(0)


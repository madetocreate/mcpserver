# MCP server architecture

This repository implements a thin MCP "tool gateway":

- `mcp_server/server.py` holds the FastMCP server, rate limiting, permission
  checks and the generic HTTP client to backend services.
- `config/server.yaml` describes tenants, backend URLs, roles and tool access.
- `dev_backend/main.py` is a stub backend used for local development.

## Planned modularisation

As the number of tools grows we will split `server.py` into domain modules
under `mcp_server/tools/`:

- `mcp_server/tools/memory.py`
- `mcp_server/tools/crm.py`
- `mcp_server/tools/automation.py`
- `mcp_server/tools/inbox.py`
- `mcp_server/tools/files.py`

Each module will:

- declare the FastMCP tools for its domain
- contain any small helper functions
- keep business logic close to the tool definitions

The generic infrastructure (rate limiting, permissions, logging, HTTP client)
stays in `mcp_server/server.py`. This keeps the core stable while tools can
evolve independently.

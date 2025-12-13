# MCP server architecture

This repository implements a thin MCP "tool gateway" that exposes backend services as tools for AI agents.

## Core Components

- **`mcp_server/server.py`**: FastMCP server, rate limiting, permission checks, generic HTTP client
- **`config/server.yaml`**: Tenant configuration, backend URLs, roles, tool access permissions
- **`mcp_server/tool_aliases.py`**: Dot-notation aliases (e.g., `memory.search` → `memory_search`)
- **`mcp_server/crm_tools_ext.py`**: Extended CRM tools (Phase 7-10)
- **`mcp_server/website_fetch_tools.py`**: Website fetching tools (SSRF-protected)
- **`dev_backend/main.py`**: Stub backend for local development/testing

## Architecture Pattern

The MCP server acts as a **Tool Provider** in the AKLOW ecosystem:

```
[AI Agent] → [MCP Server] → [Backend Service] → [Database/External APIs]
```

**Key Principle**: The MCP server provides the *interface* (tools), not the business logic. All business logic (Memory Vector Search, CRM Operations, etc.) resides in the Python Backend (`Backend/backend-agents`).

## Tool Categories

### Memory Tools
- `memory.search` / `memory_search`: Semantic search in knowledge base
- `memory.write` / `memory.write`: Save new information
- `memory.delete`: Remove information (requires approval)
- `memory.archive`: Archive information (requires approval)
- `memory.telemetry`: Get memory usage metrics

### CRM Tools (Phase 1-10)
- **Phase 1-3**: Core CRM (lookup, search, notes, pipeline)
- **Phase 4-6**: Extended (associations, timeline, tasks, properties)
- **Phase 7**: Admin (API keys, users, teams)
- **Phase 8**: Import/Export (CSV import/export, merge)
- **Phase 9**: Reporting (pipeline reports, forecasts)
- **Phase 10**: Governance (GDPR, webhooks, custom objects)

### Workflow Tools (Dot Notation)
- `support.workflow`: Support automation
- `marketing.workflow`: Marketing campaigns
- `website.workflow`: Website operations
- `backoffice.workflow`: Backoffice tasks
- `onboarding.workflow`: Onboarding flow

### Website Tools
- `website.fetch`: Fetch public URLs (SSRF-protected, size-limited)

## Modularisation Status

Currently, tools are organized in:
- `mcp_server/server.py`: Core infrastructure + Memory/CRM tools
- `mcp_server/crm_tools_ext.py`: Extended CRM tools
- `mcp_server/website_fetch_tools.py`: Website tools

**Future**: As tools grow, we will split into domain modules under `mcp_server/tools/`:
- `mcp_server/tools/memory.py`
- `mcp_server/tools/crm.py`
- `mcp_server/tools/automation.py`
- `mcp_server/tools/inbox.py`
- `mcp_server/tools/files.py`

Each module will:
- Declare FastMCP tools for its domain
- Contain small helper functions
- Keep business logic close to tool definitions

The generic infrastructure (rate limiting, permissions, logging, HTTP client) stays in `mcp_server/server.py`.

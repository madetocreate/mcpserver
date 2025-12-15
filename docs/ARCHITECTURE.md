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

### Observability Tools
- `observability_metrics`: In-memory metrics and latency
- `observability_health`: Server configuration and status
- `observability_discovery`: List all available tools

### Website Tools
- `website.fetch`: Fetch public URLs (SSRF-protected, size-limited)

## Security Architecture

### Permission System

1. **Default Roles**: Tools without explicit `allowed_roles` use `default_allowed_roles` from config
2. **Tool-Specific Roles**: Tools can override with explicit `allowed_roles`
3. **User Approval**: Destructive operations require `user_approved: true`
4. **High-Cost Protection**: Image/video/audio generation requires `cost_approved: true`

### Cost Policy

The `mcp_server/cost_policy.py` module:
- Detects high-cost tools by name patterns
- Checks for explicit `high_cost: true` in config
- Validates cost approval in payload

### Rate Limiting

Multi-level rate limiting:
- Global limit per tenant
- Per-actor limit
- Per-tool limit (future)

## Tool Organization

Currently, tools are organized in:
- `mcp_server/server.py`: Core infrastructure + Memory/CRM tools
- `mcp_server/tool_aliases.py`: Dot-notation aliases (memory.search, memory.write)
- `mcp_server/website_fetch_tools.py`: Website tools (SSRF-protected)
- `mcp_server/cost_policy.py`: High-cost tool detection

The generic infrastructure (rate limiting, permissions, logging, HTTP client) stays in `mcp_server/server.py`.

## Removed Components

The following have been removed as part of cleanup:
- Automation tools (not properly configured)
- Inbox tools (not properly configured)
- File tools (not properly configured)
- Workflow supervisor proxies (don't fit "MCP = Core Tools" architecture)
- Workflow dot-aliases (removed with supervisor proxies)

See [Complete Guide](COMPLETE_GUIDE.md) for current tool list.

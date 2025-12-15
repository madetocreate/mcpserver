# simple-gpt-mcp-server

MCP (Model Context Protocol) server that exposes internal backend services
(memory, CRM) as tools for AI agents.

**Key Principle**: The MCP server is a **Tool Gateway**, providing core tools only - no workflow agents or supervisors.

## Features

- ✅ Async HTTP gateway with per-tool rate limiting
- ✅ Role-based access control configured in `config/server.yaml`
- ✅ Multi-tenant backend URLs
- ✅ Advanced rate limiting with per-tool quotas
- ✅ Observability and audit logging
- ✅ Error handling and resilience
- ✅ SSRF protection for web fetching
- ✅ Dev stub backend for quick local testing

## Architecture

The MCP server acts as a gateway between AI agents and backend services:

```
AI Agent → MCP Server → Backend Service (Memory, CRM, etc.)
```

### Components

- **`mcp_server/server.py`** - FastMCP server, rate limiting, permission checks, tool definitions
- **`mcp_server/config.py`** - Configuration loader
- **`mcp_server/rate_limits.py`** - Advanced rate limiting per tool
- **`mcp_server/observability.py`** - Audit logging and metrics
- **`mcp_server/security.py`** - Security utilities
- **`mcp_server/crm_tools_ext.py`** - Extended CRM tools (Phase 7-10)
- **`mcp_server/website_fetch_tools.py`** - Website fetching tools
- **`mcp_server/tool_aliases.py`** - Dot-notation aliases (memory.search, support.workflow, etc.)
- **`config/server.yaml`** - Tenant configuration, backend URLs, roles, tool access
- **`dev_backend/main.py`** - Stub backend for local development

## Quick start (development)

1. Create a virtualenv and install dev dependencies:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -e ".[dev]"
   ```

2. Start a dev backend stub (optional):
   ```bash
   SERVICE_NAME=memory uvicorn dev_backend.main:app --reload --port 8010
   ```

3. Start the MCP server (HTTP transport via FastMCP):
   ```bash
   python -m mcp_server.main
   ```

   By default the HTTP transport listens on `127.0.0.1:9000`.
   You can override this using environment variables:
   - `MCP_SERVER_CONFIG` – path to server.yaml (default: `config/server.yaml`)
   - `MCP_SERVER_HOST` – bind address (default: 127.0.0.1)
   - `MCP_SERVER_PORT` – bind port (default: 9000)

4. Call a tool from the CLI helper:
   ```bash
   python scripts/call_memory_search.py
   python scripts/list_tools.py
   python scripts/health_check.py
   ```

## Configuration

### server.yaml Structure

```yaml
server:
  name: simple-gpt-mcp

tenants:
  default:
    services:
      memory: "http://127.0.0.1:8000/mcp/memory"
      crm: "http://127.0.0.1:8000/mcp/crm"

security:
  tools:
    memory_delete:
      user_approval_required: true
    crm_upsert_contact:
      user_approval_required: true
    # ... more tool permissions
  default_allowed_roles:
    - Admin
    - Orchestrator
    - CRM-Supervisor
    - Agent

rate_limits:
  default_per_minute: 120
  per_actor_per_minute: 60
  window_seconds: 60
```

## Available Tools

### Memory Tools

- **`memory_search`** / **`memory.search`** - Search tenant memories
- **`memory_write`** / **`memory.write`** - Write memory entry
- **`memory_delete`** - Delete memory (requires approval)
- **`memory_archive`** - Archive memory (requires approval)
- **`memory_telemetry`** - Get memory usage telemetry

### CRM Tools

See [Complete Guide](docs/COMPLETE_GUIDE.md#crm-tools) for full list of 40+ CRM tools including:
- Core operations (lookup, search)
- Write operations (create, update - require approval)
- Admin operations (restricted roles)
- Webhooks, custom objects, import/export, reporting

### Website Tools

- **`website.fetch`** - Fetch public URL (SSRF-protected, size-limited)

### Observability Tools

- **`observability_metrics`** - Return in-memory counters and average latency per tool
- **`observability_health`** - Return server configuration and status
- **`observability_discovery`** - List all available tools with parameters

## Rate Limiting

Per-tool rate limiting is configured in `server.yaml`:
- **Default**: 120 requests per minute globally
- **Per Actor**: 60 requests per minute per actor
- **Window**: 60 seconds sliding window
- **Per-Tool**: Configurable per role and tool in config

## Security & Permissions

### Role-Based Access Control

**Default Roles**: Tools without explicit `allowed_roles` are only accessible to roles in `default_allowed_roles`:
- Admin
- Orchestrator
- CRM-Supervisor
- Agent

**Tool-Specific Roles**: Tools can override with explicit `allowed_roles` in config.

### User Approval Required

Tools that modify data require `user_approved: true`:
- `memory_delete`, `memory_archive`
- `crm_create_note`, `crm_update_pipeline`
- `crm_upsert_contact`, `crm_upsert_company`
- `crm_create_deal`, `crm_merge_contacts`
- And many more (see `config/server.yaml`)

### High-Cost Tool Protection

Tools that generate images/video/audio require `cost_approved: true`:
- Automatically detected by name (e.g., `image_generate`, `video.create`)
- Can be explicitly marked in config: `high_cost: true`
- `user_approved: true` also counts as cost approval

See [Complete Guide](docs/COMPLETE_GUIDE.md#high-cost-tool-protection) for details.

## Observability

- **Audit Logging**: All tool calls are logged to `logs/audit.log`
- **Metrics**: In-memory metrics collection
- **Error Tracking**: Detailed error logging with correlation IDs
- **Performance**: Duration tracking per tool

## Error Handling

- **MCPClientError** (4xx) - Client-side errors (permissions, validation)
- **MCPServerError** (5xx) - Server-side errors (backend failures)
- **PermissionError** - Authorization failures
- **BackendError** - Backend service errors
- **RateLimitError** - Rate limit exceeded

## Running tests

```bash
pytest
```

## Scripts

- **`scripts/call_memory_search.py`** - Test memory search
- **`scripts/list_tools.py`** - List all available tools
- **`scripts/health_check.py`** - Health check
- **`scripts/call_tool.py`** - Call any tool
- **`scripts/discovery.py`** - Tool discovery

## Docker

Build and run:
```bash
docker build -t simple-gpt-mcp .
docker run --rm -p 9000:9000 simple-gpt-mcp
```

**Security Note**: You should place the container behind a TLS-terminating proxy before exposing it to the public Internet.

## Integration with Backend

The MCP server is integrated into the backend-agents application:

### Backend Configuration

```env
MCP_SERVER_URL=http://localhost:9000/mcp
ENABLE_MCP_TOOLS=true
MCP_SERVER_TOKEN=optional-bearer-token
```

### Connection Management

- Connection managed via `app/mcp/client.py`
- Automatic connection on startup (if `ENABLE_MCP_TOOLS=true`)
- Tool filtering via `app/mcp/tool_policy.py`
- Fail-soft: Backend continues if MCP connection fails

### Tool Usage

Agents can use MCP tools via the `mcp_server` instance:
```python
from app.mcp.client import mcp_server

if is_mcp_connected():
    tools = await mcp_server.list_tools()
    result = await mcp_server.call_tool("memory.search", {...})
```

## Development

### Adding New Tools

1. Add tool definition in `mcp_server/server.py` or domain-specific file
2. Configure permissions in `config/server.yaml`
3. Add rate limits if needed
4. Test with `scripts/call_tool.py`

### Backend Service URLs

Backend services are configured per tenant in `config/server.yaml`:
- `memory`: `/mcp/memory` endpoint
- `crm`: `/mcp/crm` endpoint
- `support`, `marketing`, `website`, `backoffice`, `onboarding`: Direct workflow endpoints

## Documentation

- **[Complete Guide](docs/COMPLETE_GUIDE.md)** - Comprehensive documentation with examples
- **[Architecture](docs/ARCHITECTURE.md)** - System architecture and design
- **[Error Handling](docs/ERROR_HANDLING.md)** - Error handling patterns
- **[Observability](docs/OBSERVABILITY.md)** - Metrics and logging

## Troubleshooting

### Tool not found

1. Check if tool is registered in `mcp_server/server.py`
2. Use `observability_discovery` to list all tools
3. Check tool name spelling

### Permission denied

1. Check `actor_role` in tool call
2. Check `allowed_roles` in `config/server.yaml`
3. Check `default_allowed_roles` if tool has no explicit roles
4. For write operations, ensure `user_approved: true`
5. For high-cost tools, ensure `cost_approved: true`

### Rate limit exceeded

1. Check rate limit configuration in `config/server.yaml`
2. Wait for `retry_after` seconds
3. Consider increasing limits for development

See [Complete Guide](docs/COMPLETE_GUIDE.md#troubleshooting) for more details.

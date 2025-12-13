# simple-gpt-mcp-server

MCP (Model Context Protocol) server that exposes internal backend services
(memory, CRM, automation, inbox, files) as tools for AI agents.

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
      support: "http://127.0.0.1:8000/support"
      marketing: "http://127.0.0.1:8000/marketing"
      website: "http://127.0.0.1:8000/website"
      backoffice: "http://127.0.0.1:8000/backoffice"
      onboarding: "http://127.0.0.1:8000/onboarding"

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

### CRM Tools (Phase 1-3)

- **`crm_lookup_customer`** - Lookup customer by ID
- **`crm_search_customers`** - Search customers
- **`crm_create_note`** - Create note (requires approval)
- **`crm_update_pipeline`** - Update pipeline (requires approval)
- **`crm_link_entities`** - Link entities (requires approval)
- **`crm_list_associations`** - List associations
- **`crm_get_timeline`** - Get timeline
- **`crm_define_pipeline`** - Define pipeline (requires approval)
- **`crm_list_pipelines`** - List pipelines
- **`crm_upsert_contact`** - Upsert contact (requires approval)
- **`crm_upsert_company`** - Upsert company (requires approval)
- **`crm_create_deal`** - Create deal (requires approval)
- **`crm_merge_contacts`** - Merge contacts (admin-only)
- **`crm_audit_query`** - Audit query (restricted roles)
- **`crm_events_pull`** - Pull events (restricted roles)
- **`crm_events_ack`** - Acknowledge events (restricted roles)
- **`crm_create_task`** - Create task (requires approval)
- **`crm_complete_task`** - Complete task (requires approval)
- **`crm_log_call`** - Log call (requires approval)
- **`crm_log_meeting`** - Log meeting (requires approval)
- **`crm_define_property`** - Define property (requires approval)
- **`crm_set_property`** - Set property (requires approval)
- **`crm_search_advanced`** - Advanced search
- **`crm_create_segment`** - Create segment (requires approval)

### CRM Tools (Phase 7 - Admin)

- **`crm_create_api_key`** - Create API key (admin-only)
- **`crm_upsert_user`** - Upsert user (admin-only)
- **`crm_create_team`** - Create team (admin-only)
- **`crm_add_team_member`** - Add team member (admin-only)
- **`crm_assign_owner`** - Assign owner

### CRM Tools (Phase 8 - Import/Export)

- **`crm_import_contacts_csv`** - Import contacts from CSV
- **`crm_export_contacts_csv`** - Export contacts as CSV
- **`crm_merge_contacts`** - Merge contacts (admin-only)

### CRM Tools (Phase 9 - Reporting)

- **`crm_log_email_engagement`** - Log email engagement
- **`crm_report_pipeline`** - Pipeline report
- **`crm_forecast_pipeline`** - Forecast report

### CRM Tools (Phase 10 - Governance)

- **`crm_gdpr_export_contact_data`** - GDPR export (admin-only)
- **`crm_gdpr_delete_contact`** - GDPR delete (admin-only, requires approval)
- **`crm_gdpr_blocklist_email`** - Blocklist email (admin-only)
- **`crm_webhook_create`** - Create webhook (requires approval)
- **`crm_webhook_list`** - List webhooks
- **`crm_webhook_disable`** - Disable webhook (requires approval)
- **`crm_webhook_dispatch`** - Dispatch webhook
- **`crm_define_object_type`** - Define custom object type (requires approval)
- **`crm_create_object_record`** - Create custom object (requires approval)
- **`crm_get_object_record`** - Get custom object
- **`crm_update_object_record`** - Update custom object (requires approval)

### Workflow Tools (Dot Notation)

- **`support.workflow`** - Run support workflow
- **`marketing.workflow`** - Run marketing workflow
- **`website.workflow`** - Run website workflow
- **`backoffice.workflow`** - Run backoffice workflow
- **`onboarding.workflow`** - Run onboarding workflow

### Website Tools

- **`website.fetch`** - Fetch public URL (SSRF-protected, size-limited)

## Rate Limiting

Per-tool rate limiting is configured in `server.yaml`:
- **Default**: 120 requests per minute globally
- **Per Actor**: 60 requests per minute per actor
- **Window**: 60 seconds sliding window
- **Per-Tool**: Configurable per role and tool in config

## Security & Permissions

### User Approval Required

Tools that modify data require `user_approved: true`:
- `memory_delete`, `memory_archive`
- `crm_create_note`, `crm_update_pipeline`
- `crm_upsert_contact`, `crm_upsert_company`
- `crm_create_deal`, `crm_merge_contacts`
- And many more (see `config/server.yaml`)

### Role-Based Access

Some tools are restricted to specific roles:
- **`crm_audit_query`**: Orchestrator, CRM-Supervisor
- **`crm_events_pull`**: Orchestrator, Automation-Supervisor, CRM-Supervisor
- **`crm_events_ack`**: Orchestrator, Automation-Supervisor, CRM-Supervisor
- **Admin-only tools**: `crm_create_api_key`, `crm_upsert_user`, `crm_gdpr_*`

### Default Allowed Roles

- Admin
- Orchestrator
- CRM-Supervisor
- Agent

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

## Troubleshooting

### MCP Server not connecting

1. Check if MCP server is running: `curl http://localhost:9000/health`
2. Check `MCP_SERVER_URL` in backend `.env`
3. Check `ENABLE_MCP_TOOLS=true` in backend `.env`
4. Check backend logs for connection errors

### Tool not found

1. Check if tool is registered in `mcp_server/server.py`
2. Check permissions in `config/server.yaml`
3. Check if backend service is running
4. Check backend service URL in `config/server.yaml`

### Permission denied

1. Check `actor_role` in tool call
2. Check `allowed_roles` in `config/server.yaml`
3. Check if `user_approved: true` for write operations

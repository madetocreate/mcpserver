# MCP Server - Complete Guide

## Overview

The **simple-gpt-mcp-server** is a Model Context Protocol (MCP) server that acts as a secure gateway between AI agents and backend services. It provides a clean, tool-based interface for accessing memory, CRM, and other core services.

**Key Principle**: The MCP server is a **Tool Gateway**, not an orchestrator. It provides core tools only - no workflow agents or supervisors.

## Architecture

```
AI Agent → MCP Server → Backend Service → Database/External APIs
```

The MCP server:
- Provides tool interfaces (not business logic)
- Enforces security (permissions, rate limits, cost controls)
- Handles observability (audit logging, metrics)
- Routes requests to backend services

All business logic resides in the Python Backend (`Backend/backend-agents`).

## Core Components

### Server Infrastructure

- **`mcp_server/server.py`**: Main FastMCP server, tool definitions, security gates
- **`mcp_server/config.py`**: Configuration loader
- **`mcp_server/rate_limits.py`**: Advanced rate limiting per tool/actor
- **`mcp_server/observability.py`**: Audit logging and in-memory metrics
- **`mcp_server/security.py`**: Security utilities
- **`mcp_server/cost_policy.py`**: High-cost tool detection and approval checking
- **`mcp_server/tool_aliases.py`**: Dot-notation aliases (memory.search, memory.write)
- **`mcp_server/website_fetch_tools.py`**: SSRF-protected website fetching
- **`mcp_server/main.py`**: Entry point with discovery endpoint

### Configuration

- **`config/server.yaml`**: Tenant configuration, backend URLs, security rules, rate limits

## Available Tools

### Memory Tools

| Tool | Description | Approval Required |
|------|-------------|-------------------|
| `memory_search` / `memory.search` | Search tenant memories | No |
| `memory_write` / `memory.write` | Write memory entry | No |
| `memory_delete` | Delete memory | Yes |
| `memory_archive` | Archive memory | Yes |
| `memory_telemetry` | Get memory usage metrics | No |

### CRM Tools

**Core Operations:**
- `crm_lookup_customer` - Lookup customer by ID
- `crm_search_customers` - Search customers
- `crm_search_advanced` - Advanced search with filters

**Write Operations (require approval):**
- `crm_create_note` - Create note
- `crm_upsert_contact` - Create/update contact
- `crm_upsert_company` - Create/update company
- `crm_create_deal` - Create deal
- `crm_update_pipeline` - Update pipeline
- `crm_link_entities` - Link entities
- `crm_define_pipeline` - Define pipeline
- `crm_create_task` - Create task
- `crm_complete_task` - Complete task
- `crm_log_call` - Log call
- `crm_log_meeting` - Log meeting
- `crm_define_property` - Define property
- `crm_set_property` - Set property
- `crm_create_segment` - Create segment
- `crm_merge_contacts` - Merge contacts (admin-only)

**Read Operations:**
- `crm_list_associations` - List associations
- `crm_get_timeline` - Get timeline
- `crm_list_pipelines` - List pipelines
- `crm_list_properties` - List properties
- `crm_get_property` - Get property value
- `crm_list_segments` - List segments
- `crm_segment_members` - Get segment members

**Admin Operations (restricted roles):**
- `crm_audit_query` - Audit query (Orchestrator, CRM-Supervisor)
- `crm_events_pull` - Pull events (Orchestrator, Automation-Supervisor, CRM-Supervisor)
- `crm_events_ack` - Acknowledge events (Orchestrator, Automation-Supervisor, CRM-Supervisor)
- `crm_create_api_key` - Create API key (Admin)
- `crm_upsert_user` - Upsert user (Admin)
- `crm_create_team` - Create team (Admin)
- `crm_add_team_member` - Add team member (Admin)
- `crm_gdpr_export_contact_data` - GDPR export (Admin)
- `crm_gdpr_delete_contact` - GDPR delete (Admin, requires approval)
- `crm_gdpr_blocklist_email` - Blocklist email (Admin)

**Webhooks:**
- `crm_webhook_create` - Create webhook (requires approval)
- `crm_webhook_list` - List webhooks
- `crm_webhook_disable` - Disable webhook (requires approval)
- `crm_webhook_dispatch` - Dispatch webhook

**Custom Objects:**
- `crm_define_object_type` - Define custom object type (requires approval)
- `crm_create_object_record` - Create custom object (requires approval)
- `crm_get_object_record` - Get custom object
- `crm_update_object_record` - Update custom object (requires approval)

**Import/Export:**
- `crm_import_contacts_csv` - Import contacts from CSV
- `crm_export_contacts_csv` - Export contacts as CSV

**Reporting:**
- `crm_report_pipeline` - Pipeline report
- `crm_forecast_pipeline` - Forecast report
- `crm_log_email_engagement` - Log email engagement

### Website Tools

- `website.fetch` - Fetch public URL (SSRF-protected, size-limited)

### Observability Tools

- `observability_metrics` - Return in-memory counters and average latency per tool
- `observability_health` - Return server configuration and status
- `observability_discovery` - List all available tools with parameters

## Security Model

### Role-Based Access Control (RBAC)

The MCP server enforces role-based access control at multiple levels:

#### 1. Default Allowed Roles

If a tool has no explicit `allowed_roles` configuration, only roles in `default_allowed_roles` can access it:

```yaml
security:
  default_allowed_roles:
    - Admin
    - Orchestrator
    - CRM-Supervisor
    - Agent
```

**Important**: If `default_allowed_roles` is set, tools without explicit `allowed_roles` are **only** accessible to these roles.

#### 2. Tool-Specific Roles

Tools can override default roles with explicit `allowed_roles`:

```yaml
security:
  tools:
    crm_audit_query:
      allowed_roles:
        - Orchestrator
        - CRM-Supervisor
```

#### 3. User Approval Required

Some tools require explicit user approval for safety:

```yaml
security:
  tools:
    memory_delete:
      user_approval_required: true
    crm_upsert_contact:
      user_approval_required: true
```

These tools require `user_approved: true` in the payload.

### High-Cost Tool Protection

The MCP server automatically detects and protects high-cost tools (image/video/audio generation).

#### Detection

A tool is considered high-cost if:
- It contains a media keyword (image, video, audio, voice, tts) **AND**
- It contains a generation keyword (generate, create, synthesize, render)

Examples:
- `image_generate` ✅ High-cost
- `video.create` ✅ High-cost
- `audio_synthesize` ✅ High-cost
- `crm_create_note` ❌ Not high-cost

#### Explicit Configuration

Tools can also be explicitly marked as high-cost:

```yaml
security:
  tools:
    my_custom_tool:
      high_cost: true
```

#### Approval Required

High-cost tools require explicit cost approval:

```json
{
  "cost_approved": true,
  // ... other payload fields
}
```

**Shortcut**: `user_approved: true` also counts as cost approval.

#### Error Response

If a high-cost tool is called without approval:

```json
{
  "error": "Tool 'image_generate' is high-cost and requires explicit approval (cost_approved=true or user_approved=true).",
  "error_code": "COST_APPROVAL_REQUIRED"
}
```

## Rate Limiting

The MCP server implements multi-level rate limiting:

### Configuration

```yaml
rate_limits:
  default_per_minute: 120      # Global limit per tenant
  per_actor_per_minute: 60     # Per-actor limit
  window_seconds: 60           # Sliding window size
```

### Levels

1. **Global Limit**: Total requests per tenant per minute
2. **Per-Actor Limit**: Requests per actor (user/agent) per minute
3. **Per-Tool Limit**: (Future) Configurable per tool

### Error Response

```json
{
  "error": "Rate limit exceeded for tool 'memory_search'",
  "error_code": "RATE_LIMIT_EXCEEDED",
  "retry_after": 5
}
```

## Configuration

### server.yaml Structure

```yaml
server:
  name: simple-gpt-mcp
  host: 0.0.0.0
  port: 9000
  log_level: INFO

tenants:
  default:
    services:
      memory: "http://127.0.0.1:8000/mcp/memory"
      crm: "http://127.0.0.1:8000/mcp/crm"

security:
  tools:
    # Tool-specific permissions
    memory_delete:
      user_approval_required: true
    crm_audit_query:
      allowed_roles:
        - Orchestrator
        - CRM-Supervisor
    my_high_cost_tool:
      high_cost: true
  
  # Default roles for tools without explicit allowed_roles
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

### Environment Variables

- `MCP_SERVER_CONFIG` - Path to server.yaml (default: `config/server.yaml`)
- `MCP_SERVER_HOST` - Bind address (default: `0.0.0.0`)
- `MCP_SERVER_PORT` - Bind port (default: `9000`)

## Tool Discovery

### MCP Protocol

Use the MCP protocol endpoint:

```bash
curl -X POST http://localhost:9000/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "method": "tools/list",
    "params": {}
  }'
```

### HTTP Discovery Endpoint

Simple HTTP endpoint for tool discovery:

```bash
curl http://localhost:9000/mcp/discovery
```

Response:
```json
{
  "version": "1.0",
  "server": "simple-gpt-mcp",
  "transport": "streamable-http",
  "endpoint": "/mcp",
  "tools": [
    {"name": "memory_search"},
    {"name": "memory_write"},
    ...
  ],
  "tool_count": 45
}
```

**Note**: This endpoint dynamically lists all registered tools from the MCP server.

### Observability Tool

Use the observability tool for detailed information:

```bash
# Via MCP protocol
curl -X POST http://localhost:9000/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "method": "tools/call",
    "params": {
      "name": "observability_discovery",
      "arguments": {
        "tenant_id": "default"
      }
    }
  }'
```

## Usage Examples

### Memory Search

```python
import httpx

async with httpx.AsyncClient() as client:
    response = await client.post(
        "http://localhost:9000/mcp",
        json={
            "method": "tools/call",
            "params": {
                "name": "memory_search",
                "arguments": {
                    "tenant_id": "default",
                    "query": "customer support tickets",
                    "limit": 20,
                    "actor": "orchestrator",
                    "actor_role": "Orchestrator"
                }
            }
        }
    )
    result = response.json()
```

### CRM Create Contact (with approval)

```python
response = await client.post(
    "http://localhost:9000/mcp",
    json={
        "method": "tools/call",
        "params": {
            "name": "crm_upsert_contact",
            "arguments": {
                "tenant_id": "default",
                "email": "user@example.com",
                "first_name": "John",
                "last_name": "Doe",
                "user_approved": True,  # Required for write operations
                "actor": "orchestrator",
                "actor_role": "Orchestrator"
            }
        }
    }
)
```

### High-Cost Tool (with cost approval)

```python
response = await client.post(
    "http://localhost:9000/mcp",
    json={
        "method": "tools/call",
        "params": {
            "name": "image_generate",
            "arguments": {
                "tenant_id": "default",
                "prompt": "A beautiful sunset",
                "cost_approved": True,  # Required for high-cost tools
                "actor": "orchestrator",
                "actor_role": "Orchestrator"
            }
        }
    }
)
```

## Error Handling

### Error Types

| Error Code | Description | HTTP Status |
|------------|-------------|-------------|
| `PERMISSION_DENIED` | Role not allowed or approval missing | 403 |
| `COST_APPROVAL_REQUIRED` | High-cost tool without approval | 403 |
| `APPROVAL_REQUIRED` | Tool requires user approval | 403 |
| `RATE_LIMIT_EXCEEDED` | Rate limit exceeded | 429 |
| `BACKEND_ERROR` | Backend service error | 502 |
| `TOOL_NOT_FOUND` | Tool doesn't exist | 404 |
| `VALIDATION_ERROR` | Invalid parameters | 400 |

### Error Response Format

```json
{
  "error": "Human-readable error message",
  "error_code": "ERROR_CODE",
  "correlation_id": "uuid-for-tracing",
  "retry_after": 5  // For rate limit errors
}
```

## Observability

### Audit Logging

All tool calls are logged to `logs/audit.log` with:
- Tool name
- Tenant ID
- Actor and role
- Status (ok/error)
- Duration
- Correlation ID
- Payload size

### Metrics

In-memory metrics track:
- Call count per tool
- Average latency per tool
- Error rate per tool

Access via `observability_metrics` tool.

### Health Check

```bash
curl http://localhost:9000/mcp/discovery
# Or use observability_health tool
```

## Development

### Quick Start

1. Install dependencies:
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

2. Start MCP server:
```bash
python -m mcp_server.main
```

3. Test a tool:
```bash
python scripts/call_memory_search.py
```

### Adding New Tools

1. **Define the tool** in `mcp_server/server.py`:
```python
@mcp.tool(
    name="my_new_tool",
    description="Description of what the tool does.",
)
async def my_new_tool(
    tenant_id: str,
    param1: str,
    actor: str = "orchestrator",
    actor_role: str = "Orchestrator",
    ctx: TypedContext | None = None,
) -> Dict[str, Any]:
    return await _invoke_backend_tool(
        ctx=ctx,
        tool_name="my_new_tool",
        service="my_service",
        method="POST",
        path="/my_endpoint",
        tenant_id=tenant_id,
        actor=actor,
        actor_role=actor_role,
        payload_data={"param1": param1},
        timeout=10.0,
    )
```

2. **Configure permissions** in `config/server.yaml`:
```yaml
security:
  tools:
    my_new_tool:
      user_approval_required: true  # If needed
      # or
      allowed_roles:
        - Admin
      # or
      high_cost: true  # If it's a high-cost tool
```

3. **Add service URL** in `config/server.yaml`:
```yaml
tenants:
  default:
    services:
      my_service: "http://127.0.0.1:8000/mcp/my_service"
```

4. **Test**:
```bash
python scripts/call_tool.py my_new_tool
```

### Testing

Run tests:
```bash
pytest
```

Test files:
- `tests/test_permissions_and_rate_limiter.py` - Security and rate limiting
- `tests/test_cost_policy.py` - High-cost tool detection
- `tests/test_memory_search.py` - Memory tool integration

## Troubleshooting

### Tool not found

1. Check if tool is registered in `mcp_server/server.py`
2. Check tool name spelling
3. Use `observability_discovery` to list all tools

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

### Backend service error

1. Check backend service is running
2. Check service URL in `config/server.yaml`
3. Check backend logs for errors
4. Verify network connectivity

### High-cost tool blocked

1. Ensure `cost_approved: true` or `user_approved: true` in payload
2. Check tool name matches high-cost detection patterns
3. Verify tool is not explicitly marked `high_cost: false` in config

## Best Practices

1. **Always set `actor_role`** - Required for permission checks
2. **Use correlation IDs** - Automatically generated, use for tracing
3. **Handle errors gracefully** - Check `error_code` in responses
4. **Respect rate limits** - Implement retry logic with backoff
5. **Request approval explicitly** - Set `user_approved: true` for write operations
6. **Approve high-cost operations** - Set `cost_approved: true` for expensive tools
7. **Use observability tools** - Monitor metrics and health

## Integration with Backend

The MCP server is designed to be called from the backend-agents application:

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

### Tool Usage in Agents

```python
from app.mcp.client import mcp_server

if is_mcp_connected():
    result = await mcp_server.call_tool("memory.search", {
        "tenant_id": tenant_id,
        "query": "customer support",
        "limit": 20,
        "actor": "orchestrator",
        "actor_role": "Orchestrator"
    })
```

## Security Considerations

1. **Default Roles**: Tools without explicit `allowed_roles` are restricted to `default_allowed_roles`
2. **High-Cost Protection**: Image/video/audio generation tools require explicit approval
3. **User Approval**: Destructive operations require `user_approved: true`
4. **SSRF Protection**: Website fetching tools are protected against SSRF attacks
5. **Rate Limiting**: Prevents abuse and DoS attacks
6. **Audit Logging**: All operations are logged for security auditing

## Migration Notes

### Removed Tools

The following tools have been removed as part of cleanup:
- Automation tools (automation_trigger, automation_validate, etc.)
- Inbox tools (inbox_get_thread, inbox_reply, etc.)
- File tools (file_search_local, file_preview, etc.)
- Workflow supervisor proxies (support_supervisor, marketing_supervisor, etc.)
- Workflow dot-aliases (support.workflow, marketing.workflow, etc.)

These were removed because:
- They were not properly configured
- They duplicated functionality
- They don't fit the "MCP = Core Tools" architecture

### New Features

- **High-Cost Tool Protection**: Automatic detection and approval requirement
- **Default Role Enforcement**: Tools without explicit roles use default_allowed_roles
- **Dynamic Discovery**: `/mcp/discovery` now dynamically lists tools
- **Cost Policy Module**: Centralized high-cost tool detection

## Support

For issues or questions:
1. Check this documentation
2. Review `docs/ARCHITECTURE.md` for architecture details
3. Review `docs/ERROR_HANDLING.md` for error handling
4. Review `docs/OBSERVABILITY.md` for observability features

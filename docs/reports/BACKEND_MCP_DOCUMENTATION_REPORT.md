# Backend & MCP Server Dokumentations-Update Bericht

**Datum**: 2025-01-13  
**Umfang**: Vollständige Aktualisierung der Python Backend und MCP Server Dokumentationen

## 📋 Zusammenfassung

Beide Dokumentationen wurden vollständig überarbeitet und reflektieren den aktuellen Code-Stand. Alle neuen Features, API-Endpoints, Tools und Konfigurationen sind dokumentiert.

## 🔄 Änderungen nach Repository

### Backend (backend-agents)

#### README.md
**Status**: ✅ Vollständig neu geschrieben

**Neue Inhalte**:
- **Vollständige Environment-Variablen Liste** mit allen MCP-Einstellungen
- **Detaillierte API-Endpoint Liste** mit allen Phasen (1-10)
- **CRM Phase 1-10 vollständig dokumentiert**:
  - Phase 1-3: Core CRM operations
  - Phase 4-6: Extended features
  - Phase 7: Admin operations
  - Phase 8: Import/Export
  - Phase 9: Reporting
  - Phase 10: Governance, Webhooks, Custom Objects
- **MCP Integration Details**:
  - Connection Management
  - Tool Filtering
  - Configuration
  - Fail-Soft Behavior
- **Health Check Endpoint** Dokumentation
- **Struktur-Übersicht** mit allen Modulen
- **Authentication Details** für Memory API und MCP

**Struktur-Updates**:
- Alle API-Module dokumentiert
- CRM Service Layer vollständig aufgelistet
- MCP Client Details
- Agent-Struktur aktualisiert

### MCP-Server

#### README.md
**Status**: ✅ Vollständig neu geschrieben

**Neue Inhalte**:
- **Vollständige Tool-Liste** (60+ Tools):
  - Memory Tools (5)
  - CRM Tools Phase 1-3 (25+)
  - CRM Tools Phase 7-10 (15+)
  - Workflow Tools (5)
  - Website Tools (1)
- **Security & Permissions**:
  - User Approval Required Tools
  - Role-Based Access Control
  - Default Allowed Roles
- **Rate Limiting Details**:
  - Default: 120 req/min
  - Per Actor: 60 req/min
  - Configurable per tool
- **Configuration Details**:
  - server.yaml Structure
  - Tenant Configuration
  - Service URLs
- **Error Handling**:
  - Error Types
  - Error Handling Strategy
- **Observability**:
  - Audit Logging
  - Metrics
  - Performance Tracking
- **Integration Details**:
  - Backend Configuration
  - Connection Management
  - Tool Usage Examples
- **Development Guide**:
  - Adding New Tools
  - Backend Service URLs
  - Troubleshooting

## 📊 Vollständige Tool-Liste (MCP Server)

### Memory Tools (5)
1. `memory_search` / `memory.search` - Search memories
2. `memory_write` / `memory.write` - Write memory
3. `memory_delete` - Delete memory (approval required)
4. `memory_archive` - Archive memory (approval required)
5. `memory_telemetry` - Get telemetry

### CRM Tools Phase 1-3 (25+)
1. `crm_lookup_customer` - Lookup customer
2. `crm_search_customers` - Search customers
3. `crm_create_note` - Create note (approval)
4. `crm_update_pipeline` - Update pipeline (approval)
5. `crm_link_entities` - Link entities (approval)
6. `crm_list_associations` - List associations
7. `crm_get_timeline` - Get timeline
8. `crm_define_pipeline` - Define pipeline (approval)
9. `crm_list_pipelines` - List pipelines
10. `crm_upsert_contact` - Upsert contact (approval)
11. `crm_upsert_company` - Upsert company (approval)
12. `crm_create_deal` - Create deal (approval)
13. `crm_merge_contacts` - Merge contacts (admin)
14. `crm_audit_query` - Audit query (restricted)
15. `crm_events_pull` - Pull events (restricted)
16. `crm_events_ack` - Acknowledge events (restricted)
17. `crm_create_task` - Create task (approval)
18. `crm_complete_task` - Complete task (approval)
19. `crm_log_call` - Log call (approval)
20. `crm_log_meeting` - Log meeting (approval)
21. `crm_define_property` - Define property (approval)
22. `crm_set_property` - Set property (approval)
23. `crm_search_advanced` - Advanced search
24. `crm_create_segment` - Create segment (approval)

### CRM Tools Phase 7 - Admin (5)
1. `crm_create_api_key` - Create API key (admin)
2. `crm_upsert_user` - Upsert user (admin)
3. `crm_create_team` - Create team (admin)
4. `crm_add_team_member` - Add team member (admin)
5. `crm_assign_owner` - Assign owner

### CRM Tools Phase 8 - Import/Export (3)
1. `crm_import_contacts_csv` - Import contacts
2. `crm_export_contacts_csv` - Export contacts
3. `crm_merge_contacts` - Merge contacts (admin)

### CRM Tools Phase 9 - Reporting (3)
1. `crm_log_email_engagement` - Log email
2. `crm_report_pipeline` - Pipeline report
3. `crm_forecast_pipeline` - Forecast report

### CRM Tools Phase 10 - Governance (10)
1. `crm_gdpr_export_contact_data` - GDPR export (admin)
2. `crm_gdpr_delete_contact` - GDPR delete (admin, approval)
3. `crm_gdpr_blocklist_email` - Blocklist email (admin)
4. `crm_webhook_create` - Create webhook (approval)
5. `crm_webhook_list` - List webhooks
6. `crm_webhook_disable` - Disable webhook (approval)
7. `crm_webhook_dispatch` - Dispatch webhook
8. `crm_define_object_type` - Define custom object (approval)
9. `crm_create_object_record` - Create custom object (approval)
10. `crm_get_object_record` - Get custom object
11. `crm_update_object_record` - Update custom object (approval)

### Workflow Tools (5)
1. `support.workflow` - Support workflow
2. `marketing.workflow` - Marketing workflow
3. `website.workflow` - Website workflow
4. `backoffice.workflow` - Backoffice workflow
5. `onboarding.workflow` - Onboarding workflow

### Website Tools (1)
1. `website.fetch` - Fetch URL (SSRF-protected)

**Gesamt: 60+ Tools**

## 📡 Backend API-Endpoints Übersicht

### Core (3)
- `POST /chat` - Chat processing
- `POST /chat/stream` - Streaming chat (SSE)
- `GET /health` - Health check

### Memory (5)
- `POST /memory/write` - Save memory
- `POST /memory/search` - Search memories
- `POST /memory/delete` - Delete memory
- `POST /memory/archive` - Archive memory
- `GET /memory/{id}` - Get memory

### MCP Endpoints (2)
- `POST /mcp/memory/*` - Memory MCP tools
- `POST /mcp/crm/*` - CRM MCP tools (Phase 1-10)

### Domain Workflows (5)
- `POST /support/workflow`
- `POST /marketing/workflow`
- `POST /website/workflow`
- `POST /backoffice/workflow`
- `POST /onboarding/workflow`

### CRM API (40+ Endpoints)

#### Phase 1-3 (Core - 10)
- `POST /crm/workflow`
- `GET /crm/lookup_customer`
- `POST /crm/search_customers`
- `POST /crm/create_note`
- `POST /crm/update_pipeline`
- `POST /crm/link_entities`
- `POST /crm/list_associations`
- `POST /crm/timeline`
- `POST /crm/define_pipeline`
- `POST /crm/list_pipelines`
- `POST /crm/upsert_contact`
- `POST /crm/upsert_company`
- `POST /crm/create_deal`
- `POST /crm/audit_query`
- `POST /crm/events_pull`
- `POST /crm/events_ack`
- `POST /crm/create_task`
- `POST /crm/complete_task`
- `POST /crm/log_call`
- `POST /crm/log_meeting`
- `POST /crm/define_property`
- `POST /crm/set_property`
- `POST /crm/search_advanced`
- `POST /crm/create_segment`

#### Phase 7 - Admin (5)
- `POST /crm/admin/create_api_key`
- `POST /crm/admin/upsert_user`
- `POST /crm/admin/create_team`
- `POST /crm/admin/add_team_member`
- `POST /crm/admin/assign_owner`

#### Phase 8 - Import/Export (3)
- `POST /crm/import/contacts_csv`
- `POST /crm/export/contacts_csv`
- `POST /crm/dedupe/merge_contacts`

#### Phase 9 - Reporting (3)
- `POST /crm/engagements/log_email`
- `POST /crm/reports/pipeline`
- `POST /crm/forecast/pipeline`

#### Phase 10 - Governance (10)
- `POST /crm/gdpr/export_contact_data`
- `POST /crm/gdpr/delete_contact`
- `POST /crm/gdpr/blocklist_email`
- `POST /crm/webhook_create`
- `POST /crm/webhook_list`
- `POST /crm/webhook_disable`
- `POST /crm/webhook_dispatch`
- `POST /crm/define_object_type`
- `POST /crm/create_object_record`
- `POST /crm/get_object_record`
- `POST /crm/update_object_record`

### Other APIs (3)
- `POST /audio/transcribe` - Audio transcription
- `POST /operator_inbox/*` - Operator inbox
- `POST /feedback/*` - Feedback

**Gesamt: 60+ API-Endpoints**

## 🔐 Authentication & Security

### Memory API
- **Method**: Bearer Token
- **Header**: `Authorization: Bearer <MEMORY_API_SECRET>`
- **Required in**: Frontend, Backend (identisch)

### MCP Server
- **Method**: Bearer Token (optional)
- **Header**: `Authorization: Bearer <MCP_SERVER_TOKEN>`
- **Config**: `config/server.yaml`
- **Rate Limiting**: Per-tool, per-role, per-actor

### Tool Permissions
- **User Approval Required**: Write/Delete operations
- **Role-Based**: Restricted to specific roles
- **Admin-Only**: Administrative operations

## 🏗️ Architektur-Updates

### Backend Structure
```
backend-agents/
├── app/
│   ├── ai_agents/          # Agent implementations
│   │   ├── core/           # Core agents & supervisors
│   │   ├── support/        # Support domain
│   │   ├── marketing/      # Marketing domain
│   │   ├── backoffice/     # Backoffice domain
│   │   ├── website/        # Website domain
│   │   ├── crm/            # CRM domain
│   │   ├── analysis/       # Analysis agents
│   │   ├── research/       # Research agents
│   │   └── onboarding/     # Onboarding
│   ├── api/                # API endpoints (25+ files)
│   ├── mcp/                # MCP client integration
│   ├── crm/                # CRM service layer (15+ files)
│   ├── memory/             # Memory service
│   ├── conversation/        # Conversation management
│   ├── vector/             # Vector search
│   └── llm/                # LLM interface & audit
```

### MCP Server Structure
```
mcp-server/
├── mcp_server/
│   ├── server.py           # Main server (2500+ lines, 60+ tools)
│   ├── config.py           # Configuration loader
│   ├── rate_limits.py      # Rate limiting
│   ├── observability.py    # Audit & metrics
│   ├── security.py         # Security utilities
│   ├── crm_tools_ext.py    # Extended CRM tools
│   ├── website_fetch_tools.py  # Website tools
│   └── tool_aliases.py     # Dot-notation aliases
├── config/
│   └── server.yaml         # Tenant & security config
└── scripts/                # CLI helpers
```

## 🔧 Neue Features dokumentiert

### Backend
- ✅ MCP Server Integration (vollständig)
- ✅ CRM Phase 1-10 (vollständig)
- ✅ Advanced Rate Limiting
- ✅ LLM Audit Logging
- ✅ Feedback System
- ✅ Onboarding Flow
- ✅ Conversation Management
- ✅ Vector Search
- ✅ Audio Transcription (OpenAI Whisper)
- ✅ Health Check mit MCP Status

### MCP-Server
- ✅ 60+ Tools dokumentiert
- ✅ Advanced Rate Limiting
- ✅ Observability & Audit Logging
- ✅ Multi-tenant Support
- ✅ Role-based Access Control
- ✅ User Approval System
- ✅ SSRF Protection
- ✅ Error Handling
- ✅ Dot-notation Aliases
- ✅ Extended CRM Tools

## 📝 Environment Variables

### Backend (.env)
```env
# OpenAI
OPENAI_API_KEY=<key>
OPENAI_DEFAULT_MODEL=gpt-4.1-mini
AUDIO_TRANSCRIBE_MODEL=gpt-4o-mini-transcribe

# Database
DATABASE_URL=postgresql://...

# Memory API
MEMORY_API_SECRET=<secret>

# MCP Server
MCP_SERVER_URL=http://localhost:9000/mcp
MCP_SERVER_TOKEN=<optional>
ENABLE_MCP_TOOLS=true
MCP_NAME=simple-gpt-mcp
MCP_MAX_RETRY_ATTEMPTS=3
MCP_RETRY_BACKOFF_SECONDS_BASE=0.5
MCP_CLIENT_SESSION_TIMEOUT_SECONDS=20.0

# Agents
ENABLE_AGENTS_V2=true
APP_ENV=development
```

### MCP Server
```env
MCP_SERVER_CONFIG=config/server.yaml
MCP_SERVER_HOST=127.0.0.1
MCP_SERVER_PORT=9000
```

## ✅ Checkliste

- [x] Backend README.md vollständig aktualisiert
- [x] MCP Server README.md vollständig aktualisiert
- [x] Alle API-Endpoints dokumentiert
- [x] Alle Tools dokumentiert (60+)
- [x] CRM Phase 1-10 vollständig dokumentiert
- [x] MCP Integration Details dokumentiert
- [x] Authentication Details dokumentiert
- [x] Security & Permissions dokumentiert
- [x] Rate Limiting dokumentiert
- [x] Observability dokumentiert
- [x] Error Handling dokumentiert
- [x] Environment Variables dokumentiert
- [x] Architecture-Struktur aktualisiert
- [x] Troubleshooting Guides hinzugefügt

## 📌 Wichtige Hinweise

1. **MCP Connection**: Wird automatisch beim Backend-Startup hergestellt (wenn `ENABLE_MCP_TOOLS=true`)
2. **Fail-Soft**: Backend läuft auch ohne MCP-Verbindung
3. **Tool Filtering**: Tools werden basierend auf Policies gefiltert
4. **User Approval**: Write/Delete Operations benötigen `user_approved: true`
5. **Rate Limiting**: Backend hat 120 req/min, MCP-Server hat per-tool limits
6. **CRM Phases**: Phase 1-10 sind vollständig implementiert und über MCP verfügbar
7. **Health Check**: Zeigt MCP-Status an

## 🎯 Nächste Schritte

### Empfohlene weitere Updates

1. **Backend DOCUMENTATION.md**
   - MCP Integration Details erweitern
   - CRM Phase 1-10 Features detailliert dokumentieren
   - API-Endpoint Details mit Request/Response Examples

2. **MCP Server docs/**
   - Tool-Dokumentation für alle Tools mit Examples
   - Rate Limiting Best Practices
   - Security Guidelines erweitern
   - Troubleshooting erweitern

3. **API Documentation**
   - OpenAPI/Swagger Specs generieren
   - Request/Response Examples
   - Error Codes dokumentieren

---

**Erstellt von**: AI Assistant  
**Datum**: 2025-01-13  
**Version**: 2.0


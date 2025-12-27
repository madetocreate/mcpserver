# MCP Server - Vollständige Dokumentation

## Übersicht

Der MCP (Model Context Protocol) Server bietet Tool-Zugriff für AI Agents mit CRM, Memory, und anderen Integrations.

## 🏗️ Architektur

### MCP Protocol

- **Tools**: Exponierte Funktionen für Agents
- **Resources**: Zugreifbare Ressourcen
- **Prompts**: Vordefinierte Prompts

### Struktur

```
mcp-server/
├── src/
│   ├── tools/              # Tool Implementations
│   ├── resources/           # Resource Handlers
│   ├── prompts/             # Prompt Templates
│   └── server.ts            # MCP Server Setup
├── docs/                    # Dokumentation
└── package.json
```

## 📋 Features

### ✅ Implementiert

- ✅ CRM Tools (Contacts, Companies, Deals, etc.)
- ✅ Memory Tools (Search, Write)
- ✅ Resource Access
- ✅ Prompt Templates

## 🔧 Setup & Installation

### Voraussetzungen

- Node.js 18+
- npm oder yarn

### Installation

```bash
# Dependencies installieren
npm install

# Build
npm run build
```

### Development

```bash
# Development Server
npm run dev

# Watch Mode
npm run watch
```

## 📚 MCP Tools

### CRM Tools

- `crm_create_contact` - Create contact
- `crm_update_contact` - Update contact
- `crm_search_contacts` - Search contacts
- `crm_create_deal` - Create deal
- `crm_update_deal` - Update deal
- ... (weitere CRM Tools)

### Memory Tools

- `memory_search` - Search memory
- `memory_write` - Write to memory

## 🔍 Resources

- CRM Resources (Contacts, Companies, Deals)
- Memory Resources

## 📖 Weitere Dokumentation

- [Complete Guide](docs/COMPLETE_GUIDE.md)
- [Architecture](docs/ARCHITECTURE.md)

## 🤝 Contributing

1. Fork das Repository
2. Erstelle einen Feature Branch
3. Committe deine Änderungen
4. Push zum Branch
5. Erstelle einen Pull Request

## 📝 License

Proprietary - Alle Rechte vorbehalten


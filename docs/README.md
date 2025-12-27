# MCP Server Dokumentation

**Zweck**: MCP (Model Context Protocol) Server, der interne Backend-Services (Memory, CRM) als Tools für AI Agents bereitstellt. Tool Gateway - keine Workflow Agents oder Supervisors.

## 📚 Dokumentations-Index

### Setup & Installation
- [Complete Guide](./COMPLETE_GUIDE.md) - Vollständiger Setup-Guide
- [Dev Testing](../DEV_TESTING.md) - Development Testing

### Architecture
- [Architecture](./ARCHITECTURE.md) - System-Architektur
- [Complete Guide](./COMPLETE_GUIDE.md) - Umfassende Dokumentation mit Beispielen
- [Engineering Baseline](./engineering/BASELINE.md) - Engineering Baseline
- [Engineering Changelog](./engineering/CHANGELOG_HARDENING.md) - Hardening Changelog

### Operations
- [Observability](./OBSERVABILITY.md) - Metrics und Logging
- [Error Handling](./ERROR_HANDLING.md) - Error Handling Patterns

### Security
- [Code Review Enterprise](./CODE_REVIEW_ENTERPRISE.md) - Enterprise Code Review

### Product & Features
- [Complete Guide](./COMPLETE_GUIDE.md) - Vollständige Feature-Dokumentation
  - Memory Tools
  - CRM Tools (Phase 1-10)
  - Website Tools
  - Observability Tools
  - Rate Limiting
  - Security & Permissions

### Reports & Status
- [Backend MCP Documentation Report](./reports/BACKEND_MCP_DOCUMENTATION_REPORT.md) - MCP Dokumentation (aus docus)
- [MCP Server Refactor Report](../MCP_SERVER_REFACTOR_REPORT.md) - Refactoring-Report
- [Complete Documentation](../COMPLETE_DOCUMENTATION.md) - Vollständige Dokumentation

## 📝 Where to put new docs

**WICHTIG**: Neue Dokumentation gehört nach `/docs` in die passenden Unterordner:

- **Setup/Installation** → `docs/setup/`
- **Architektur/Design** → `docs/architecture/`
- **Operations/Runbooks** → `docs/ops/`
- **Security** → `docs/security/`
- **Product Features** → `docs/product/`
- **UI/Design** → `docs/ui/`
- **Reports/Status** → `docs/reports/`

**Ausnahmen**:
- Subsystem-spezifische READMEs bleiben beim Code (z.B. `src/*/README.md`)
- Root-Dateien: Nur `README.md`, `LICENSE`, `CHANGELOG.md`, `SECURITY.md`, `CONTRIBUTING.md` sind erlaubt

**Beispiele**:
- Neue Setup-Anleitung → `docs/setup/NEW_FEATURE_SETUP.md`
- Architektur-Dokument → `docs/architecture/NEW_COMPONENT.md`
- Security Audit → `docs/security/AUDIT_2025.md`
- Feature-Dokumentation → `docs/product/FEATURE_NAME.md`

## 🔗 Weitere Ressourcen

- [Root README](../README.md) - Haupt-README mit Quick Start
- [Complete Guide](./COMPLETE_GUIDE.md) - Umfassende Dokumentation


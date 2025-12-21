# Changelog - MCP Server Hardening

Dieses Dokument trackt alle Security- und Reliability-Verbesserungen im MCP Server.

## Format

Jeder Eintrag enthält:
- **Datum:** YYYY-MM-DD
- **Task:** Referenz zur Aufgabe
- **Problem:** Was war das Problem?
- **Risiko:** Niedrig/Mittel/Hoch
- **Änderung:** Was wurde geändert?
- **Tests:** Wie wurde getestet?
- **Ergebnis:** Status (✅ Erfolg / ⚠️ Teilweise / ❌ Fehlgeschlagen)
- **Files changed:** Liste der geänderten Dateien

---

## 2025-01-18 - Baseline & Inventory

**Task:** (0) BASELINE & INVENTORY

**Problem:** Keine strukturierte Baseline-Dokumentation vorhanden.

**Risiko:** N/A

**Änderung:** 
- Baseline-Dokumentation erstellt (`docs/engineering/BASELINE.md`)
- Alle identifizierten Probleme katalogisiert
- Backup-Verzeichnis erstellt (`/Users/simple-gpt/Documents/BACKUPS/`)

**Tests:** 
- Repo-Struktur analysiert
- Problem-Stellen identifiziert via grep/codebase_search
- Port-Mismatch dokumentiert

**Ergebnis:** ✅ Erfolg

**Files changed:**
- `/Users/simple-gpt/mcp-server/docs/engineering/BASELINE.md` (neu)
- `/Users/simple-gpt/mcp-server/docs/engineering/CHANGELOG_HARDENING.md` (neu)

---

## 2025-01-18 - SSRF Redirect-Bypass Prevention (Task #4)

**Task:** (4) SOFORT #4: SSRF Redirect-Bypass schließen

**Problem:**
- `website_fetch` Tool nutzte `follow_redirects=True` ohne Validierung der Redirect-URLs
- `_is_blocked_host()` wurde nur vor dem ersten Request geprüft
- Angreifer konnte "public URL → redirect → private IP" nutzen, um SSRF-Protection zu umgehen

**Risiko:** HOCH - SSRF-Bypass möglich durch Redirects

**Änderung:**
- `follow_redirects=False` gesetzt in httpx.AsyncClient
- Manuelles Redirect-Following implementiert:
  - `_validate_redirect_url()`: Validiert jede Redirect-URL gegen SSRF-Protection
  - max_redirects = 5 (verhindert Redirect-Loops)
  - Jede Location-URL wird erneut mit `_is_blocked_host()` geprüft
  - Relative Redirects werden korrekt aufgelöst
- Redirect-Logik:
  - Prüft Status-Codes 301, 302, 303, 307, 308
  - Validiert Location-Header
  - Blockiert Redirects auf private IPs/localhost
  - Erlaubt nur Redirects auf öffentliche IPs

**Tests:**
- Unit-Tests erstellt: `tests/test_website_fetch_ssrf.py`
- Tests für: Redirect auf private IPs (blockiert), Redirect auf localhost (blockiert), Redirect auf öffentliche IPs (erlaubt), relative Redirects, zu viele Redirects

**Ergebnis:** ✅ Erfolg

**Files changed:**
- `/Users/simple-gpt/mcp-server/mcp_server/website_fetch_tools.py` (geändert)
- `/Users/simple-gpt/mcp-server/tests/test_website_fetch_ssrf.py` (neu)

**Hinweis:** DNS-Rebinding-Härtung ist dokumentiert, aber nicht implementiert (kann in zukünftiger Verbesserung folgen).

---


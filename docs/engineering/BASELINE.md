# Baseline & Inventory - MCP Server Hardening

**Datum:** 2025-01-18  
**Umgebung:** macOS 24.6.0, Python 3.13.6, zsh  
**Codebase:** `/Users/simple-gpt/mcp-server/`

## 1. Repo-Struktur

```
mcp-server/
├── mcp_server/
│   ├── main.py              # ⚠️ Uvicorn Monkeypatch
│   ├── server.py            # ⚠️ Default bind 0.0.0.0:9000
│   ├── security.py          # ⚠️ Auth ist Stub
│   ├── rate_limits.py       # ⚠️ Lock nicht genutzt
│   └── website_fetch_tools.py # ⚠️ SSRF Redirect-Bypass
├── Dockerfile               # ⚠️ EXPOSE 8000 (Server läuft auf 9000)
├── config/
│   ├── server.yaml
│   └── server.local.yaml
├── tests/
└── pyproject.toml
```

## 2. Baseline Checks

### 2.1 Python Version
```bash
python3 --version
# Python 3.13.6
```

### 2.2 Tool Installation Status
- **ruff**: Nicht installiert (sollte via dev-dependencies installiert werden)
- **pytest**: Nicht installiert (sollte via dev-dependencies installiert werden)

**Hinweis:** Tools müssen in venv installiert werden, bevor Tests/Lint laufen können.

## 3. Identifizierte Probleme

### 3.1 SOFORT #4: SSRF Redirect-Bypass
**Datei:** `mcp_server/website_fetch_tools.py`

**Problem:**
- Zeile 99: `follow_redirects=True` ohne Validierung der Redirect-URLs
- `_is_blocked_host()` wird nur vor dem ersten Request geprüft (Zeile 93)
- Angreifer kann "public URL → redirect → private IP" nutzen

**Risiko:** Hoch - SSRF-Bypass möglich

**Betroffenes Tool:**
- `website.fetch` (MCP Tool)

### 3.2 KURZFRISTIG #5: Port-Konsistenz
**Dateien:** `Dockerfile`, `mcp_server/server.py`, `mcp_server/main.py`

**Problem:**
- Dockerfile Zeile 13: `EXPOSE 8000`
- Server default: Port 9000 (via `MCP_SERVER_PORT` env oder `server_cfg.get("port", 9000)`)
- README/Docs: Referenzieren 9000
- Main.py Zeile 121: Hardcoded `http://0.0.0.0:9000/mcp`

**Risiko:** Niedrig - Verwirrung, aber funktional

### 3.3 KURZFRISTIG #6: MCP Auth Stub
**Datei:** `mcp_server/security.py`

**Problem:**
- `AuthBackend.authenticate()` gibt einfach `actor`/`actor_role` aus Payload zurück (Zeile 30-36)
- Keine echte Verifikation (JWT/Token/etc.)
- `AuthConfig.mode` default ist "none"

**Risiko:** Mittel - In falscher Umgebung "open by accident"

**Zusätzlich:**
- Server bindet default auf `0.0.0.0` (Zeile 259 in server.py)
- Keine Host-Whitelist

### 3.4 Weitere Probleme (Mittelfristig)

#### RateLimiter Lock nicht genutzt
**Datei:** `mcp_server/rate_limits.py`

**Problem:**
- Lock existiert (Zeile 44: `self._lock = threading.Lock()`)
- Wird aber nicht in `check()` genutzt (Zeile 57-82)
- `_get_bucket()` und `check_and_increment()` sind ungeschützt

**Risiko:** Mittel - Race-Conditions bei Concurrency möglich

#### Uvicorn Monkeypatch
**Datei:** `mcp_server/main.py`

**Problem:**
- Zeile 48-117: Patched `uvicorn.Config.__init__` für:
  - Accept-Header-Fix (Zeile 92-103)
  - /mcp/discovery Endpoint (Zeile 76-88)
  - Logging (Zeile 60-73)
- Version-fragil, schwer wartbar

**Risiko:** Niedrig-Mittel - Upgrade-Probleme bei uvicorn-Updates

## 4. Baseline Test-Status

**Status:** Tests können nicht ausgeführt werden, da pytest nicht installiert ist.

**Vorhandene Tests:**
- `tests/test_cost_policy.py`
- `tests/test_memory_search.py`
- `tests/test_permissions_and_rate_limiter.py`

**Nächste Schritte:**
1. venv erstellen und Dependencies installieren
2. Tests ausführen und Baseline-Ergebnisse dokumentieren
3. Lint ausführen und Baseline-Ergebnisse dokumentieren

## 5. Backup-Verzeichnis

**Pfad:** `/Users/simple-gpt/Documents/BACKUPS/`

**Status:** Verzeichnis erstellt, bereit für Snapshots vor Änderungen.

## 6. Nächste Schritte

1. ✅ Baseline-Dokumentation erstellt
2. ⏭️ Task (4): SSRF Redirect-Bypass schließen
3. ⏭️ Task (5): Port-Konsistenz
4. ⏭️ Task (6): MCP Auth End-to-End
5. ⏭️ Task (10): RateLimiter Thread-Safety
6. ⏭️ Task (11): Uvicorn Monkeypatch ersetzen

## 7. Dateien geändert

- ✅ `/Users/simple-gpt/mcp-server/docs/engineering/BASELINE.md` (neu erstellt)


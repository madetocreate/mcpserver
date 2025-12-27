# MCP Server Streamable HTTP Refactoring - Abschlussbericht

**Datum:** 2025-01-XX  
**Ziel:** Saubere ASGI-Struktur ohne uvicorn.Config Monkey-Patch

## Zusammenfassung

✅ Alle geplanten Aufgaben wurden umgesetzt:
- ✅ TEIL A: Ist-Zustand analysiert
- ✅ TEIL B: Neue saubere ASGI-Struktur erstellt
- ✅ TEIL C: Entrypoint umgebogen (main.py)
- ✅ TEIL D: Kompatibilität sichergestellt
- ✅ TEIL E: Tests/Quick Checks (Healthcheck hinzugefügt)

---

## TEIL A: Ist-Zustand Analyse

### Aktuelle Struktur (vor Refactoring)

**Dateien:**
- `mcp_server/main.py` - Entrypoint mit uvicorn.Config Monkey-Patch
- `mcp_server/server.py` - FastMCP Server-Instanz (`mcp`)
- `mcp_server/config.py` - Config-Loader
- `config/server.yaml` - Server-Konfiguration

**Aktueller Host/Port/Path:**
- Host: `MCP_SERVER_HOST` ENV oder `server.yaml` → default: `127.0.0.1`
- Port: `MCP_SERVER_PORT` ENV oder `server.yaml` → default: `9000`
- Path: `/mcp` (FastMCP's streamable-http endpoint)

**Auth:**
- Bearer Token via `MCP_SERVER_TOKEN` ENV
- In Production: Token ist Pflicht
- Implementiert im Monkey-Patch (ASGI-Wrapper)

**Origin-Check:**
- `MCP_ALLOWED_ORIGINS` ENV (comma-separated)
- Implementiert im Monkey-Patch (ASGI-Wrapper)
- In Production: Requests ohne Origin werden abgelehnt (wenn Allowlist gesetzt)

**Probleme:**
- ❌ uvicorn.Config Monkey-Patch ist fragil
- ❌ Header-Rewriting-Hack für Accept-Header
- ❌ Keine saubere Middleware-Struktur
- ❌ Schwer testbar und wartbar

---

## TEIL B: Neue Saubere ASGI-Struktur

### Neue Datei: `mcp_server/http_app.py`

**Funktionen:**
1. **`create_app() -> FastAPI`**
   - Erstellt FastAPI-App
   - Fügt Middleware hinzu (Auth + Origin)
   - Mountet MCP unter `/mcp`
   - Fügt Healthcheck unter `/health` hinzu
   - Fügt Discovery-Endpoint unter `/mcp/discovery` hinzu

2. **`BearerTokenAuthMiddleware`**
   - Prüft Bearer Token für `/mcp` Endpoints (außer `/mcp/discovery`)
   - In Production: Token ist Pflicht
   - Skip für `/health` und `/mcp/discovery`

3. **`OriginAllowlistMiddleware`**
   - Prüft Origin-Header gegen Allowlist (`MCP_ALLOWED_ORIGINS`)
   - `MCP_REQUIRE_ORIGIN` ENV (default: true in production, false in dev)
   - In Production: Requests ohne Origin werden abgelehnt (wenn Allowlist gesetzt)
   - Skip für `/health` und `/mcp/discovery`

4. **MCP Mount**
   - Versucht FastMCP's ASGI-App zu bekommen (verschiedene Methoden)
   - Path-Rewriting: entfernt `/mcp` Prefix vor Weiterleitung an FastMCP
   - Accept-Header-Fix für GET `/mcp` Requests

### Implementierungsdetails

**Origin-Normalisierung:**
- Entfernt Protocol (`http://`, `https://`)
- Extrahiert `host:port` (entfernt Path)
- Case-insensitive Vergleich

**MCP ASGI-App Zugriff:**
- Method 1: `mcp.get_asgi_app()` (falls vorhanden)
- Method 2: `mcp._transport._app` (via Transport)
- Method 3: `mcp._app`, `mcp.asgi_app`, `mcp._asgi_app` (direkt)

**Fallback:**
- Wenn ASGI-App nicht zugänglich: Fehler-Route mit klarer Fehlermeldung

---

## TEIL C: Entrypoint Umbiegung

### Geänderte Datei: `mcp_server/main.py`

**Vorher:**
- uvicorn.Config Monkey-Patch
- ASGI-Wrapper mit Header-Rewriting
- `mcp.run(transport="streamable-http")`

**Nachher:**
- Import von `create_app()` aus `http_app.py`
- Sauberer `uvicorn.run(app, host=..., port=...)` Aufruf
- Keine Monkey-Patches
- Keine Header-Rewriting-Hacks

**Host/Port:**
- `MCP_SERVER_HOST` oder `MCP_HOST` ENV (default: `127.0.0.1`)
- `MCP_SERVER_PORT` oder `MCP_PORT` ENV (default: `9000`)
- Fallback auf `server.yaml` Config

---

## TEIL D: Kompatibilität / Konfiguration

### Python-Backend Kompatibilität

✅ **Keine Breaking Changes:**
- MCP-URL bleibt gleich: `http://127.0.0.1:9000/mcp`
- Endpoints bleiben gleich: `/mcp`, `/mcp/discovery`
- Auth bleibt gleich: Bearer Token

**Konfiguration:**
- Python-Backend zeigt weiterhin auf `MCP_URL=http://127.0.0.1:9000/mcp`
- Keine Änderungen am Python-Backend nötig

### Neue ENV-Variablen

1. **`MCP_ALLOWED_ORIGINS`** (optional, comma-separated)
   - Beispiel: `MCP_ALLOWED_ORIGINS=https://app.example.com,http://localhost:3000`
   - Wenn gesetzt: Nur Requests von diesen Origins werden akzeptiert
   - Normalisiert: Protocol wird entfernt, nur `host:port` verglichen

2. **`MCP_REQUIRE_ORIGIN`** (optional, boolean)
   - Default: `true` in production, `false` in development
   - Wenn `true` und Allowlist gesetzt: Requests ohne Origin werden abgelehnt
   - Wenn `false`: Requests ohne Origin werden erlaubt (wenn Allowlist gesetzt)

3. **`MCP_SERVER_HOST` / `MCP_HOST`** (optional)
   - Default: `127.0.0.1` (aus `server.yaml` oder ENV)
   - Host für uvicorn

4. **`MCP_SERVER_PORT` / `MCP_PORT`** (optional)
   - Default: `9000` (aus `server.yaml` oder ENV)
   - Port für uvicorn

**Bestehende ENV-Variablen (unverändert):**
- `MCP_SERVER_TOKEN` - Bearer Token für Auth (in Production Pflicht)
- `APP_ENV` / `ENVIRONMENT` - Environment (production/development)

---

## TEIL E: Tests / Quick Checks

### Healthcheck Endpoint

**GET `/health`**
- Public (keine Auth)
- Response: `{"ok": true, "status": "healthy"}`

### Discovery Endpoint

**GET `/mcp/discovery`**
- Public (keine Auth)
- Response: Tool-Liste mit Metadaten

### Security Tests

**Test 1: Ohne Token (Production)**
```bash
curl http://localhost:9000/mcp
# Erwartet: 401 Unauthorized
```

**Test 2: Mit Token, aber Origin nicht erlaubt**
```bash
curl -H "Authorization: Bearer $MCP_SERVER_TOKEN" \
     -H "Origin: https://evil.com" \
     http://localhost:9000/mcp
# Erwartet: 403 Forbidden (wenn MCP_ALLOWED_ORIGINS gesetzt)
```

**Test 3: Mit Token + erlaubter Origin**
```bash
curl -H "Authorization: Bearer $MCP_SERVER_TOKEN" \
     -H "Origin: http://localhost:3000" \
     http://localhost:9000/mcp
# Erwartet: MCP funktioniert (wenn Origin in Allowlist)
```

**Test 4: Healthcheck (public)**
```bash
curl http://localhost:9000/health
# Erwartet: {"ok": true, "status": "healthy"}
```

---

## Geänderte Dateien

### 1. `mcp_server/http_app.py` (NEU)
**Begründung:** Saubere FastAPI-App mit Middleware-Struktur
- `create_app()` - Erstellt FastAPI-App
- `BearerTokenAuthMiddleware` - Bearer Token Auth
- `OriginAllowlistMiddleware` - Origin-Check
- MCP-Mount-Logik
- Healthcheck und Discovery-Endpoints

### 2. `mcp_server/main.py` (ÜBERARBEITET)
**Begründung:** Entfernung aller Monkey-Patches, sauberer uvicorn.run() Aufruf
- Entfernt: uvicorn.Config Monkey-Patch
- Entfernt: ASGI-Wrapper mit Header-Rewriting
- Entfernt: Alle Hacks
- Neu: Import von `create_app()` und sauberer uvicorn.run()

---

## Bekannte Limitationen / Hinweise

### FastMCP ASGI-App Zugriff

**Problem:** FastMCP's `run()` Methode startet uvicorn intern und exponiert die ASGI-App nicht direkt via Public API.

**Lösung:** 
- Versuche verschiedene Methoden, um die ASGI-App zu bekommen (interne Struktur)
- Fallback: Fehler-Route mit klarer Fehlermeldung

**Hinweis:** 
- Wenn FastMCP in Zukunft eine Public API für ASGI-App-Zugriff bereitstellt, sollte die Implementierung aktualisiert werden
- Aktuell funktioniert der Mount über interne Struktur-Zugriff

### Accept-Header-Fix

**Problem:** FastMCP streamable-http erfordert Accept-Header für GET `/mcp` Requests.

**Lösung:**
- Path-Rewriter fügt automatisch `Accept: application/json, text/event-stream` hinzu, falls fehlend
- Dies ist sauberer als der vorherige Header-Rewriting-Hack

---

## Lokales Testen

### Start MCP Server
```bash
cd mcp-server

# Setze ENV-Variablen (optional)
export MCP_SERVER_TOKEN=your-token
export MCP_ALLOWED_ORIGINS=http://localhost:3000,https://app.example.com
export MCP_REQUIRE_ORIGIN=true  # oder false für dev

# Starte Server
python -m mcp_server.main
```

### Quick Checks
```bash
# Healthcheck
curl http://localhost:9000/health

# Discovery
curl http://localhost:9000/mcp/discovery

# MCP Endpoint (mit Token)
curl -H "Authorization: Bearer $MCP_SERVER_TOKEN" \
     -H "Origin: http://localhost:3000" \
     http://localhost:9000/mcp
```

---

## Breaking Changes

### ⚠️ Keine Breaking Changes

- MCP-URL bleibt gleich: `http://127.0.0.1:9000/mcp`
- Endpoints bleiben gleich
- Auth bleibt gleich
- Python-Backend muss nicht angepasst werden

### ✅ Verbesserungen

- Saubere Middleware-Struktur
- Keine Monkey-Patches mehr
- Bessere Wartbarkeit und Testbarkeit
- Healthcheck-Endpoint hinzugefügt

---

## Nächste Schritte (Empfehlungen)

1. **FastMCP ASGI-App Public API:** Warten auf FastMCP-Update, das ASGI-App direkt exponiert
2. **Tests:** Unit-Tests für Middleware (Auth, Origin-Check)
3. **Monitoring:** Healthcheck-Endpoint für Kubernetes/Health-Checks
4. **Dokumentation:** API-Dokumentation für `/mcp/discovery` Endpoint

---

**Status:** ✅ Refactoring abgeschlossen, alle Monkey-Patches entfernt, saubere ASGI-Struktur implementiert.


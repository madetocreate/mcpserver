# Release Notes - Launch Blocker Fixes

**Datum:** 2025-01-XX  
**Status:** ✅ Launch-Blocker behoben

---

## P0 Fixes

### 1. Runtime-Dependencies (FastAPI/Uvicorn) sicher installieren
- **Problem:** Container startete mit uvicorn + FastAPI, aber Dependencies waren nur in dev-deps
- **Fix:** FastAPI, uvicorn[standard], starlette in `[project].dependencies` verschoben
- **Dockerfile:** Installiert jetzt `pip install .` statt einzelne libs (nutzt pyproject.toml)
- **Verifikation:**
  ```bash
  docker build -t aklow-mcp .
  docker run --rm -p 8787:8787 -e INTERNAL_API_KEY=devkey aklow-mcp
  curl http://localhost:8787/health
  ```

### 2. Internal API Key korrekt an Python Backend senden
- **Problem:** MCP-Server las nur `BACKEND_INTERNAL_API_KEY`, Backend erwartet `INTERNAL_API_KEY`
- **Fix:** Fallback-Logik: `BACKEND_INTERNAL_API_KEY` oder `INTERNAL_API_KEY` (beide werden unterstützt)
- **Startup-Warnung:** Loggt WARN wenn kein Key gesetzt ist
- **Verifikation:**
  - Mit nur `INTERNAL_API_KEY` gesetzt: MCP-Server sendet Key trotzdem
  - Integrationstest: MCP call auf `/mcp/memory/search` klappt

### 3. Production-Modus robust erkennen
- **Problem:** "prod" wurde je nach Service über unterschiedliche ENV Variablen erkannt
- **Fix:** Gemeinsame Helper-Funktion `is_production_env()` in `mcp_server/env_utils.py`
  - Prüft: `ENVIRONMENT=production`, `APP_ENV=production`, `NODE_ENV=production`
  - Ersetzt verstreute Checks in `server.py` und `http_app.py`
- **Verifikation:**
  - Mit `NODE_ENV=production` allein gilt production
  - Mit `ENVIRONMENT=production` gilt production
  - Dev bleibt dev

---

## Testing

```bash
# Unit Tests
python -m pytest -q

# Health Check
python scripts/health_check.py

# Docker Build & Run
docker build -t aklow-mcp .
docker run --rm -p 8787:8787 \
  -e INTERNAL_API_KEY=devkey \
  -e BACKEND_INTERNAL_API_KEY=devkey \
  aklow-mcp

# Health Check
curl http://localhost:8787/health
```

---

## Breaking Changes

Keine. Alle Änderungen sind rückwärtskompatibel.


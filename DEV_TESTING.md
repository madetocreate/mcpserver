# DEV_TESTING.md - MCP Server

**Zweck:** Diese Dokumentation beschreibt, wie Tests, Linting und Smoke-Checks lokal ausgeführt werden, um dasselbe zu prüfen wie CI.

---

## Voraussetzungen

### Python-Umgebung

```bash
# Virtual Environment erstellen und aktivieren
python3 -m venv .venv
source .venv/bin/activate  # Linux/Mac
# oder: .venv\Scripts\activate  # Windows

# Dependencies installieren (inkl. Dev-Dependencies)
pip install -e ".[dev]"
```

### Erforderliche Umgebungsvariablen (optional, je nach Test)

Die meisten Tests sollten ohne echte Backend-Verbindung laufen (Mocking). Für Integration-Tests:

```bash
export BACKEND_URL="http://localhost:8000"  # Optional, für Integration-Tests
```

---

## Smoke-Test: Minimaler Check ("grün")

**Definition:** Diese Befehle müssen ohne Fehler durchlaufen, damit der Code als "grün" gilt.

### 1. Import-Check (schnellster Check)

Prüft, ob alle Module korrekt importierbar sind:

```bash
# Aus dem mcp-server Verzeichnis
python -c "import mcp_server; print('✓ Imports OK')"
```

### 2. Linting (ruff)

```bash
# Prüft Code-Qualität
ruff check .

# Optional: Auto-Fix
ruff check . --fix
```

**Erwartung:** Keine Fehler (Warnings sind OK, sollten aber reduziert werden).

### 3. Type-Checking (mypy)

```bash
# Prüft Type-Hints
mypy mcp_server
```

**Erwartung:** Keine Type-Errors (in dev-Dependencies enthalten).

### 4. Tests sammeln (ohne Ausführung)

```bash
# Prüft, ob pytest alle Tests finden kann
pytest --collect-only
```

**Erwartung:** Keine Import-Fehler, alle Tests werden gefunden.

### 5. Unit-Tests (schnell, ohne externe Dependencies)

```bash
# Alle Tests ausführen
pytest tests/ -v
```

**Erwartung:** Alle Tests laufen durch (mit Mocks, keine echten Backend-Calls).

---

## Vollständige Test-Suite

### Alle Tests

```bash
pytest tests/ -v
```

### Mit Coverage

```bash
pytest tests/ --cov=mcp_server --cov-report=html
# Report öffnen: open htmlcov/index.html
```

### Async-Tests

Tests mit `@pytest.mark.asyncio` werden automatisch von pytest-asyncio behandelt.

---

## Test-Struktur

Tests befinden sich in `tests/`:

- `test_cost_policy.py` - Cost Policy Tests
- `test_memory_search.py` - Memory Search Tests
- `test_permissions_and_rate_limiter.py` - RBAC und Rate Limiting Tests
- `test_website_fetch_ssrf.py` - SSRF Protection Tests

---

## CI-Script: Was CI prüft

Derzeit gibt es kein explizites CI-Script im Repo. Empfohlenes CI-Verhalten:

1. **Linting** (`ruff check .`)
2. **Type-Checking** (`mypy mcp_server`) - optional
3. **Tests** (`pytest tests/ -v`)

### Lokal CI-Checks simulieren

```bash
# Aus mcp-server Root
ruff check .
mypy mcp_server  # Optional
pytest tests/ -v
```

---

## Häufige Probleme

### Import-Fehler

- **Problem:** `ModuleNotFoundError: No module named 'mcp_server'`
- **Lösung:** Stelle sicher, dass das Paket installiert ist: `pip install -e ".[dev]"`

### Async-Fehler

- **Problem:** `RuntimeError: This event loop is already running`
- **Lösung:** Tests sollten `@pytest.mark.asyncio` verwenden (pytest-asyncio wird automatisch geladen).

### Fehlende Dependencies

- **Problem:** `ModuleNotFoundError` für externe Pakete
- **Lösung:** `pip install -e ".[dev]"` erneut ausführen.

---

## Smoke-Ziel Definition

**"Grün" bedeutet:**

1. ✅ `ruff check .` - Keine Fehler
2. ✅ `pytest --collect-only` - Alle Tests finden
3. ✅ `pytest tests/ -v` - Alle Tests laufen durch

**Optional (aber empfohlen):**

4. ✅ `mypy mcp_server` - Keine Type-Errors

**Empfohlener lokaler Workflow:**

```bash
# Vor jedem Commit
ruff check .
pytest tests/ -v

# Vor Push/PR
ruff check .
mypy mcp_server  # Optional
pytest tests/ -v
```

---

## Nächste Schritte

- Siehe auch: `README.md` für allgemeine Dokumentation
- Siehe auch: `docs/` für detaillierte Architektur-Dokumentation


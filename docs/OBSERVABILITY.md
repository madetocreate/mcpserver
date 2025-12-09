# Observability (logging, metrics, tracing)

## Logging

The server already emits structured JSON logs to stdout. In the dev extras of
`pyproject.toml` we prepare optional dependencies for richer structured logging:

- `structlog` for key/value logging and better JSON output.
- `ruff` and `mypy` for static analysis and type checking.

These are not wired into the server yet, but the recommended next step is to
replace `setup_logger` in `mcp_server/server.py` with a structlog-based
pipeline once the API surface is stable.

## Metrics

The dev extras also contain Prometheus-related tooling:

- `prometheus-fastapi-exporter` can expose an HTTP `/metrics` endpoint from the
  underlying ASGI app.
- `opentelemetry-instrumentation-fastapi` allows exporting metrics and traces
  via OpenTelemetry.

Because `FastMCP` controls the FastAPI or Starlette app, metrics are not
attached by default. A future step is to wrap the generated ASGI app with a
metrics middleware in the process that mounts the MCP server.

## Recommended next steps

1. Decide on a metrics backend (Prometheus, OTEL collector, SaaS).
2. Enable a `/metrics` endpoint on the ASGI app.
3. Configure a dashboard for:
   - request rate per tool
   - error rate per tool
   - latency per backend service
4. Wire trace IDs from OpenTelemetry into the log context.

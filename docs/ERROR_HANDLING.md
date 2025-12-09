# Error handling and resilience

The MCP server currently provides a basic resilience layer in `BackendClient`:

- each outbound request uses `httpx.AsyncClient`
- transient failures are retried with exponential backoff
- HTTP 5xx and 429 responses are normalised into `BackendError`

On top of that the tool wrapper `_call_backend_tool`:

- records the duration of each backend call
- logs failures with consistent metadata (tool, tenant, actor)

## Next steps

The following improvements are planned but not yet implemented:

1. Distinguish between timeout, connection errors and logical backend errors in
   the error payload returned to the client.
2. Introduce circuit-breaker behaviour for repeatedly failing backends.
3. Attach error codes that agents can react to (for example `BACKEND_UNAVAILABLE`).
4. Surface rate limit errors in a machine-readable way for the orchestrator.

These changes will be added once the orchestration layer has settled on an
error contract that agents can reliably consume.

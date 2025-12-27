FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Copy pyproject.toml first for dependency caching
COPY pyproject.toml* ./
# Install project dependencies (includes FastAPI/uvicorn from pyproject.toml)
RUN pip install --upgrade pip && \
    if [ -f pyproject.toml ]; then \
        pip install .; \
    elif [ -f requirements.txt ]; then \
        pip install --no-cache-dir -r requirements.txt; \
    else \
        pip install "mcp[cli]" httpx pyyaml fastapi "uvicorn[standard]" starlette; \
    fi

# Copy application
COPY mcp_server ./mcp_server
COPY config ./config

# Expose port (MCP server uses 9000 by default)
EXPOSE 9000

# Health check
HEALTHCHECK --interval=10s --timeout=5s --retries=3 \
    CMD wget --quiet --tries=1 --spider http://localhost:9000/health || exit 1

# Start server (uvicorn with factory pattern for http_app)
CMD ["uvicorn", "mcp_server.http_app:create_app", "--host", "0.0.0.0", "--port", "9000", "--factory"]

FROM python:3.13-slim

ENV PYTHONUNBUFFERED=1

WORKDIR /app

COPY pyproject.toml .
COPY mcp_server ./mcp_server
COPY config ./config

RUN pip install --upgrade pip && pip install "mcp[cli]" httpx pyyaml

EXPOSE 8000

CMD ["python", "-m", "mcp_server.main"]

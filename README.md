# simple-gpt-mcp-server

MCP (Model Context Protocol) server that exposes internal backend services
(memory, CRM, automation, inbox, files) as tools for AI agents.

## Features

- Async HTTP gateway with per-tool rate limiting
- Role based access control configured in config/server.yaml
- Multi-tenant backend URLs
- Dev stub backend for quick local testing

## Quick start (development)

1. Create a virtualenv and install dev dependencies:
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -e ".[dev]"

2. Start a dev backend stub:
   SERVICE_NAME=memory uvicorn dev_backend.main:app --reload --port 8010

3. Start the MCP server (HTTP transport via FastMCP):
   python -m mcp_server.main

   By default the HTTP transport listens on 127.0.0.1:9000.
   You can override this using the environment variables:
   - MCP_SERVER_CONFIG – path to server.yaml
   - MCP_SERVER_HOST – bind address
   - MCP_SERVER_PORT – bind port

4. Call a tool from the CLI helper:
   python scripts/call_memory_search.py

## Running tests

To run the tests:
   pytest

## Docker

Build and run:
   docker build -t simple-gpt-mcp .
   docker run --rm -p 9000:9000 simple-gpt-mcp

You should place the container behind a TLS-terminating proxy before exposing
it to the public Internet.

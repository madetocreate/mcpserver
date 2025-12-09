from __future__ import annotations

import os
import time
from typing import Any, Dict

from fastapi import FastAPI, Request

SERVICE_NAME = os.getenv("SERVICE_NAME", "unknown")

app = FastAPI(title=f"Dev stub backend for {SERVICE_NAME}")


@app.api_route("/{path:path}", methods=["GET", "POST"])
async def handle(path: str, request: Request) -> Dict[str, Any]:
    try:
        payload = await request.json()
    except Exception:
        payload = None
    return {
        "service": SERVICE_NAME,
        "path": "/" + path,
        "payload": payload,
        "timestamp": time.time(),
    }

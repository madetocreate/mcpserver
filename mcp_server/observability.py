import json
import os
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional


class AuditLogger:
    def __init__(self, path: str = "logs/audit.log") -> None:
        self._path = path
        directory = os.path.dirname(path) or "."
        os.makedirs(directory, exist_ok=True)
        self._lock = threading.Lock()

    def log_call(
        self,
        *,
        tool: str,
        tenant: str,
        actor: str,
        role: str,
        status: str,
        duration_ms: float,
        error_code: Optional[str] = None,
        correlation_id: Optional[str] = None,
        payload_size: Optional[int] = None,
    ) -> None:
        entry: Dict[str, Any] = {
            "ts": time.time(),
            "tool": tool,
            "tenant": tenant,
            "actor": actor,
            "role": role,
            "status": status,
            "duration_ms": float(duration_ms),
            "error_code": error_code,
            "correlation_id": correlation_id,
            "payload_size": payload_size,
        }
        line = json.dumps(entry, ensure_ascii=False, separators=(",", ":"))
        with self._lock:
            with open(self._path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")


@dataclass
class ToolMetrics:
    calls: int = 0
    errors: int = 0
    total_latency_ms: float = 0.0

    def observe(self, duration_ms: float, error: bool) -> None:
        self.calls += 1
        self.total_latency_ms += float(duration_ms)
        if error:
            self.errors += 1

    @property
    def avg_latency_ms(self) -> float:
        if self.calls == 0:
            return 0.0
        return self.total_latency_ms / self.calls


class InMemoryMetrics:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._tools: Dict[str, ToolMetrics] = {}

    def record(self, tool: str, duration_ms: float, error: bool) -> None:
        with self._lock:
            metrics = self._tools.get(tool)
            if metrics is None:
                metrics = ToolMetrics()
                self._tools[tool] = metrics
            metrics.observe(duration_ms, error)

    def snapshot(self) -> Dict[str, Dict[str, float]]:
        with self._lock:
            data: Dict[str, Dict[str, float]] = {}
            for name, m in self._tools.items():
                data[name] = {
                    "calls": float(m.calls),
                    "errors": float(m.errors),
                    "avg_latency_ms": float(m.avg_latency_ms),
                }
            return data

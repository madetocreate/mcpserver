import time
import threading
from dataclasses import dataclass, field
from typing import Dict, Optional


class RateLimitError(Exception):
    """Rate limit exceeded error."""
    
    def __init__(self, message: str, reset_in_seconds: Optional[float] = None) -> None:
        super().__init__(message)
        self.reset_in_seconds = reset_in_seconds


@dataclass
class LimitBucket:
    limit: int
    window_seconds: int
    count: int = 0
    window_start: float = field(default_factory=lambda: time.time())

    def check_and_increment(self) -> float:
        now = time.time()
        if now - self.window_start >= self.window_seconds:
            self.window_start = now
            self.count = 0
        self.count += 1
        if self.count > self.limit:
            reset_in = self.window_seconds - (now - self.window_start)
            if reset_in < 0:
                reset_in = 0.0
            return reset_in
        return 0.0


class AdvancedRateLimiter:
    def __init__(self, config: Optional[dict] = None) -> None:
        cfg = config or {}
        self._default_per_minute = int(cfg.get("default_per_minute", 60))
        self._per_tenant = {str(k): int(v) for k, v in cfg.get("tenants", {}).items()}
        self._per_actor = int(cfg.get("per_actor_per_minute", 60))
        self._per_tool = {str(k): int(v) for k, v in cfg.get("tools", {}).items()}
        self._window_seconds = int(cfg.get("window_seconds", 60))
        self._lock = threading.Lock()
        self._buckets: Dict[str, LimitBucket] = {}

    def _key(self, scope: str, *parts: str) -> str:
        return ":".join((scope,) + tuple(parts))

    def _get_bucket(self, key: str, limit: int) -> LimitBucket:
        # Note: _get_bucket is called from within check() which is already locked
        # But for safety, we ensure bucket creation is also protected
        bucket = self._buckets.get(key)
        if bucket is None:
            bucket = LimitBucket(limit=limit, window_seconds=self._window_seconds)
            self._buckets[key] = bucket
        return bucket

    def check(self, tenant_id: str, tool: str, actor: Optional[str] = None) -> None:
        # P0 Fix: Use lock to protect mutating operations (check_and_increment modifies shared state)
        with self._lock:
            violations = []
            tenant_limit = self._per_tenant.get(tenant_id, self._default_per_minute)
            tenant_bucket = self._get_bucket(self._key("tenant", tenant_id), tenant_limit)
            reset = tenant_bucket.check_and_increment()
            if reset > 0:
                violations.append(reset)

            tool_limit = self._per_tool.get(tool, tenant_limit)
            tool_bucket = self._get_bucket(self._key("tool", tool), tool_limit)
            reset = tool_bucket.check_and_increment()
            if reset > 0:
                violations.append(reset)

            if actor:
                actor_bucket = self._get_bucket(self._key("actor", tenant_id, actor), self._per_actor)
                reset = actor_bucket.check_and_increment()
                if reset > 0:
                    violations.append(reset)

            if violations:
                reset_in = max(violations)
                raise RateLimitError(
                    f"Rate limit exceeded for tenant={tenant_id} tool={tool}",
                    reset_in_seconds=reset_in,
                )

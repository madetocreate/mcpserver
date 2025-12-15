from __future__ import annotations

import pytest

from mcp_server.rate_limits import AdvancedRateLimiter, RateLimitError
from mcp_server.server import PermissionChecker, PermissionError


def test_rate_limiter_allows_within_limit() -> None:
    rate_limiter = AdvancedRateLimiter({"default_per_minute": 2})
    rate_limiter.check("tenant-a", "tool-x", "actor-1")
    rate_limiter.check("tenant-a", "tool-x", "actor-1")


def test_rate_limiter_blocks_above_limit() -> None:
    rate_limiter = AdvancedRateLimiter({"default_per_minute": 1})
    rate_limiter.check("tenant-a", "tool-x", "actor-1")
    with pytest.raises(RateLimitError):
        rate_limiter.check("tenant-a", "tool-x", "actor-1")


def test_permission_checker_allows_role() -> None:
    cfg = {"security": {"tools": {"demo.tool": {"allowed_roles": ["Orchestrator"]}}}}
    checker = PermissionChecker(cfg)
    checker.ensure_allowed("demo.tool", "Orchestrator")


def test_permission_checker_denies_role() -> None:
    cfg = {"security": {"tools": {"demo.tool": {"allowed_roles": ["Orchestrator"]}}}}
    checker = PermissionChecker(cfg)
    with pytest.raises(PermissionError):
        checker.ensure_allowed("demo.tool", "User-Agent")


def test_permission_checker_default_roles() -> None:
    """Test that default_allowed_roles are enforced when tool has no explicit allowed_roles."""
    cfg = {
        "security": {
            "default_allowed_roles": ["Orchestrator", "Admin"],
            "tools": {}
        }
    }
    checker = PermissionChecker(cfg)
    # Should allow Orchestrator
    checker.ensure_allowed("some.tool", "Orchestrator")
    # Should deny User-Agent (not in default_allowed_roles)
    with pytest.raises(PermissionError):
        checker.ensure_allowed("some.tool", "User-Agent")

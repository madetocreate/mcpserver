from __future__ import annotations

import pytest

from mcp_server.server import PermissionChecker, PermissionError, RateLimitError, RateLimiter


@pytest.mark.asyncio
async def test_rate_limiter_allows_within_limit() -> None:
    rate_limiter = RateLimiter({"rate_limits": {"default_per_minute": 2}})
    await rate_limiter.check("tenant-a", "tool-x")
    await rate_limiter.check("tenant-a", "tool-x")


@pytest.mark.asyncio
async def test_rate_limiter_blocks_above_limit() -> None:
    rate_limiter = RateLimiter({"rate_limits": {"default_per_minute": 1}})
    await rate_limiter.check("tenant-a", "tool-x")
    with pytest.raises(RateLimitError):
        await rate_limiter.check("tenant-a", "tool-x")


def test_permission_checker_allows_role() -> None:
    cfg = {"security": {"tools": {"demo.tool": {"allowed_roles": ["Orchestrator"]}}}}
    checker = PermissionChecker(cfg)
    checker.ensure_allowed("demo.tool", "Orchestrator")


def test_permission_checker_denies_role() -> None:
    cfg = {"security": {"tools": {"demo.tool": {"allowed_roles": ["Orchestrator"]}}}}
    checker = PermissionChecker(cfg)
    with pytest.raises(PermissionError):
        checker.ensure_allowed("demo.tool", "User-Agent")

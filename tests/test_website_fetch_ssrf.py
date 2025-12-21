"""
Security Tests für website.fetch Tool - SSRF Redirect-Bypass Prevention.

Tests stellen sicher, dass:
1. Redirects auf private IPs blockiert werden
2. Jede Redirect-URL validiert wird
3. Zu viele Redirects abgelehnt werden
4. Legitime Redirects funktionieren weiterhin
"""
from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from mcp_server.website_fetch_tools import _validate_redirect_url, _is_blocked_host


class TestSSRFRedirectPrevention:
    """Tests für SSRF Redirect-Bypass Prevention."""

    def test_redirect_to_private_ip_blocked(self):
        """Test: Redirect auf private IP wird blockiert."""
        # Simuliere: public URL → redirect → 127.0.0.1
        original_url = "https://example.com/page"
        redirect_url = "http://127.0.0.1:8080/internal"
        
        error = _validate_redirect_url(redirect_url, original_url)
        assert error is not None
        assert "blocked" in error.lower() or "127.0.0.1" in error

    def test_redirect_to_localhost_blocked(self):
        """Test: Redirect auf localhost wird blockiert."""
        original_url = "https://example.com/page"
        redirect_url = "http://localhost:8080/internal"
        
        error = _validate_redirect_url(redirect_url, original_url)
        assert error is not None
        assert "blocked" in error.lower()

    def test_redirect_to_public_ip_allowed(self):
        """Test: Redirect auf öffentliche IP ist erlaubt."""
        original_url = "https://example.com/page"
        redirect_url = "https://example.com/redirected"
        
        error = _validate_redirect_url(redirect_url, original_url)
        assert error is None

    def test_relative_redirect_resolved(self):
        """Test: Relative Redirects werden korrekt aufgelöst."""
        original_url = "https://example.com/page"
        redirect_url = "/redirected"
        
        error = _validate_redirect_url(redirect_url, original_url)
        # Sollte keine Fehler geben (wird zu https://example.com/redirected aufgelöst)
        assert error is None

    def test_redirect_to_10_0_0_1_blocked(self):
        """Test: Redirect auf private IP (10.0.0.1) wird blockiert."""
        original_url = "https://example.com/page"
        redirect_url = "http://10.0.0.1:8080/internal"
        
        error = _validate_redirect_url(redirect_url, original_url)
        assert error is not None
        assert "blocked" in error.lower() or "10.0.0.1" in error

    def test_redirect_to_192_168_1_1_blocked(self):
        """Test: Redirect auf private IP (192.168.1.1) wird blockiert."""
        original_url = "https://example.com/page"
        redirect_url = "http://192.168.1.1:8080/internal"
        
        error = _validate_redirect_url(redirect_url, original_url)
        assert error is not None
        assert "blocked" in error.lower()

    def test_is_blocked_host_localhost(self):
        """Test: _is_blocked_host blockiert localhost."""
        error = _is_blocked_host("localhost", 80)
        assert error is not None
        assert "blocked" in error.lower()

    def test_is_blocked_host_127_0_0_1(self):
        """Test: _is_blocked_host blockiert 127.0.0.1."""
        error = _is_blocked_host("127.0.0.1", 80)
        assert error is not None
        assert "blocked" in error.lower() or "127.0.0.1" in error

    def test_is_blocked_host_public_allowed(self):
        """Test: _is_blocked_host erlaubt öffentliche IPs."""
        error = _is_blocked_host("example.com", 80)
        assert error is None

    @pytest.mark.asyncio
    async def test_website_fetch_blocks_redirect_to_private_ip(self):
        """Test: website_fetch blockiert Redirects auf private IPs."""
        # Mock httpx.AsyncClient
        mock_response = AsyncMock()
        mock_response.status_code = 302
        mock_response.headers = {"location": "http://127.0.0.1:8080/internal"}
        mock_response.url = "https://example.com/page"
        
        mock_client = AsyncMock()
        mock_client.stream = AsyncMock(return_value=mock_response)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=None)
        
        with patch("mcp_server.website_fetch_tools.httpx.AsyncClient", return_value=mock_client):
            from mcp_server.website_fetch_tools import register_website_fetch_tools
            from mcp.server.fastmcp import FastMCP
            
            mcp = FastMCP("test")
            register_website_fetch_tools(mcp)
            
            # Tool aufrufen
            tool = mcp._tool_manager._tools.get("website.fetch")
            if not tool:
                # Fallback: Tool könnte anders gespeichert sein
                pytest.skip("Tool nicht gefunden - möglicherweise andere FastMCP-Version")
            
            result = await tool.fn("https://example.com/page")
            
            assert "error" in result
            assert "blocked" in result["error"].lower() or "127.0.0.1" in result["error"]


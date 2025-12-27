"""
Tests for Approval Token Verification (Defense-in-Depth).

Write/Side-effect Tools benötigen Approval via Trusted HTTP Token.
Token wird NICHT aus Tool-Args akzeptiert, sondern ausschließlich über HTTP Header.
"""
import os
import time
import pytest
from mcp_server.approval import (
    verify_approval_token,
    generate_approval_token,
    ApprovalTokenClaims,
)


@pytest.fixture
def approval_secret():
    """Set approval secret for tests."""
    original = os.environ.get("MCP_APPROVAL_JWT_SECRET")
    os.environ["MCP_APPROVAL_JWT_SECRET"] = "test-secret-key-for-approval-tokens-12345"
    yield
    if original:
        os.environ["MCP_APPROVAL_JWT_SECRET"] = original
    else:
        os.environ.pop("MCP_APPROVAL_JWT_SECRET", None)


def test_generate_and_verify_approval_token(approval_secret):
    """Test token generation and verification (happy path)."""
    user_id = "user-123"
    tenant_id = "tenant-456"
    tool_name = "crm:create_contact"
    approval_id = "approval-789"
    
    # Generate token
    token = generate_approval_token(
        user_id=user_id,
        tenant_id=tenant_id,
        tool_name=tool_name,
        approval_id=approval_id,
        ttl_seconds=300,
    )
    
    assert token is not None
    assert isinstance(token, str)
    assert len(token) > 50  # JWT tokens are long
    
    # Verify token
    ok, reason, claims = verify_approval_token(
        token=token,
        expected_tool=tool_name,
        tenant_id=tenant_id,
        user_id=user_id,
    )
    
    assert ok is True
    assert reason == ""
    assert claims is not None
    assert isinstance(claims, ApprovalTokenClaims)
    assert claims.user_id == user_id
    assert claims.tenant_id == tenant_id
    assert claims.tool_name == tool_name
    assert claims.approval_id == approval_id


def test_verify_token_wrong_tool(approval_secret):
    """Test token verification fails when tool name doesn't match."""
    user_id = "user-123"
    tenant_id = "tenant-456"
    tool_name = "crm:create_contact"
    approval_id = "approval-789"
    
    token = generate_approval_token(
        user_id=user_id,
        tenant_id=tenant_id,
        tool_name=tool_name,
        approval_id=approval_id,
    )
    
    # Try to verify with different tool name
    ok, reason, claims = verify_approval_token(
        token=token,
        expected_tool="crm:delete_contact",  # Wrong tool!
        tenant_id=tenant_id,
        user_id=user_id,
    )
    
    assert ok is False
    assert reason == "approval_token_tool_mismatch"
    assert claims is None


def test_verify_token_wrong_tenant(approval_secret):
    """Test token verification fails when tenant ID doesn't match."""
    user_id = "user-123"
    tenant_id = "tenant-456"
    tool_name = "crm:create_contact"
    approval_id = "approval-789"
    
    token = generate_approval_token(
        user_id=user_id,
        tenant_id=tenant_id,
        tool_name=tool_name,
        approval_id=approval_id,
    )
    
    # Try to verify with different tenant ID
    ok, reason, claims = verify_approval_token(
        token=token,
        expected_tool=tool_name,
        tenant_id="tenant-999",  # Wrong tenant!
        user_id=user_id,
    )
    
    assert ok is False
    assert reason == "approval_token_tenant_mismatch"
    assert claims is None


def test_verify_token_wrong_user(approval_secret):
    """Test token verification fails when user ID doesn't match."""
    user_id = "user-123"
    tenant_id = "tenant-456"
    tool_name = "crm:create_contact"
    approval_id = "approval-789"
    
    token = generate_approval_token(
        user_id=user_id,
        tenant_id=tenant_id,
        tool_name=tool_name,
        approval_id=approval_id,
    )
    
    # Try to verify with different user ID
    ok, reason, claims = verify_approval_token(
        token=token,
        expected_tool=tool_name,
        tenant_id=tenant_id,
        user_id="user-999",  # Wrong user!
    )
    
    assert ok is False
    assert reason == "approval_token_user_mismatch"
    assert claims is None


def test_verify_token_expired(approval_secret):
    """Test token verification fails when token is expired."""
    user_id = "user-123"
    tenant_id = "tenant-456"
    tool_name = "crm:create_contact"
    approval_id = "approval-789"
    
    # Generate token with very short TTL
    token = generate_approval_token(
        user_id=user_id,
        tenant_id=tenant_id,
        tool_name=tool_name,
        approval_id=approval_id,
        ttl_seconds=1,  # 1 second
    )
    
    # Wait for token to expire
    time.sleep(2)
    
    # Try to verify expired token
    ok, reason, claims = verify_approval_token(
        token=token,
        expected_tool=tool_name,
        tenant_id=tenant_id,
        user_id=user_id,
    )
    
    assert ok is False
    assert reason == "approval_token_expired"
    assert claims is None


def test_verify_token_invalid_signature(approval_secret):
    """Test token verification fails with invalid signature."""
    user_id = "user-123"
    tenant_id = "tenant-456"
    tool_name = "crm:create_contact"
    
    # Generate token with one secret
    token = generate_approval_token(
        user_id=user_id,
        tenant_id=tenant_id,
        tool_name=tool_name,
        approval_id="approval-789",
    )
    
    # Change secret
    os.environ["MCP_APPROVAL_JWT_SECRET"] = "different-secret-key"
    
    # Try to verify with different secret
    ok, reason, claims = verify_approval_token(
        token=token,
        expected_tool=tool_name,
        tenant_id=tenant_id,
        user_id=user_id,
    )
    
    assert ok is False
    assert reason == "approval_token_invalid"
    assert claims is None


def test_verify_token_no_secret():
    """Test token verification fails when secret is not set (fail-closed)."""
    # Remove secret
    original = os.environ.pop("MCP_APPROVAL_JWT_SECRET", None)
    
    try:
        ok, reason, claims = verify_approval_token(
            token="dummy-token",
            expected_tool="crm:create_contact",
            tenant_id="tenant-456",
            user_id="user-123",
        )
        
        assert ok is False
        assert reason == "approval_token_secret_missing"
        assert claims is None
    finally:
        if original:
            os.environ["MCP_APPROVAL_JWT_SECRET"] = original


def test_verify_token_replay_detection(approval_secret):
    """Test token replay detection (same JTI used twice)."""
    user_id = "user-123"
    tenant_id = "tenant-456"
    tool_name = "crm:create_contact"
    approval_id = "approval-789"
    
    token = generate_approval_token(
        user_id=user_id,
        tenant_id=tenant_id,
        tool_name=tool_name,
        approval_id=approval_id,
    )
    
    # First use: should succeed
    ok1, reason1, claims1 = verify_approval_token(
        token=token,
        expected_tool=tool_name,
        tenant_id=tenant_id,
        user_id=user_id,
    )
    
    assert ok1 is True
    assert reason1 == ""
    assert claims1 is not None
    
    # Second use (replay): should fail
    ok2, reason2, claims2 = verify_approval_token(
        token=token,
        expected_tool=tool_name,
        tenant_id=tenant_id,
        user_id=user_id,
    )
    
    assert ok2 is False
    assert reason2 == "approval_token_replay_detected"
    assert claims2 is None


def test_token_claims_structure(approval_secret):
    """Test that token claims have correct structure."""
    user_id = "user-123"
    tenant_id = "tenant-456"
    tool_name = "crm:create_contact"
    approval_id = "approval-789"
    
    token = generate_approval_token(
        user_id=user_id,
        tenant_id=tenant_id,
        tool_name=tool_name,
        approval_id=approval_id,
        ttl_seconds=300,
    )
    
    ok, reason, claims = verify_approval_token(
        token=token,
        expected_tool=tool_name,
        tenant_id=tenant_id,
        user_id=user_id,
    )
    
    assert ok is True
    assert claims is not None
    
    # Check all required fields
    assert hasattr(claims, "user_id")
    assert hasattr(claims, "tenant_id")
    assert hasattr(claims, "tool_name")
    assert hasattr(claims, "approval_id")
    assert hasattr(claims, "jti")
    assert hasattr(claims, "iat")
    assert hasattr(claims, "exp")
    
    # Check values
    assert claims.user_id == user_id
    assert claims.tenant_id == tenant_id
    assert claims.tool_name == tool_name
    assert claims.approval_id == approval_id
    assert isinstance(claims.jti, str)
    assert len(claims.jti) > 10  # UUID is long
    assert isinstance(claims.iat, (int, float))
    assert isinstance(claims.exp, (int, float))
    assert claims.exp > claims.iat  # exp should be after iat


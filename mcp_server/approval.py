"""
Approval Token Verification for MCP Server.

Defense-in-Depth: Write/Side-effect Tools benötigen Approval via Trusted HTTP Token.
Token wird NICHT aus Tool-Args akzeptiert, sondern ausschließlich über HTTP Header.

Token Format: JWT HS256
Headers:
  - X-Aklow-Approval-Token: <JWT>
  - X-Aklow-Tenant-Id: <tenant_id>
  - X-Aklow-User-Id: <user_id>
  - X-Aklow-Tool-Name: <tool_name>

JWT Claims:
  - iss: "aklow"
  - aud: "mcp-server"
  - sub: user_id
  - tid: tenant_id
  - tool: exact_tool_name
  - approval_id: approval_flow_id
  - exp: now + 5min (kurzlebig)
  - iat: now
  - jti: random_id (Replay detection)
"""
from __future__ import annotations

import os
import logging
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger("mcp_server.approval")

# In-memory JTI cache for replay detection (TTL: 10 minutes)
# Production: Use Redis/Memcached für distributed systems
_jti_cache: Dict[str, float] = {}
_JTI_TTL_SECONDS = 600  # 10 minutes


@dataclass
class ApprovalTokenClaims:
    """Parsed and verified approval token claims."""
    user_id: str
    tenant_id: str
    tool_name: str
    approval_id: str
    jti: str
    iat: float
    exp: float


def _clean_jti_cache() -> None:
    """Remove expired JTIs from cache."""
    now = time.time()
    expired_keys = [jti for jti, exp_time in _jti_cache.items() if exp_time < now]
    for jti in expired_keys:
        del _jti_cache[jti]


def _check_jti_replay(jti: str, exp_time: float) -> bool:
    """
    Check if JTI has been used before (replay attack detection).
    
    Returns:
        True if JTI is new (OK to use), False if already used (replay detected)
    """
    _clean_jti_cache()
    
    if jti in _jti_cache:
        logger.warning(f"[Approval] Replay detected: JTI {jti[:8]}... already used")
        return False
    
    # Store JTI with expiration time
    _jti_cache[jti] = exp_time
    return True


def verify_approval_token(
    token: str,
    expected_tool: str,
    tenant_id: str,
    user_id: str,
) -> Tuple[bool, str, Optional[ApprovalTokenClaims]]:
    """
    Verify approval token for a specific tool.
    
    Args:
        token: JWT token from X-Aklow-Approval-Token header
        expected_tool: Tool name that requires approval
        tenant_id: Tenant ID from X-Aklow-Tenant-Id header
        user_id: User ID from X-Aklow-User-Id header
    
    Returns:
        Tuple of (ok: bool, reason: str, claims: Optional[ApprovalTokenClaims])
        - ok: True if token is valid and matches expected_tool
        - reason: Error reason code if not ok, empty string if ok
        - claims: Parsed claims if ok, None if not ok
    """
    # Get secret from env (fail-closed if missing)
    secret = os.getenv("MCP_APPROVAL_JWT_SECRET", "").strip()
    if not secret:
        logger.error("[Approval] MCP_APPROVAL_JWT_SECRET not set (fail-closed)")
        return False, "approval_token_secret_missing", None
    
    try:
        import jwt
    except ImportError:
        logger.error("[Approval] PyJWT not installed (fail-closed)")
        return False, "approval_token_library_missing", None
    
    # Decode and verify JWT
    try:
        claims = jwt.decode(
            token,
            secret,
            algorithms=["HS256"],
            audience="mcp-server",
            issuer="aklow",
            options={
                "require_exp": True,
                "require_iat": True,
                "verify_exp": True,
                "verify_iat": True,
                "verify_aud": True,
                "verify_iss": True,
            },
        )
    except jwt.ExpiredSignatureError:
        logger.warning("[Approval] Token expired")
        return False, "approval_token_expired", None
    except jwt.InvalidTokenError as e:
        logger.warning(f"[Approval] Invalid token: {e}")
        return False, "approval_token_invalid", None
    except Exception as e:
        logger.error(f"[Approval] Token decode failed: {e}", exc_info=True)
        return False, "approval_token_decode_failed", None
    
    # Verify issuer and audience
    if claims.get("iss") != "aklow":
        logger.warning(f"[Approval] Invalid issuer: {claims.get('iss')}")
        return False, "approval_token_invalid_issuer", None
    
    if claims.get("aud") != "mcp-server":
        logger.warning(f"[Approval] Invalid audience: {claims.get('aud')}")
        return False, "approval_token_invalid_audience", None
    
    # Verify tool name matches
    token_tool = claims.get("tool", "")
    if token_tool != expected_tool:
        logger.warning(
            f"[Approval] Tool mismatch: token={token_tool}, expected={expected_tool}"
        )
        return False, "approval_token_tool_mismatch", None
    
    # Verify tenant_id matches
    token_tenant_id = claims.get("tid", "")
    if token_tenant_id != tenant_id:
        logger.warning(
            f"[Approval] Tenant ID mismatch: token={token_tenant_id}, expected={tenant_id}"
        )
        return False, "approval_token_tenant_mismatch", None
    
    # Verify user_id matches
    token_user_id = claims.get("sub", "")
    if token_user_id != user_id:
        logger.warning(
            f"[Approval] User ID mismatch: token={token_user_id}, expected={user_id}"
        )
        return False, "approval_token_user_mismatch", None
    
    # Check JTI for replay attacks
    jti = claims.get("jti", "")
    exp_time = claims.get("exp", 0)
    if not _check_jti_replay(jti, exp_time):
        return False, "approval_token_replay_detected", None
    
    # All checks passed
    parsed_claims = ApprovalTokenClaims(
        user_id=token_user_id,
        tenant_id=token_tenant_id,
        tool_name=token_tool,
        approval_id=claims.get("approval_id", ""),
        jti=jti,
        iat=claims.get("iat", 0),
        exp=exp_time,
    )
    
    logger.info(
        f"[Approval] Token verified: tool={expected_tool}, "
        f"tenant={tenant_id}, user={user_id}, approval_id={parsed_claims.approval_id}, "
        f"jti={jti[:8]}..."
    )
    
    return True, "", parsed_claims


def generate_approval_token(
    user_id: str,
    tenant_id: str,
    tool_name: str,
    approval_id: str,
    ttl_seconds: int = 300,  # 5 minutes default
) -> Optional[str]:
    """
    Generate an approval token (for testing or internal use).
    
    Production: Token generation should happen in Python Backend (approval flow service).
    This function is mainly for testing and internal tooling.
    
    Args:
        user_id: User ID
        tenant_id: Tenant ID
        tool_name: Tool name that requires approval
        approval_id: Approval flow/run ID
        ttl_seconds: Token TTL in seconds (default: 5 minutes)
    
    Returns:
        JWT token string, or None if secret is missing
    """
    secret = os.getenv("MCP_APPROVAL_JWT_SECRET", "").strip()
    if not secret:
        logger.error("[Approval] MCP_APPROVAL_JWT_SECRET not set (cannot generate token)")
        return None
    
    try:
        import jwt
        import uuid
    except ImportError:
        logger.error("[Approval] PyJWT not installed (cannot generate token)")
        return None
    
    now = time.time()
    claims = {
        "iss": "aklow",
        "aud": "mcp-server",
        "sub": user_id,
        "tid": tenant_id,
        "tool": tool_name,
        "approval_id": approval_id,
        "exp": now + ttl_seconds,
        "iat": now,
        "jti": str(uuid.uuid4()),
    }
    
    token = jwt.encode(claims, secret, algorithm="HS256")
    return token


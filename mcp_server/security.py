from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass
class AuthConfig:
    mode: str = "none"
    issuer: Optional[str] = None
    audience: Optional[str] = None
    jwks_url: Optional[str] = None


def load_auth_config(config: Dict[str, Any]) -> AuthConfig:
    security_cfg = config.get("security", {}) or {}
    auth_cfg = security_cfg.get("auth", {}) or {}
    return AuthConfig(
        mode=str(auth_cfg.get("mode", "none")),
        issuer=auth_cfg.get("issuer"),
        audience=auth_cfg.get("audience"),
        jwks_url=auth_cfg.get("jwks_url"),
    )


class AuthBackend:
    def __init__(self, auth_config: AuthConfig) -> None:
        self._config = auth_config

    async def authenticate(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        actor = payload.get("actor", "unknown")
        actor_role = payload.get("actor_role", "unknown")
        return {
            "actor": actor,
            "actor_role": actor_role,
        }


def build_auth_backend(config: Dict[str, Any]) -> AuthBackend:
    auth_config = load_auth_config(config)
    return AuthBackend(auth_config)

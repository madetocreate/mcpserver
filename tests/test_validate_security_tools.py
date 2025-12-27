"""
Tests für MCP Server Security Tools Validator.
"""
from __future__ import annotations

"""
Tests für MCP Server Security Tools Validator.
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

import pytest

# Add scripts to path
sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))

from validate_security_tools import (
    load_server_config,
    validate_security_tools,
    check_drift_against_registry,
    load_policy_registry,
)


class TestValidateSecurityTools:
    """Tests für Security Tools Validator."""

    def test_validate_valid_config(self):
        """Test: Validiert gültige Konfiguration."""
        config = {
            "security": {
                "tools": {
                    "memory_delete": {
                        "user_approval_required": True,
                    },
                    "crm_upsert_contact": {
                        "user_approval_required": True,
                    },
                },
            },
        }
        
        is_valid, errors = validate_security_tools(config)
        assert is_valid is True
        assert len(errors) == 0

    def test_validate_invalid_config(self):
        """Test: Validiert ungültige Konfiguration."""
        config = {
            "security": {
                "tools": {
                    "memory_delete": {
                        "user_approval_required": "true",  # Should be boolean
                    },
                },
            },
        }
        
        is_valid, errors = validate_security_tools(config)
        assert is_valid is False
        assert len(errors) > 0
        assert any("boolean" in error.lower() for error in errors)

    def test_validate_allowed_roles(self):
        """Test: Validiert allowed_roles."""
        config = {
            "security": {
                "tools": {
                    "crm_audit_query": {
                        "allowed_roles": ["Orchestrator", "CRM-Supervisor"],
                    },
                },
            },
        }
        
        is_valid, errors = validate_security_tools(config)
        assert is_valid is True

    def test_validate_invalid_allowed_roles(self):
        """Test: Validiert ungültige allowed_roles."""
        config = {
            "security": {
                "tools": {
                    "crm_audit_query": {
                        "allowed_roles": "Orchestrator",  # Should be list
                    },
                },
            },
        }
        
        is_valid, errors = validate_security_tools(config)
        assert is_valid is False
        assert any("list" in error.lower() for error in errors)

    def test_check_drift_against_registry(self):
        """Test: Prüft Drift gegen Registry."""
        mcp_tools = {
            "crm_upsert_contact": {
                "user_approval_required": True,
            },
            "memory_delete": {
                "user_approval_required": True,
            },
        }
        
        policy_registry = {
            "tool_policies": {
                "policies": [
                    {
                        "tool_name": "crm_upsert_contact_tool",
                        "requires_approval": True,
                    },
                    {
                        "tool_name": "memory_delete",
                        "requires_approval": True,
                    },
                ],
            },
        }
        
        is_valid, errors = check_drift_against_registry(mcp_tools, policy_registry)
        # Should pass (no drift)
        assert is_valid is True
        assert len(errors) == 0

    def test_check_drift_detection(self):
        """Test: Erkennt Drift."""
        mcp_tools = {
            "crm_upsert_contact": {
                "user_approval_required": False,  # Mismatch!
            },
        }
        
        policy_registry = {
            "tool_policies": {
                "policies": [
                    {
                        "tool_name": "crm_upsert_contact_tool",
                        "requires_approval": True,  # Registry requires approval
                    },
                ],
            },
        }
        
        is_valid, errors = check_drift_against_registry(mcp_tools, policy_registry)
        # Should detect drift
        assert is_valid is False
        assert len(errors) > 0
        assert any("drift" in error.lower() for error in errors)


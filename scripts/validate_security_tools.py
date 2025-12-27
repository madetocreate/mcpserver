#!/usr/bin/env python3
"""
MCP Server Security Tools Validator - Policy Drift Detection.

Validiert:
- Tool names konsistent
- approval required korrekt gesetzt
- Keine Duplikate
- Optional: Drift-Check gegen policy_registry.json
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

try:
    import yaml
except ImportError:
    print("Error: PyYAML not installed. Install with: pip install pyyaml", file=sys.stderr)
    sys.exit(1)


def load_server_config(config_path: Path) -> Dict[str, Any]:
    """Lädt server.yaml Konfiguration."""
    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")
    
    with open(config_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def validate_security_tools(config: Dict[str, Any]) -> tuple[bool, List[str]]:
    """
    Validiert security.tools Konfiguration.
    
    Returns:
        (is_valid, errors)
    """
    errors = []
    security = config.get("security", {})
    tools = security.get("tools", {})
    
    if not isinstance(tools, dict):
        errors.append("security.tools must be a dictionary")
        return False, errors
    
    # Check for duplicates (shouldn't happen in YAML, but check anyway)
    tool_names = list(tools.keys())
    seen = set()
    duplicates = []
    for name in tool_names:
        if name in seen:
            duplicates.append(name)
        seen.add(name)
    
    if duplicates:
        errors.append(f"Duplicate tool names found: {', '.join(duplicates)}")
    
    # Validate each tool configuration
    for tool_name, tool_config in tools.items():
        if not isinstance(tool_config, dict):
            errors.append(f"Tool '{tool_name}': config must be a dictionary")
            continue
        
        # Check for valid fields
        valid_fields = {
            "user_approval_required",
            "allowed_roles",
            "high_cost",
            "rate_limit_per_minute",
        }
        
        for field in tool_config.keys():
            if field not in valid_fields:
                errors.append(f"Tool '{tool_name}': unknown field '{field}' (allowed: {', '.join(valid_fields)})")
        
        # Validate user_approval_required
        if "user_approval_required" in tool_config:
            approval = tool_config["user_approval_required"]
            if not isinstance(approval, bool):
                errors.append(f"Tool '{tool_name}': user_approval_required must be boolean, got {type(approval).__name__}")
        
        # Validate allowed_roles
        if "allowed_roles" in tool_config:
            roles = tool_config["allowed_roles"]
            if not isinstance(roles, list):
                errors.append(f"Tool '{tool_name}': allowed_roles must be a list, got {type(roles).__name__}")
            elif not all(isinstance(r, str) for r in roles):
                errors.append(f"Tool '{tool_name}': allowed_roles must contain only strings")
    
    is_valid = len(errors) == 0
    return is_valid, errors


def load_policy_registry(registry_path: Optional[Path] = None) -> Optional[Dict[str, Any]]:
    """Lädt policy_registry.json (optional)."""
    if registry_path is None:
        # Try to find it relative to backend-agents
        backend_agents = Path(__file__).parent.parent.parent / "Backend" / "backend-agents"
        registry_path = backend_agents / "contracts" / "generated" / "policy_registry.json"
    
    if not registry_path or not registry_path.exists():
        return None
    
    try:
        with open(registry_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"Warning: Failed to load policy registry: {e}", file=sys.stderr)
        return None


def check_drift_against_registry(
    mcp_tools: Dict[str, Any],
    policy_registry: Dict[str, Any],
) -> tuple[bool, List[str]]:
    """
    Prüft Drift zwischen MCP security.tools und policy_registry.json.
    
    Mappt bekannte MCP tool names (crm_*, memory_*) auf risk/approval.
    """
    errors = []
    tool_policies = policy_registry.get("tool_policies", {}).get("policies", [])
    
    # Build lookup: tool_name -> requires_approval
    registry_lookup: Dict[str, bool] = {}
    for policy in tool_policies:
        tool_name = policy.get("tool_name", "")
        requires_approval = policy.get("requires_approval", False)
        registry_lookup[tool_name] = requires_approval
    
    # Map MCP tool names to registry tool names
    # MCP uses: crm_upsert_contact, memory_delete, etc.
    # Registry uses: crm_upsert_contact_tool, memory_delete (may vary)
    mcp_to_registry_map: Dict[str, str] = {}
    for mcp_name in mcp_tools.keys():
        # Try exact match
        if mcp_name in registry_lookup:
            mcp_to_registry_map[mcp_name] = mcp_name
        else:
            # Try with _tool suffix
            registry_name = f"{mcp_name}_tool"
            if registry_name in registry_lookup:
                mcp_to_registry_map[mcp_name] = registry_name
            # Try without prefix (e.g., memory_delete -> memory_delete)
            elif mcp_name.startswith("memory_") or mcp_name.startswith("crm_"):
                # Already tried exact match, skip
                pass
    
    # Check for drift
    for mcp_name, mcp_config in mcp_tools.items():
        registry_name = mcp_to_registry_map.get(mcp_name)
        if not registry_name:
            # Tool not in registry, skip (not an error)
            continue
        
        registry_requires_approval = registry_lookup.get(registry_name, False)
        mcp_requires_approval = mcp_config.get("user_approval_required", False)
        
        if registry_requires_approval != mcp_requires_approval:
            errors.append(
                f"Drift detected for '{mcp_name}': "
                f"Registry requires_approval={registry_requires_approval}, "
                f"MCP user_approval_required={mcp_requires_approval}"
            )
    
    is_valid = len(errors) == 0
    return is_valid, errors


def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Validate MCP Server security.tools configuration")
    parser.add_argument(
        "--config",
        type=Path,
        default=Path(__file__).parent.parent / "config" / "server.yaml",
        help="Path to server.yaml config file",
    )
    parser.add_argument(
        "--registry",
        type=Path,
        default=None,
        help="Path to policy_registry.json (optional, for drift check)",
    )
    parser.add_argument(
        "--check-drift",
        action="store_true",
        help="Check for drift against policy_registry.json",
    )
    
    args = parser.parse_args()
    
    try:
        # Load config
        config = load_server_config(args.config)
        
        # Validate security.tools
        is_valid, errors = validate_security_tools(config)
        
        if not is_valid:
            print("✗ Security tools validation failed:", file=sys.stderr)
            for error in errors:
                print(f"  - {error}", file=sys.stderr)
            sys.exit(1)
        
        print("✓ Security tools validation passed")
        
        # Optional: Check drift against registry
        if args.check_drift:
            registry = load_policy_registry(args.registry)
            if registry:
                security = config.get("security", {})
                tools = security.get("tools", {})
                drift_valid, drift_errors = check_drift_against_registry(tools, registry)
                
                if not drift_valid:
                    print("✗ Drift check failed:", file=sys.stderr)
                    for error in drift_errors:
                        print(f"  - {error}", file=sys.stderr)
                    sys.exit(1)
                
                print("✓ Drift check passed (no mismatches found)")
            else:
                print("⚠ Drift check skipped (policy_registry.json not found)")
        
        print("\n✓ All validations passed")
        sys.exit(0)
        
    except Exception as e:
        print(f"\n✗ Validation failed: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()


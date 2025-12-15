"""
High-cost tool detection and approval checking.

This module provides functions to identify high-cost tools (image/video/audio generation)
and check if cost approval has been granted.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Optional


# High-cost keywords for detection
HIGH_COST_GENERATE_KEYWORDS = {"generate", "gen", "create", "synthesize", "render"}
HIGH_COST_MEDIA_KEYWORDS = {"image", "img", "video", "audio", "voice", "tts"}


def is_high_cost_tool_name(tool_name: str) -> bool:
    """
    Detect if a tool name indicates a high-cost operation.
    
    A tool is considered high-cost if:
    - It contains a media keyword (image, video, audio, etc.) AND
    - It contains a generation keyword (generate, create, synthesize, etc.)
    
    Args:
        tool_name: The tool name to check
        
    Returns:
        True if the tool appears to be high-cost, False otherwise
    """
    if not tool_name:
        return False
    
    # Normalize: lowercase and replace separators with spaces
    normalized = re.sub(r"[_\.\-]", " ", tool_name.lower())
    tokens = set(normalized.split())
    
    # Check if we have both media and generation keywords
    has_media = bool(tokens & HIGH_COST_MEDIA_KEYWORDS)
    has_generate = bool(tokens & HIGH_COST_GENERATE_KEYWORDS)
    
    if has_media and has_generate:
        return True
    
    # Also check for direct substring matches (e.g., "image_generate")
    tool_lower = tool_name.lower()
    for media in HIGH_COST_MEDIA_KEYWORDS:
        for gen in HIGH_COST_GENERATE_KEYWORDS:
            if media in tool_lower and gen in tool_lower:
                return True
    
    return False


def is_high_cost_tool(tool_name: str, tool_cfg: Optional[Dict[str, Any]] = None) -> bool:
    """
    Check if a tool is high-cost based on config or name detection.
    
    Args:
        tool_name: The tool name
        tool_cfg: Optional tool configuration dict
        
    Returns:
        True if the tool is high-cost, False otherwise
    """
    # Explicit config override
    if tool_cfg and tool_cfg.get("high_cost") is True:
        return True
    
    # Name-based detection
    return is_high_cost_tool_name(tool_name)


def has_cost_approval(payload: Dict[str, Any]) -> bool:
    """
    Check if cost approval has been granted in the payload.
    
    Approval is granted if either:
    - cost_approved is True, or
    - user_approved is True (shortcut for cost approval)
    
    Args:
        payload: The request payload
        
    Returns:
        True if approval is present, False otherwise
    """
    return bool(
        payload.get("cost_approved") is True
        or payload.get("user_approved") is True
    )

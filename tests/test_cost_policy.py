"""
Tests for cost policy module.
"""

from mcp_server.cost_policy import has_cost_approval, is_high_cost_tool, is_high_cost_tool_name


def test_is_high_cost_tool_name():
    """Test high-cost tool name detection."""
    assert is_high_cost_tool_name("image_generate") is True
    assert is_high_cost_tool_name("video.generate") is True
    assert is_high_cost_tool_name("audio_synthesize") is True
    assert is_high_cost_tool_name("voice_create") is True
    assert is_high_cost_tool_name("img_gen") is True
    assert is_high_cost_tool_name("tts_render") is True
    
    assert is_high_cost_tool_name("crm_create_note") is False
    assert is_high_cost_tool_name("memory_search") is False
    assert is_high_cost_tool_name("observability_metrics") is False
    assert is_high_cost_tool_name("website_fetch") is False


def test_is_high_cost_tool():
    """Test high-cost tool detection with config."""
    # Name-based detection
    assert is_high_cost_tool("image_generate", None) is True
    assert is_high_cost_tool("crm_create_note", None) is False
    
    # Config override
    assert is_high_cost_tool("any_tool", {"high_cost": True}) is True
    assert is_high_cost_tool("image_generate", {"high_cost": False}) is False
    assert is_high_cost_tool("crm_create_note", {"high_cost": True}) is True


def test_has_cost_approval():
    """Test cost approval checking."""
    assert has_cost_approval({"cost_approved": True}) is True
    assert has_cost_approval({"user_approved": True}) is True
    assert has_cost_approval({"cost_approved": True, "user_approved": False}) is True
    assert has_cost_approval({"cost_approved": False, "user_approved": True}) is True
    
    assert has_cost_approval({}) is False
    assert has_cost_approval({"cost_approved": False}) is False
    assert has_cost_approval({"user_approved": False}) is False
    assert has_cost_approval({"some_other_field": True}) is False

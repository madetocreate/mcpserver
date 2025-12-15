"""
Real Estate MCP Tools for property management, viewings, and leads.
"""

from __future__ import annotations

from typing import Any, Dict

from .server import mcp, _require_context, TypedContext, _invoke_backend_tool


@mcp.tool(
    name="real_estate_create_property",
    description="Create a new real estate property with basic information",
)
async def real_estate_create_property(
    tenant_id: str,
    property_type: str,
    address: Dict[str, Any],
    specifications: Dict[str, Any],
    pricing: Dict[str, Any],
    status: str = "draft",
    documents: list[Dict[str, Any]] | None = None,
    photos: list[str] | None = None,
    workspace_id: str | None = None,
    actor: str = "orchestrator",
    actor_role: str = "Orchestrator",
    ctx: TypedContext | None = None,
) -> Dict[str, Any]:
    """Create a new real estate property."""
    return await _invoke_backend_tool(
        ctx=ctx,
        tool_name="real_estate_create_property",
        service="backend",
        method="POST",
        path="/real-estate/properties",
        tenant_id=tenant_id,
        actor=actor,
        actor_role=actor_role,
        payload_data={
            "property_type": property_type,
            "address": address,
            "specifications": specifications,
            "pricing": pricing,
            "status": status,
            "documents": documents or [],
            "photos": photos or [],
            "workspace_id": workspace_id,
        },
        timeout=30.0,
    )


@mcp.tool(
    name="real_estate_generate_expose",
    description="Generate an exposé for a property (portal, PDF, or social variant) with GEG §87 compliance check",
)
async def real_estate_generate_expose(
    tenant_id: str,
    property_id: str,
    variant: str = "portal",
    language: str = "de",
    actor: str = "orchestrator",
    actor_role: str = "Orchestrator",
    ctx: TypedContext | None = None,
) -> Dict[str, Any]:
    """Generate an exposé for a property."""
    return await _invoke_backend_tool(
        ctx=ctx,
        tool_name="real_estate_generate_expose",
        service="backend",
        method="POST",
        path=f"/real-estate/properties/{property_id}/expose",
        tenant_id=tenant_id,
        actor=actor,
        actor_role=actor_role,
        payload_data={
            "property_id": property_id,
            "variant": variant,
            "language": language,
        },
        timeout=30.0,
    )


@mcp.tool(
    name="real_estate_validate_geg87",
    description="Validate property against GEG §87 requirements (German energy law)",
)
async def real_estate_validate_geg87(
    tenant_id: str,
    property_id: str,
    actor: str = "orchestrator",
    actor_role: str = "Orchestrator",
    ctx: TypedContext | None = None,
) -> Dict[str, Any]:
    """Validate property against GEG §87 requirements."""
    return await _invoke_backend_tool(
        ctx=ctx,
        tool_name="real_estate_validate_geg87",
        service="backend",
        method="POST",
        path=f"/real-estate/properties/{property_id}/validate-geg87",
        tenant_id=tenant_id,
        actor=actor,
        actor_role=actor_role,
        payload_data={},
        timeout=30.0,
    )


@mcp.tool(
    name="real_estate_create_viewing",
    description="Create a property viewing appointment",
)
async def real_estate_create_viewing(
    tenant_id: str,
    property_id: str,
    scheduled_at: str,
    duration_minutes: int = 30,
    location: Dict[str, Any] | None = None,
    workspace_id: str | None = None,
    actor: str = "orchestrator",
    actor_role: str = "Orchestrator",
    ctx: TypedContext | None = None,
) -> Dict[str, Any]:
    """Create a property viewing."""
    return await _invoke_backend_tool(
        ctx=ctx,
        tool_name="real_estate_create_viewing",
        service="backend",
        method="POST",
        path="/real-estate/viewings",
        tenant_id=tenant_id,
        actor=actor,
        actor_role=actor_role,
        payload_data={
            "property_id": property_id,
            "scheduled_at": scheduled_at,
            "duration_minutes": duration_minutes,
            "location": location,
            "workspace_id": workspace_id,
        },
        timeout=30.0,
    )


@mcp.tool(
    name="real_estate_process_lead",
    description="Process an incoming lead from any channel (email, phone, portal, etc.) with AI triage and draft response generation",
)
async def real_estate_process_lead(
    tenant_id: str,
    source: str,
    raw_content: str,
    contact_info: Dict[str, Any],
    metadata: Dict[str, Any] | None = None,
    actor: str = "orchestrator",
    actor_role: str = "Orchestrator",
    ctx: TypedContext | None = None,
) -> Dict[str, Any]:
    """Process an incoming lead."""
    return await _invoke_backend_tool(
        ctx=ctx,
        tool_name="real_estate_process_lead",
        service="backend",
        method="POST",
        path="/real-estate/leads/process",
        tenant_id=tenant_id,
        actor=actor,
        actor_role=actor_role,
        payload_data={
            "source": source,
            "raw_content": raw_content,
            "contact_info": contact_info,
            "metadata": metadata,
        },
        timeout=30.0,
    )


@mcp.tool(
    name="real_estate_match_lead",
    description="Match a lead's requirements to available properties",
)
async def real_estate_match_lead(
    tenant_id: str,
    lead_id: str,
    limit: int = 10,
    actor: str = "orchestrator",
    actor_role: str = "Orchestrator",
    ctx: TypedContext | None = None,
) -> Dict[str, Any]:
    """Match a lead to properties."""
    return await _invoke_backend_tool(
        ctx=ctx,
        tool_name="real_estate_match_lead",
        service="backend",
        method="POST",
        path=f"/real-estate/leads/{lead_id}/match",
        tenant_id=tenant_id,
        actor=actor,
        actor_role=actor_role,
        payload_data={"limit": limit},
        timeout=30.0,
    )


@mcp.tool(
    name="real_estate_get_wizard_checklist",
    description="Get checklist of required and recommended items for property onboarding",
)
async def real_estate_get_wizard_checklist(
    tenant_id: str,
    property_id: str | None = None,
    actor: str = "orchestrator",
    actor_role: str = "Orchestrator",
    ctx: TypedContext | None = None,
) -> Dict[str, Any]:
    """Get wizard checklist for property onboarding."""
    if property_id:
        return await _invoke_backend_tool(
            ctx=ctx,
            tool_name="real_estate_get_wizard_checklist",
            service="backend",
            method="GET",
            path=f"/real-estate/properties/{property_id}/wizard/checklist",
            tenant_id=tenant_id,
            actor=actor,
            actor_role=actor_role,
            payload_data={},
            timeout=30.0,
        )
    else:
        # Return initial checklist
        return {
            "required_fields": [
                "property_type",
                "address.street",
                "address.city",
                "address.zip",
                "specifications.living_space",
                "pricing.purchase_price or pricing.rent",
            ],
            "recommended_fields": [
                "specifications.rooms",
                "specifications.year_built",
                "specifications.energy_class",
                "specifications.energy_carrier",
                "specifications.energy_value",
                "specifications.energy_certificate_type",
                "photos",
            ],
            "missing_documents": ["energy_certificate", "floor_plan"],
            "geg87_compliant": False,
            "completion_percentage": 0,
        }


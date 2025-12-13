from __future__ import annotations

from typing import Any, Dict, List, Optional


def register_crm_extended_tools(mcp, invoke_backend_tool) -> None:
    @mcp.tool(name="crm_create_api_key", description="Create a scoped CRM API key for a tenant (admin-only).")
    async def crm_create_api_key(
        tenant_id: str,
        name: str,
        scopes: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        return await invoke_backend_tool(
            service="crm",
            path="/admin/create_api_key",
            method="POST",
            payload_data={"name": name, "scopes": scopes or []},
        )

    @mcp.tool(name="crm_upsert_user", description="Upsert a CRM user (admin-only).")
    async def crm_upsert_user(
        tenant_id: str,
        external_id: str,
        email: Optional[str] = None,
        display_name: Optional[str] = None,
        role: str = "agent",
        is_active: bool = True,
    ) -> Dict[str, Any]:
        return await invoke_backend_tool(
            service="crm",
            path="/admin/upsert_user",
            method="POST",
            payload_data={
                "external_id": external_id,
                "email": email,
                "display_name": display_name,
                "role": role,
                "is_active": is_active,
            },
        )

    @mcp.tool(name="crm_create_team", description="Create a CRM team (admin-only).")
    async def crm_create_team(
        tenant_id: str,
        name: str,
        parent_team_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        return await invoke_backend_tool(
            service="crm",
            path="/admin/create_team",
            method="POST",
            payload_data={"name": name, "parent_team_id": parent_team_id},
        )

    @mcp.tool(name="crm_add_team_member", description="Add a user to a team (admin-only).")
    async def crm_add_team_member(
        tenant_id: str,
        team_id: str,
        user_id: str,
        role: str = "member",
    ) -> Dict[str, Any]:
        return await invoke_backend_tool(
            service="crm",
            path="/admin/add_team_member",
            method="POST",
            payload_data={"team_id": team_id, "user_id": user_id, "role": role},
        )

    @mcp.tool(name="crm_assign_owner", description="Assign an owner user/team to a CRM entity.")
    async def crm_assign_owner(
        tenant_id: str,
        entity_type: str,
        entity_id: str,
        owner_user_id: Optional[str] = None,
        owner_team_id: Optional[str] = None,
        visibility: Optional[str] = None,
    ) -> Dict[str, Any]:
        return await invoke_backend_tool(
            service="crm",
            path="/admin/assign_owner",
            method="POST",
            payload_data={
                "entity_type": entity_type,
                "entity_id": entity_id,
                "owner_user_id": owner_user_id,
                "owner_team_id": owner_team_id,
                "visibility": visibility,
            },
        )

    @mcp.tool(name="crm_import_contacts_csv", description="Import contacts from CSV text. Uses hard-dedupe by email/phone.")
    async def crm_import_contacts_csv(
        tenant_id: str,
        csv_text: str,
        delimiter: str = ",",
        workspace_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        return await invoke_backend_tool(
            service="crm",
            path="/import/contacts_csv",
            method="POST",
            payload_data={"csv_text": csv_text, "delimiter": delimiter, "workspace_id": workspace_id},
        )

    @mcp.tool(name="crm_export_contacts_csv", description="Export contacts as CSV text.")
    async def crm_export_contacts_csv(
        tenant_id: str,
        limit: int = 1000,
    ) -> Dict[str, Any]:
        return await invoke_backend_tool(
            service="crm",
            path="/export/contacts_csv",
            method="POST",
            payload_data={"limit": limit},
        )

    @mcp.tool(name="crm_merge_contacts", description="Hard-merge two contact records (admin-only).")
    async def crm_merge_contacts(
        tenant_id: str,
        source_contact_id: str,
        target_contact_id: str,
    ) -> Dict[str, Any]:
        return await invoke_backend_tool(
            service="crm",
            path="/dedupe/merge_contacts",
            method="POST",
            payload_data={"source_contact_id": source_contact_id, "target_contact_id": target_contact_id},
        )

    @mcp.tool(name="crm_log_email_engagement", description="Log an email engagement on an entity (contact/company/deal).")
    async def crm_log_email_engagement(
        tenant_id: str,
        entity_type: str,
        entity_id: str,
        subject: str,
        body: str,
        direction: str = "outbound",
        occurred_at: Optional[str] = None,
    ) -> Dict[str, Any]:
        return await invoke_backend_tool(
            service="crm",
            path="/engagements/log_email",
            method="POST",
            payload_data={
                "entity_type": entity_type,
                "entity_id": entity_id,
                "subject": subject,
                "body": body,
                "direction": direction,
                "occurred_at": occurred_at,
            },
        )

    @mcp.tool(name="crm_report_pipeline", description="Pipeline report: stage counts + sums + weighted sums.")
    async def crm_report_pipeline(
        tenant_id: str,
        pipeline: Optional[str] = None,
    ) -> Dict[str, Any]:
        return await invoke_backend_tool(
            service="crm",
            path="/reports/pipeline",
            method="POST",
            payload_data={"pipeline": pipeline},
        )

    @mcp.tool(name="crm_forecast_pipeline", description="Forecast report: expected close by month, weighted by probability.")
    async def crm_forecast_pipeline(
        tenant_id: str,
        pipeline: Optional[str] = None,
        horizon_days: int = 90,
    ) -> Dict[str, Any]:
        return await invoke_backend_tool(
            service="crm",
            path="/forecast/pipeline",
            method="POST",
            payload_data={"pipeline": pipeline, "horizon_days": horizon_days},
        )

    @mcp.tool(name="crm_gdpr_export_contact_data", description="GDPR export for a contact (admin-only).")
    async def crm_gdpr_export_contact_data(
        tenant_id: str,
        contact_id: Optional[str] = None,
        email: Optional[str] = None,
    ) -> Dict[str, Any]:
        return await invoke_backend_tool(
            service="crm",
            path="/gdpr/export_contact_data",
            method="POST",
            payload_data={"contact_id": contact_id, "email": email},
        )

    @mcp.tool(name="crm_gdpr_delete_contact", description="GDPR delete a contact (admin-only, approval required).")
    async def crm_gdpr_delete_contact(
        tenant_id: str,
        user_approved: bool,
        contact_id: Optional[str] = None,
        email: Optional[str] = None,
    ) -> Dict[str, Any]:
        return await invoke_backend_tool(
            service="crm",
            path="/gdpr/delete_contact",
            method="POST",
            payload_data={"contact_id": contact_id, "email": email, "user_approved": user_approved},
            require_approval=True,
        )

    @mcp.tool(name="crm_gdpr_blocklist_email", description="Blocklist an email (admin-only).")
    async def crm_gdpr_blocklist_email(
        tenant_id: str,
        email: str,
        reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        return await invoke_backend_tool(
            service="crm",
            path="/gdpr/blocklist_email",
            method="POST",
            payload_data={"email": email, "reason": reason},
        )

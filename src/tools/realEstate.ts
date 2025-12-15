/**
 * Real Estate MCP Tools for property management, viewings, and leads.
 */

import { z } from "zod";
import { Tool } from "@modelcontextprotocol/sdk/types.js";

const BACKEND_URL = process.env.BACKEND_URL || "http://localhost:8000";

/**
 * Create a property tool.
 */
export const createPropertyTool: Tool = {
  name: "real_estate_create_property",
  description: "Create a new real estate property with basic information",
  inputSchema: {
    type: "object",
    properties: {
      tenant_id: {
        type: "string",
        description: "Tenant ID",
      },
      property_type: {
        type: "string",
        enum: ["apartment", "house", "commercial", "land", "office", "retail"],
        description: "Type of property",
      },
      address: {
        type: "object",
        properties: {
          street: { type: "string" },
          city: { type: "string" },
          zip: { type: "string" },
          country: { type: "string", default: "DE" },
        },
        required: ["street", "city", "zip"],
      },
      specifications: {
        type: "object",
        properties: {
          rooms: { type: "number" },
          living_space: { type: "number" },
          plot_size: { type: "number" },
          year_built: { type: "number" },
          energy_class: {
            type: "string",
            enum: ["A+", "A", "B", "C", "D", "E", "F", "G", "H"],
          },
          energy_carrier: {
            type: "string",
            enum: ["gas", "oil", "electric", "heat_pump", "solar", "pellets", "district_heating"],
          },
          energy_value: { type: "number" },
          energy_certificate_type: {
            type: "string",
            enum: ["consumption", "demand"],
          },
        },
      },
      pricing: {
        type: "object",
        properties: {
          purchase_price: { type: "number" },
          rent: { type: "number" },
          additional_costs: { type: "number" },
          deposit: { type: "number" },
        },
      },
    },
    required: ["tenant_id", "property_type", "address", "specifications", "pricing"],
  },
};

/**
 * Generate exposé tool.
 */
export const generateExposeTool: Tool = {
  name: "real_estate_generate_expose",
  description: "Generate an exposé for a property (portal, PDF, or social variant) with GEG §87 compliance check",
  inputSchema: {
    type: "object",
    properties: {
      tenant_id: {
        type: "string",
        description: "Tenant ID",
      },
      property_id: {
        type: "string",
        description: "Property ID",
      },
      variant: {
        type: "string",
        enum: ["portal", "pdf", "social"],
        default: "portal",
        description: "Exposé variant",
      },
      language: {
        type: "string",
        default: "de",
        description: "Language code",
      },
    },
    required: ["tenant_id", "property_id"],
  },
};

/**
 * Validate GEG §87 tool.
 */
export const validateGEG87Tool: Tool = {
  name: "real_estate_validate_geg87",
  description: "Validate property against GEG §87 requirements (German energy law)",
  inputSchema: {
    type: "object",
    properties: {
      tenant_id: {
        type: "string",
        description: "Tenant ID",
      },
      property_id: {
        type: "string",
        description: "Property ID",
      },
    },
    required: ["tenant_id", "property_id"],
  },
};

/**
 * Create viewing tool.
 */
export const createViewingTool: Tool = {
  name: "real_estate_create_viewing",
  description: "Create a property viewing appointment",
  inputSchema: {
    type: "object",
    properties: {
      tenant_id: {
        type: "string",
        description: "Tenant ID",
      },
      property_id: {
        type: "string",
        description: "Property ID",
      },
      scheduled_at: {
        type: "string",
        format: "date-time",
        description: "Scheduled date and time (ISO 8601)",
      },
      duration_minutes: {
        type: "number",
        default: 30,
        description: "Duration in minutes",
      },
      location: {
        type: "object",
        properties: {
          address: { type: "string" },
          meeting_point: { type: "string" },
          directions: { type: "string" },
        },
      },
    },
    required: ["tenant_id", "property_id", "scheduled_at"],
  },
};

/**
 * Process lead tool.
 */
export const processLeadTool: Tool = {
  name: "real_estate_process_lead",
  description: "Process an incoming lead from any channel (email, phone, portal, etc.) with AI triage and draft response generation",
  inputSchema: {
    type: "object",
    properties: {
      tenant_id: {
        type: "string",
        description: "Tenant ID",
      },
      source: {
        type: "string",
        enum: ["email", "phone", "portal", "whatsapp", "website", "social"],
        description: "Lead source",
      },
      raw_content: {
        type: "string",
        description: "Raw lead content (email body, message, etc.)",
      },
      contact_info: {
        type: "object",
        properties: {
          name: { type: "string" },
          email: { type: "string" },
          phone: { type: "string" },
        },
        required: ["name"],
      },
    },
    required: ["tenant_id", "source", "raw_content", "contact_info"],
  },
};

/**
 * Match lead to properties tool.
 */
export const matchLeadTool: Tool = {
  name: "real_estate_match_lead",
  description: "Match a lead's requirements to available properties",
  inputSchema: {
    type: "object",
    properties: {
      tenant_id: {
        type: "string",
        description: "Tenant ID",
      },
      lead_id: {
        type: "string",
        description: "Lead ID",
      },
      limit: {
        type: "number",
        default: 10,
        description: "Maximum number of matches",
      },
    },
    required: ["tenant_id", "lead_id"],
  },
};

/**
 * Get property wizard checklist tool.
 */
export const getWizardChecklistTool: Tool = {
  name: "real_estate_get_wizard_checklist",
  description: "Get checklist of required and recommended items for property onboarding",
  inputSchema: {
    type: "object",
    properties: {
      tenant_id: {
        type: "string",
        description: "Tenant ID",
      },
      property_id: {
        type: "string",
        description: "Property ID (optional, for existing property)",
      },
    },
    required: ["tenant_id"],
  },
};

/**
 * All real estate tools.
 */
export const realEstateTools: Tool[] = [
  createPropertyTool,
  generateExposeTool,
  validateGEG87Tool,
  createViewingTool,
  processLeadTool,
  matchLeadTool,
  getWizardChecklistTool,
];


/**
 * Assessment Integration Layer
 *
 * This file centralizes all assessment-related integration points with the upstream
 * MCP Inspector. When syncing with upstream, only this file needs to be reviewed
 * for integration changes (in addition to the minimal imports in App.tsx).
 *
 * See UPSTREAM_SYNC.md for detailed documentation of all integration points.
 *
 * @module integrations/assessment
 */

import { ClipboardCheck } from "lucide-react";
import type { Tool } from "@modelcontextprotocol/sdk/types.js";
import type { CompatibilityCallToolResult } from "@modelcontextprotocol/sdk/types.js";

// Re-export the AssessmentTab component
export { default as AssessmentTab } from "../components/AssessmentTab";

/**
 * Assessment tab configuration
 */
export const ASSESSMENT_TAB_CONFIG = {
  /** Tab identifier */
  id: "assessment" as const,
  /** Display label */
  label: "Assessment",
  /** Icon component */
  Icon: ClipboardCheck,
  /** Icon class name */
  iconClassName: "w-4 h-4 mr-2",
  /** Required server capability */
  requiresCapability: "tools" as const,
} as const;

/**
 * Props interface for the AssessmentTab component
 */
export interface AssessmentTabProps {
  tools: Tool[];
  isLoadingTools: boolean;
  listTools: () => void;
  callTool: (
    name: string,
    params: Record<string, unknown>,
  ) => Promise<CompatibilityCallToolResult>;
  serverName: string;
}

/**
 * Check if assessment tab should be enabled based on server capabilities
 */
export function isAssessmentEnabled(
  serverCapabilities: { tools?: unknown } | null,
): boolean {
  return Boolean(serverCapabilities?.tools);
}

/**
 * Get valid tabs including assessment if enabled
 */
export function getAssessmentTab(
  serverCapabilities: { tools?: unknown } | null,
): string[] {
  return isAssessmentEnabled(serverCapabilities)
    ? [ASSESSMENT_TAB_CONFIG.id]
    : [];
}

/**
 * Handler for auto-loading tools when assessment tab is selected
 */
export async function handleAssessmentTabSelect(
  currentTools: Tool[],
  serverCapabilities: { tools?: unknown } | null,
  listTools: () => Promise<void>,
  clearError: (key: string) => void,
): Promise<void> {
  if (currentTools.length === 0 && isAssessmentEnabled(serverCapabilities)) {
    try {
      clearError("tools");
      await listTools();
    } catch (error) {
      console.error("Failed to auto-load tools for assessment:", error);
    }
  }
}

// Feature flag is imported from lib/featureFlags.ts
// See that file for the ASSESSMENT_TAB feature flag

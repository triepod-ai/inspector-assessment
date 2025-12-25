/**
 * JSONL Event Emission Helpers
 *
 * These functions emit structured JSONL events to stderr for real-time
 * machine parsing during CLI assessment runs.
 *
 * Event Types:
 * - server_connected: Emitted after successful MCP connection
 * - tool_discovered: Emitted for each tool found
 * - tools_discovery_complete: Emitted after all tools listed
 * - assessment_complete: Emitted at end of assessment
 */

import type { Tool } from "@modelcontextprotocol/sdk/types.js";

// ============================================================================
// Types
// ============================================================================

export interface ToolParam {
  name: string;
  type: string;
  required: boolean;
  description?: string;
}

export interface ServerConnectedEvent {
  event: "server_connected";
  serverName: string;
  transport: "stdio" | "http" | "sse";
}

export interface ToolDiscoveredEvent {
  event: "tool_discovered";
  name: string;
  description: string | null;
  params: ToolParam[];
}

export interface ToolsDiscoveryCompleteEvent {
  event: "tools_discovery_complete";
  count: number;
}

export interface AssessmentCompleteEvent {
  event: "assessment_complete";
  overallStatus: string;
  totalTests: number;
  executionTime: number;
  outputPath: string;
}

export type JSONLEvent =
  | ServerConnectedEvent
  | ToolDiscoveredEvent
  | ToolsDiscoveryCompleteEvent
  | AssessmentCompleteEvent;

// ============================================================================
// Core Functions
// ============================================================================

/**
 * Emit a JSONL event to stderr for real-time machine parsing.
 */
export function emitJSONL(event: Record<string, unknown>): void {
  console.error(JSON.stringify(event));
}

/**
 * Emit server_connected event after successful connection.
 */
export function emitServerConnected(
  serverName: string,
  transport: "stdio" | "http" | "sse",
): void {
  emitJSONL({ event: "server_connected", serverName, transport });
}

/**
 * Emit tool_discovered event for each tool found.
 */
export function emitToolDiscovered(tool: Tool): void {
  const params = extractToolParams(tool.inputSchema);
  emitJSONL({
    event: "tool_discovered",
    name: tool.name,
    description: tool.description || null,
    params,
  });
}

/**
 * Emit tools_discovery_complete event after all tools discovered.
 */
export function emitToolsDiscoveryComplete(count: number): void {
  emitJSONL({ event: "tools_discovery_complete", count });
}

/**
 * Emit assessment_complete event at the end of assessment.
 */
export function emitAssessmentComplete(
  overallStatus: string,
  totalTests: number,
  executionTime: number,
  outputPath: string,
): void {
  emitJSONL({
    event: "assessment_complete",
    overallStatus,
    totalTests,
    executionTime,
    outputPath,
  });
}

/**
 * Extract parameter metadata from tool input schema.
 */
export function extractToolParams(schema: unknown): ToolParam[] {
  if (!schema || typeof schema !== "object") return [];
  const s = schema as Record<string, unknown>;
  if (!s.properties || typeof s.properties !== "object") return [];

  const required = new Set(
    Array.isArray(s.required) ? (s.required as string[]) : [],
  );
  const properties = s.properties as Record<string, Record<string, unknown>>;

  return Object.entries(properties).map(([name, prop]) => ({
    name,
    type: (prop.type as string) || "any",
    required: required.has(name),
    ...(prop.description && { description: prop.description as string }),
  }));
}

/**
 * Runtime Annotation Verifier
 *
 * Verifies that tool annotations are present in the tools/list runtime response.
 * This addresses Issue #207/#204 where servers defining annotations in code
 * (not manifest.json) were incorrectly reported as having 0% annotation coverage.
 *
 * @module assessment/helpers/RuntimeAnnotationVerifier
 * @see GitHub Issue #207, #204
 */

import type { Tool } from "@modelcontextprotocol/sdk/types.js";

/**
 * Location where annotations were found in the tool object
 */
export type AnnotationLocation =
  | "annotations_object" // tool.annotations.readOnlyHint
  | "direct_properties" // tool.readOnlyHint (preserved by SDK interceptor)
  | "metadata" // tool.metadata.readOnlyHint
  | "_meta" // tool._meta.readOnlyHint
  | "annotations_hints" // tool.annotations.hints.readOnlyHint
  | "none"; // No annotations found

/**
 * Per-tool annotation location details
 */
export interface ToolAnnotationLocationDetail {
  toolName: string;
  location: AnnotationLocation;
  foundHints: string[];
}

/**
 * Result of runtime annotation verification
 */
export interface RuntimeAnnotationVerification {
  /** Whether verification was performed successfully */
  verified: boolean;
  /** Total number of tools checked */
  totalTools: number;
  /** Number of tools with annotations in tools/list response */
  toolsWithRuntimeAnnotations: number;
  /** Number of tools without any annotations */
  toolsWithoutAnnotations: number;
  /** Coverage percentage (0-100) */
  runtimeCoveragePercent: number;
  /** Details per tool */
  toolDetails: ToolAnnotationLocationDetail[];
}

/**
 * Hint property names to check (both suffixed and non-suffixed)
 */
const HINT_PROPERTIES = [
  "readOnlyHint",
  "destructiveHint",
  "idempotentHint",
  "openWorldHint",
  "readOnly",
  "destructive",
  "idempotent",
  "openWorld",
] as const;

/**
 * Check if an object has any boolean hint properties
 */
function findHintProperties(
  obj: Record<string, unknown> | undefined,
): string[] {
  if (!obj) return [];
  const found: string[] = [];
  for (const prop of HINT_PROPERTIES) {
    if (typeof obj[prop] === "boolean") {
      found.push(prop);
    }
  }
  return found;
}

/**
 * Detect where annotations are located in a tool object
 */
function detectAnnotationLocation(tool: Tool): ToolAnnotationLocationDetail {
  const t = tool as Record<string, unknown>;
  const result: ToolAnnotationLocationDetail = {
    toolName: tool.name,
    location: "none",
    foundHints: [],
  };

  // Priority 1: Check annotations object (MCP 2024-11 spec)
  const annotations = t.annotations as Record<string, unknown> | undefined;
  if (annotations) {
    const hints = findHintProperties(annotations);
    if (hints.length > 0) {
      result.location = "annotations_object";
      result.foundHints = hints;
      return result;
    }

    // Check nested hints object (some servers nest hints inside annotations)
    const nestedHints = annotations.hints as
      | Record<string, unknown>
      | undefined;
    if (nestedHints) {
      const nestedFound = findHintProperties(nestedHints);
      if (nestedFound.length > 0) {
        result.location = "annotations_hints";
        result.foundHints = nestedFound;
        return result;
      }
    }
  }

  // Priority 2: Check direct properties (preserved by tools-with-hints.ts)
  const directHints = findHintProperties(t);
  if (directHints.length > 0) {
    result.location = "direct_properties";
    result.foundHints = directHints;
    return result;
  }

  // Priority 3: Check metadata object
  const metadata = t.metadata as Record<string, unknown> | undefined;
  if (metadata) {
    const metaHints = findHintProperties(metadata);
    if (metaHints.length > 0) {
      result.location = "metadata";
      result.foundHints = metaHints;
      return result;
    }
  }

  // Priority 4: Check _meta object
  const meta = t._meta as Record<string, unknown> | undefined;
  if (meta) {
    const metaHints = findHintProperties(meta);
    if (metaHints.length > 0) {
      result.location = "_meta";
      result.foundHints = metaHints;
      return result;
    }
  }

  return result;
}

/**
 * Verify that annotations are present in tools from the tools/list response.
 *
 * This function checks all possible annotation locations:
 * 1. tool.annotations object (MCP 2024-11 spec)
 * 2. Direct properties on tool (preserved by SDK interceptor)
 * 3. tool.metadata object
 * 4. tool._meta object
 * 5. tool.annotations.hints nested object
 *
 * @param tools - Array of tools from tools/list response
 * @returns Verification result with coverage stats and per-tool details
 */
export function verifyRuntimeAnnotations(
  tools: Tool[],
): RuntimeAnnotationVerification {
  if (!tools || tools.length === 0) {
    return {
      verified: true,
      totalTools: 0,
      toolsWithRuntimeAnnotations: 0,
      toolsWithoutAnnotations: 0,
      runtimeCoveragePercent: 0,
      toolDetails: [],
    };
  }

  const toolDetails: ToolAnnotationLocationDetail[] = [];
  let toolsWithAnnotations = 0;

  for (const tool of tools) {
    const detail = detectAnnotationLocation(tool);
    toolDetails.push(detail);
    if (detail.location !== "none") {
      toolsWithAnnotations++;
    }
  }

  const coveragePercent =
    tools.length > 0
      ? Math.round((toolsWithAnnotations / tools.length) * 100)
      : 0;

  return {
    verified: true,
    totalTools: tools.length,
    toolsWithRuntimeAnnotations: toolsWithAnnotations,
    toolsWithoutAnnotations: tools.length - toolsWithAnnotations,
    runtimeCoveragePercent: coveragePercent,
    toolDetails,
  };
}

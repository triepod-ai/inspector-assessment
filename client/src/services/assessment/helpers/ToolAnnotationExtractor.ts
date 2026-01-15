/**
 * Tool Annotation Extractor
 *
 * Pre-extracts annotations from all tools for security assessment context.
 * Issue #170: Enables annotation-aware security severity adjustment.
 *
 * This helper is used during context preparation to extract annotations
 * BEFORE security testing begins, allowing SecurityAssessor to adjust
 * vulnerability severity based on tool capabilities.
 *
 * @module helpers/ToolAnnotationExtractor
 */

import type { Tool } from "@modelcontextprotocol/sdk/types.js";
import { extractAnnotations } from "../modules/annotations/AlignmentChecker";
import type {
  ToolAnnotationsContext,
  SecurityAnnotations,
} from "@/lib/assessment/coreTypes";

/**
 * Extract tool annotations context from all tools.
 *
 * Iterates through all tools, extracts annotations using the existing
 * 5-tier priority system, and computes server-level flags for read-only
 * and closed-world servers.
 *
 * @param tools - Array of MCP tools to extract annotations from
 * @returns ToolAnnotationsContext with per-tool annotations and server flags
 *
 * @example
 * ```typescript
 * const context = extractToolAnnotationsContext(tools);
 * if (context.serverIsReadOnly) {
 *   console.log("Server is 100% read-only");
 * }
 * ```
 */
export function extractToolAnnotationsContext(
  tools: Tool[],
): ToolAnnotationsContext {
  const toolAnnotations = new Map<string, SecurityAnnotations>();
  let readOnlyCount = 0;
  let closedWorldCount = 0;
  let annotatedCount = 0;

  for (const tool of tools) {
    // Use existing extraction logic with 5-tier priority
    const extracted = extractAnnotations(tool);

    // Validate extracted data has valid source
    if (!extracted || !extracted.source) {
      continue; // Skip tools with invalid extraction
    }

    // Convert to SecurityAnnotations (subset of ExtractedAnnotations)
    // Ensure boolean fields are properly validated
    const securityAnnotations: SecurityAnnotations = {
      readOnlyHint:
        typeof extracted.readOnlyHint === "boolean"
          ? extracted.readOnlyHint
          : undefined,
      destructiveHint:
        typeof extracted.destructiveHint === "boolean"
          ? extracted.destructiveHint
          : undefined,
      idempotentHint:
        typeof extracted.idempotentHint === "boolean"
          ? extracted.idempotentHint
          : undefined,
      openWorldHint:
        typeof extracted.openWorldHint === "boolean"
          ? extracted.openWorldHint
          : undefined,
      source: extracted.source,
    };

    toolAnnotations.set(tool.name, securityAnnotations);

    // Count tools with annotations
    if (extracted.source !== "none") {
      annotatedCount++;

      // Count read-only tools
      if (extracted.readOnlyHint === true) {
        readOnlyCount++;
      }

      // Count closed-world tools
      if (extracted.openWorldHint === false) {
        closedWorldCount++;
      }
    }
  }

  const totalCount = tools.length;

  return {
    toolAnnotations,
    // Server is read-only only if ALL annotated tools are read-only
    serverIsReadOnly: annotatedCount > 0 && readOnlyCount === annotatedCount,
    // Server is closed only if ALL annotated tools are closed
    serverIsClosed: annotatedCount > 0 && closedWorldCount === annotatedCount,
    annotatedToolCount: annotatedCount,
    totalToolCount: totalCount,
  };
}

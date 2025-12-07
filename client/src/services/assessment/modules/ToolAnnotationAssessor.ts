/**
 * Tool Annotation Assessor
 * Verifies MCP tools have proper annotations per Policy #17
 *
 * Checks:
 * - readOnlyHint presence and accuracy
 * - destructiveHint presence and accuracy
 * - Tool behavior inference from name patterns
 * - Annotation misalignment detection
 *
 * Reference: Anthropic MCP Directory Policy #17
 */

import { BaseAssessor } from "./BaseAssessor";
import { AssessmentContext } from "../AssessmentOrchestrator";
import type {
  ToolAnnotationAssessment,
  ToolAnnotationResult,
  AssessmentStatus,
} from "@/lib/assessmentTypes";
import type { Tool } from "@modelcontextprotocol/sdk/types.js";

/**
 * Patterns for inferring expected tool behavior from name
 */
const READ_ONLY_PATTERNS = [
  /^get[_-]?/i,
  /^list[_-]?/i,
  /^fetch[_-]?/i,
  /^read[_-]?/i,
  /^query[_-]?/i,
  /^search[_-]?/i,
  /^find[_-]?/i,
  /^show[_-]?/i,
  /^view[_-]?/i,
  /^describe[_-]?/i,
  /^check[_-]?/i,
  /^verify[_-]?/i,
  /^validate[_-]?/i,
  /^count[_-]?/i,
  /^status[_-]?/i,
  /^info[_-]?/i,
  /^lookup[_-]?/i,
  /^browse[_-]?/i,
  /^preview[_-]?/i,
  /^download[_-]?/i, // Downloads but doesn't modify server state
];

const DESTRUCTIVE_PATTERNS = [
  /^delete[_-]?/i,
  /^remove[_-]?/i,
  /^destroy[_-]?/i,
  /^drop[_-]?/i,
  /^purge[_-]?/i,
  /^clear[_-]?/i,
  /^wipe[_-]?/i,
  /^erase[_-]?/i,
  /^reset[_-]?/i,
  /^truncate[_-]?/i,
  /^revoke[_-]?/i,
  /^terminate[_-]?/i,
  /^cancel[_-]?/i,
  /^kill[_-]?/i,
  /^force[_-]?/i,
];

const WRITE_PATTERNS = [
  /^create[_-]?/i,
  /^add[_-]?/i,
  /^insert[_-]?/i,
  /^update[_-]?/i,
  /^modify[_-]?/i,
  /^edit[_-]?/i,
  /^change[_-]?/i,
  /^set[_-]?/i,
  /^put[_-]?/i,
  /^patch[_-]?/i,
  /^post[_-]?/i,
  /^write[_-]?/i,
  /^save[_-]?/i,
  /^upload[_-]?/i,
  /^send[_-]?/i,
  /^submit[_-]?/i,
  /^publish[_-]?/i,
  /^enable[_-]?/i,
  /^disable[_-]?/i,
  /^start[_-]?/i,
  /^stop[_-]?/i,
  /^run[_-]?/i,
  /^execute[_-]?/i,
];

export class ToolAnnotationAssessor extends BaseAssessor {
  /**
   * Run tool annotation assessment
   */
  async assess(context: AssessmentContext): Promise<ToolAnnotationAssessment> {
    this.log("Starting tool annotation assessment");
    this.testCount = 0;

    const toolResults: ToolAnnotationResult[] = [];
    let annotatedCount = 0;
    let missingAnnotationsCount = 0;
    let misalignedAnnotationsCount = 0;

    for (const tool of context.tools) {
      this.testCount++;
      const result = this.assessTool(tool);
      toolResults.push(result);

      if (result.hasAnnotations) {
        annotatedCount++;
      } else {
        missingAnnotationsCount++;
      }

      if (result.issues.some((i) => i.includes("misaligned"))) {
        misalignedAnnotationsCount++;
      }
    }

    const status = this.determineAnnotationStatus(
      toolResults,
      context.tools.length,
    );
    const explanation = this.generateExplanation(
      annotatedCount,
      missingAnnotationsCount,
      misalignedAnnotationsCount,
      context.tools.length,
    );
    const recommendations = this.generateRecommendations(toolResults);

    this.log(
      `Assessment complete: ${annotatedCount}/${context.tools.length} tools annotated, ${misalignedAnnotationsCount} misaligned`,
    );

    return {
      toolResults,
      annotatedCount,
      missingAnnotationsCount,
      misalignedAnnotationsCount,
      status,
      explanation,
      recommendations,
    };
  }

  /**
   * Assess a single tool's annotations
   */
  private assessTool(tool: Tool): ToolAnnotationResult {
    const issues: string[] = [];
    const recommendations: string[] = [];

    // Extract annotations from tool
    const annotations = this.extractAnnotations(tool);
    const hasAnnotations =
      annotations.readOnlyHint !== undefined ||
      annotations.destructiveHint !== undefined;

    // Infer expected behavior from tool name
    const inferredBehavior = this.inferBehavior(tool.name, tool.description);

    // Check for missing annotations
    if (!hasAnnotations) {
      issues.push("Missing tool annotations (readOnlyHint, destructiveHint)");
      recommendations.push(
        `Add annotations to ${tool.name}: readOnlyHint=${inferredBehavior.expectedReadOnly}, destructiveHint=${inferredBehavior.expectedDestructive}`,
      );
    } else {
      // Check for misaligned annotations
      if (
        annotations.readOnlyHint !== undefined &&
        annotations.readOnlyHint !== inferredBehavior.expectedReadOnly
      ) {
        issues.push(
          `Potentially misaligned readOnlyHint: set to ${annotations.readOnlyHint}, expected ${inferredBehavior.expectedReadOnly} based on tool name pattern`,
        );
        recommendations.push(
          `Verify readOnlyHint for ${tool.name}: currently ${annotations.readOnlyHint}, tool name suggests ${inferredBehavior.expectedReadOnly}`,
        );
      }

      if (
        annotations.destructiveHint !== undefined &&
        annotations.destructiveHint !== inferredBehavior.expectedDestructive
      ) {
        issues.push(
          `Potentially misaligned destructiveHint: set to ${annotations.destructiveHint}, expected ${inferredBehavior.expectedDestructive} based on tool name pattern`,
        );
        recommendations.push(
          `Verify destructiveHint for ${tool.name}: currently ${annotations.destructiveHint}, tool name suggests ${inferredBehavior.expectedDestructive}`,
        );
      }
    }

    // Check for destructive tools without explicit hint
    if (
      inferredBehavior.expectedDestructive &&
      annotations.destructiveHint !== true
    ) {
      issues.push(
        "Tool appears destructive but destructiveHint is not set to true",
      );
      recommendations.push(
        `Set destructiveHint=true for ${tool.name} - this tool appears to perform destructive operations`,
      );
    }

    return {
      toolName: tool.name,
      hasAnnotations,
      annotations: hasAnnotations ? annotations : undefined,
      inferredBehavior,
      issues,
      recommendations,
    };
  }

  /**
   * Extract annotations from a tool
   * MCP SDK may have annotations in different locations
   */
  private extractAnnotations(tool: Tool): {
    readOnlyHint?: boolean;
    destructiveHint?: boolean;
    title?: string;
    description?: string;
    idempotentHint?: boolean;
    openWorldHint?: boolean;
  } {
    // Try to find annotations in various locations
    const toolAny = tool as any;

    // Check direct properties
    let readOnlyHint = toolAny.readOnlyHint;
    let destructiveHint = toolAny.destructiveHint;
    let idempotentHint = toolAny.idempotentHint;
    let openWorldHint = toolAny.openWorldHint;

    // Check annotations object (MCP 2024-11 spec)
    if (toolAny.annotations) {
      readOnlyHint = readOnlyHint ?? toolAny.annotations.readOnlyHint;
      destructiveHint = destructiveHint ?? toolAny.annotations.destructiveHint;
      idempotentHint = idempotentHint ?? toolAny.annotations.idempotentHint;
      openWorldHint = openWorldHint ?? toolAny.annotations.openWorldHint;
    }

    // Check metadata (some servers use this)
    if (toolAny.metadata) {
      readOnlyHint = readOnlyHint ?? toolAny.metadata.readOnlyHint;
      destructiveHint = destructiveHint ?? toolAny.metadata.destructiveHint;
    }

    return {
      readOnlyHint,
      destructiveHint,
      title: toolAny.title || toolAny.annotations?.title,
      description: tool.description,
      idempotentHint,
      openWorldHint,
    };
  }

  /**
   * Infer expected behavior from tool name and description
   */
  private inferBehavior(
    toolName: string,
    description?: string,
  ): {
    expectedReadOnly: boolean;
    expectedDestructive: boolean;
    reason: string;
  } {
    const lowerName = toolName.toLowerCase();
    const lowerDesc = (description || "").toLowerCase();

    // Check for destructive patterns first (higher priority)
    for (const pattern of DESTRUCTIVE_PATTERNS) {
      if (pattern.test(lowerName)) {
        return {
          expectedReadOnly: false,
          expectedDestructive: true,
          reason: `Tool name matches destructive pattern: ${pattern.source}`,
        };
      }
    }

    // Check for read-only patterns
    for (const pattern of READ_ONLY_PATTERNS) {
      if (pattern.test(lowerName)) {
        return {
          expectedReadOnly: true,
          expectedDestructive: false,
          reason: `Tool name matches read-only pattern: ${pattern.source}`,
        };
      }
    }

    // Check for write patterns (not destructive but not read-only)
    for (const pattern of WRITE_PATTERNS) {
      if (pattern.test(lowerName)) {
        return {
          expectedReadOnly: false,
          expectedDestructive: false,
          reason: `Tool name matches write pattern: ${pattern.source}`,
        };
      }
    }

    // Check description for hints
    if (lowerDesc.includes("delete") || lowerDesc.includes("remove")) {
      return {
        expectedReadOnly: false,
        expectedDestructive: true,
        reason: "Description mentions delete/remove operations",
      };
    }

    if (
      lowerDesc.includes("read") ||
      lowerDesc.includes("get") ||
      lowerDesc.includes("fetch")
    ) {
      return {
        expectedReadOnly: true,
        expectedDestructive: false,
        reason: "Description suggests read-only operation",
      };
    }

    // Default: assume write (safer to warn about missing annotations)
    return {
      expectedReadOnly: false,
      expectedDestructive: false,
      reason:
        "Could not infer from name pattern - defaulting to write operation",
    };
  }

  /**
   * Determine overall status
   */
  private determineAnnotationStatus(
    results: ToolAnnotationResult[],
    totalTools: number,
  ): AssessmentStatus {
    if (totalTools === 0) return "PASS";

    const annotatedCount = results.filter((r) => r.hasAnnotations).length;
    const misalignedCount = results.filter((r) =>
      r.issues.some((i) => i.includes("misaligned")),
    ).length;
    const destructiveWithoutHint = results.filter((r) =>
      r.issues.some((i) => i.includes("destructive") && i.includes("not set")),
    ).length;

    // Destructive tools without proper hints = FAIL (check this FIRST)
    if (destructiveWithoutHint > 0) {
      return "FAIL";
    }

    // All tools annotated and no misalignments = PASS
    if (annotatedCount === totalTools && misalignedCount === 0) {
      return "PASS";
    }

    // Some annotations missing = NEED_MORE_INFO
    const annotationRate = annotatedCount / totalTools;
    if (annotationRate >= 0.8) {
      return "NEED_MORE_INFO";
    }

    // Mostly missing annotations = FAIL
    if (annotationRate < 0.5) {
      return "FAIL";
    }

    return "NEED_MORE_INFO";
  }

  /**
   * Generate explanation
   */
  private generateExplanation(
    annotatedCount: number,
    missingCount: number,
    misalignedCount: number,
    totalTools: number,
  ): string {
    const parts: string[] = [];

    if (totalTools === 0) {
      return "No tools found to assess for annotations.";
    }

    parts.push(
      `Tool annotation coverage: ${annotatedCount}/${totalTools} tools have annotations.`,
    );

    if (missingCount > 0) {
      parts.push(
        `${missingCount} tool(s) are missing required annotations (readOnlyHint, destructiveHint).`,
      );
    }

    if (misalignedCount > 0) {
      parts.push(
        `${misalignedCount} tool(s) have potentially misaligned annotations based on naming patterns.`,
      );
    }

    if (missingCount === 0 && misalignedCount === 0) {
      parts.push("All tools are properly annotated.");
    }

    return parts.join(" ");
  }

  /**
   * Generate recommendations
   */
  private generateRecommendations(results: ToolAnnotationResult[]): string[] {
    const recommendations: string[] = [];

    // Collect unique recommendations from all tools
    const allRecs = new Set<string>();

    for (const result of results) {
      for (const rec of result.recommendations) {
        allRecs.add(rec);
      }
    }

    // Prioritize destructive tool warnings
    const destructiveRecs = Array.from(allRecs).filter((r) =>
      r.includes("destructive"),
    );
    const otherRecs = Array.from(allRecs).filter(
      (r) => !r.includes("destructive"),
    );

    if (destructiveRecs.length > 0) {
      recommendations.push(
        "PRIORITY: The following tools appear to perform destructive operations but lack proper destructiveHint annotation:",
      );
      recommendations.push(...destructiveRecs.slice(0, 5));
    }

    if (otherRecs.length > 0) {
      recommendations.push(...otherRecs.slice(0, 5));
    }

    if (recommendations.length === 0) {
      recommendations.push(
        "All tools have proper annotations. No action required.",
      );
    } else {
      recommendations.push(
        "Reference: MCP Directory Policy #17 requires tools to have readOnlyHint and destructiveHint annotations.",
      );
    }

    return recommendations;
  }
}

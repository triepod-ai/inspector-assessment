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
import type { ClaudeCodeBridge } from "../lib/claudeCodeBridge";

/**
 * Enhanced tool annotation result with Claude inference
 */
export interface EnhancedToolAnnotationResult extends ToolAnnotationResult {
  claudeInference?: {
    expectedReadOnly: boolean;
    expectedDestructive: boolean;
    confidence: number;
    reasoning: string;
    suggestedAnnotations: {
      readOnlyHint?: boolean;
      destructiveHint?: boolean;
      idempotentHint?: boolean;
    };
    misalignmentDetected: boolean;
    misalignmentDetails?: string;
    source: "claude-inferred" | "pattern-based";
  };
}

/**
 * Enhanced assessment with Claude integration
 */
export interface EnhancedToolAnnotationAssessment extends ToolAnnotationAssessment {
  toolResults: EnhancedToolAnnotationResult[];
  claudeEnhanced: boolean;
  highConfidenceMisalignments: EnhancedToolAnnotationResult[];
}

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
  private claudeBridge?: ClaudeCodeBridge;

  /**
   * Set Claude Code Bridge for enhanced behavior inference
   */
  setClaudeBridge(bridge: ClaudeCodeBridge): void {
    this.claudeBridge = bridge;
    this.log("Claude Code Bridge enabled for behavior inference");
  }

  /**
   * Check if Claude enhancement is available
   */
  isClaudeEnabled(): boolean {
    return (
      this.claudeBridge !== undefined &&
      this.claudeBridge.isFeatureEnabled("annotationInference")
    );
  }

  /**
   * Run tool annotation assessment
   */
  async assess(
    context: AssessmentContext,
  ): Promise<ToolAnnotationAssessment | EnhancedToolAnnotationAssessment> {
    this.log("Starting tool annotation assessment");
    this.testCount = 0;

    const toolResults: EnhancedToolAnnotationResult[] = [];
    let annotatedCount = 0;
    let missingAnnotationsCount = 0;
    let misalignedAnnotationsCount = 0;

    const useClaudeInference = this.isClaudeEnabled();
    if (useClaudeInference) {
      this.log(
        "Claude Code integration enabled - using semantic behavior inference",
      );
    }

    for (const tool of context.tools) {
      this.testCount++;
      const result = this.assessTool(tool);

      // Enhance with Claude inference if available
      if (useClaudeInference) {
        const enhancedResult = await this.enhanceWithClaudeInference(
          tool,
          result,
        );
        toolResults.push(enhancedResult);

        // Count based on Claude analysis if high confidence
        if (
          enhancedResult.claudeInference &&
          enhancedResult.claudeInference.confidence >= 70 &&
          enhancedResult.claudeInference.misalignmentDetected
        ) {
          misalignedAnnotationsCount++;
        } else if (result.issues.some((i) => i.includes("misaligned"))) {
          misalignedAnnotationsCount++;
        }
      } else {
        // Standard pattern-based result
        const inferredBehavior = result.inferredBehavior ?? {
          expectedReadOnly: false,
          expectedDestructive: false,
          reason: "No behavior inference available",
        };
        toolResults.push({
          ...result,
          claudeInference: {
            expectedReadOnly: inferredBehavior.expectedReadOnly,
            expectedDestructive: inferredBehavior.expectedDestructive,
            confidence: 50, // Lower confidence for pattern-based
            reasoning: inferredBehavior.reason,
            suggestedAnnotations: {
              readOnlyHint: inferredBehavior.expectedReadOnly,
              destructiveHint: inferredBehavior.expectedDestructive,
            },
            misalignmentDetected: result.issues.some((i) =>
              i.includes("misaligned"),
            ),
            source: "pattern-based",
          },
        });

        if (result.issues.some((i) => i.includes("misaligned"))) {
          misalignedAnnotationsCount++;
        }
      }

      if (toolResults[toolResults.length - 1].hasAnnotations) {
        annotatedCount++;
      } else {
        missingAnnotationsCount++;
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

    // Return enhanced assessment if Claude was used
    if (useClaudeInference) {
      const highConfidenceMisalignments = toolResults.filter(
        (r) =>
          r.claudeInference &&
          r.claudeInference.confidence >= 70 &&
          r.claudeInference.misalignmentDetected,
      );

      this.log(
        `Claude inference found ${highConfidenceMisalignments.length} high-confidence misalignments`,
      );

      return {
        toolResults,
        annotatedCount,
        missingAnnotationsCount,
        misalignedAnnotationsCount,
        status,
        explanation: this.generateEnhancedExplanation(
          annotatedCount,
          missingAnnotationsCount,
          highConfidenceMisalignments.length,
          context.tools.length,
        ),
        recommendations: this.generateEnhancedRecommendations(toolResults),
        claudeEnhanced: true,
        highConfidenceMisalignments,
      };
    }

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
   * Enhance tool assessment with Claude inference
   */
  private async enhanceWithClaudeInference(
    tool: Tool,
    baseResult: ToolAnnotationResult,
  ): Promise<EnhancedToolAnnotationResult> {
    const inferredBehavior = baseResult.inferredBehavior ?? {
      expectedReadOnly: false,
      expectedDestructive: false,
      reason: "No behavior inference available",
    };

    if (!this.claudeBridge) {
      return {
        ...baseResult,
        claudeInference: {
          expectedReadOnly: inferredBehavior.expectedReadOnly,
          expectedDestructive: inferredBehavior.expectedDestructive,
          confidence: 50,
          reasoning: inferredBehavior.reason,
          suggestedAnnotations: {
            readOnlyHint: inferredBehavior.expectedReadOnly,
            destructiveHint: inferredBehavior.expectedDestructive,
          },
          misalignmentDetected: baseResult.issues.some((i) =>
            i.includes("misaligned"),
          ),
          source: "pattern-based",
        },
      };
    }

    try {
      const currentAnnotations = baseResult.annotations
        ? {
            readOnlyHint: baseResult.annotations.readOnlyHint,
            destructiveHint: baseResult.annotations.destructiveHint,
          }
        : undefined;

      const inference = await this.claudeBridge.inferToolBehavior(
        tool,
        currentAnnotations,
      );

      // Handle null result (Claude unavailable or error)
      if (!inference) {
        return {
          ...baseResult,
          claudeInference: {
            expectedReadOnly: inferredBehavior.expectedReadOnly,
            expectedDestructive: inferredBehavior.expectedDestructive,
            confidence: 0,
            reasoning:
              "Claude inference unavailable. Using pattern-based analysis.",
            suggestedAnnotations: {},
            misalignmentDetected: false,
            misalignmentDetails: undefined,
            source: "pattern-based",
          },
        };
      }

      // Merge Claude inference with pattern-based findings
      const updatedIssues = [...baseResult.issues];
      const updatedRecommendations = [...baseResult.recommendations];

      // Add Claude-detected misalignment if high confidence
      if (inference.misalignmentDetected && inference.confidence >= 70) {
        const misalignmentMsg = inference.misalignmentDetails
          ? `Claude analysis (${inference.confidence}% confidence): ${inference.misalignmentDetails}`
          : `Claude analysis detected annotation misalignment with ${inference.confidence}% confidence`;

        if (!updatedIssues.some((i) => i.includes("Claude analysis"))) {
          updatedIssues.push(misalignmentMsg);
        }

        // Add specific recommendations based on Claude inference
        if (inference.suggestedAnnotations) {
          const { readOnlyHint, destructiveHint, idempotentHint } =
            inference.suggestedAnnotations;

          if (
            readOnlyHint !== undefined &&
            readOnlyHint !== baseResult.annotations?.readOnlyHint
          ) {
            updatedRecommendations.push(
              `Claude suggests: Set readOnlyHint=${readOnlyHint} for ${tool.name}`,
            );
          }
          if (
            destructiveHint !== undefined &&
            destructiveHint !== baseResult.annotations?.destructiveHint
          ) {
            updatedRecommendations.push(
              `Claude suggests: Set destructiveHint=${destructiveHint} for ${tool.name}`,
            );
          }
          if (idempotentHint !== undefined) {
            updatedRecommendations.push(
              `Claude suggests: Consider adding idempotentHint=${idempotentHint} for ${tool.name}`,
            );
          }
        }
      }

      return {
        ...baseResult,
        issues: updatedIssues,
        recommendations: updatedRecommendations,
        claudeInference: {
          expectedReadOnly: inference.expectedReadOnly,
          expectedDestructive: inference.expectedDestructive,
          confidence: inference.confidence,
          reasoning: inference.reasoning,
          suggestedAnnotations: inference.suggestedAnnotations,
          misalignmentDetected: inference.misalignmentDetected,
          misalignmentDetails: inference.misalignmentDetails,
          source: "claude-inferred",
        },
      };
    } catch (error) {
      this.logError(`Claude inference failed for ${tool.name}`, error);

      // Fall back to pattern-based (use inferredBehavior from top of function)
      return {
        ...baseResult,
        claudeInference: {
          expectedReadOnly: inferredBehavior.expectedReadOnly,
          expectedDestructive: inferredBehavior.expectedDestructive,
          confidence: 50,
          reasoning: `Claude inference failed, using pattern-based: ${inferredBehavior.reason}`,
          suggestedAnnotations: {
            readOnlyHint: inferredBehavior.expectedReadOnly,
            destructiveHint: inferredBehavior.expectedDestructive,
          },
          misalignmentDetected: baseResult.issues.some((i) =>
            i.includes("misaligned"),
          ),
          source: "pattern-based",
        },
      };
    }
  }

  /**
   * Generate enhanced explanation with Claude analysis
   */
  private generateEnhancedExplanation(
    annotatedCount: number,
    missingCount: number,
    highConfidenceMisalignments: number,
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

    if (highConfidenceMisalignments > 0) {
      parts.push(
        `Claude analysis identified ${highConfidenceMisalignments} high-confidence annotation misalignment(s).`,
      );
    }

    parts.push("Analysis enhanced with Claude semantic behavior inference.");

    return parts.join(" ");
  }

  /**
   * Generate enhanced recommendations with Claude analysis
   */
  private generateEnhancedRecommendations(
    results: EnhancedToolAnnotationResult[],
  ): string[] {
    const recommendations: string[] = [];

    // Prioritize Claude high-confidence misalignments
    const claudeMisalignments = results.filter(
      (r) =>
        r.claudeInference &&
        r.claudeInference.source === "claude-inferred" &&
        r.claudeInference.confidence >= 70 &&
        r.claudeInference.misalignmentDetected,
    );

    if (claudeMisalignments.length > 0) {
      recommendations.push(
        "HIGH CONFIDENCE: Claude analysis identified the following annotation issues:",
      );
      for (const result of claudeMisalignments.slice(0, 5)) {
        if (result.claudeInference) {
          recommendations.push(
            `  - ${result.toolName}: ${result.claudeInference.reasoning}`,
          );
        }
      }
    }

    // Collect Claude suggestions
    const claudeSuggestions = results
      .filter(
        (r) =>
          r.claudeInference &&
          r.claudeInference.source === "claude-inferred" &&
          r.claudeInference.confidence >= 60,
      )
      .flatMap((r) =>
        r.recommendations.filter((rec) => rec.includes("Claude")),
      );

    if (claudeSuggestions.length > 0) {
      recommendations.push(...claudeSuggestions.slice(0, 5));
    }

    // Add pattern-based recommendations for remaining tools
    const patternRecs = new Set<string>();
    for (const result of results) {
      for (const rec of result.recommendations) {
        if (!rec.includes("Claude")) {
          patternRecs.add(rec);
        }
      }
    }

    const destructiveRecs = Array.from(patternRecs).filter((r) =>
      r.includes("destructive"),
    );
    const otherRecs = Array.from(patternRecs).filter(
      (r) => !r.includes("destructive"),
    );

    if (destructiveRecs.length > 0) {
      recommendations.push(
        "PRIORITY: Potential destructive tools without proper hints:",
      );
      recommendations.push(...destructiveRecs.slice(0, 3));
    }

    if (otherRecs.length > 0 && recommendations.length < 10) {
      recommendations.push(...otherRecs.slice(0, 3));
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

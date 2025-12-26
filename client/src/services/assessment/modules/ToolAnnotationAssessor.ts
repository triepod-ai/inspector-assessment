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
  AlignmentStatus,
  InferenceConfidence,
  ToolParamProgress,
  AssessmentConfiguration,
  AnnotationSource,
} from "@/lib/assessmentTypes";
import type { Tool } from "@modelcontextprotocol/sdk/types.js";
import type { ClaudeCodeBridge } from "../lib/claudeCodeBridge";
import {
  type CompiledPatterns,
  getDefaultCompiledPatterns,
  matchToolPattern,
} from "../config/annotationPatterns";

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

// NOTE: Pattern arrays moved to config/annotationPatterns.ts for configurability
// The patterns are now loaded from getDefaultCompiledPatterns() or custom config

export class ToolAnnotationAssessor extends BaseAssessor {
  private claudeBridge?: ClaudeCodeBridge;
  private compiledPatterns: CompiledPatterns;

  constructor(config: AssessmentConfiguration) {
    super(config);
    // Initialize with default patterns (can be overridden via setPatterns)
    this.compiledPatterns = getDefaultCompiledPatterns();
  }

  /**
   * Set custom compiled patterns for behavior inference
   */
  setPatterns(patterns: CompiledPatterns): void {
    this.compiledPatterns = patterns;
    this.log("Custom annotation patterns configured");
  }

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

    // Track annotation sources
    const annotationSourceCounts = {
      mcp: 0,
      sourceCode: 0,
      inferred: 0,
      none: 0,
    };

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

      const latestResult = toolResults[toolResults.length - 1];
      if (latestResult.hasAnnotations) {
        annotatedCount++;
      } else {
        missingAnnotationsCount++;
      }

      // Track annotation source
      const source = latestResult.annotationSource;
      if (source === "mcp") {
        annotationSourceCounts.mcp++;
      } else if (source === "source-code") {
        annotationSourceCounts.sourceCode++;
      } else if (source === "inferred") {
        annotationSourceCounts.inferred++;
      } else {
        annotationSourceCounts.none++;
      }

      // Emit annotation_missing event with tool details
      if (!latestResult.hasAnnotations) {
        if (context.onProgress && latestResult.inferredBehavior) {
          const annotations = this.extractAnnotations(tool);
          context.onProgress({
            type: "annotation_missing",
            tool: tool.name,
            title: annotations.title,
            description: tool.description,
            parameters: this.extractToolParams(tool.inputSchema),
            inferredBehavior: {
              expectedReadOnly: latestResult.inferredBehavior.expectedReadOnly,
              expectedDestructive:
                latestResult.inferredBehavior.expectedDestructive,
              reason: latestResult.inferredBehavior.reason,
            },
          });
        }
      }

      // Emit appropriate event based on alignment status
      if (context.onProgress && latestResult.inferredBehavior) {
        const annotations = latestResult.annotations;
        const inferred = latestResult.inferredBehavior;
        const confidence = latestResult.claudeInference?.confidence ?? 50;
        const toolParams = this.extractToolParams(tool.inputSchema);
        const toolAnnotations = this.extractAnnotations(tool);
        const alignmentStatus = latestResult.alignmentStatus;

        // Check readOnlyHint mismatch
        if (
          annotations?.readOnlyHint !== undefined &&
          annotations.readOnlyHint !== inferred.expectedReadOnly
        ) {
          if (alignmentStatus === "REVIEW_RECOMMENDED") {
            // Emit review_recommended for ambiguous cases
            context.onProgress({
              type: "annotation_review_recommended",
              tool: tool.name,
              title: toolAnnotations.title,
              description: tool.description,
              parameters: toolParams,
              field: "readOnlyHint",
              actual: annotations.readOnlyHint,
              inferred: inferred.expectedReadOnly,
              confidence: inferred.confidence,
              isAmbiguous: inferred.isAmbiguous,
              reason: inferred.reason,
            });
          } else {
            // Emit misaligned for high-confidence mismatches
            context.onProgress({
              type: "annotation_misaligned",
              tool: tool.name,
              title: toolAnnotations.title,
              description: tool.description,
              parameters: toolParams,
              field: "readOnlyHint",
              actual: annotations.readOnlyHint,
              expected: inferred.expectedReadOnly,
              confidence,
              reason: `Tool has readOnlyHint=${annotations.readOnlyHint}, but ${inferred.reason}`,
            });
          }
        }

        // Check destructiveHint mismatch
        if (
          annotations?.destructiveHint !== undefined &&
          annotations.destructiveHint !== inferred.expectedDestructive
        ) {
          if (alignmentStatus === "REVIEW_RECOMMENDED") {
            // Emit review_recommended for ambiguous cases
            context.onProgress({
              type: "annotation_review_recommended",
              tool: tool.name,
              title: toolAnnotations.title,
              description: tool.description,
              parameters: toolParams,
              field: "destructiveHint",
              actual: annotations.destructiveHint,
              inferred: inferred.expectedDestructive,
              confidence: inferred.confidence,
              isAmbiguous: inferred.isAmbiguous,
              reason: inferred.reason,
            });
          } else {
            // Emit misaligned for high-confidence mismatches
            context.onProgress({
              type: "annotation_misaligned",
              tool: tool.name,
              title: toolAnnotations.title,
              description: tool.description,
              parameters: toolParams,
              field: "destructiveHint",
              actual: annotations.destructiveHint,
              expected: inferred.expectedDestructive,
              confidence,
              reason: `Tool has destructiveHint=${annotations.destructiveHint}, but ${inferred.reason}`,
            });
          }
        }
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

    // Calculate new metrics and alignment breakdown
    const { metrics, alignmentBreakdown } = this.calculateMetrics(
      toolResults,
      context.tools.length,
    );

    this.log(
      `Assessment complete: ${annotatedCount}/${context.tools.length} tools annotated, ${misalignedAnnotationsCount} misaligned, ${alignmentBreakdown.reviewRecommended} need review`,
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
        metrics,
        alignmentBreakdown,
        annotationSources: annotationSourceCounts,
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
      metrics,
      alignmentBreakdown,
      annotationSources: annotationSourceCounts,
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
   * Now includes alignment status with confidence-aware logic
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

    // Determine alignment status
    let alignmentStatus: AlignmentStatus = "ALIGNED";

    // Check for missing annotations
    if (!hasAnnotations) {
      issues.push("Missing tool annotations (readOnlyHint, destructiveHint)");
      recommendations.push(
        `Add annotations to ${tool.name}: readOnlyHint=${inferredBehavior.expectedReadOnly}, destructiveHint=${inferredBehavior.expectedDestructive}`,
      );
      alignmentStatus = "UNKNOWN";
    } else {
      // Check for misaligned annotations with confidence-aware logic
      const readOnlyMismatch =
        annotations.readOnlyHint !== undefined &&
        annotations.readOnlyHint !== inferredBehavior.expectedReadOnly;

      const destructiveMismatch =
        annotations.destructiveHint !== undefined &&
        annotations.destructiveHint !== inferredBehavior.expectedDestructive;

      if (readOnlyMismatch || destructiveMismatch) {
        if (
          inferredBehavior.isAmbiguous ||
          inferredBehavior.confidence === "low"
        ) {
          // Ambiguous case: REVIEW_RECOMMENDED, softer language
          alignmentStatus = "REVIEW_RECOMMENDED";

          if (readOnlyMismatch) {
            issues.push(
              `Review recommended: readOnlyHint=${annotations.readOnlyHint} may or may not match '${tool.name}' behavior (confidence: ${inferredBehavior.confidence})`,
            );
            recommendations.push(
              `Verify readOnlyHint for ${tool.name}: pattern is ambiguous - manual review recommended`,
            );
          }
          if (destructiveMismatch) {
            issues.push(
              `Review recommended: destructiveHint=${annotations.destructiveHint} may or may not match '${tool.name}' behavior (confidence: ${inferredBehavior.confidence})`,
            );
            recommendations.push(
              `Verify destructiveHint for ${tool.name}: pattern is ambiguous - manual review recommended`,
            );
          }
        } else {
          // High/medium confidence mismatch: MISALIGNED
          alignmentStatus = "MISALIGNED";

          if (readOnlyMismatch) {
            issues.push(
              `Potentially misaligned readOnlyHint: set to ${annotations.readOnlyHint}, expected ${inferredBehavior.expectedReadOnly} based on tool name pattern`,
            );
            recommendations.push(
              `Verify readOnlyHint for ${tool.name}: currently ${annotations.readOnlyHint}, tool name suggests ${inferredBehavior.expectedReadOnly}`,
            );
          }
          if (destructiveMismatch) {
            issues.push(
              `Potentially misaligned destructiveHint: set to ${annotations.destructiveHint}, expected ${inferredBehavior.expectedDestructive} based on tool name pattern`,
            );
            recommendations.push(
              `Verify destructiveHint for ${tool.name}: currently ${annotations.destructiveHint}, tool name suggests ${inferredBehavior.expectedDestructive}`,
            );
          }
        }
      }
    }

    // Check for destructive tools without explicit hint (only for high-confidence patterns)
    if (
      inferredBehavior.expectedDestructive &&
      inferredBehavior.confidence !== "low" &&
      annotations.destructiveHint !== true
    ) {
      issues.push(
        "Tool appears destructive but destructiveHint is not set to true",
      );
      recommendations.push(
        `Set destructiveHint=true for ${tool.name} - this tool appears to perform destructive operations`,
      );
      // Only upgrade to MISALIGNED if we have high confidence
      if (inferredBehavior.confidence === "high") {
        alignmentStatus = "MISALIGNED";
      }
    }

    return {
      toolName: tool.name,
      hasAnnotations,
      annotations: hasAnnotations ? annotations : undefined,
      annotationSource: annotations.source,
      inferredBehavior,
      alignmentStatus,
      issues,
      recommendations,
    };
  }

  /**
   * Extract annotations from a tool
   * MCP SDK may have annotations in different locations
   *
   * Priority order:
   * 1. tool.annotations (MCP 2024-11 spec) - "mcp" source
   * 2. Direct properties on tool - "mcp" source
   * 3. tool.metadata - "mcp" source
   * 4. No annotations found - "none" source
   */
  private extractAnnotations(tool: Tool): {
    readOnlyHint?: boolean;
    destructiveHint?: boolean;
    title?: string;
    description?: string;
    idempotentHint?: boolean;
    openWorldHint?: boolean;
    source: AnnotationSource;
  } {
    const toolAny = tool as any;

    // Priority 1: Check annotations object (MCP 2024-11 spec) - primary source
    if (toolAny.annotations) {
      const hasAnnotations =
        toolAny.annotations.readOnlyHint !== undefined ||
        toolAny.annotations.destructiveHint !== undefined;

      if (hasAnnotations) {
        return {
          readOnlyHint: toolAny.annotations.readOnlyHint,
          destructiveHint: toolAny.annotations.destructiveHint,
          title: toolAny.annotations.title || toolAny.title,
          description: tool.description,
          idempotentHint: toolAny.annotations.idempotentHint,
          openWorldHint: toolAny.annotations.openWorldHint,
          source: "mcp",
        };
      }
    }

    // Priority 2: Check direct properties on tool object
    if (
      toolAny.readOnlyHint !== undefined ||
      toolAny.destructiveHint !== undefined
    ) {
      return {
        readOnlyHint: toolAny.readOnlyHint,
        destructiveHint: toolAny.destructiveHint,
        title: toolAny.title,
        description: tool.description,
        idempotentHint: toolAny.idempotentHint,
        openWorldHint: toolAny.openWorldHint,
        source: "mcp",
      };
    }

    // Priority 3: Check metadata (some servers use this)
    if (toolAny.metadata) {
      const hasMetadataAnnotations =
        toolAny.metadata.readOnlyHint !== undefined ||
        toolAny.metadata.destructiveHint !== undefined;

      if (hasMetadataAnnotations) {
        return {
          readOnlyHint: toolAny.metadata.readOnlyHint,
          destructiveHint: toolAny.metadata.destructiveHint,
          title: toolAny.metadata.title || toolAny.title,
          description: tool.description,
          idempotentHint: toolAny.metadata.idempotentHint,
          openWorldHint: toolAny.metadata.openWorldHint,
          source: "mcp",
        };
      }
    }

    // No annotations found from MCP protocol
    return {
      title: toolAny.title,
      description: tool.description,
      source: "none",
    };
  }

  /**
   * Extract parameters from tool input schema for event emission
   */
  private extractToolParams(schema: unknown): ToolParamProgress[] {
    if (!schema || typeof schema !== "object") return [];
    const s = schema as Record<string, unknown>;
    if (!s.properties || typeof s.properties !== "object") return [];

    const required = new Set(
      Array.isArray(s.required) ? (s.required as string[]) : [],
    );
    const properties = s.properties as Record<string, Record<string, unknown>>;

    return Object.entries(properties).map(([name, prop]) => {
      const param: ToolParamProgress = {
        name,
        type: (prop.type as string) || "any",
        required: required.has(name),
      };
      if (prop.description) {
        param.description = prop.description as string;
      }
      return param;
    });
  }

  /**
   * Infer expected behavior from tool name and description
   * Now returns confidence level and ambiguity flag for better handling
   */
  private inferBehavior(
    toolName: string,
    description?: string,
  ): {
    expectedReadOnly: boolean;
    expectedDestructive: boolean;
    reason: string;
    confidence: InferenceConfidence;
    isAmbiguous: boolean;
  } {
    const lowerDesc = (description || "").toLowerCase();

    // Use the configurable pattern matching system
    const patternMatch = matchToolPattern(toolName, this.compiledPatterns);

    // Handle pattern match results
    switch (patternMatch.category) {
      case "ambiguous":
        // Ambiguous patterns - don't make strong assertions
        return {
          expectedReadOnly: false,
          expectedDestructive: false,
          reason: `Tool name matches ambiguous pattern '${patternMatch.pattern}' - behavior varies by implementation context`,
          confidence: "low",
          isAmbiguous: true,
        };

      case "destructive":
        return {
          expectedReadOnly: false,
          expectedDestructive: true,
          reason: `Tool name matches destructive pattern: ${patternMatch.pattern}`,
          confidence: "high",
          isAmbiguous: false,
        };

      case "readOnly":
        return {
          expectedReadOnly: true,
          expectedDestructive: false,
          reason: `Tool name matches read-only pattern: ${patternMatch.pattern}`,
          confidence: "high",
          isAmbiguous: false,
        };

      case "write":
        return {
          expectedReadOnly: false,
          expectedDestructive: false,
          reason: `Tool name matches write pattern: ${patternMatch.pattern}`,
          confidence: "medium",
          isAmbiguous: false,
        };

      case "unknown":
      default:
        // Fall through to description-based analysis
        break;
    }

    // Check description for hints (medium confidence)
    if (lowerDesc.includes("delete") || lowerDesc.includes("remove")) {
      return {
        expectedReadOnly: false,
        expectedDestructive: true,
        reason: "Description mentions delete/remove operations",
        confidence: "medium",
        isAmbiguous: false,
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
        confidence: "medium",
        isAmbiguous: false,
      };
    }

    // Default: assume write with low confidence (ambiguous)
    return {
      expectedReadOnly: false,
      expectedDestructive: false,
      reason:
        "Could not infer from name pattern - defaulting to write operation",
      confidence: "low",
      isAmbiguous: true,
    };
  }

  /**
   * Determine overall status using alignment status.
   * Only MISALIGNED counts as failure; REVIEW_RECOMMENDED does not fail.
   */
  private determineAnnotationStatus(
    results: ToolAnnotationResult[],
    totalTools: number,
  ): AssessmentStatus {
    if (totalTools === 0) return "PASS";

    const annotatedCount = results.filter((r) => r.hasAnnotations).length;

    // Only count actual MISALIGNED, not REVIEW_RECOMMENDED
    const misalignedCount = results.filter(
      (r) => r.alignmentStatus === "MISALIGNED",
    ).length;

    // Count high-confidence destructive tools without proper hints
    const destructiveWithoutHint = results.filter(
      (r) =>
        r.inferredBehavior?.expectedDestructive === true &&
        r.inferredBehavior?.confidence === "high" &&
        r.annotations?.destructiveHint !== true,
    ).length;

    // Destructive tools without proper hints = FAIL (critical safety issue)
    if (destructiveWithoutHint > 0) {
      return "FAIL";
    }

    // High-confidence misalignments = FAIL
    if (misalignedCount > 0) {
      return "FAIL";
    }

    // All tools annotated = PASS
    if (annotatedCount === totalTools) {
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
   * Calculate metrics and alignment breakdown for the assessment
   */
  private calculateMetrics(
    results: ToolAnnotationResult[],
    totalTools: number,
  ): {
    metrics: {
      coverage: number;
      consistency: number;
      correctness: number;
      reviewRequired: number;
    };
    alignmentBreakdown: {
      aligned: number;
      misaligned: number;
      reviewRecommended: number;
      unknown: number;
    };
  } {
    const alignmentBreakdown = {
      aligned: results.filter((r) => r.alignmentStatus === "ALIGNED").length,
      misaligned: results.filter((r) => r.alignmentStatus === "MISALIGNED")
        .length,
      reviewRecommended: results.filter(
        (r) => r.alignmentStatus === "REVIEW_RECOMMENDED",
      ).length,
      unknown: results.filter((r) => r.alignmentStatus === "UNKNOWN").length,
    };

    const annotatedCount = results.filter((r) => r.hasAnnotations).length;

    const metrics = {
      // Coverage: percentage of tools with annotations
      coverage: totalTools > 0 ? (annotatedCount / totalTools) * 100 : 100,
      // Consistency: percentage without contradictions (not MISALIGNED)
      consistency:
        totalTools > 0
          ? ((totalTools - alignmentBreakdown.misaligned) / totalTools) * 100
          : 100,
      // Correctness: percentage of annotated tools that are ALIGNED
      correctness:
        annotatedCount > 0
          ? (alignmentBreakdown.aligned / annotatedCount) * 100
          : 0,
      // Review required: count of tools needing manual review
      reviewRequired: alignmentBreakdown.reviewRecommended,
    };

    return { metrics, alignmentBreakdown };
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

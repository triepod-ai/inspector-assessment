/**
 * Tool Annotation Assessor
 * Verifies MCP tools have proper annotations per Policy #17
 *
 * Checks:
 * - readOnlyHint presence and accuracy
 * - destructiveHint presence and accuracy
 * - Tool behavior inference from name patterns
 * - Annotation misalignment detection
 * - Description poisoning detection (Issue #8)
 *
 * Reference: Anthropic MCP Directory Policy #17
 *
 * This module orchestrates annotation assessment by coordinating:
 * - BehaviorInference: Infers expected behavior from tool names
 * - AnnotationDeceptionDetector: Detects keyword-based misalignments
 * - DescriptionPoisoningDetector: Detects malicious content in descriptions
 */

import { BaseAssessor } from "./BaseAssessor";
import { AssessmentContext } from "../AssessmentOrchestrator";
import type {
  ToolAnnotationAssessment,
  ToolAnnotationResult,
  AssessmentStatus,
  AlignmentStatus,
  ToolParamProgress,
  AssessmentConfiguration,
  AnnotationSource,
} from "@/lib/assessmentTypes";
import type { Tool } from "@modelcontextprotocol/sdk/types.js";
import type { ClaudeCodeBridge } from "../lib/claudeCodeBridge";
import {
  type CompiledPatterns,
  type ServerPersistenceContext,
  getDefaultCompiledPatterns,
  detectPersistenceModel,
} from "../config/annotationPatterns";

// Import from extracted modules
import {
  scanDescriptionForPoisoning,
  detectAnnotationDeception,
  isActionableConfidence,
  inferBehavior,
} from "./annotations";

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

export class ToolAnnotationAssessor extends BaseAssessor {
  private claudeBridge?: ClaudeCodeBridge;
  private compiledPatterns: CompiledPatterns;
  private persistenceContext?: ServerPersistenceContext;

  constructor(config: AssessmentConfiguration) {
    super(config);
    this.compiledPatterns = getDefaultCompiledPatterns();
  }

  /**
   * Get the detected persistence context (for testing/debugging)
   */
  getPersistenceContext(): ServerPersistenceContext | undefined {
    return this.persistenceContext;
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
    let poisonedDescriptionsCount = 0;

    const annotationSourceCounts = {
      mcp: 0,
      sourceCode: 0,
      inferred: 0,
      none: 0,
    };

    // Extended metadata counters (Issue #54)
    const extendedMetadataCounts = {
      toolsWithRateLimits: 0,
      toolsWithPermissions: 0,
      toolsWithReturnSchema: 0,
      toolsWithBulkSupport: 0,
    };

    // Detect server persistence model from tool names
    const toolNames = context.tools.map((t) => t.name);
    this.persistenceContext = detectPersistenceModel(toolNames);
    this.log(
      `Persistence model detected: ${this.persistenceContext.model} (confidence: ${this.persistenceContext.confidence})`,
    );

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
            confidence: 50,
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

      // Track extended metadata (Issue #54)
      if (latestResult.extendedMetadata) {
        if (latestResult.extendedMetadata.rateLimit) {
          extendedMetadataCounts.toolsWithRateLimits++;
        }
        if (latestResult.extendedMetadata.permissions) {
          extendedMetadataCounts.toolsWithPermissions++;
        }
        if (latestResult.extendedMetadata.returnSchema?.hasSchema) {
          extendedMetadataCounts.toolsWithReturnSchema++;
        }
        if (latestResult.extendedMetadata.bulkOperations) {
          extendedMetadataCounts.toolsWithBulkSupport++;
        }
      }

      // Emit poisoned description event
      if (latestResult.descriptionPoisoning?.detected) {
        poisonedDescriptionsCount++;
        this.log(
          `POISONED DESCRIPTION DETECTED: ${tool.name} contains suspicious patterns`,
        );
        if (context.onProgress) {
          context.onProgress({
            type: "annotation_poisoned",
            tool: tool.name,
            description: tool.description,
            patterns: latestResult.descriptionPoisoning.patterns,
            riskLevel: latestResult.descriptionPoisoning.riskLevel,
          });
        }
      }

      // Emit annotation events
      this.emitAnnotationEvents(context, tool, latestResult);
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

    const { metrics, alignmentBreakdown } = this.calculateMetrics(
      toolResults,
      context.tools.length,
    );

    this.log(
      `Assessment complete: ${annotatedCount}/${context.tools.length} tools annotated, ${misalignedAnnotationsCount} misaligned, ${alignmentBreakdown.reviewRecommended} need review, ${poisonedDescriptionsCount} poisoned`,
    );

    if (useClaudeInference) {
      const highConfidenceMisalignments = toolResults.filter(
        (r) =>
          r.claudeInference &&
          r.claudeInference.confidence >= 70 &&
          r.claudeInference.misalignmentDetected,
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
        poisonedDescriptionsDetected: poisonedDescriptionsCount,
        extendedMetadataMetrics: extendedMetadataCounts,
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
      poisonedDescriptionsDetected: poisonedDescriptionsCount,
      extendedMetadataMetrics: extendedMetadataCounts,
    };
  }

  /**
   * Emit annotation-related progress events
   */
  private emitAnnotationEvents(
    context: AssessmentContext,
    tool: Tool,
    result: EnhancedToolAnnotationResult,
  ): void {
    if (!context.onProgress || !result.inferredBehavior) return;

    const annotations = result.annotations;
    const inferred = result.inferredBehavior;
    const confidence = result.claudeInference?.confidence ?? 50;
    const toolParams = this.extractToolParams(tool.inputSchema);
    const toolAnnotations = this.extractAnnotations(tool);

    // Emit missing annotation event
    if (!result.hasAnnotations) {
      context.onProgress({
        type: "annotation_missing",
        tool: tool.name,
        title: toolAnnotations.title,
        description: tool.description,
        parameters: toolParams,
        inferredBehavior: {
          expectedReadOnly: inferred.expectedReadOnly,
          expectedDestructive: inferred.expectedDestructive,
          reason: inferred.reason,
        },
      });
      return;
    }

    // Emit aligned event
    if (result.alignmentStatus === "ALIGNED") {
      context.onProgress({
        type: "annotation_aligned",
        tool: tool.name,
        confidence: inferred.confidence ?? "medium",
        annotations: {
          readOnlyHint: annotations?.readOnlyHint,
          destructiveHint: annotations?.destructiveHint,
          openWorldHint: annotations?.openWorldHint,
          idempotentHint: annotations?.idempotentHint,
        },
      });
      return;
    }

    // Check readOnlyHint mismatch
    if (
      annotations?.readOnlyHint !== undefined &&
      annotations.readOnlyHint !== inferred.expectedReadOnly
    ) {
      this.emitMismatchEvent(
        context,
        tool,
        toolParams,
        toolAnnotations,
        "readOnlyHint",
        annotations.readOnlyHint,
        inferred.expectedReadOnly,
        confidence,
        inferred,
        result.alignmentStatus!,
      );
    }

    // Check destructiveHint mismatch
    if (
      annotations?.destructiveHint !== undefined &&
      annotations.destructiveHint !== inferred.expectedDestructive
    ) {
      this.emitMismatchEvent(
        context,
        tool,
        toolParams,
        toolAnnotations,
        "destructiveHint",
        annotations.destructiveHint,
        inferred.expectedDestructive,
        confidence,
        inferred,
        result.alignmentStatus!,
      );
    }
  }

  /**
   * Emit mismatch event (misaligned or review_recommended)
   */
  private emitMismatchEvent(
    context: AssessmentContext,
    tool: Tool,
    toolParams: ToolParamProgress[],
    toolAnnotations: { title?: string },
    field: "readOnlyHint" | "destructiveHint",
    actual: boolean | undefined,
    expected: boolean,
    confidence: number,
    inferred: NonNullable<ToolAnnotationResult["inferredBehavior"]>,
    alignmentStatus: AlignmentStatus,
  ): void {
    if (!context.onProgress) return;

    if (alignmentStatus === "REVIEW_RECOMMENDED") {
      context.onProgress({
        type: "annotation_review_recommended",
        tool: tool.name,
        title: toolAnnotations.title,
        description: tool.description,
        parameters: toolParams,
        field,
        actual,
        inferred: expected,
        confidence: inferred.confidence,
        isAmbiguous: inferred.isAmbiguous,
        reason: inferred.reason,
      });
    } else if (
      !inferred.isAmbiguous &&
      isActionableConfidence(inferred.confidence)
    ) {
      context.onProgress({
        type: "annotation_misaligned",
        tool: tool.name,
        title: toolAnnotations.title,
        description: tool.description,
        parameters: toolParams,
        field,
        actual,
        expected,
        confidence,
        reason: `Tool has ${field}=${actual}, but ${inferred.reason}`,
      });
    }
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
            source: "pattern-based",
          },
        };
      }

      const updatedIssues = [...baseResult.issues];
      const updatedRecommendations = [...baseResult.recommendations];

      if (inference.misalignmentDetected && inference.confidence >= 70) {
        const misalignmentMsg = inference.misalignmentDetails
          ? `Claude analysis (${inference.confidence}% confidence): ${inference.misalignmentDetails}`
          : `Claude analysis detected annotation misalignment with ${inference.confidence}% confidence`;

        if (!updatedIssues.some((i) => i.includes("Claude analysis"))) {
          updatedIssues.push(misalignmentMsg);
        }

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
   * Assess a single tool's annotations
   */
  private assessTool(tool: Tool): ToolAnnotationResult {
    const issues: string[] = [];
    const recommendations: string[] = [];

    const annotations = this.extractAnnotations(tool);
    const hasAnnotations =
      annotations.readOnlyHint !== undefined ||
      annotations.destructiveHint !== undefined;

    const inferredBehavior = inferBehavior(
      tool.name,
      tool.description,
      this.compiledPatterns,
      this.persistenceContext,
    );

    let alignmentStatus: AlignmentStatus = "ALIGNED";

    if (!hasAnnotations) {
      issues.push("Missing tool annotations (readOnlyHint, destructiveHint)");
      recommendations.push(
        `Add annotations to ${tool.name}: readOnlyHint=${inferredBehavior.expectedReadOnly}, destructiveHint=${inferredBehavior.expectedDestructive}`,
      );
      alignmentStatus = "UNKNOWN";
    } else {
      // Check for high-confidence deception
      const deception = detectAnnotationDeception(tool.name, {
        readOnlyHint: annotations.readOnlyHint,
        destructiveHint: annotations.destructiveHint,
      });

      if (deception) {
        alignmentStatus = "MISALIGNED";
        issues.push(`DECEPTIVE ANNOTATION: ${deception.reason}`);
        recommendations.push(
          `CRITICAL: Fix deceptive ${deception.field} for ${tool.name} - tool name contains '${deception.matchedKeyword}' which contradicts the annotation`,
        );

        if (deception.field === "readOnlyHint") {
          inferredBehavior.expectedReadOnly = false;
          inferredBehavior.confidence = "high";
          inferredBehavior.isAmbiguous = false;
          inferredBehavior.reason = deception.reason;
        } else {
          inferredBehavior.expectedDestructive = true;
          inferredBehavior.confidence = "high";
          inferredBehavior.isAmbiguous = false;
          inferredBehavior.reason = deception.reason;
        }
      } else {
        // Check for misaligned annotations
        const readOnlyMismatch =
          annotations.readOnlyHint !== undefined &&
          annotations.readOnlyHint !== inferredBehavior.expectedReadOnly;

        const destructiveMismatch =
          annotations.destructiveHint !== undefined &&
          annotations.destructiveHint !== inferredBehavior.expectedDestructive;

        if (readOnlyMismatch || destructiveMismatch) {
          if (
            !inferredBehavior.isAmbiguous &&
            isActionableConfidence(inferredBehavior.confidence)
          ) {
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
    }

    // Check for destructive tools without explicit hint
    if (
      inferredBehavior.expectedDestructive &&
      isActionableConfidence(inferredBehavior.confidence) &&
      annotations.destructiveHint !== true
    ) {
      issues.push(
        "Tool appears destructive but destructiveHint is not set to true",
      );
      recommendations.push(
        `Set destructiveHint=true for ${tool.name} - this tool appears to perform destructive operations`,
      );
      if (inferredBehavior.confidence === "high") {
        alignmentStatus = "MISALIGNED";
      }
    }

    // Scan for description poisoning
    const descriptionPoisoning = scanDescriptionForPoisoning(tool);
    if (descriptionPoisoning.detected) {
      issues.push(
        `Tool description contains suspicious patterns: ${descriptionPoisoning.patterns.map((p) => p.name).join(", ")}`,
      );
      recommendations.push(
        `Review ${tool.name} description for potential prompt injection or hidden instructions`,
      );
    }

    // Extract extended metadata (Issue #54)
    const extendedMetadata = this.extractExtendedMetadata(tool);

    return {
      toolName: tool.name,
      hasAnnotations,
      annotations: hasAnnotations ? annotations : undefined,
      annotationSource: annotations.source,
      inferredBehavior,
      alignmentStatus,
      issues,
      recommendations,
      descriptionPoisoning,
      extendedMetadata,
    };
  }

  /**
   * Extract annotations from a tool
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

    // Priority 1: Check annotations object (MCP 2024-11 spec)
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

    // Priority 2: Check direct properties
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

    // Priority 3: Check metadata
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

    return {
      title: toolAny.title,
      description: tool.description,
      source: "none",
    };
  }

  /**
   * Extract extended metadata from tool (Issue #54)
   * Extracts rate limits, permissions, return schemas, and bulk operation support
   */
  private extractExtendedMetadata(
    tool: Tool,
  ): ToolAnnotationResult["extendedMetadata"] {
    const toolAny = tool as any;
    const metadata: NonNullable<ToolAnnotationResult["extendedMetadata"]> = {};

    // Rate limiting - check annotations, metadata, and direct props
    const rateLimit =
      toolAny.rateLimit ||
      toolAny.annotations?.rateLimit ||
      toolAny.metadata?.rateLimit;
    if (rateLimit && typeof rateLimit === "object") {
      metadata.rateLimit = {
        windowMs: rateLimit.windowMs,
        maxRequests: rateLimit.maxRequests,
        requestsPerMinute: rateLimit.requestsPerMinute,
        requestsPerSecond: rateLimit.requestsPerSecond,
      };
    }

    // Permissions - check requiredPermission, permissions, scopes
    const permissions =
      toolAny.requiredPermission ||
      toolAny.permissions ||
      toolAny.annotations?.permissions ||
      toolAny.metadata?.requiredPermission ||
      toolAny.metadata?.permissions;
    if (permissions) {
      const required = Array.isArray(permissions) ? permissions : [permissions];
      const scopes =
        toolAny.scopes ||
        toolAny.annotations?.scopes ||
        toolAny.metadata?.scopes;
      metadata.permissions = {
        required: required.filter((p: unknown) => typeof p === "string"),
        scopes: Array.isArray(scopes)
          ? scopes.filter((s: unknown) => typeof s === "string")
          : undefined,
      };
    }

    // Return schema - check outputSchema (MCP 2025-06-18 spec)
    if (toolAny.outputSchema) {
      metadata.returnSchema = {
        hasSchema: true,
        schema: toolAny.outputSchema,
      };
    }

    // Bulk operations - check metadata for batch support
    const bulkSupport =
      toolAny.supportsBulkOperations ||
      toolAny.annotations?.supportsBulkOperations ||
      toolAny.metadata?.supportsBulkOperations;
    const maxBatchSize = toolAny.metadata?.maxBatchSize;
    if (bulkSupport !== undefined || maxBatchSize !== undefined) {
      metadata.bulkOperations = {
        supported: !!bulkSupport,
        maxBatchSize:
          typeof maxBatchSize === "number" ? maxBatchSize : undefined,
      };
    }

    return Object.keys(metadata).length > 0 ? metadata : undefined;
  }

  /**
   * Extract parameters from tool input schema
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
   * Determine overall status
   */
  private determineAnnotationStatus(
    results: ToolAnnotationResult[],
    totalTools: number,
  ): AssessmentStatus {
    if (totalTools === 0) return "PASS";

    const annotatedCount = results.filter((r) => r.hasAnnotations).length;
    const poisonedCount = results.filter(
      (r) => r.descriptionPoisoning?.detected === true,
    ).length;

    if (poisonedCount > 0) return "FAIL";

    const misalignedCount = results.filter(
      (r) => r.alignmentStatus === "MISALIGNED",
    ).length;

    const destructiveWithoutHint = results.filter(
      (r) =>
        r.inferredBehavior?.expectedDestructive === true &&
        r.inferredBehavior?.confidence === "high" &&
        r.annotations?.destructiveHint !== true,
    ).length;

    if (destructiveWithoutHint > 0) return "FAIL";
    if (misalignedCount > 0) return "FAIL";
    if (annotatedCount === totalTools) return "PASS";

    const annotationRate = annotatedCount / totalTools;
    if (annotationRate >= 0.8) return "NEED_MORE_INFO";
    if (annotationRate < 0.5) return "FAIL";

    return "NEED_MORE_INFO";
  }

  /**
   * Calculate metrics and alignment breakdown
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
      coverage: totalTools > 0 ? (annotatedCount / totalTools) * 100 : 100,
      consistency:
        totalTools > 0
          ? ((totalTools - alignmentBreakdown.misaligned) / totalTools) * 100
          : 100,
      correctness:
        annotatedCount > 0
          ? (alignmentBreakdown.aligned / annotatedCount) * 100
          : 0,
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
   * Generate recommendations
   */
  private generateRecommendations(results: ToolAnnotationResult[]): string[] {
    const recommendations: string[] = [];
    const allRecs = new Set<string>();

    for (const result of results) {
      for (const rec of result.recommendations) {
        allRecs.add(rec);
      }
    }

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

  /**
   * Generate enhanced recommendations with Claude analysis
   */
  private generateEnhancedRecommendations(
    results: EnhancedToolAnnotationResult[],
  ): string[] {
    const recommendations: string[] = [];

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
}

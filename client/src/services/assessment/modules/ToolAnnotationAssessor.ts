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
 *
 * Refactored in Issue #105 to delegate to extracted helper modules:
 * - AlignmentChecker: Tool alignment assessment and metrics
 * - ExplanationGenerator: Explanation and recommendation generation
 * - EventEmitter: Progress event emission
 * - ClaudeIntegration: Claude-enhanced behavior inference
 */

import { BaseAssessor } from "./BaseAssessor";
import { AssessmentContext } from "../AssessmentOrchestrator";
import type {
  ToolAnnotationAssessment,
  AssessmentConfiguration,
} from "@/lib/assessmentTypes";
import type { ClaudeCodeBridge } from "../lib/claudeCodeBridge";
import {
  type CompiledPatterns,
  type ServerPersistenceContext,
  getDefaultCompiledPatterns,
  detectPersistenceModel,
} from "../config/annotationPatterns";

// Import from extracted modules (Issue #105)
import {
  detectArchitecture,
  type ArchitectureContext,
  // Alignment checking
  assessSingleTool,
  determineAnnotationStatus,
  calculateMetrics,
  // Explanation generation
  generateExplanation,
  generateEnhancedExplanation,
  generateRecommendations,
  generateEnhancedRecommendations,
  // Event emission
  emitAnnotationEvents,
  // Claude integration
  enhanceWithClaudeInference,
  createPatternBasedInference,
  type EnhancedToolAnnotationResult,
} from "./annotations";

/**
 * Enhanced tool annotation result with Claude inference
 * Re-exported for backwards compatibility
 */
export { EnhancedToolAnnotationResult };

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
    this.logger.info("Custom annotation patterns configured");
  }

  /**
   * Set Claude Code Bridge for enhanced behavior inference
   */
  setClaudeBridge(bridge: ClaudeCodeBridge): void {
    this.claudeBridge = bridge;
    this.logger.info("Claude Code Bridge enabled for behavior inference");
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
    this.logger.info("Starting tool annotation assessment");
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
    this.logger.info(
      `Persistence model detected: ${this.persistenceContext.model} (confidence: ${this.persistenceContext.confidence})`,
    );

    // Issue #57: Detect server architecture
    const architectureContext: ArchitectureContext = {
      tools: context.tools.map((t) => ({
        name: t.name,
        description: t.description,
        inputSchema: t.inputSchema,
      })),
      transportType: context.transportConfig?.type,
      sourceCodeFiles: context.sourceCodeFiles,
      packageJson:
        context.packageJson && typeof context.packageJson === "object"
          ? (context.packageJson as {
              dependencies?: Record<string, string>;
              devDependencies?: Record<string, string>;
            })
          : undefined,
    };
    const architectureAnalysis = detectArchitecture(architectureContext);
    this.logger.info(
      `Architecture detected: ${architectureAnalysis.serverType} server, databases: ${architectureAnalysis.databaseBackends.join(", ") || "none"}, network: ${architectureAnalysis.requiresNetworkAccess}`,
    );

    // Issue #57: Behavior inference metrics tracking
    const behaviorInferenceMetrics = {
      namePatternMatches: 0,
      descriptionMatches: 0,
      schemaMatches: 0,
      aggregatedConfidenceSum: 0,
      toolCount: 0,
    };

    const useClaudeInference = this.isClaudeEnabled();
    if (useClaudeInference) {
      this.logger.info(
        "Claude Code integration enabled - using semantic behavior inference",
      );
    }

    for (const tool of context.tools) {
      this.testCount++;
      // Use extracted assessSingleTool function
      const result = assessSingleTool(
        tool,
        this.compiledPatterns,
        this.persistenceContext,
      );

      // Enhance with Claude inference if available
      if (useClaudeInference) {
        const enhancedResult = await enhanceWithClaudeInference(
          tool,
          result,
          this.claudeBridge,
          this.logger,
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
        // Use pattern-based inference fallback
        const enhancedResult = createPatternBasedInference(result);
        toolResults.push(enhancedResult);

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

      // Issue #57: Track behavior inference metrics
      if (latestResult.inferredBehavior) {
        behaviorInferenceMetrics.toolCount++;
        // Check if name pattern was primary signal
        if (
          latestResult.inferredBehavior.reason.includes("pattern") ||
          latestResult.inferredBehavior.confidence === "high"
        ) {
          behaviorInferenceMetrics.namePatternMatches++;
        }
        // Check if description was a factor
        if (
          latestResult.inferredBehavior.reason.includes("Description") ||
          latestResult.inferredBehavior.reason.includes("description")
        ) {
          behaviorInferenceMetrics.descriptionMatches++;
        }
        // Calculate confidence contribution
        const confVal =
          latestResult.inferredBehavior.confidence === "high"
            ? 90
            : latestResult.inferredBehavior.confidence === "medium"
              ? 70
              : 40;
        behaviorInferenceMetrics.aggregatedConfidenceSum += confVal;
      }

      // Emit poisoned description event
      if (latestResult.descriptionPoisoning?.detected) {
        poisonedDescriptionsCount++;
        this.logger.info(
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

      // Emit annotation events using extracted function
      emitAnnotationEvents(context.onProgress, tool, latestResult);
    }

    // Use extracted functions for status, explanation, and recommendations
    const status = determineAnnotationStatus(toolResults, context.tools.length);
    const explanation = generateExplanation(
      annotatedCount,
      missingAnnotationsCount,
      misalignedAnnotationsCount,
      context.tools.length,
    );
    const recommendations = generateRecommendations(toolResults);

    const { metrics, alignmentBreakdown } = calculateMetrics(
      toolResults,
      context.tools.length,
    );

    this.logger.info(
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
        explanation: generateEnhancedExplanation(
          annotatedCount,
          missingAnnotationsCount,
          highConfidenceMisalignments.length,
          context.tools.length,
        ),
        recommendations: generateEnhancedRecommendations(toolResults),
        metrics,
        alignmentBreakdown,
        annotationSources: annotationSourceCounts,
        poisonedDescriptionsDetected: poisonedDescriptionsCount,
        extendedMetadataMetrics: extendedMetadataCounts,
        // Issue #57: Architecture and behavior inference
        architectureAnalysis,
        behaviorInferenceMetrics: {
          namePatternMatches: behaviorInferenceMetrics.namePatternMatches,
          descriptionMatches: behaviorInferenceMetrics.descriptionMatches,
          schemaMatches: behaviorInferenceMetrics.schemaMatches,
          aggregatedConfidenceAvg:
            behaviorInferenceMetrics.toolCount > 0
              ? Math.round(
                  behaviorInferenceMetrics.aggregatedConfidenceSum /
                    behaviorInferenceMetrics.toolCount,
                )
              : 0,
        },
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
      // Issue #57: Architecture and behavior inference
      architectureAnalysis,
      behaviorInferenceMetrics: {
        namePatternMatches: behaviorInferenceMetrics.namePatternMatches,
        descriptionMatches: behaviorInferenceMetrics.descriptionMatches,
        schemaMatches: behaviorInferenceMetrics.schemaMatches,
        aggregatedConfidenceAvg:
          behaviorInferenceMetrics.toolCount > 0
            ? Math.round(
                behaviorInferenceMetrics.aggregatedConfidenceSum /
                  behaviorInferenceMetrics.toolCount,
              )
            : 0,
      },
    };
  }
}

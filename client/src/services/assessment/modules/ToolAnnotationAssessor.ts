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
  type ServerPersistenceContext,
  getDefaultCompiledPatterns,
  matchToolPattern,
  detectPersistenceModel,
  checkDescriptionForImmediatePersistence,
} from "../config/annotationPatterns";

/**
 * Tool description poisoning patterns (Issue #8)
 * Detects hidden instructions and malicious content in tool descriptions
 */
interface PoisoningPattern {
  name: string;
  pattern: RegExp;
  severity: "LOW" | "MEDIUM" | "HIGH";
  category: string;
}

/**
 * High-confidence deception detection patterns
 * These patterns detect obvious misalignment between annotations and tool names
 * where keywords appear ANYWHERE in the tool name (not just as prefixes)
 */

/** Keywords that contradict readOnlyHint=true (these tools modify state) */
const READONLY_CONTRADICTION_KEYWORDS = [
  // Execution keywords - tools that execute code/commands are never read-only
  "exec",
  "execute",
  "run",
  "shell",
  "command",
  "cmd",
  "spawn",
  "invoke",
  // Write/modify keywords
  "write",
  "create",
  "delete",
  "remove",
  "modify",
  "update",
  "edit",
  "change",
  "set",
  "put",
  "patch",
  // Deployment/installation keywords
  "install",
  "deploy",
  "upload",
  "push",
  // Communication keywords (sending data)
  "send",
  "post",
  "submit",
  "publish",
  // Destructive keywords
  "destroy",
  "drop",
  "purge",
  "wipe",
  "clear",
  "truncate",
  "reset",
  "kill",
  "terminate",
];

/** Keywords that contradict destructiveHint=false (these tools delete/destroy data) */
const DESTRUCTIVE_CONTRADICTION_KEYWORDS = [
  "delete",
  "remove",
  "drop",
  "destroy",
  "purge",
  "wipe",
  "erase",
  "truncate",
  "clear",
  "reset",
  "kill",
  "terminate",
  "revoke",
  "cancel",
  "force",
];

/**
 * Check if a tool name contains any of the given keywords (case-insensitive)
 * Looks for keywords anywhere in the name, not just as prefixes
 */
function containsKeyword(toolName: string, keywords: string[]): string | null {
  const lowerName = toolName.toLowerCase();
  for (const keyword of keywords) {
    if (lowerName.includes(keyword)) {
      return keyword;
    }
  }
  return null;
}

/**
 * Detect high-confidence annotation deception
 * Returns misalignment info if obvious deception detected, null otherwise
 */
function detectAnnotationDeception(
  toolName: string,
  annotations: { readOnlyHint?: boolean; destructiveHint?: boolean },
): {
  field: "readOnlyHint" | "destructiveHint";
  matchedKeyword: string;
  reason: string;
} | null {
  // Check readOnlyHint=true contradiction
  if (annotations.readOnlyHint === true) {
    const keyword = containsKeyword(toolName, READONLY_CONTRADICTION_KEYWORDS);
    if (keyword) {
      return {
        field: "readOnlyHint",
        matchedKeyword: keyword,
        reason: `Tool name contains '${keyword}' but claims readOnlyHint=true - this is likely deceptive`,
      };
    }
  }

  // Check destructiveHint=false contradiction
  if (annotations.destructiveHint === false) {
    const keyword = containsKeyword(
      toolName,
      DESTRUCTIVE_CONTRADICTION_KEYWORDS,
    );
    if (keyword) {
      return {
        field: "destructiveHint",
        matchedKeyword: keyword,
        reason: `Tool name contains '${keyword}' but claims destructiveHint=false - this is likely deceptive`,
      };
    }
  }

  return null;
}

const DESCRIPTION_POISONING_PATTERNS: PoisoningPattern[] = [
  // Hidden instruction tags
  {
    name: "hidden_tag",
    pattern: /<HIDDEN>[\s\S]*?<\/HIDDEN>/gi,
    severity: "HIGH",
    category: "hidden_instructions",
  },
  {
    name: "important_tag",
    pattern: /<IMPORTANT>[\s\S]*?<\/IMPORTANT>/gi,
    severity: "HIGH",
    category: "hidden_instructions",
  },
  {
    name: "system_tag",
    pattern: /<SYSTEM>[\s\S]*?<\/SYSTEM>/gi,
    severity: "HIGH",
    category: "hidden_instructions",
  },
  {
    name: "instruction_tag",
    pattern: /<INSTRUCTION>[\s\S]*?<\/INSTRUCTION>/gi,
    severity: "HIGH",
    category: "hidden_instructions",
  },

  // Override commands
  {
    name: "ignore_instructions",
    pattern: /ignore\s+(all\s+)?(previous|prior|above)\s+instructions/i,
    severity: "HIGH",
    category: "override",
  },
  {
    name: "disregard_instructions",
    pattern: /disregard\s+(all\s+)?(previous|prior)\s+instructions/i,
    severity: "HIGH",
    category: "override",
  },
  {
    name: "you_are_now",
    pattern: /you\s+are\s+now\s+(a|an|the)/i,
    severity: "MEDIUM",
    category: "override",
  },
  {
    name: "system_override",
    pattern: /system:\s*override/i,
    severity: "HIGH",
    category: "override",
  },

  // Secrecy/concealment
  {
    name: "do_not_mention",
    pattern: /do\s+not\s+(mention|tell|inform|reveal)/i,
    severity: "HIGH",
    category: "concealment",
  },
  {
    name: "secretly",
    pattern: /\bsecretly\b/i,
    severity: "MEDIUM",
    category: "concealment",
  },
  {
    name: "hide_from_user",
    pattern: /hide\s+(this\s+)?from\s+(the\s+)?user/i,
    severity: "HIGH",
    category: "concealment",
  },

  // Data exfiltration
  {
    name: "return_keys",
    pattern: /return\s+(all\s+)?(api\s*)?keys/i,
    severity: "HIGH",
    category: "exfiltration",
  },
  {
    name: "include_credentials",
    // More specific: requires directive context (in/with/when/to) to reduce false positives
    // from legitimate documentation like "does not include credential storage"
    pattern:
      /include\s+(the\s+|all\s+|your\s+)?(api.?key|credential|password|secret)s?\s*(in|with|when|to)/i,
    severity: "HIGH",
    category: "exfiltration",
  },
  {
    name: "reveal_secrets",
    pattern: /reveal\s+(all\s+)?(secrets|credentials|api\s*keys)/i,
    severity: "HIGH",
    category: "exfiltration",
  },
  {
    name: "access_internal_secrets",
    pattern:
      /access\s+(the\s+)?internal\s+(api\s*)?(key|secret|credential|password|token)/i,
    severity: "HIGH",
    category: "exfiltration",
  },

  // Delimiter injection
  {
    name: "system_codeblock",
    pattern: /```system[\s\S]*?```/gi,
    severity: "HIGH",
    category: "delimiter",
  },
  {
    name: "inst_tags",
    pattern: /\[INST\][\s\S]*?\[\/INST\]/gi,
    severity: "HIGH",
    category: "delimiter",
  },
  {
    name: "chatml_system",
    pattern: /<\|im_start\|>system/gi,
    severity: "HIGH",
    category: "delimiter",
  },
  {
    name: "llama_sys",
    pattern: /<<SYS>>/gi,
    severity: "HIGH",
    category: "delimiter",
  },
  {
    name: "user_assistant_block",
    pattern: /\[USER\][\s\S]*?\[ASSISTANT\]/gi,
    severity: "HIGH",
    category: "delimiter",
  },

  // Role/persona injection (Warning #4)
  {
    name: "act_as",
    pattern: /act\s+(like|as)\s+(a|an|the)/i,
    severity: "MEDIUM",
    category: "override",
  },
  {
    name: "pretend_to_be",
    pattern: /pretend\s+(to\s+be|you\s*'?re)/i,
    severity: "MEDIUM",
    category: "override",
  },
  {
    name: "roleplay_as",
    pattern: /role\s*play\s+(as|like)/i,
    severity: "MEDIUM",
    category: "override",
  },
  {
    name: "new_task",
    pattern: /new\s+(task|instruction|objective):\s*/i,
    severity: "HIGH",
    category: "override",
  },

  // Encoding bypass detection (Warning #1)
  {
    name: "base64_encoded_block",
    pattern: /[A-Za-z0-9+/]{50,}={0,2}/g, // Large Base64 strings (50+ chars)
    severity: "MEDIUM",
    category: "encoding_bypass",
  },
  {
    name: "unicode_escape_sequence",
    pattern: /(?:\\u[0-9a-fA-F]{4}){3,}/gi, // 3+ consecutive Unicode escapes
    severity: "MEDIUM",
    category: "encoding_bypass",
  },
  {
    name: "html_entity_block",
    pattern: /(?:&#x?[0-9a-fA-F]+;){3,}/gi, // 3+ consecutive HTML entities
    severity: "MEDIUM",
    category: "encoding_bypass",
  },

  // Typoglycemia/evasion patterns (Warning #2)
  {
    name: "ignore_instructions_typo",
    pattern:
      /ign[o0]r[e3]?\s+(all\s+)?(pr[e3]v[i1][o0]us|pr[i1][o0]r|ab[o0]v[e3])\s+[i1]nstruct[i1][o0]ns?/i,
    severity: "HIGH",
    category: "override",
  },
  {
    name: "disregard_typo",
    pattern:
      /d[i1]sr[e3]g[a4]rd\s+(all\s+)?(pr[e3]v[i1][o0]us|pr[i1][o0]r)\s+[i1]nstruct[i1][o0]ns?/i,
    severity: "HIGH",
    category: "override",
  },

  // DVMCP-specific patterns (CTF testbed coverage)
  {
    name: "override_auth_protocol",
    pattern: /override[-_]?auth[-_]?protocol/gi,
    severity: "HIGH",
    category: "auth_bypass",
  },
  {
    name: "internal_resource_uri",
    pattern:
      /(?:internal|system|admin|secret|company|confidential):\/\/[a-z_\-\/]+/gi,
    severity: "HIGH",
    category: "resource_access",
  },
  {
    name: "get_secrets_call",
    pattern: /get[-_]?secrets?\s*\(/gi,
    severity: "HIGH",
    category: "secret_access",
  },
  {
    name: "master_password",
    pattern: /master[-_]?password/gi,
    severity: "HIGH",
    category: "credential_exposure",
  },
  {
    name: "access_confidential",
    pattern: /access\s+(the\s+)?confidential/gi,
    severity: "HIGH",
    category: "exfiltration",
  },
  {
    name: "hidden_trigger_phrase",
    pattern:
      /if\s+(the\s+)?(query|input|text)\s+contains\s+(the\s+)?(exact\s+)?(phrase|word)/gi,
    severity: "HIGH",
    category: "hidden_trigger",
  },
];

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
  private persistenceContext?: ServerPersistenceContext;

  constructor(config: AssessmentConfiguration) {
    super(config);
    // Initialize with default patterns (can be overridden via setPatterns)
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

    // Track annotation sources
    const annotationSourceCounts = {
      mcp: 0,
      sourceCode: 0,
      inferred: 0,
      none: 0,
    };

    // Detect server persistence model from tool names (Three-Tier Classification)
    const toolNames = context.tools.map((t) => t.name);
    this.persistenceContext = detectPersistenceModel(toolNames);
    this.log(
      `Persistence model detected: ${this.persistenceContext.model} (confidence: ${this.persistenceContext.confidence})`,
    );
    for (const indicator of this.persistenceContext.indicators) {
      this.log(`  - ${indicator}`);
    }

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

      // Track and emit poisoned description detection (Issue #8)
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

      // Emit annotation_aligned event when annotations correctly match behavior
      if (
        latestResult.hasAnnotations &&
        latestResult.alignmentStatus === "ALIGNED"
      ) {
        if (context.onProgress) {
          const annotations = latestResult.annotations;
          const inferredConfidence =
            latestResult.inferredBehavior?.confidence ?? "medium";
          context.onProgress({
            type: "annotation_aligned",
            tool: tool.name,
            confidence: inferredConfidence,
            annotations: {
              readOnlyHint: annotations?.readOnlyHint,
              destructiveHint: annotations?.destructiveHint,
              openWorldHint: annotations?.openWorldHint,
              idempotentHint: annotations?.idempotentHint,
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
        // Only emit events when inference is confident enough to contradict explicit annotations
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
          } else if (!inferred.isAmbiguous && inferred.confidence !== "low") {
            // Emit misaligned only for medium/high-confidence mismatches
            // When inference is low-confidence/ambiguous, trust explicit annotation
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
          // When inference is ambiguous/low-confidence, trust explicit annotation - no event emitted
        }

        // Check destructiveHint mismatch
        // Only emit events when inference is confident enough to contradict explicit annotations
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
          } else if (!inferred.isAmbiguous && inferred.confidence !== "low") {
            // Emit misaligned only for medium/high-confidence mismatches
            // When inference is low-confidence/ambiguous, trust explicit annotation
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
          // When inference is ambiguous/low-confidence, trust explicit annotation - no event emitted
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
      `Assessment complete: ${annotatedCount}/${context.tools.length} tools annotated, ${misalignedAnnotationsCount} misaligned, ${alignmentBreakdown.reviewRecommended} need review, ${poisonedDescriptionsCount} poisoned`,
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
        poisonedDescriptionsDetected: poisonedDescriptionsCount,
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
   * Enhanced with high-confidence deception detection for obvious misalignments
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
      // FIRST: Check for high-confidence deception (keywords anywhere in tool name)
      // This catches obvious cases like "vulnerable_system_exec_tool" + readOnlyHint=true
      const deception = detectAnnotationDeception(tool.name, {
        readOnlyHint: annotations.readOnlyHint,
        destructiveHint: annotations.destructiveHint,
      });

      if (deception) {
        // High-confidence deception detected - this is MISALIGNED, not REVIEW_RECOMMENDED
        alignmentStatus = "MISALIGNED";
        issues.push(`DECEPTIVE ANNOTATION: ${deception.reason}`);
        recommendations.push(
          `CRITICAL: Fix deceptive ${deception.field} for ${tool.name} - tool name contains '${deception.matchedKeyword}' which contradicts the annotation`,
        );

        // Override inferred behavior to match the detected deception
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
        // Normal flow: Check for misaligned annotations with confidence-aware logic
        const readOnlyMismatch =
          annotations.readOnlyHint !== undefined &&
          annotations.readOnlyHint !== inferredBehavior.expectedReadOnly;

        const destructiveMismatch =
          annotations.destructiveHint !== undefined &&
          annotations.destructiveHint !== inferredBehavior.expectedDestructive;

        if (readOnlyMismatch || destructiveMismatch) {
          // Only flag misalignment for medium/high confidence inference
          // When confidence is low/ambiguous, trust the explicit annotation
          // Note: High-confidence deception detection (exec/install keywords)
          // is handled in the `deception` block above, not here
          if (
            !inferredBehavior.isAmbiguous &&
            inferredBehavior.confidence !== "low"
          ) {
            // Medium/high confidence mismatch: MISALIGNED
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
          // When inference is ambiguous/low confidence, trust the explicit annotation
          // and keep alignmentStatus as ALIGNED (no change needed)
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

    // Scan for description poisoning (Issue #8)
    const descriptionPoisoning = this.scanDescriptionForPoisoning(tool);
    if (descriptionPoisoning.detected) {
      issues.push(
        `Tool description contains suspicious patterns: ${descriptionPoisoning.patterns.map((p) => p.name).join(", ")}`,
      );
      recommendations.push(
        `Review ${tool.name} description for potential prompt injection or hidden instructions`,
      );
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
      descriptionPoisoning,
    };
  }

  /**
   * Scan tool description for poisoning patterns (Issue #8)
   * Detects hidden instructions, override commands, concealment, and exfiltration attempts
   */
  private scanDescriptionForPoisoning(tool: Tool): {
    detected: boolean;
    patterns: Array<{
      name: string;
      pattern: string;
      severity: "LOW" | "MEDIUM" | "HIGH";
      category: string;
      evidence: string;
    }>;
    riskLevel: "NONE" | "LOW" | "MEDIUM" | "HIGH";
  } {
    const description = tool.description || "";
    const matches: Array<{
      name: string;
      pattern: string;
      severity: "LOW" | "MEDIUM" | "HIGH";
      category: string;
      evidence: string;
    }> = [];

    for (const patternDef of DESCRIPTION_POISONING_PATTERNS) {
      // Create a fresh regex to reset lastIndex
      const regex = new RegExp(
        patternDef.pattern.source,
        patternDef.pattern.flags,
      );
      // Loop to find all matches (not just first)
      let match;
      while ((match = regex.exec(description)) !== null) {
        matches.push({
          name: patternDef.name,
          pattern: patternDef.pattern.toString(),
          severity: patternDef.severity,
          category: patternDef.category,
          evidence:
            match[0].substring(0, 100) + (match[0].length > 100 ? "..." : ""),
        });
        // Prevent infinite loop for patterns without 'g' flag
        if (!regex.global) break;
      }
    }

    // Determine overall risk level based on highest severity match
    let riskLevel: "NONE" | "LOW" | "MEDIUM" | "HIGH" = "NONE";
    if (matches.some((m) => m.severity === "HIGH")) {
      riskLevel = "HIGH";
    } else if (matches.some((m) => m.severity === "MEDIUM")) {
      riskLevel = "MEDIUM";
    } else if (matches.length > 0) {
      riskLevel = "LOW";
    }

    return {
      detected: matches.length > 0,
      patterns: matches,
      riskLevel,
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

      case "write": {
        // CREATE operations are NEVER destructive - they only ADD new data
        // Only UPDATE/MODIFY operations can be considered destructive when they modify existing data
        const isCreateOperation = /^(create|add|insert|new|generate)[_-]/i.test(
          toolName,
        );
        if (isCreateOperation) {
          return {
            expectedReadOnly: false,
            expectedDestructive: false,
            reason: `Tool name matches create pattern: ${patternMatch.pattern} - create operations only add data and are not destructive`,
            confidence: "high",
            isAmbiguous: false,
          };
        }

        // Three-Tier Classification: Check persistence model for UPDATE/MODIFY operations
        // If immediate persistence detected, update operations should be marked destructive
        const descriptionCheck = checkDescriptionForImmediatePersistence(
          description || "",
        );

        // Priority 1: Description explicitly indicates deferred persistence
        if (descriptionCheck.indicatesDeferred) {
          return {
            expectedReadOnly: false,
            expectedDestructive: false,
            reason: `Tool name matches write pattern (${patternMatch.pattern}), description indicates deferred/in-memory operation`,
            confidence: "medium",
            isAmbiguous: false,
          };
        }

        // Priority 2: Description explicitly indicates immediate persistence
        if (descriptionCheck.indicatesImmediate) {
          return {
            expectedReadOnly: false,
            expectedDestructive: true,
            reason: `Tool name matches write pattern (${patternMatch.pattern}), description indicates immediate persistence to storage (${descriptionCheck.matchedPatterns.slice(0, 2).join(", ")})`,
            confidence: "medium",
            isAmbiguous: false,
          };
        }

        // Priority 3: Server-level persistence model (no save operations = immediate)
        if (this.persistenceContext?.model === "immediate") {
          return {
            expectedReadOnly: false,
            expectedDestructive: true,
            reason: `Tool name matches write pattern (${patternMatch.pattern}), server has no save operations → write operations likely persist immediately`,
            confidence: "medium",
            isAmbiguous: false,
          };
        }

        // Priority 4: Server has save operations = deferred (in-memory until save)
        if (this.persistenceContext?.model === "deferred") {
          return {
            expectedReadOnly: false,
            expectedDestructive: false,
            reason: `Tool name matches write pattern (${patternMatch.pattern}), server has save operations → write operations likely in-memory until explicit save`,
            confidence: "medium",
            isAmbiguous: false,
          };
        }

        // Default: Unknown persistence model - conservative approach (not destructive)
        return {
          expectedReadOnly: false,
          expectedDestructive: false,
          reason: `Tool name matches write pattern: ${patternMatch.pattern}`,
          confidence: "medium",
          isAmbiguous: false,
        };
      }

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
      reason: "Could not infer behavior from name pattern",
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

    // Check for poisoned descriptions (Issue #8) - critical security issue
    const poisonedCount = results.filter(
      (r) => r.descriptionPoisoning?.detected === true,
    ).length;
    if (poisonedCount > 0) {
      return "FAIL";
    }

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

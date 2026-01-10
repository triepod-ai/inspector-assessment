/**
 * Temporal Assessor Module
 * Detects "rug pull" vulnerabilities - tools that behave safely for first N invocations
 * then change behavior after a threshold is reached.
 *
 * This addresses a critical gap: standard assessments call tools with many different
 * payloads but never call the same tool repeatedly with identical payloads.
 *
 * Refactored in Issue #106 to extract MutationDetector and VarianceClassifier
 * into focused helper modules for maintainability.
 */

import {
  AssessmentConfiguration,
  AssessmentStatus,
  TemporalAssessment,
  TemporalToolResult,
  VarianceClassification,
} from "@/lib/assessmentTypes";
import { Tool } from "@modelcontextprotocol/sdk/types.js";
import { AssessmentContext } from "../AssessmentOrchestrator";
import { BaseAssessor } from "./BaseAssessor";
import {
  MutationDetector,
  DefinitionSnapshot,
  VarianceClassifier,
} from "./temporal";

interface InvocationResult {
  invocation: number;
  response: unknown;
  error?: string;
  timestamp: number;
}

// Security: Maximum response size to prevent memory exhaustion attacks
const MAX_RESPONSE_SIZE = 1_000_000; // 1MB

export class TemporalAssessor extends BaseAssessor {
  private invocationsPerTool: number;
  private mutationDetector: MutationDetector;
  private varianceClassifier: VarianceClassifier;

  // P2-2: Per-invocation timeout to prevent long-running tools from blocking
  private readonly PER_INVOCATION_TIMEOUT = 10_000; // 10 seconds

  constructor(config: AssessmentConfiguration) {
    super(config);
    this.invocationsPerTool = config.temporalInvocations ?? 25;
    this.mutationDetector = new MutationDetector();
    this.varianceClassifier = new VarianceClassifier(this.mutationDetector);
  }

  async assess(context: AssessmentContext): Promise<TemporalAssessment> {
    const results: TemporalToolResult[] = [];
    let rugPullsDetected = 0;
    let definitionMutationsDetected = 0;

    // Check if definition tracking is available
    const canTrackDefinitions = typeof context.listTools === "function";
    if (canTrackDefinitions) {
      this.logger.info(
        `Starting temporal assessment with ${this.invocationsPerTool} invocations per tool (definition tracking enabled)`,
      );
    } else {
      this.logger.info(
        `Starting temporal assessment with ${this.invocationsPerTool} invocations per tool (definition tracking unavailable)`,
      );
    }

    for (const tool of context.tools) {
      // Skip if tool selection is configured and this tool isn't selected
      if (
        this.config.selectedToolsForTesting !== undefined &&
        !this.config.selectedToolsForTesting.includes(tool.name)
      ) {
        continue;
      }

      const result = await this.assessTool(context, tool);
      results.push(result);

      if (result.vulnerable) {
        rugPullsDetected++;
        this.logger.info(
          `RUG PULL DETECTED: ${tool.name} changed behavior at invocation ${result.firstDeviationAt}`,
        );
      }

      if (result.definitionMutated) {
        definitionMutationsDetected++;
        this.logger.info(
          `DEFINITION MUTATION DETECTED: ${tool.name} changed description at invocation ${result.definitionMutationAt}`,
        );
      }

      // Respect delay between tests
      if (this.config.delayBetweenTests) {
        await this.sleep(this.config.delayBetweenTests);
      }
    }

    // Status fails if either response or definition mutations detected
    const totalVulnerabilities = rugPullsDetected + definitionMutationsDetected;
    const status = this.determineTemporalStatus(totalVulnerabilities, results);

    return {
      toolsTested: results.length,
      invocationsPerTool: this.invocationsPerTool,
      rugPullsDetected,
      definitionMutationsDetected,
      details: results,
      status,
      explanation: this.generateExplanation(
        rugPullsDetected,
        definitionMutationsDetected,
        results,
      ),
      recommendations: this.generateRecommendations(results),
    };
  }

  private async assessTool(
    context: AssessmentContext,
    tool: Tool,
  ): Promise<TemporalToolResult> {
    const responses: InvocationResult[] = [];
    const definitionSnapshots: DefinitionSnapshot[] = [];
    const payload = this.generateSafePayload(tool);

    // Reduce invocations for potentially destructive tools
    const isDestructive = this.varianceClassifier.isDestructiveTool(tool);
    const invocations = isDestructive
      ? Math.min(5, this.invocationsPerTool)
      : this.invocationsPerTool;

    // Check if definition tracking is available
    const canTrackDefinitions = typeof context.listTools === "function";

    this.logger.info(
      `Testing ${tool.name} with ${invocations} invocations${isDestructive ? " (reduced - destructive)" : ""}`,
    );

    for (let i = 1; i <= invocations; i++) {
      this.testCount++;

      // Track tool definition BEFORE each invocation (if available)
      // This detects rug pulls where description mutates after N calls
      if (canTrackDefinitions) {
        try {
          const currentTools = await this.executeWithTimeout(
            context.listTools!(),
            this.PER_INVOCATION_TIMEOUT,
          );
          const currentTool = currentTools.find((t) => t.name === tool.name);
          if (currentTool) {
            definitionSnapshots.push({
              invocation: i,
              description: currentTool.description,
              inputSchema: currentTool.inputSchema,
              timestamp: Date.now(),
            });
          }
        } catch {
          // Definition tracking failed - continue with response tracking
          this.logger.info(
            `Warning: Failed to fetch tool definition for ${tool.name} at invocation ${i}`,
          );
        }
      }

      try {
        // P2-2: Use shorter per-invocation timeout (10s vs default 30s)
        const response = await this.executeWithTimeout(
          context.callTool(tool.name, payload),
          this.PER_INVOCATION_TIMEOUT,
        );

        // Security: Prevent memory exhaustion from large responses
        const responseSize = JSON.stringify(response).length;
        if (responseSize > MAX_RESPONSE_SIZE) {
          responses.push({
            invocation: i,
            response: null,
            error: `Response exceeded size limit (${responseSize} > ${MAX_RESPONSE_SIZE} bytes)`,
            timestamp: Date.now(),
          });
          continue;
        }

        responses.push({
          invocation: i,
          response,
          timestamp: Date.now(),
        });
      } catch (err) {
        // Errors mid-stream could indicate rug pull behavior!
        responses.push({
          invocation: i,
          response: null,
          error: this.extractErrorMessage(err),
          timestamp: Date.now(),
        });
      }

      // P2-4: Small delay between invocations to prevent rate limiting false positives
      if (i < invocations) {
        await this.sleep(50);
      }
    }

    // Analyze responses for temporal behavior changes
    const result = this.analyzeResponses(tool, responses);

    // Analyze definitions for mutation (rug pull via description change)
    const definitionMutation =
      this.mutationDetector.detectDefinitionMutation(definitionSnapshots);

    return {
      ...result,
      reducedInvocations: isDestructive,
      // Add definition mutation results
      definitionMutated: definitionMutation !== null,
      definitionMutationAt: definitionMutation?.detectedAt ?? null,
      definitionEvidence: definitionMutation
        ? {
            baselineDescription: definitionMutation.baselineDescription,
            mutatedDescription: definitionMutation.mutatedDescription,
            baselineSchema: definitionMutation.baselineSchema,
            mutatedSchema: definitionMutation.mutatedSchema,
          }
        : undefined,
      // If definition mutated, mark as vulnerable with DEFINITION pattern
      vulnerable: result.vulnerable || definitionMutation !== null,
      pattern:
        definitionMutation !== null ? "RUG_PULL_DEFINITION" : result.pattern,
      severity:
        definitionMutation !== null || result.vulnerable ? "HIGH" : "NONE",
    };
  }

  private analyzeResponses(
    tool: Tool,
    responses: InvocationResult[],
  ): TemporalToolResult {
    if (responses.length === 0) {
      return {
        tool: tool.name,
        vulnerable: false,
        totalInvocations: 0,
        firstDeviationAt: null,
        deviationCount: 0,
        errorCount: 0,
        pattern: null,
        severity: "NONE",
      };
    }

    const baseline = this.varianceClassifier.normalizeResponse(
      responses[0].response,
    );
    const deviations: number[] = [];
    const errors: number[] = [];

    // Issue #69: Track variance details for transparency
    const varianceDetails: Array<{
      invocation: number;
      classification: VarianceClassification;
    }> = [];

    // Determine comparison strategy
    // 1. Stateful tools (search, list, etc.) - use schema comparison
    // 2. Resource-creating tools (create, insert, etc.) - use variance classification
    // 3. All other tools - use exact comparison
    const isStateful = this.varianceClassifier.isStatefulTool(tool);
    const isResourceCreating =
      this.varianceClassifier.isResourceCreatingTool(tool);

    if (isStateful) {
      this.logger.info(
        `${tool.name} classified as stateful - using schema comparison`,
      );
    } else if (isResourceCreating) {
      this.logger.info(
        `${tool.name} classified as resource-creating - using variance classification`,
      );
    }

    for (let i = 1; i < responses.length; i++) {
      if (responses[i].error) {
        errors.push(i + 1); // Track errors as potential indicators
        deviations.push(i + 1);
      } else if (isStateful) {
        // Original stateful tool logic: schema comparison + behavioral content check
        // Content variance is allowed as long as schema is consistent
        let isDifferent = !this.varianceClassifier.compareSchemas(
          responses[0].response,
          responses[i].response,
        );

        // Secondary detection: Check for content semantic changes (rug pull patterns)
        // This catches cases where schema is same but content shifts from helpful to harmful
        if (!isDifferent) {
          const contentChange =
            this.mutationDetector.detectStatefulContentChange(
              responses[0].response,
              responses[i].response,
            );
          if (contentChange.detected) {
            isDifferent = true;
            this.logger.info(
              `${tool.name}: Content semantic change detected at invocation ${i + 1} - ${contentChange.reason}`,
            );
          }
        }

        if (isDifferent) {
          deviations.push(i + 1);
        }
      } else if (isResourceCreating) {
        // Issue #69: Use variance classification for resource-creating tools
        // These need intelligent classification to distinguish ID variance from rug pulls
        const classification = this.varianceClassifier.classifyVariance(
          responses[0].response,
          responses[i].response,
        );

        varianceDetails.push({
          invocation: i + 1,
          classification,
        });

        // Only flag SUSPICIOUS and BEHAVIORAL as deviations
        // LEGITIMATE variance is expected for resource-creating tools
        if (classification.type !== "LEGITIMATE") {
          deviations.push(i + 1);
          this.logger.info(
            `${tool.name}: ${classification.type} variance at invocation ${i + 1} - ${classification.reasons.join(", ")}`,
          );
        }
      } else {
        // Exact comparison for non-stateful, non-resource-creating tools
        const normalized = this.varianceClassifier.normalizeResponse(
          responses[i].response,
        );
        if (normalized !== baseline) {
          deviations.push(i + 1); // 1-indexed
        }
      }
    }

    // Note: errorCount is a SUBSET of deviationCount
    // Errors ARE behavioral changes worth flagging
    // - deviationCount = total behavior changes (including errors)
    // - errorCount = how many of those were errors specifically
    const isVulnerable = deviations.length > 0;

    // Generate appropriate note based on tool type and result
    let note: string | undefined;
    if (isStateful) {
      // Preserve original stateful tool messages for backward compatibility
      note = isVulnerable
        ? "Stateful tool - secondary content analysis detected rug pull"
        : "Stateful tool - content variation expected, schema consistent";
    } else if (isResourceCreating) {
      note = isVulnerable
        ? "Resource-creating tool - variance classification detected suspicious/behavioral change"
        : "Resource-creating tool - ID/timestamp variance expected, no suspicious patterns";
    }

    // Issue #69: Get the first suspicious/behavioral classification for evidence
    const firstSuspiciousClassification = varianceDetails.find(
      (v) => v.classification.type !== "LEGITIMATE",
    );

    return {
      tool: tool.name,
      vulnerable: isVulnerable,
      totalInvocations: responses.length,
      firstDeviationAt: deviations[0] ?? null,
      deviationCount: deviations.length,
      errorCount: errors.length,
      pattern: isVulnerable ? "RUG_PULL_TEMPORAL" : null,
      severity: isVulnerable ? "HIGH" : "NONE",
      evidence: isVulnerable
        ? {
            safeResponseExample: responses[0].response,
            maliciousResponseExample:
              responses[deviations[0] - 1]?.response ?? null,
          }
        : undefined,
      note,
      // Issue #69: Include variance classification for transparency
      varianceClassification: firstSuspiciousClassification?.classification,
      varianceDetails: varianceDetails.length > 0 ? varianceDetails : undefined,
    };
  }

  /**
   * Generate a safe/neutral payload for a tool based on its input schema.
   * Only populates required parameters with minimal test values.
   */
  private generateSafePayload(tool: Tool): Record<string, unknown> {
    const schema = (tool.inputSchema as Record<string, unknown>) ?? {};
    const properties = (schema.properties as Record<string, unknown>) ?? {};
    const required = (schema.required as string[]) ?? [];
    const payload: Record<string, unknown> = {};

    for (const [key, propValue] of Object.entries(properties)) {
      // Only populate required params to minimize side effects
      if (!required.includes(key)) continue;

      const prop = propValue as Record<string, unknown>;
      const propType = prop.type as string;

      switch (propType) {
        case "string":
          payload[key] = "test";
          break;
        case "number":
        case "integer":
          payload[key] = 1;
          break;
        case "boolean":
          payload[key] = false;
          break;
        case "array":
          payload[key] = [];
          break;
        case "object":
          payload[key] = {};
          break;
        default:
          payload[key] = "test";
      }
    }

    return payload;
  }

  private determineTemporalStatus(
    rugPullsDetected: number,
    results: TemporalToolResult[],
  ): AssessmentStatus {
    if (rugPullsDetected > 0) {
      return "FAIL";
    }
    if (results.length === 0) {
      return "NEED_MORE_INFO";
    }
    return "PASS";
  }

  private generateExplanation(
    rugPullsDetected: number,
    definitionMutationsDetected: number,
    results: TemporalToolResult[],
  ): string {
    if (results.length === 0) {
      return "No tools were tested for temporal vulnerabilities.";
    }

    const parts: string[] = [];

    // Report response-based rug pulls
    if (rugPullsDetected > 0) {
      const responseVulnerableTools = results
        .filter((r) => r.vulnerable && r.pattern === "RUG_PULL_TEMPORAL")
        .map((r) => `${r.tool} (changed at invocation ${r.firstDeviationAt})`)
        .join(", ");

      if (responseVulnerableTools) {
        parts.push(
          `CRITICAL: ${rugPullsDetected} tool(s) showed temporal response changes: ${responseVulnerableTools}`,
        );
      }
    }

    // Report definition mutations
    if (definitionMutationsDetected > 0) {
      const definitionVulnerableTools = results
        .filter((r) => r.definitionMutated)
        .map(
          (r) =>
            `${r.tool} (description changed at invocation ${r.definitionMutationAt})`,
        )
        .join(", ");

      parts.push(
        `CRITICAL: ${definitionMutationsDetected} tool(s) mutated their definition/description: ${definitionVulnerableTools}`,
      );
    }

    if (parts.length === 0) {
      return `All ${results.length} tools showed consistent behavior and definitions across repeated invocations.`;
    }

    return parts.join(" ");
  }

  private generateRecommendations(results: TemporalToolResult[]): string[] {
    const recommendations: string[] = [];

    // Response-based rug pulls
    const responseVulnerableTools = results.filter(
      (r) => r.vulnerable && r.pattern === "RUG_PULL_TEMPORAL",
    );

    if (responseVulnerableTools.length > 0) {
      recommendations.push(
        "Immediately investigate tools with temporal behavior changes - this pattern is characteristic of rug pull attacks.",
      );

      for (const tool of responseVulnerableTools) {
        recommendations.push(
          `Review ${tool.tool}: behavior changed after ${tool.firstDeviationAt} invocations. Compare safe vs malicious responses in evidence.`,
        );
      }

      recommendations.push(
        "Check for invocation counters, time-based triggers, or state accumulation in the tool implementation.",
      );
    }

    // Definition mutation rug pulls
    const definitionMutatedTools = results.filter((r) => r.definitionMutated);

    if (definitionMutatedTools.length > 0) {
      recommendations.push(
        "CRITICAL: Tool definition/description mutations detected - this is a sophisticated rug pull attack that injects malicious instructions after N calls.",
      );

      for (const tool of definitionMutatedTools) {
        const baseline = tool.definitionEvidence?.baselineDescription
          ? `"${tool.definitionEvidence.baselineDescription.substring(0, 100)}..."`
          : "unknown";
        const mutated = tool.definitionEvidence?.mutatedDescription
          ? `"${tool.definitionEvidence.mutatedDescription.substring(0, 100)}..."`
          : "unknown";

        recommendations.push(
          `${tool.tool}: Description changed at invocation ${tool.definitionMutationAt}. Baseline: ${baseline} -> Mutated: ${mutated}`,
        );
      }

      recommendations.push(
        "Review tool source code for global state that mutates __doc__, description, or tool metadata based on call count.",
      );
    }

    const errorTools = results.filter((r) => r.errorCount > 0);
    if (
      errorTools.length > 0 &&
      responseVulnerableTools.length === 0 &&
      definitionMutatedTools.length === 0
    ) {
      recommendations.push(
        `${errorTools.length} tool(s) had errors during repeated invocations. Review error handling and rate limiting.`,
      );
    }

    return recommendations;
  }
}

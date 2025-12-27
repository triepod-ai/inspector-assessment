/**
 * Temporal Assessor Module
 * Detects "rug pull" vulnerabilities - tools that behave safely for first N invocations
 * then change behavior after a threshold is reached.
 *
 * This addresses a critical gap: standard assessments call tools with many different
 * payloads but never call the same tool repeatedly with identical payloads.
 */

import {
  AssessmentConfiguration,
  AssessmentStatus,
  TemporalAssessment,
  TemporalToolResult,
} from "@/lib/assessmentTypes";
import { Tool } from "@modelcontextprotocol/sdk/types.js";
import { AssessmentContext } from "../AssessmentOrchestrator";
import { BaseAssessor } from "./BaseAssessor";

interface InvocationResult {
  invocation: number;
  response: unknown;
  error?: string;
  timestamp: number;
}

export class TemporalAssessor extends BaseAssessor {
  private invocationsPerTool: number;

  // Patterns that suggest a tool may have side effects
  private readonly DESTRUCTIVE_PATTERNS = [
    "create",
    "write",
    "delete",
    "remove",
    "update",
    "insert",
    "post",
    "put",
    "send",
    "submit",
    "execute",
    "run",
  ];

  constructor(config: AssessmentConfiguration) {
    super(config);
    this.invocationsPerTool = config.temporalInvocations ?? 25;
  }

  async assess(context: AssessmentContext): Promise<TemporalAssessment> {
    const results: TemporalToolResult[] = [];
    let rugPullsDetected = 0;

    this.log(
      `Starting temporal assessment with ${this.invocationsPerTool} invocations per tool`,
    );

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
        this.log(
          `RUG PULL DETECTED: ${tool.name} changed behavior at invocation ${result.firstDeviationAt}`,
        );
      }

      // Respect delay between tests
      if (this.config.delayBetweenTests) {
        await this.sleep(this.config.delayBetweenTests);
      }
    }

    const status = this.determineTemporalStatus(rugPullsDetected, results);

    return {
      toolsTested: results.length,
      invocationsPerTool: this.invocationsPerTool,
      rugPullsDetected,
      details: results,
      status,
      explanation: this.generateExplanation(rugPullsDetected, results),
      recommendations: this.generateRecommendations(results),
    };
  }

  private async assessTool(
    context: AssessmentContext,
    tool: Tool,
  ): Promise<TemporalToolResult> {
    const responses: InvocationResult[] = [];
    const payload = this.generateSafePayload(tool);

    // Reduce invocations for potentially destructive tools
    const isDestructive = this.isDestructiveTool(tool);
    const invocations = isDestructive
      ? Math.min(5, this.invocationsPerTool)
      : this.invocationsPerTool;

    this.log(
      `Testing ${tool.name} with ${invocations} invocations${isDestructive ? " (reduced - destructive)" : ""}`,
    );

    for (let i = 1; i <= invocations; i++) {
      this.testCount++;
      try {
        const response = await this.executeWithTimeout(
          context.callTool(tool.name, payload),
        );
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
    }

    const result = this.analyzeResponses(tool, responses);
    return {
      ...result,
      reducedInvocations: isDestructive,
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

    const baseline = this.normalizeResponse(responses[0].response);
    const deviations: number[] = [];
    const errors: number[] = [];

    for (let i = 1; i < responses.length; i++) {
      if (responses[i].error) {
        errors.push(i + 1); // Track errors as potential indicators
        deviations.push(i + 1);
      } else {
        const normalized = this.normalizeResponse(responses[i].response);
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

  /**
   * Normalize response for comparison by removing naturally varying data.
   * Prevents false positives from timestamps, UUIDs, request IDs, counters, etc.
   * Handles both direct JSON and nested JSON strings (e.g., content[].text).
   */
  private normalizeResponse(response: unknown): string {
    const str = JSON.stringify(response);

    return (
      str
        // ISO timestamps
        .replace(/"\d{4}-\d{2}-\d{2}T[\d:.]+Z?"/g, '"<TIMESTAMP>"')
        // Unix timestamps (13 digits)
        .replace(/"\d{13}"/g, '"<TIMESTAMP>"')
        // UUIDs
        .replace(
          /"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"/gi,
          '"<UUID>"',
        )
        // Common ID fields (string values)
        .replace(/"request_id":\s*"[^"]+"/g, '"request_id": "<ID>"')
        .replace(/"requestId":\s*"[^"]+"/g, '"requestId": "<ID>"')
        .replace(/"trace_id":\s*"[^"]+"/g, '"trace_id": "<ID>"')
        // Numeric ID fields (normalize incrementing IDs) - both direct and escaped
        .replace(/"id":\s*\d+/g, '"id": <NUMBER>')
        .replace(/"Id":\s*\d+/g, '"Id": <NUMBER>')
        .replace(/\\"id\\":\s*\d+/g, '\\"id\\": <NUMBER>')
        .replace(/\\"Id\\":\s*\d+/g, '\\"Id\\": <NUMBER>')
        // Counter/sequence fields - both direct and escaped (for nested JSON)
        .replace(/"total_items":\s*\d+/g, '"total_items": <NUMBER>')
        .replace(/\\"total_items\\":\s*\d+/g, '\\"total_items\\": <NUMBER>')
        .replace(/"count":\s*\d+/g, '"count": <NUMBER>')
        .replace(/\\"count\\":\s*\d+/g, '\\"count\\": <NUMBER>')
        .replace(/"invocation_count":\s*\d+/g, '"invocation_count": <NUMBER>')
        .replace(
          /\\"invocation_count\\":\s*\d+/g,
          '\\"invocation_count\\": <NUMBER>',
        )
        .replace(/"sequence":\s*\d+/g, '"sequence": <NUMBER>')
        .replace(/\\"sequence\\":\s*\d+/g, '\\"sequence\\": <NUMBER>')
        .replace(/"index":\s*\d+/g, '"index": <NUMBER>')
        .replace(/\\"index\\":\s*\d+/g, '\\"index\\": <NUMBER>')
        // String IDs
        .replace(/"id":\s*"[^"]+"/g, '"id": "<ID>"')
    );
  }

  /**
   * Detect if a tool may have side effects based on naming patterns.
   */
  private isDestructiveTool(tool: Tool): boolean {
    const name = tool.name.toLowerCase();
    return this.DESTRUCTIVE_PATTERNS.some((p) => name.includes(p));
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
    results: TemporalToolResult[],
  ): string {
    if (results.length === 0) {
      return "No tools were tested for temporal vulnerabilities.";
    }

    if (rugPullsDetected === 0) {
      return `All ${results.length} tools showed consistent behavior across repeated invocations.`;
    }

    const vulnerableTools = results
      .filter((r) => r.vulnerable)
      .map((r) => `${r.tool} (changed at invocation ${r.firstDeviationAt})`)
      .join(", ");

    return `CRITICAL: ${rugPullsDetected} tool(s) showed temporal behavior changes indicating potential rug pull vulnerability: ${vulnerableTools}`;
  }

  private generateRecommendations(results: TemporalToolResult[]): string[] {
    const recommendations: string[] = [];

    const vulnerableTools = results.filter((r) => r.vulnerable);

    if (vulnerableTools.length > 0) {
      recommendations.push(
        "Immediately investigate tools with temporal behavior changes - this pattern is characteristic of rug pull attacks.",
      );

      for (const tool of vulnerableTools) {
        recommendations.push(
          `Review ${tool.tool}: behavior changed after ${tool.firstDeviationAt} invocations. Compare safe vs malicious responses in evidence.`,
        );
      }

      recommendations.push(
        "Check for invocation counters, time-based triggers, or state accumulation in the tool implementation.",
      );
    }

    const errorTools = results.filter((r) => r.errorCount > 0);
    if (errorTools.length > 0 && vulnerableTools.length === 0) {
      recommendations.push(
        `${errorTools.length} tool(s) had errors during repeated invocations. Review error handling and rate limiting.`,
      );
    }

    return recommendations;
  }
}

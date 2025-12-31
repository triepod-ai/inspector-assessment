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

/**
 * Tracks tool definition snapshots across invocations to detect rug pull mutations.
 * DVMCP Challenge 4: Tool descriptions that mutate after N calls to inject malicious instructions.
 */
interface DefinitionSnapshot {
  invocation: number;
  description: string | undefined;
  inputSchema: unknown;
  timestamp: number;
}

interface DefinitionMutation {
  detectedAt: number; // Invocation number where mutation was detected
  baselineDescription?: string;
  mutatedDescription?: string;
  baselineSchema?: unknown;
  mutatedSchema?: unknown;
}

// Security: Maximum response size to prevent memory exhaustion attacks
const MAX_RESPONSE_SIZE = 1_000_000; // 1MB

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
    // P2-3: Additional destructive patterns
    "drop",
    "truncate",
    "clear",
    "purge",
    "destroy",
    "reset",
  ];

  // P2-2: Per-invocation timeout to prevent long-running tools from blocking
  private readonly PER_INVOCATION_TIMEOUT = 10_000; // 10 seconds

  /**
   * Tool name patterns that are expected to have state-dependent responses.
   * These tools legitimately return different results based on data state,
   * which is NOT a rug pull vulnerability.
   *
   * Includes both:
   * - READ operations: search, list, query return more results after data stored
   * - ACCUMULATION operations: add, append, store return accumulated state (counts, IDs)
   *
   * NOTE: Does NOT include patterns already in DESTRUCTIVE_PATTERNS (create, write,
   * insert, etc.) - those need strict comparison to detect real rug pulls.
   *
   * Uses word-boundary matching to prevent false matches.
   * "add_observations" matches "add" but "address_validator" does not.
   */
  private readonly STATEFUL_TOOL_PATTERNS = [
    // READ operations - results depend on current data state
    "search",
    "list",
    "query",
    "find",
    "get",
    "fetch",
    "read",
    "browse",
    // ACCUMULATION operations (non-destructive) that return accumulated state
    // These legitimately return different counts/IDs as data accumulates
    // NOTE: "add" is NOT in DESTRUCTIVE_PATTERNS, unlike "insert", "create", "write"
    "add",
    "append",
    "store",
    "save",
    "log",
    "record",
    "push",
    "enqueue",
  ];

  constructor(config: AssessmentConfiguration) {
    super(config);
    this.invocationsPerTool = config.temporalInvocations ?? 25;
  }

  async assess(context: AssessmentContext): Promise<TemporalAssessment> {
    const results: TemporalToolResult[] = [];
    let rugPullsDetected = 0;
    let definitionMutationsDetected = 0;

    // Check if definition tracking is available
    const canTrackDefinitions = typeof context.listTools === "function";
    if (canTrackDefinitions) {
      this.log(
        `Starting temporal assessment with ${this.invocationsPerTool} invocations per tool (definition tracking enabled)`,
      );
    } else {
      this.log(
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
        this.log(
          `RUG PULL DETECTED: ${tool.name} changed behavior at invocation ${result.firstDeviationAt}`,
        );
      }

      if (result.definitionMutated) {
        definitionMutationsDetected++;
        this.log(
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
    const isDestructive = this.isDestructiveTool(tool);
    const invocations = isDestructive
      ? Math.min(5, this.invocationsPerTool)
      : this.invocationsPerTool;

    // Check if definition tracking is available
    const canTrackDefinitions = typeof context.listTools === "function";

    this.log(
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
          this.log(
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
      this.detectDefinitionMutation(definitionSnapshots);

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

  /**
   * Detect mutations in tool definition across invocation snapshots.
   * DVMCP Challenge 4: Tool descriptions that mutate after N calls.
   */
  private detectDefinitionMutation(
    snapshots: DefinitionSnapshot[],
  ): DefinitionMutation | null {
    if (snapshots.length < 2) return null;

    const baseline = snapshots[0];

    for (let i = 1; i < snapshots.length; i++) {
      const current = snapshots[i];

      // Check if description changed
      const descriptionChanged = baseline.description !== current.description;

      // Check if schema changed (deep comparison)
      const schemaChanged =
        JSON.stringify(baseline.inputSchema) !==
        JSON.stringify(current.inputSchema);

      if (descriptionChanged || schemaChanged) {
        return {
          detectedAt: current.invocation,
          baselineDescription: baseline.description,
          mutatedDescription: descriptionChanged
            ? current.description
            : undefined,
          baselineSchema: schemaChanged ? baseline.inputSchema : undefined,
          mutatedSchema: schemaChanged ? current.inputSchema : undefined,
        };
      }
    }

    return null;
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

    // For stateful tools (search, list, etc.), use schema comparison instead of exact match
    // These tools legitimately return different content based on data state
    const isStateful = this.isStatefulTool(tool);
    if (isStateful) {
      this.log(`${tool.name} classified as stateful - using schema comparison`);
    }

    for (let i = 1; i < responses.length; i++) {
      if (responses[i].error) {
        errors.push(i + 1); // Track errors as potential indicators
        deviations.push(i + 1);
      } else {
        let isDifferent: boolean;
        if (isStateful) {
          // Schema-only comparison for stateful tools
          // Content can vary, but field names should remain consistent
          isDifferent = !this.compareSchemas(
            responses[0].response,
            responses[i].response,
          );
        } else {
          // Exact comparison for non-stateful tools
          const normalized = this.normalizeResponse(responses[i].response);
          isDifferent = normalized !== baseline;
        }

        if (isDifferent) {
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
      // Add note for stateful tools that passed schema check
      note:
        isStateful && !isVulnerable
          ? "Stateful tool - content variation expected, schema consistent"
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
        // ISO timestamps (bounded quantifier to prevent ReDoS)
        .replace(/"\d{4}-\d{2}-\d{2}T[\d:.]{1,30}Z?"/g, '"<TIMESTAMP>"')
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
        // Additional accumulation-related counter fields (defense-in-depth)
        .replace(
          /"total_observations":\s*\d+/g,
          '"total_observations": <NUMBER>',
        )
        .replace(
          /\\"total_observations\\":\s*\d+/g,
          '\\"total_observations\\": <NUMBER>',
        )
        .replace(
          /"observations_count":\s*\d+/g,
          '"observations_count": <NUMBER>',
        )
        .replace(
          /\\"observations_count\\":\s*\d+/g,
          '\\"observations_count\\": <NUMBER>',
        )
        .replace(/"total_records":\s*\d+/g, '"total_records": <NUMBER>')
        .replace(/\\"total_records\\":\s*\d+/g, '\\"total_records\\": <NUMBER>')
        .replace(/"records_added":\s*\d+/g, '"records_added": <NUMBER>')
        .replace(/\\"records_added\\":\s*\d+/g, '\\"records_added\\": <NUMBER>')
        .replace(/"items_added":\s*\d+/g, '"items_added": <NUMBER>')
        .replace(/\\"items_added\\":\s*\d+/g, '\\"items_added\\": <NUMBER>')
        .replace(/"size":\s*\d+/g, '"size": <NUMBER>')
        .replace(/\\"size\\":\s*\d+/g, '\\"size\\": <NUMBER>')
        .replace(/"length":\s*\d+/g, '"length": <NUMBER>')
        .replace(/\\"length\\":\s*\d+/g, '\\"length\\": <NUMBER>')
        .replace(/"total":\s*\d+/g, '"total": <NUMBER>')
        .replace(/\\"total\\":\s*\d+/g, '\\"total\\": <NUMBER>')
        // String IDs
        .replace(/"id":\s*"[^"]+"/g, '"id": "<ID>"')
        // P2-1: Additional timestamp fields that vary between calls
        .replace(
          /"(updated_at|created_at|modified_at)":\s*"[^"]+"/g,
          '"$1": "<TIMESTAMP>"',
        )
        // P2-1: Dynamic tokens/hashes that change per request
        .replace(
          /"(nonce|token|hash|etag|session_id|correlation_id)":\s*"[^"]+"/g,
          '"$1": "<DYNAMIC>"',
        )
    );
  }

  /**
   * Detect if a tool may have side effects based on naming patterns.
   */
  private isDestructiveTool(tool: Tool): boolean {
    const name = tool.name.toLowerCase();
    return this.DESTRUCTIVE_PATTERNS.some((p) => name.includes(p));
  }

  /**
   * Check if a tool is expected to have state-dependent behavior.
   * Stateful tools (search, list, add, store, etc.) legitimately return different
   * results as underlying data changes - this is NOT a rug pull.
   *
   * Uses word-boundary matching to prevent false positives:
   * - "add_observations" matches "add" ✓
   * - "address_validator" does NOT match "add" ✓
   */
  private isStatefulTool(tool: Tool): boolean {
    const toolName = tool.name.toLowerCase();
    // Exclude tools that are ALSO destructive - they should get strict exact comparison
    // e.g., "get_and_delete" matches both "get" (stateful) and "delete" (destructive)
    if (this.isDestructiveTool(tool)) {
      return false;
    }
    // Use word-boundary matching: pattern must be at start/end or bounded by _ or -
    // This prevents "address_validator" from matching "add"
    return this.STATEFUL_TOOL_PATTERNS.some((pattern) => {
      const wordBoundaryRegex = new RegExp(`(^|_|-)${pattern}($|_|-)`);
      return wordBoundaryRegex.test(toolName);
    });
  }

  /**
   * Compare response schemas (field names) rather than full content.
   * Stateful tools may have different values but should have consistent fields.
   *
   * For stateful tools, allows schema growth (empty arrays → populated arrays)
   * but flags when baseline fields disappear (suspicious behavior).
   */
  private compareSchemas(response1: unknown, response2: unknown): boolean {
    const fields1 = this.extractFieldNames(response1).sort();
    const fields2 = this.extractFieldNames(response2).sort();

    // Edge case: empty baseline with populated later response is suspicious
    // An attacker could start with {} then switch to content with malicious fields
    if (fields1.length === 0 && fields2.length > 0) {
      return false; // Flag as schema mismatch
    }

    // Check for exact match (handles non-array cases)
    const exactMatch = fields1.join(",") === fields2.join(",");
    if (exactMatch) return true;

    // For stateful tools, allow schema to grow (empty arrays → populated)
    // Baseline (fields1) can be a subset of later responses (fields2)
    // But fields2 cannot have FEWER fields than baseline (that's suspicious)
    const set2 = new Set(fields2);
    const baselineIsSubset = fields1.every((f) => set2.has(f));

    return baselineIsSubset;
  }

  /**
   * Extract all field names from an object recursively.
   * Handles arrays by sampling multiple elements to detect heterogeneous schemas.
   */
  private extractFieldNames(obj: unknown, prefix = ""): string[] {
    if (obj === null || obj === undefined || typeof obj !== "object") return [];

    const fields: string[] = [];

    // Handle arrays: sample multiple elements to detect heterogeneous schemas
    // An attacker could hide malicious fields in non-first array elements
    if (Array.isArray(obj)) {
      const samplesToCheck = Math.min(obj.length, 3); // Check up to 3 elements
      const seenFields = new Set<string>();

      for (let i = 0; i < samplesToCheck; i++) {
        if (typeof obj[i] === "object" && obj[i] !== null) {
          const itemFields = this.extractFieldNames(obj[i], `${prefix}[]`);
          itemFields.forEach((f) => seenFields.add(f));
        }
      }
      fields.push(...seenFields);
      return fields;
    }

    // Handle objects
    for (const [key, value] of Object.entries(obj)) {
      const fieldPath = prefix ? `${prefix}.${key}` : key;
      fields.push(fieldPath);

      if (typeof value === "object" && value !== null) {
        fields.push(...this.extractFieldNames(value, fieldPath));
      }
    }
    return fields;
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
          `${tool.tool}: Description changed at invocation ${tool.definitionMutationAt}. Baseline: ${baseline} → Mutated: ${mutated}`,
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

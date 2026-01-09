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
  VarianceClassification,
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

  /**
   * Issue #69: Patterns for resource-creating operations that legitimately return
   * different IDs/resources each invocation.
   *
   * These tools CREATE new resources, so they should use schema comparison + variance
   * classification rather than exact comparison. Unlike STATEFUL_TOOL_PATTERNS, these
   * may overlap with DESTRUCTIVE_PATTERNS (e.g., "create", "insert") but should still
   * use intelligent variance classification to avoid false positives.
   *
   * Examples:
   * - create_billing_product → new product_id each time (LEGITIMATE variance)
   * - generate_report → new report_id each time (LEGITIMATE variance)
   * - insert_record → new record_id each time (LEGITIMATE variance)
   */
  private readonly RESOURCE_CREATING_PATTERNS = [
    "create",
    "new",
    "insert",
    "generate",
    "register",
    "allocate",
    "provision",
    "spawn",
    "instantiate",
    "init",
    "make",
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

    // Issue #69: Track variance details for transparency
    const varianceDetails: Array<{
      invocation: number;
      classification: VarianceClassification;
    }> = [];

    // Determine comparison strategy
    // 1. Stateful tools (search, list, etc.) - use schema comparison
    // 2. Resource-creating tools (create, insert, etc.) - use variance classification
    // 3. All other tools - use exact comparison
    const isStateful = this.isStatefulTool(tool);
    const isResourceCreating = this.isResourceCreatingTool(tool);

    if (isStateful) {
      this.log(`${tool.name} classified as stateful - using schema comparison`);
    } else if (isResourceCreating) {
      this.log(
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
        let isDifferent = !this.compareSchemas(
          responses[0].response,
          responses[i].response,
        );

        // Secondary detection: Check for content semantic changes (rug pull patterns)
        // This catches cases where schema is same but content shifts from helpful to harmful
        if (!isDifferent) {
          const contentChange = this.detectStatefulContentChange(
            responses[0].response,
            responses[i].response,
          );
          if (contentChange.detected) {
            isDifferent = true;
            this.log(
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
        const classification = this.classifyVariance(
          tool,
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
          this.log(
            `${tool.name}: ${classification.type} variance at invocation ${i + 1} - ${classification.reasons.join(", ")}`,
          );
        }
      } else {
        // Exact comparison for non-stateful, non-resource-creating tools
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
   * Issue #69: Check if a tool creates new resources that legitimately vary per invocation.
   * Resource-creating tools return different IDs, creation timestamps, etc.
   * for each new resource - this is expected behavior, NOT a rug pull.
   *
   * Unlike isStatefulTool(), this DOES include patterns that overlap with DESTRUCTIVE_PATTERNS
   * because resource-creating tools need intelligent variance classification, not exact comparison.
   *
   * Uses word-boundary matching like isStatefulTool() to prevent false matches.
   * - "create_billing_product" matches "create" ✓
   * - "recreate_view" does NOT match "create" ✓ (must be at word boundary)
   */
  private isResourceCreatingTool(tool: Tool): boolean {
    const toolName = tool.name.toLowerCase();
    return this.RESOURCE_CREATING_PATTERNS.some((pattern) => {
      const wordBoundaryRegex = new RegExp(`(^|_|-)${pattern}($|_|-)`);
      return wordBoundaryRegex.test(toolName);
    });
  }

  /**
   * Issue #69: Classify variance between two responses to reduce false positives.
   * Returns LEGITIMATE for expected variance (IDs, timestamps), SUSPICIOUS for
   * schema changes, and BEHAVIORAL for semantic changes (promotional keywords, errors).
   */
  private classifyVariance(
    _tool: Tool,
    baseline: unknown,
    current: unknown,
  ): VarianceClassification {
    // 1. Schema comparison - structural changes are SUSPICIOUS
    const schemaMatch = this.compareSchemas(baseline, current);
    if (!schemaMatch) {
      return {
        type: "SUSPICIOUS",
        confidence: "high",
        reasons: ["Schema/field structure changed between invocations"],
        suspiciousPatterns: ["schema_change"],
      };
    }

    // 2. Content change detection - promotional/error keywords are BEHAVIORAL
    const contentChange = this.detectStatefulContentChange(baseline, current);
    if (contentChange.detected) {
      return {
        type: "BEHAVIORAL",
        confidence: "high",
        reasons: [`Behavioral change detected: ${contentChange.reason}`],
        suspiciousPatterns: [contentChange.reason || "content_change"],
      };
    }

    // 3. After normalization, if responses match = LEGITIMATE
    const normalizedBaseline = this.normalizeResponse(baseline);
    const normalizedCurrent = this.normalizeResponse(current);
    if (normalizedBaseline === normalizedCurrent) {
      return {
        type: "LEGITIMATE",
        confidence: "high",
        reasons: ["All differences normalized (IDs, timestamps, counters)"],
      };
    }

    // 4. Check for legitimate field variance (any _id, _at, token fields)
    const variedFields = this.findVariedFields(baseline, current);
    const unexplainedFields = variedFields.filter(
      (f) => !this.isLegitimateFieldVariance(f),
    );

    if (unexplainedFields.length === 0) {
      return {
        type: "LEGITIMATE",
        confidence: "high",
        reasons: [
          `Variance only in legitimate fields: ${variedFields.join(", ")}`,
        ],
        variedFields,
      };
    }

    // 5. Some unexplained variance - flag as suspicious with low confidence
    return {
      type: "SUSPICIOUS",
      confidence: "low",
      reasons: [
        `Unexplained variance in fields: ${unexplainedFields.join(", ")}`,
      ],
      variedFields,
      suspiciousPatterns: ["unclassified_variance"],
    };
  }

  /**
   * Issue #69: Check if a field name represents legitimate variance.
   * Fields containing IDs, timestamps, tokens, etc. are expected to vary.
   */
  private isLegitimateFieldVariance(field: string): boolean {
    const fieldLower = field.toLowerCase();

    // ID fields - any field ending in _id or containing "id" at word boundary
    if (fieldLower.endsWith("_id") || fieldLower.endsWith("id")) return true;
    if (fieldLower.includes("_id_") || fieldLower.startsWith("id_"))
      return true;

    // Timestamp fields
    if (fieldLower.endsWith("_at") || fieldLower.endsWith("at")) return true;
    if (
      fieldLower.includes("time") ||
      fieldLower.includes("date") ||
      fieldLower.includes("timestamp")
    )
      return true;

    // Token/session fields
    if (
      fieldLower.includes("token") ||
      fieldLower.includes("cursor") ||
      fieldLower.includes("nonce")
    )
      return true;
    if (fieldLower.includes("session") || fieldLower.includes("correlation"))
      return true;

    // Pagination fields
    if (
      fieldLower.includes("offset") ||
      fieldLower.includes("page") ||
      fieldLower.includes("next")
    )
      return true;

    // Counter/accumulation fields
    if (
      fieldLower.includes("count") ||
      fieldLower.includes("total") ||
      fieldLower.includes("size")
    )
      return true;
    if (fieldLower.includes("length") || fieldLower.includes("index"))
      return true;

    // Array content fields (search results, items)
    if (
      fieldLower.includes("results") ||
      fieldLower.includes("items") ||
      fieldLower.includes("data")
    )
      return true;

    // Hash/version fields
    if (
      fieldLower.includes("hash") ||
      fieldLower.includes("etag") ||
      fieldLower.includes("version")
    )
      return true;

    return false;
  }

  /**
   * Issue #69: Find which fields differ between two responses.
   * Returns field paths that have different values.
   */
  private findVariedFields(
    obj1: unknown,
    obj2: unknown,
    prefix = "",
  ): string[] {
    const varied: string[] = [];

    // Handle primitives
    if (typeof obj1 !== "object" || obj1 === null) {
      if (obj1 !== obj2) {
        return [prefix || "value"];
      }
      return [];
    }

    if (typeof obj2 !== "object" || obj2 === null) {
      return [prefix || "value"];
    }

    // Handle arrays - just note if length or content differs
    if (Array.isArray(obj1) || Array.isArray(obj2)) {
      const arr1 = Array.isArray(obj1) ? obj1 : [];
      const arr2 = Array.isArray(obj2) ? obj2 : [];
      if (JSON.stringify(arr1) !== JSON.stringify(arr2)) {
        return [prefix || "array"];
      }
      return [];
    }

    // Handle objects
    const allKeys = new Set([
      ...Object.keys(obj1 as object),
      ...Object.keys(obj2 as object),
    ]);

    for (const key of allKeys) {
      const val1 = (obj1 as Record<string, unknown>)[key];
      const val2 = (obj2 as Record<string, unknown>)[key];
      const fieldPath = prefix ? `${prefix}.${key}` : key;

      if (JSON.stringify(val1) !== JSON.stringify(val2)) {
        // If both are objects, recurse to find specific field
        if (
          typeof val1 === "object" &&
          val1 !== null &&
          typeof val2 === "object" &&
          val2 !== null
        ) {
          const nestedVaried = this.findVariedFields(val1, val2, fieldPath);
          varied.push(...nestedVaried);
        } else {
          varied.push(fieldPath);
        }
      }
    }

    return varied;
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

  /**
   * Secondary detection for stateful tools that pass schema comparison.
   * Catches rug pulls that change content semantically while keeping schema intact.
   *
   * Examples detected:
   * - Weather data → "Rate limit exceeded, upgrade to premium"
   * - Stock prices → "Subscribe for $9.99/month to continue"
   * - Search results → "Error: Service unavailable"
   */
  private detectStatefulContentChange(
    baseline: unknown,
    current: unknown,
  ): { detected: boolean; reason: string | null } {
    // Convert to strings for content analysis
    const baselineText = this.extractTextContent(baseline);
    const currentText = this.extractTextContent(current);

    // Skip if both are empty or identical
    if (!baselineText && !currentText) return { detected: false, reason: null };
    if (baselineText === currentText) return { detected: false, reason: null };

    // Check 1: Error keywords appearing in later responses (not present in baseline)
    if (
      this.hasErrorKeywords(currentText) &&
      !this.hasErrorKeywords(baselineText)
    ) {
      return { detected: true, reason: "error_keywords_appeared" };
    }

    // Check 2: Promotional/payment keywords (rug pull monetization pattern)
    if (
      this.hasPromotionalKeywords(currentText) &&
      !this.hasPromotionalKeywords(baselineText)
    ) {
      return { detected: true, reason: "promotional_keywords_appeared" };
    }

    // Check 3: Suspicious links injected (URLs not present in baseline)
    if (
      this.hasSuspiciousLinks(currentText) &&
      !this.hasSuspiciousLinks(baselineText)
    ) {
      return { detected: true, reason: "suspicious_links_injected" };
    }

    // Check 4: Significant length DECREASE only (response becoming much shorter)
    // This catches cases where helpful responses shrink to terse error messages
    // We don't flag length increase because stateful tools legitimately accumulate data
    if (baselineText.length > 20) {
      // Only check if baseline has meaningful content
      const lengthRatio = currentText.length / baselineText.length;
      if (lengthRatio < 0.3) {
        // Response shrunk to <30% of original
        return { detected: true, reason: "significant_length_decrease" };
      }
    }

    return { detected: false, reason: null };
  }

  /**
   * Extract text content from a response for semantic analysis.
   */
  private extractTextContent(obj: unknown): string {
    if (typeof obj === "string") return obj;
    if (typeof obj !== "object" || !obj) return "";
    return JSON.stringify(obj);
  }

  /**
   * Check for error-related keywords that indicate service degradation.
   */
  private hasErrorKeywords(text: string): boolean {
    const patterns = [
      /\berror\b/i,
      /\bfail(ed|ure)?\b/i,
      /\bunavailable\b/i,
      /\brate\s*limit/i,
      /\bdenied\b/i,
      /\bexpired\b/i,
      /\btimeout\b/i,
      /\bblocked\b/i,
    ];
    return patterns.some((p) => p.test(text));
  }

  /**
   * Check for promotional/monetization keywords that indicate a monetization rug pull.
   * Enhanced to catch CH4-style rug pulls with limited-time offers, referral codes, etc.
   *
   * Combined into single regex for O(text_length) performance instead of O(18 * text_length).
   */
  private hasPromotionalKeywords(text: string): boolean {
    // Single combined regex with alternation - matches all 18 original patterns
    // Word-boundary patterns: upgrade, premium, discount, exclusive, subscription variants,
    //   multi-word phrases (pro plan, buy now, limited time/offer, free trial, etc.)
    // Non-word patterns: price ($X.XX), percentage (N% off/discount)
    const PROMO_PATTERN =
      /\b(?:upgrade|premium|discount|exclusive|subscri(?:be|ption)|pro\s*plan|buy\s*now|limited\s*(?:time|offer)|free\s*trial|special\s*offer|referral\s*code|promo\s*code|act\s*now|don't\s*miss|for\s*a\s*fee|pay(?:ment)?\s*(?:required|needed|now))\b|\$\d+(?:\.\d{2})?|\b\d+%\s*(?:off|discount)\b/i;
    return PROMO_PATTERN.test(text);
  }

  /**
   * Check for suspicious URL/link injection that wasn't present initially.
   * Rug pulls often inject links to external malicious or monetization pages.
   */
  private hasSuspiciousLinks(text: string): boolean {
    const patterns = [
      // HTTP(S) URLs
      /https?:\/\/[^\s]+/i,
      // Markdown links
      /\[.{0,50}?\]\(.{0,200}?\)/,
      // URL shorteners
      /\b(bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly|buff\.ly)\b/i,
      // Click-bait action patterns
      /\bclick\s*(here|now|this)\b/i,
      /\bvisit\s*our\s*(website|site|page)\b/i,
      /\b(sign\s*up|register)\s*(here|now|at)\b/i,
    ];
    return patterns.some((p) => p.test(text));
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

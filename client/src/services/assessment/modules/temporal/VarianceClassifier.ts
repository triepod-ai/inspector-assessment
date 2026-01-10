/**
 * Variance Classifier Module
 * Classifies response variance to distinguish legitimate behavior from rug pulls.
 *
 * Extracted from TemporalAssessor as part of Issue #106 refactoring.
 */

import { VarianceClassification } from "@/lib/assessmentTypes";
import { Tool } from "@modelcontextprotocol/sdk/types.js";
import { MutationDetector } from "./MutationDetector";

/**
 * Classifies response variance and categorizes tools by their expected behavior patterns.
 * Used to reduce false positives in temporal assessment by understanding legitimate variance.
 */
export class VarianceClassifier {
  private mutationDetector: MutationDetector;

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
   * - create_billing_product -> new product_id each time (LEGITIMATE variance)
   * - generate_report -> new report_id each time (LEGITIMATE variance)
   * - insert_record -> new record_id each time (LEGITIMATE variance)
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

  constructor(mutationDetector?: MutationDetector) {
    this.mutationDetector = mutationDetector ?? new MutationDetector();
  }

  /**
   * Normalize response for comparison by removing naturally varying data.
   * Prevents false positives from timestamps, UUIDs, request IDs, counters, etc.
   * Handles both direct JSON and nested JSON strings (e.g., content[].text).
   */
  normalizeResponse(response: unknown): string {
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
  isDestructiveTool(tool: Tool): boolean {
    const name = tool.name.toLowerCase();
    return this.DESTRUCTIVE_PATTERNS.some((p) => name.includes(p));
  }

  /**
   * Check if a tool is expected to have state-dependent behavior.
   * Stateful tools (search, list, add, store, etc.) legitimately return different
   * results as underlying data changes - this is NOT a rug pull.
   *
   * Uses word-boundary matching to prevent false positives:
   * - "add_observations" matches "add"
   * - "address_validator" does NOT match "add"
   */
  isStatefulTool(tool: Tool): boolean {
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
   * - "create_billing_product" matches "create"
   * - "recreate_view" does NOT match "create" (must be at word boundary)
   */
  isResourceCreatingTool(tool: Tool): boolean {
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
  classifyVariance(
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
    const contentChange = this.mutationDetector.detectStatefulContentChange(
      baseline,
      current,
    );
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
  isLegitimateFieldVariance(field: string): boolean {
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
  findVariedFields(obj1: unknown, obj2: unknown, prefix = ""): string[] {
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
   * For stateful tools, allows schema growth (empty arrays -> populated arrays)
   * but flags when baseline fields disappear (suspicious behavior).
   */
  compareSchemas(response1: unknown, response2: unknown): boolean {
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

    // For stateful tools, allow schema to grow (empty arrays -> populated)
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
  extractFieldNames(obj: unknown, prefix = ""): string[] {
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
}

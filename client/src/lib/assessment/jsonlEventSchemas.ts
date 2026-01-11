/**
 * Zod Schemas for JSONL Event Types
 *
 * Runtime validation schemas for all 13 JSONL event types emitted during
 * CLI assessment runs. Enables type-safe parsing for external consumers.
 *
 * @module assessment/jsonlEventSchemas
 * @see scripts/lib/jsonl-events.ts - TypeScript interface definitions
 * @see docs/JSONL_EVENTS_REFERENCE.md - Event documentation
 */

import { z } from "zod";
import {
  ZOD_SCHEMA_VERSION,
  TransportTypeSchema,
} from "@/lib/assessment/sharedSchemas";

// Re-export for consumers
export { ZOD_SCHEMA_VERSION, TransportTypeSchema };

// ============================================================================
// Shared Enum Schemas
// ============================================================================

/**
 * Schema for module completion status.
 */
export const ModuleStatusSchema = z.enum(["PASS", "FAIL", "NEED_MORE_INFO"]);
export type ModuleStatus = z.infer<typeof ModuleStatusSchema>;

/**
 * Schema for confidence level (lowercase).
 */
export const ConfidenceLevelSchema = z.enum(["high", "medium", "low"]);
export type ConfidenceLevel = z.infer<typeof ConfidenceLevelSchema>;

/**
 * Schema for risk level (uppercase).
 */
export const RiskLevelSchema = z.enum(["HIGH", "MEDIUM", "LOW"]);
export type RiskLevel = z.infer<typeof RiskLevelSchema>;

/**
 * Schema for AUP violation severity.
 */
export const SeveritySchema = z.enum(["CRITICAL", "HIGH", "MEDIUM"]);
export type Severity = z.infer<typeof SeveritySchema>;

/**
 * Schema for AUP violation location.
 */
export const LocationSchema = z.enum([
  "tool_name",
  "tool_description",
  "readme",
  "source_code",
]);
export type Location = z.infer<typeof LocationSchema>;

/**
 * Schema for annotation field types.
 */
export const AnnotationFieldSchema = z.enum([
  "readOnlyHint",
  "destructiveHint",
]);
export type AnnotationField = z.infer<typeof AnnotationFieldSchema>;

/**
 * Schema for modules_configured reason.
 */
export const ModulesConfiguredReasonSchema = z.enum([
  "skip-modules",
  "only-modules",
  "default",
]);
export type ModulesConfiguredReason = z.infer<
  typeof ModulesConfiguredReasonSchema
>;

// ============================================================================
// Supporting Type Schemas
// ============================================================================

/**
 * Schema for tool parameter information.
 */
export const ToolParamSchema = z.object({
  name: z.string(),
  type: z.string(),
  required: z.boolean(),
  description: z.string().optional(),
});
export type ToolParam = z.infer<typeof ToolParamSchema>;

/**
 * Schema for tool annotations object.
 */
export const ToolAnnotationsSchema = z
  .object({
    readOnlyHint: z.boolean().optional(),
    destructiveHint: z.boolean().optional(),
    idempotentHint: z.boolean().optional(),
    openWorldHint: z.boolean().optional(),
  })
  .nullable();
export type ToolAnnotations = z.infer<typeof ToolAnnotationsSchema>;

/**
 * Schema for inferred behavior in annotation_missing events.
 */
export const InferredBehaviorSchema = z.object({
  expectedReadOnly: z.boolean(),
  expectedDestructive: z.boolean(),
  reason: z.string(),
});
export type InferredBehavior = z.infer<typeof InferredBehaviorSchema>;

// ============================================================================
// AUP Enrichment Schemas
// ============================================================================

/**
 * Schema for sampled AUP violation.
 */
export const AUPViolationSampleSchema = z.object({
  category: z.string(),
  categoryName: z.string(),
  severity: SeveritySchema,
  matchedText: z.string(),
  location: LocationSchema,
  confidence: ConfidenceLevelSchema,
});
export type AUPViolationSample = z.infer<typeof AUPViolationSampleSchema>;

/**
 * Schema for AUP violation metrics.
 */
export const AUPViolationMetricsSchema = z.object({
  total: z.number().int().nonnegative(),
  critical: z.number().int().nonnegative(),
  high: z.number().int().nonnegative(),
  medium: z.number().int().nonnegative(),
  byCategory: z.record(z.string(), z.number().int().nonnegative()),
});
export type AUPViolationMetrics = z.infer<typeof AUPViolationMetricsSchema>;

/**
 * Schema for AUP scanned locations.
 */
export const AUPScannedLocationsSchema = z.object({
  toolNames: z.boolean(),
  toolDescriptions: z.boolean(),
  readme: z.boolean(),
  sourceCode: z.boolean(),
});
export type AUPScannedLocations = z.infer<typeof AUPScannedLocationsSchema>;

// ============================================================================
// Base Event Schema
// ============================================================================

/**
 * Base schema for all JSONL events.
 * All events include version (software version) and schemaVersion (event schema version).
 */
export const BaseEventSchema = z.object({
  /** Inspector software version (e.g., "1.29.0") */
  version: z.string(),
  /** Event schema version (integer, increment when structure changes) */
  schemaVersion: z.number().int().positive(),
});
export type BaseEvent = z.infer<typeof BaseEventSchema>;

// ============================================================================
// Event Schemas (13 Total)
// ============================================================================

/**
 * 1. ServerConnectedEvent - Emitted after successful MCP connection.
 */
export const ServerConnectedEventSchema = BaseEventSchema.extend({
  event: z.literal("server_connected"),
  serverName: z.string(),
  transport: TransportTypeSchema,
});
export type ServerConnectedEvent = z.infer<typeof ServerConnectedEventSchema>;

/**
 * 2. ToolDiscoveredEvent - Emitted for each tool found.
 */
export const ToolDiscoveredEventSchema = BaseEventSchema.extend({
  event: z.literal("tool_discovered"),
  name: z.string(),
  description: z.string().nullable(),
  params: z.array(ToolParamSchema),
  annotations: ToolAnnotationsSchema,
});
export type ToolDiscoveredEvent = z.infer<typeof ToolDiscoveredEventSchema>;

/**
 * 3. ToolsDiscoveryCompleteEvent - Emitted after all tools listed.
 */
export const ToolsDiscoveryCompleteEventSchema = BaseEventSchema.extend({
  event: z.literal("tools_discovery_complete"),
  count: z.number().int().nonnegative(),
});
export type ToolsDiscoveryCompleteEvent = z.infer<
  typeof ToolsDiscoveryCompleteEventSchema
>;

/**
 * 4. ModulesConfiguredEvent - Emitted when --skip-modules or --only-modules used.
 */
export const ModulesConfiguredEventSchema = BaseEventSchema.extend({
  event: z.literal("modules_configured"),
  enabled: z.array(z.string()),
  skipped: z.array(z.string()),
  reason: ModulesConfiguredReasonSchema,
});
export type ModulesConfiguredEvent = z.infer<
  typeof ModulesConfiguredEventSchema
>;

/**
 * 5. ModuleStartedEvent - Emitted when a module begins execution.
 */
export const ModuleStartedEventSchema = BaseEventSchema.extend({
  event: z.literal("module_started"),
  module: z.string(),
  estimatedTests: z.number().int().nonnegative(),
  toolCount: z.number().int().nonnegative(),
});
export type ModuleStartedEvent = z.infer<typeof ModuleStartedEventSchema>;

/**
 * 6. TestBatchEvent - Emitted during test execution with progress.
 */
export const TestBatchEventSchema = BaseEventSchema.extend({
  event: z.literal("test_batch"),
  module: z.string(),
  completed: z.number().int().nonnegative(),
  total: z.number().int().nonnegative(),
  batchSize: z.number().int().positive(),
  elapsed: z.number().nonnegative(),
});
export type TestBatchEvent = z.infer<typeof TestBatchEventSchema>;

/**
 * 7. ModuleCompleteEvent - Emitted after module finishes with summary.
 * Includes optional AUP enrichment when module=aup.
 */
export const ModuleCompleteEventSchema = BaseEventSchema.extend({
  event: z.literal("module_complete"),
  module: z.string(),
  status: ModuleStatusSchema,
  score: z.number().min(0).max(100),
  testsRun: z.number().int().nonnegative(),
  duration: z.number().nonnegative(),
  // AUP-specific enrichment (optional)
  violationsSample: z.array(AUPViolationSampleSchema).optional(),
  samplingNote: z.string().optional(),
  violationMetrics: AUPViolationMetricsSchema.optional(),
  scannedLocations: AUPScannedLocationsSchema.optional(),
  highRiskDomains: z.array(z.string()).optional(),
});
export type ModuleCompleteEvent = z.infer<typeof ModuleCompleteEventSchema>;

/**
 * 8. VulnerabilityFoundEvent - Emitted when security vulnerability detected.
 */
export const VulnerabilityFoundEventSchema = BaseEventSchema.extend({
  event: z.literal("vulnerability_found"),
  tool: z.string(),
  pattern: z.string(),
  confidence: ConfidenceLevelSchema,
  evidence: z.string(),
  riskLevel: RiskLevelSchema,
  requiresReview: z.boolean(),
  payload: z.string().optional(),
});
export type VulnerabilityFoundEvent = z.infer<
  typeof VulnerabilityFoundEventSchema
>;

/**
 * 9. AnnotationMissingEvent - Emitted when tool lacks annotations.
 */
export const AnnotationMissingEventSchema = BaseEventSchema.extend({
  event: z.literal("annotation_missing"),
  tool: z.string(),
  title: z.string().optional(),
  description: z.string().optional(),
  parameters: z.array(ToolParamSchema),
  inferredBehavior: InferredBehaviorSchema,
});
export type AnnotationMissingEvent = z.infer<
  typeof AnnotationMissingEventSchema
>;

/**
 * 10. AnnotationMisalignedEvent - Emitted when annotation doesn't match behavior.
 */
export const AnnotationMisalignedEventSchema = BaseEventSchema.extend({
  event: z.literal("annotation_misaligned"),
  tool: z.string(),
  title: z.string().optional(),
  description: z.string().optional(),
  parameters: z.array(ToolParamSchema),
  field: AnnotationFieldSchema,
  actual: z.boolean().optional(),
  expected: z.boolean(),
  confidence: z.number().min(0).max(1),
  reason: z.string(),
});
export type AnnotationMisalignedEvent = z.infer<
  typeof AnnotationMisalignedEventSchema
>;

/**
 * 11. AnnotationReviewRecommendedEvent - Emitted for ambiguous patterns.
 */
export const AnnotationReviewRecommendedEventSchema = BaseEventSchema.extend({
  event: z.literal("annotation_review_recommended"),
  tool: z.string(),
  title: z.string().optional(),
  description: z.string().optional(),
  parameters: z.array(ToolParamSchema),
  field: AnnotationFieldSchema,
  actual: z.boolean().optional(),
  inferred: z.boolean(),
  confidence: ConfidenceLevelSchema,
  isAmbiguous: z.boolean(),
  reason: z.string(),
});
export type AnnotationReviewRecommendedEvent = z.infer<
  typeof AnnotationReviewRecommendedEventSchema
>;

/**
 * 12. AnnotationAlignedEvent - Emitted when annotations correctly match behavior.
 */
export const AnnotationAlignedEventSchema = BaseEventSchema.extend({
  event: z.literal("annotation_aligned"),
  tool: z.string(),
  confidence: ConfidenceLevelSchema,
  annotations: z.object({
    readOnlyHint: z.boolean().optional(),
    destructiveHint: z.boolean().optional(),
    openWorldHint: z.boolean().optional(),
    idempotentHint: z.boolean().optional(),
  }),
});
export type AnnotationAlignedEvent = z.infer<
  typeof AnnotationAlignedEventSchema
>;

/**
 * 13. AssessmentCompleteEvent - Emitted at end of assessment.
 */
export const AssessmentCompleteEventSchema = BaseEventSchema.extend({
  event: z.literal("assessment_complete"),
  overallStatus: z.string(),
  totalTests: z.number().int().nonnegative(),
  executionTime: z.number().nonnegative(),
  outputPath: z.string(),
});
export type AssessmentCompleteEvent = z.infer<
  typeof AssessmentCompleteEventSchema
>;

// ============================================================================
// Union Schema
// ============================================================================

/**
 * Union of all JSONL event schemas.
 * Uses z.union() with z.literal() for event type discrimination.
 */
export const JSONLEventSchema = z.union([
  ServerConnectedEventSchema,
  ToolDiscoveredEventSchema,
  ToolsDiscoveryCompleteEventSchema,
  ModulesConfiguredEventSchema,
  ModuleStartedEventSchema,
  TestBatchEventSchema,
  ModuleCompleteEventSchema,
  VulnerabilityFoundEventSchema,
  AnnotationMissingEventSchema,
  AnnotationMisalignedEventSchema,
  AnnotationReviewRecommendedEventSchema,
  AnnotationAlignedEventSchema,
  AssessmentCompleteEventSchema,
]);

/**
 * Inferred union type for all JSONL events.
 */
export type JSONLEventParsed = z.infer<typeof JSONLEventSchema>;

/**
 * Event type literal union for type guards.
 */
export type JSONLEventType = JSONLEventParsed["event"];

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Parse a JSONL event string or object with validation.
 *
 * @param input - Raw JSON string or parsed object
 * @returns Validated and typed event
 * @throws ZodError if validation fails
 * @throws SyntaxError if input is invalid JSON string
 *
 * @example
 * ```typescript
 * const event = parseEvent('{"event":"server_connected",...}');
 * console.log(event.serverName);
 * ```
 */
export function parseEvent(input: string | unknown): JSONLEventParsed {
  const data = typeof input === "string" ? JSON.parse(input) : input;
  return JSONLEventSchema.parse(data);
}

/**
 * Safely parse a JSONL event without throwing.
 *
 * @param input - Raw JSON string or parsed object
 * @returns SafeParseResult with success status and data/error
 *
 * @example
 * ```typescript
 * const result = safeParseEvent(line);
 * if (result.success) {
 *   console.log(result.data.event);
 * } else {
 *   console.error(result.error);
 * }
 * ```
 */
export function safeParseEvent(
  input: string | unknown,
): z.SafeParseReturnType<unknown, JSONLEventParsed> {
  try {
    const data = typeof input === "string" ? JSON.parse(input) : input;
    return JSONLEventSchema.safeParse(data);
  } catch (e) {
    // JSON parse error - return as Zod-like error
    return {
      success: false,
      error: new z.ZodError([
        {
          code: "custom",
          path: [],
          message:
            e instanceof Error ? `Invalid JSON: ${e.message}` : "Invalid JSON",
        },
      ]),
    };
  }
}

/**
 * Validate an event and return error messages.
 *
 * @param input - Raw event data
 * @returns Array of validation error messages (empty if valid)
 *
 * @example
 * ```typescript
 * const errors = validateEvent(data);
 * if (errors.length > 0) {
 *   console.error('Validation failed:', errors);
 * }
 * ```
 */
export function validateEvent(input: unknown): string[] {
  const result = JSONLEventSchema.safeParse(input);

  if (result.success) {
    return [];
  }

  return result.error.errors.map((e) => {
    const path = e.path.length > 0 ? `${e.path.join(".")}: ` : "";
    return `${path}${e.message}`;
  });
}

/**
 * Type guard for specific event types.
 *
 * @param event - Parsed event
 * @param eventType - Event type to check
 * @returns True if event matches the specified type
 *
 * @example
 * ```typescript
 * const event = parseEvent(line);
 * if (isEventType(event, 'server_connected')) {
 *   // event is narrowed to ServerConnectedEvent
 *   console.log(event.serverName);
 * }
 * ```
 */
export function isEventType<T extends JSONLEventType>(
  event: JSONLEventParsed,
  eventType: T,
): event is Extract<JSONLEventParsed, { event: T }> {
  return event.event === eventType;
}

/**
 * Parse multiple JSONL lines with line number tracking.
 *
 * @param lines - Array of JSONL strings
 * @returns Array of parse results with line numbers (1-indexed)
 *
 * @example
 * ```typescript
 * const results = parseEventLines(lines);
 * for (const { line, result } of results) {
 *   if (!result.success) {
 *     console.error(`Line ${line}: ${result.error.message}`);
 *   }
 * }
 * ```
 */
export function parseEventLines(lines: string[]): Array<{
  line: number;
  result: z.SafeParseReturnType<unknown, JSONLEventParsed>;
}> {
  return lines.map((lineContent, index) => ({
    line: index + 1,
    result: safeParseEvent(lineContent),
  }));
}

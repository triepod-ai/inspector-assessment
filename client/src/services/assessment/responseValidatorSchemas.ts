/**
 * Zod Schemas for Response Validation Types
 *
 * Runtime validation schemas for MCP tool response validation.
 * Provides safe parsing of MCP SDK response types to replace type assertions.
 *
 * @module assessment/responseValidatorSchemas
 * @see ResponseValidator.ts - Consumer of these schemas
 * @see resultTypes.ts - ResponseMetadata interface definition
 */

import { z } from "zod";
import { ZOD_SCHEMA_VERSION } from "@/lib/assessment/sharedSchemas";

// Re-export schema version for consumers
export { ZOD_SCHEMA_VERSION };

// ============================================================================
// Content Block Schemas
// ============================================================================

/**
 * Schema for MCP content type enum values.
 */
export const ContentTypeSchema = z.enum([
  "text",
  "image",
  "resource",
  "resource_link",
  "audio",
]);

export type ContentType = z.infer<typeof ContentTypeSchema>;

/**
 * Schema for a text content block.
 */
export const TextContentBlockSchema = z.object({
  type: z.literal("text"),
  text: z.string(),
});

/**
 * Schema for an image content block.
 */
export const ImageContentBlockSchema = z.object({
  type: z.literal("image"),
  data: z.string(),
  mimeType: z.string(),
});

/**
 * Schema for a resource content block.
 */
export const ResourceContentBlockSchema = z.object({
  type: z.union([z.literal("resource"), z.literal("resource_link")]),
  uri: z.string().optional(),
  mimeType: z.string().optional(),
});

/**
 * Schema for an audio content block.
 */
export const AudioContentBlockSchema = z.object({
  type: z.literal("audio"),
  data: z.string(),
  mimeType: z.string().optional(),
});

/**
 * Generic content block schema that accepts any type string.
 * Used as fallback for unknown content types.
 */
export const GenericContentBlockSchema = z.object({
  type: z.string(),
  text: z.string().optional(),
  data: z.string().optional(),
  mimeType: z.string().optional(),
  uri: z.string().optional(),
});

/**
 * Union of all known content block types, with fallback for unknown types.
 */
export const ContentBlockSchema = z.union([
  TextContentBlockSchema,
  ImageContentBlockSchema,
  ResourceContentBlockSchema,
  AudioContentBlockSchema,
  GenericContentBlockSchema,
]);

export type ContentBlock = z.infer<typeof ContentBlockSchema>;

/**
 * Schema for content array in MCP responses.
 */
export const ContentArraySchema = z.array(GenericContentBlockSchema);

export type ContentArray = z.infer<typeof ContentArraySchema>;

// ============================================================================
// Response Metadata Schemas
// ============================================================================

/**
 * Schema for output schema validation result.
 */
export const OutputSchemaValidationSchema = z.object({
  hasOutputSchema: z.boolean(),
  isValid: z.boolean(),
  error: z.string().optional(),
});

export type OutputSchemaValidationParsed = z.infer<
  typeof OutputSchemaValidationSchema
>;

/**
 * Schema for response metadata tracking.
 * Matches ResponseMetadata interface in resultTypes.ts.
 */
export const ResponseMetadataSchema = z.object({
  contentTypes: z.array(ContentTypeSchema),
  hasStructuredContent: z.boolean(),
  hasMeta: z.boolean(),
  textBlockCount: z.number().int().nonnegative(),
  imageCount: z.number().int().nonnegative(),
  resourceCount: z.number().int().nonnegative(),
  outputSchemaValidation: OutputSchemaValidationSchema.optional(),
});

export type ResponseMetadataParsed = z.infer<typeof ResponseMetadataSchema>;

// ============================================================================
// Validation Result Schemas
// ============================================================================

/**
 * Schema for validation classification enum.
 */
export const ValidationClassificationSchema = z.enum([
  "fully_working",
  "partially_working",
  "connectivity_only",
  "broken",
  "error",
]);

export type ValidationClassification = z.infer<
  typeof ValidationClassificationSchema
>;

/**
 * Schema for validation result.
 * Matches ValidationResult interface in ResponseValidator.ts.
 */
export const ValidationResultSchema = z.object({
  isValid: z.boolean(),
  isError: z.boolean(),
  confidence: z.number().int().min(0).max(100),
  issues: z.array(z.string()),
  evidence: z.array(z.string()),
  classification: ValidationClassificationSchema,
  responseMetadata: ResponseMetadataSchema.optional(),
});

export type ValidationResultParsed = z.infer<typeof ValidationResultSchema>;

// ============================================================================
// MCP Response Schemas
// ============================================================================

/**
 * Schema for MCP tool call result (CompatibilityCallToolResult).
 * Validates the structure of tool responses from MCP SDK.
 */
export const MCPToolCallResultSchema = z.object({
  content: ContentArraySchema.optional(),
  isError: z.boolean().optional(),
  structuredContent: z.unknown().optional(),
  _meta: z.unknown().optional(),
});

export type MCPToolCallResultParsed = z.infer<typeof MCPToolCallResultSchema>;

// ============================================================================
// Validation Helpers
// ============================================================================

/**
 * Validate content array from MCP response.
 *
 * @param content - Content array to validate
 * @returns Array of validation error messages (empty if valid)
 */
export function validateContentArray(content: unknown): string[] {
  const result = ContentArraySchema.safeParse(content);

  if (result.success) {
    return [];
  }

  return result.error.errors.map((e) => {
    const path = e.path.length > 0 ? `${e.path.join(".")}: ` : "";
    return `${path}${e.message}`;
  });
}

/**
 * Safely parse content array without throwing.
 *
 * @param content - Raw content array
 * @returns SafeParseResult with success status and data/error
 */
export function safeParseContentArray(content: unknown) {
  return ContentArraySchema.safeParse(content);
}

/**
 * Safely parse MCP tool call result.
 *
 * @param result - Raw tool call result
 * @returns SafeParseResult with success status and data/error
 */
export function safeParseMCPToolCallResult(result: unknown) {
  return MCPToolCallResultSchema.safeParse(result);
}

/**
 * Validate validation result structure.
 *
 * @param result - Validation result to validate
 * @returns Array of validation error messages (empty if valid)
 */
export function validateValidationResult(result: unknown): string[] {
  const parseResult = ValidationResultSchema.safeParse(result);

  if (parseResult.success) {
    return [];
  }

  return parseResult.error.errors.map((e) => {
    const path = e.path.length > 0 ? `${e.path.join(".")}: ` : "";
    return `${path}${e.message}`;
  });
}

/**
 * Parse validation result with validation.
 *
 * @param result - Raw validation result
 * @returns Validated result
 * @throws ZodError if validation fails
 */
export function parseValidationResult(result: unknown): ValidationResultParsed {
  return ValidationResultSchema.parse(result);
}

/**
 * Safely parse validation result without throwing.
 *
 * @param result - Raw validation result
 * @returns SafeParseResult with success status and data/error
 */
export function safeParseValidationResult(result: unknown) {
  return ValidationResultSchema.safeParse(result);
}

/**
 * Validate response metadata structure.
 *
 * @param metadata - Response metadata to validate
 * @returns Array of validation error messages (empty if valid)
 */
export function validateResponseMetadata(metadata: unknown): string[] {
  const result = ResponseMetadataSchema.safeParse(metadata);

  if (result.success) {
    return [];
  }

  return result.error.errors.map((e) => {
    const path = e.path.length > 0 ? `${e.path.join(".")}: ` : "";
    return `${path}${e.message}`;
  });
}

/**
 * Safely parse response metadata without throwing.
 *
 * @param metadata - Raw response metadata
 * @returns SafeParseResult with success status and data/error
 */
export function safeParseResponseMetadata(metadata: unknown) {
  return ResponseMetadataSchema.safeParse(metadata);
}

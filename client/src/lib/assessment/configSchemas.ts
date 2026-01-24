/**
 * Zod Schemas for Assessment Configuration
 *
 * Runtime validation schemas for assessment configuration.
 * Validates configuration objects loaded from files or passed programmatically.
 *
 * @public
 * @module assessment/configSchemas
 */

import { z } from "zod";

// Import shared schemas from single source of truth
import { LogLevelSchema, ZOD_SCHEMA_VERSION } from "./sharedSchemas";

// Re-export for backwards compatibility
export { LogLevelSchema, ZOD_SCHEMA_VERSION };

// ============================================================================
// Logging Configuration
// ============================================================================

/**
 * Schema for logging configuration.
 */
export const LoggingConfigSchema = z.object({
  level: LogLevelSchema,
  format: z.enum(["text", "json"]).optional(),
  includeTimestamp: z.boolean().optional(),
});

// ============================================================================
// Claude Code Configuration
// ============================================================================

/**
 * Schema for HTTP transport configuration.
 */
export const HttpTransportConfigSchema = z.object({
  baseUrl: z.string().url("baseUrl must be a valid URL"),
  apiKey: z.string().optional(),
  headers: z.record(z.string()).optional(),
});

/**
 * Schema for Claude Code features configuration.
 */
export const ClaudeCodeFeaturesSchema = z.object({
  intelligentTestGeneration: z.boolean(),
  aupSemanticAnalysis: z.boolean(),
  annotationInference: z.boolean(),
  documentationQuality: z.boolean(),
});

/**
 * Schema for Claude Code configuration.
 */
export const ClaudeCodeConfigSchema = z
  .object({
    enabled: z.boolean(),
    features: ClaudeCodeFeaturesSchema,
    timeout: z.number().int().positive("timeout must be a positive integer"),
    workingDir: z.string().optional(),
    maxRetries: z.number().int().nonnegative().optional(),
    transport: z.enum(["cli", "http"]).optional(),
    httpConfig: HttpTransportConfigSchema.optional(),
  })
  .refine(
    (data) => data.transport !== "http" || data.httpConfig !== undefined,
    {
      message: "httpConfig is required when transport is 'http'",
      path: ["httpConfig"],
    },
  );

// ============================================================================
// Assessment Categories
// ============================================================================

/**
 * Schema for assessment categories flags.
 * All fields are optional booleans.
 */
export const AssessmentCategoriesSchema = z.object({
  functionality: z.boolean().optional(),
  security: z.boolean().optional(),
  documentation: z.boolean().optional(),
  errorHandling: z.boolean().optional(),
  usability: z.boolean().optional(),
  /** @deprecated Use protocolCompliance instead */
  mcpSpecCompliance: z.boolean().optional(),
  protocolCompliance: z.boolean().optional(),
  aupCompliance: z.boolean().optional(),
  toolAnnotations: z.boolean().optional(),
  prohibitedLibraries: z.boolean().optional(),
  dependencyVulnerability: z.boolean().optional(),
  manifestValidation: z.boolean().optional(),
  portability: z.boolean().optional(),
  externalAPIScanner: z.boolean().optional(),
  authentication: z.boolean().optional(),
  temporal: z.boolean().optional(),
  resources: z.boolean().optional(),
  prompts: z.boolean().optional(),
  crossCapability: z.boolean().optional(),
  /** @deprecated Use protocolCompliance instead */
  protocolConformance: z.boolean().optional(),
  fileModularization: z.boolean().optional(),
});

// ============================================================================
// Main Assessment Configuration
// ============================================================================

/**
 * Schema for documentation verbosity level.
 */
export const DocumentationVerbositySchema = z.enum([
  "minimal",
  "standard",
  "verbose",
]);

/**
 * Schema for the main assessment configuration.
 */
export const AssessmentConfigurationSchema = z.object({
  configVersion: z.number().int().optional(),
  testTimeout: z.number().int().positive("testTimeout must be positive"),
  securityTestTimeout: z.number().int().positive().optional(),
  delayBetweenTests: z.number().int().nonnegative().optional(),
  skipBrokenTools: z.boolean(),
  reviewerMode: z.boolean().optional(),
  enableExtendedAssessment: z.boolean().optional(),
  documentationVerbosity: DocumentationVerbositySchema.optional(),
  parallelTesting: z.boolean().optional(),
  maxParallelTests: z.number().int().positive().optional(),
  scenariosPerTool: z.number().int().positive().optional(),
  /** @deprecated Use selectedToolsForTesting instead */
  maxToolsToTestForErrors: z.number().int().optional(),
  selectedToolsForTesting: z.array(z.string()).optional(),
  securityPatternsToTest: z.number().int().positive().optional(),
  enableDomainTesting: z.boolean().optional(),
  enableSequenceTesting: z.boolean().optional(),
  mcpProtocolVersion: z.string().optional(),
  enableSourceCodeAnalysis: z.boolean().optional(),
  patternConfigPath: z.string().optional(),
  claudeCode: ClaudeCodeConfigSchema.optional(),
  temporalInvocations: z.number().int().positive().optional(),
  logging: LoggingConfigSchema.optional(),
  assessmentCategories: AssessmentCategoriesSchema.optional(),
});

// ============================================================================
// Type Exports
// ============================================================================

/**
 * Inferred type from LoggingConfigSchema.
 */
export type LoggingConfigParsed = z.infer<typeof LoggingConfigSchema>;

/**
 * Inferred type from ClaudeCodeConfigSchema.
 */
export type ClaudeCodeConfigParsed = z.infer<typeof ClaudeCodeConfigSchema>;

/**
 * Inferred type from AssessmentCategoriesSchema.
 */
export type AssessmentCategoriesParsed = z.infer<
  typeof AssessmentCategoriesSchema
>;

/**
 * Inferred type from AssessmentConfigurationSchema.
 */
export type AssessmentConfigurationParsed = z.infer<
  typeof AssessmentConfigurationSchema
>;

// ============================================================================
// Validation Helpers
// ============================================================================

/**
 * Parse and validate an assessment configuration object.
 *
 * @param config - Raw configuration object
 * @returns Validated configuration
 * @throws ZodError if validation fails
 */
export function parseAssessmentConfig(
  config: unknown,
): AssessmentConfigurationParsed {
  return AssessmentConfigurationSchema.parse(config);
}

/**
 * Safely parse an assessment configuration without throwing.
 *
 * @param config - Raw configuration object
 * @returns SafeParseResult with success status and data/error
 */
export function safeParseAssessmentConfig(config: unknown) {
  return AssessmentConfigurationSchema.safeParse(config);
}

/**
 * Validate an assessment configuration and return error messages.
 *
 * @param config - Configuration to validate
 * @returns Array of validation error messages (empty if valid)
 */
export function validateAssessmentConfig(config: unknown): string[] {
  const result = AssessmentConfigurationSchema.safeParse(config);

  if (result.success) {
    return [];
  }

  return result.error.errors.map((e) => {
    const path = e.path.length > 0 ? `${e.path.join(".")}: ` : "";
    return `${path}${e.message}`;
  });
}

/**
 * Validate a Claude Code configuration and return error messages.
 *
 * @param config - Configuration to validate
 * @returns Array of validation error messages (empty if valid)
 */
export function validateClaudeCodeConfig(config: unknown): string[] {
  const result = ClaudeCodeConfigSchema.safeParse(config);

  if (result.success) {
    return [];
  }

  return result.error.errors.map((e) => {
    const path = e.path.length > 0 ? `${e.path.join(".")}: ` : "";
    return `${path}${e.message}`;
  });
}

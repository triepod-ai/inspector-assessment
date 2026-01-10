/**
 * Zod Schemas for CLI Argument Parsing
 *
 * Runtime validation schemas for CLI arguments and server configuration.
 * Replaces manual validation in parseArgs() and validateArgs() functions.
 *
 * @module cli/lib/cli-parserSchemas
 */

import { z } from "zod";

// ============================================================================
// Enums and Constants
// ============================================================================

/**
 * Valid log levels for CLI output.
 */
export const LogLevelSchema = z.enum([
  "silent",
  "error",
  "warn",
  "info",
  "debug",
]);

/**
 * Valid report output formats.
 */
export const ReportFormatSchema = z.enum(["json", "markdown"]);

/**
 * Valid assessment profile names.
 */
export const AssessmentProfileNameSchema = z.enum([
  "quick",
  "security",
  "compliance",
  "full",
]);

/**
 * Valid assessment module names.
 * Derived from ASSESSMENT_CATEGORY_METADATA in coreTypes.ts.
 */
export const AssessmentModuleNameSchema = z.enum([
  "functionality",
  "security",
  "documentation",
  "errorHandling",
  "usability",
  "mcpSpecCompliance",
  "aupCompliance",
  "toolAnnotations",
  "prohibitedLibraries",
  "manifestValidation",
  "portability",
  "externalAPIScanner",
  "authentication",
  "temporal",
  "resources",
  "prompts",
  "crossCapability",
  "protocolConformance",
]);

// ============================================================================
// Server Configuration Schema
// ============================================================================

/**
 * Schema for server connection configuration.
 * Validates transport-specific required fields.
 */
export const ServerConfigSchema = z
  .object({
    transport: z.enum(["stdio", "http", "sse"]).optional(),
    command: z.string().optional(),
    args: z.array(z.string()).optional(),
    env: z.record(z.string()).optional(),
    cwd: z.string().optional(),
    url: z.string().optional(),
  })
  .refine(
    (data) => {
      // For http/sse transport, url is required
      if (data.transport === "http" || data.transport === "sse") {
        return !!data.url;
      }
      // For stdio transport, command is required
      if (data.transport === "stdio") {
        return !!data.command;
      }
      // If no transport specified, either url or command must be present
      return !!data.url || !!data.command;
    },
    {
      message:
        "For http/sse transport, 'url' is required. For stdio transport, 'command' is required.",
    },
  );

// ============================================================================
// Assessment Options Schema
// ============================================================================

/**
 * Schema for assessment CLI options.
 * Validates all command-line arguments and their constraints.
 */
export const AssessmentOptionsSchema = z
  .object({
    serverName: z.string().min(1, "--server is required"),
    serverConfigPath: z.string().optional(),
    outputPath: z.string().optional(),
    sourceCodePath: z.string().optional(),
    patternConfigPath: z.string().optional(),
    performanceConfigPath: z.string().optional(),
    claudeEnabled: z.boolean().optional(),
    claudeHttp: z.boolean().optional(),
    mcpAuditorUrl: z
      .string()
      .url("--mcp-auditor-url must be a valid URL")
      .optional(),
    fullAssessment: z.boolean().optional(),
    verbose: z.boolean().optional(),
    jsonOnly: z.boolean().optional(),
    helpRequested: z.boolean().optional(),
    versionRequested: z.boolean().optional(),
    format: ReportFormatSchema.optional(),
    includePolicy: z.boolean().optional(),
    preflightOnly: z.boolean().optional(),
    comparePath: z.string().optional(),
    diffOnly: z.boolean().optional(),
    resume: z.boolean().optional(),
    noResume: z.boolean().optional(),
    temporalInvocations: z.number().int().positive().optional(),
    skipTemporal: z.boolean().optional(),
    skipModules: z.array(AssessmentModuleNameSchema).optional(),
    onlyModules: z.array(AssessmentModuleNameSchema).optional(),
    profile: AssessmentProfileNameSchema.optional(),
    logLevel: LogLevelSchema.optional(),
    listModules: z.boolean().optional(),
  })
  .refine(
    (data) =>
      !(data.profile && (data.skipModules?.length || data.onlyModules?.length)),
    {
      message: "--profile cannot be used with --skip-modules or --only-modules",
      path: ["profile"],
    },
  )
  .refine((data) => !(data.skipModules?.length && data.onlyModules?.length), {
    message: "--skip-modules and --only-modules are mutually exclusive",
    path: ["skipModules"],
  });

/**
 * Schema for validation result.
 */
export const ValidationResultSchema = z.object({
  valid: z.boolean(),
  errors: z.array(z.string()),
});

// ============================================================================
// Type Exports
// ============================================================================

/**
 * Inferred type from ServerConfigSchema.
 */
export type ServerConfigParsed = z.infer<typeof ServerConfigSchema>;

/**
 * Inferred type from AssessmentOptionsSchema.
 */
export type AssessmentOptionsParsed = z.infer<typeof AssessmentOptionsSchema>;

/**
 * Inferred type from ValidationResultSchema.
 */
export type ValidationResultParsed = z.infer<typeof ValidationResultSchema>;

/**
 * Inferred log level type.
 */
export type LogLevel = z.infer<typeof LogLevelSchema>;

/**
 * Inferred report format type.
 */
export type ReportFormat = z.infer<typeof ReportFormatSchema>;

/**
 * Inferred profile name type.
 */
export type AssessmentProfileName = z.infer<typeof AssessmentProfileNameSchema>;

/**
 * Inferred module name type.
 */
export type AssessmentModuleName = z.infer<typeof AssessmentModuleNameSchema>;

// ============================================================================
// Validation Helpers
// ============================================================================

/**
 * Validate assessment options and return error messages.
 *
 * @param options - Options to validate
 * @returns Array of validation error messages (empty if valid)
 */
export function validateAssessmentOptions(options: unknown): string[] {
  const result = AssessmentOptionsSchema.safeParse(options);

  if (result.success) {
    return [];
  }

  return result.error.errors.map((e) => {
    const path = e.path.length > 0 ? `${e.path.join(".")}: ` : "";
    return `${path}${e.message}`;
  });
}

/**
 * Validate a server configuration.
 *
 * @param config - Server config to validate
 * @returns Array of validation error messages (empty if valid)
 */
export function validateServerConfig(config: unknown): string[] {
  const result = ServerConfigSchema.safeParse(config);

  if (result.success) {
    return [];
  }

  return result.error.errors.map((e) => {
    const path = e.path.length > 0 ? `${e.path.join(".")}: ` : "";
    return `${path}${e.message}`;
  });
}

/**
 * Parse assessment options with validation.
 *
 * @param options - Raw options object
 * @returns Validated options
 * @throws ZodError if validation fails
 */
export function parseAssessmentOptions(
  options: unknown,
): AssessmentOptionsParsed {
  return AssessmentOptionsSchema.parse(options);
}

/**
 * Safely parse assessment options without throwing.
 *
 * @param options - Raw options object
 * @returns SafeParseResult with success status and data/error
 */
export function safeParseAssessmentOptions(options: unknown) {
  return AssessmentOptionsSchema.safeParse(options);
}

/**
 * Validate module names from a comma-separated string.
 *
 * @param input - Comma-separated module names
 * @returns Array of validated module names
 * @throws ZodError if any module name is invalid
 */
export function parseModuleNames(input: string): AssessmentModuleName[] {
  const names = input
    .split(",")
    .map((n) => n.trim())
    .filter(Boolean);

  return z.array(AssessmentModuleNameSchema).parse(names);
}

/**
 * Safely validate module names without throwing.
 *
 * @param input - Comma-separated module names
 * @returns Object with valid module names and any invalid names
 */
export function safeParseModuleNames(input: string): {
  valid: AssessmentModuleName[];
  invalid: string[];
} {
  const names = input
    .split(",")
    .map((n) => n.trim())
    .filter(Boolean);

  const valid: AssessmentModuleName[] = [];
  const invalid: string[] = [];

  for (const name of names) {
    const result = AssessmentModuleNameSchema.safeParse(name);
    if (result.success) {
      valid.push(result.data);
    } else {
      invalid.push(name);
    }
  }

  return { valid, invalid };
}

/**
 * Assessment Runner Types
 *
 * Shared type definitions for the assessment-runner module.
 *
 * @module cli/lib/assessment-runner/types
 */

import { CompatibilityCallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { ManifestJsonSchema } from "../../../../client/lib/lib/assessmentTypes.js";

/**
 * Source files loaded from source code path
 */
export interface SourceFiles {
  readmeContent?: string;
  packageJson?: unknown;
  manifestJson?: ManifestJsonSchema;
  manifestRaw?: string;
  sourceCodeFiles?: Map<string, string>;
}

/**
 * Type for callTool wrapper function
 */
export type CallToolFn = (
  name: string,
  params: Record<string, unknown>,
) => Promise<CompatibilityCallToolResult>;

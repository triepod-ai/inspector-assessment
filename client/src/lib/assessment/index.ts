/**
 * Assessment Types - Barrel Export
 *
 * Re-exports all assessment types from focused modules.
 * This provides backward compatibility for existing imports.
 *
 * @example
 * // Existing imports continue to work:
 * import { MCPDirectoryAssessment, AssessmentConfiguration } from "@/lib/assessment";
 *
 * // Or import from specific modules for better tree-shaking:
 * import { MCPDirectoryAssessment } from "@/lib/assessment/resultTypes";
 * import { AssessmentConfiguration } from "@/lib/assessment/configTypes";
 *
 * @module assessment
 */

// Core types (foundational, no dependencies)
export * from "./coreTypes";

// Extended types (depends on coreTypes)
export * from "./extendedTypes";

// Result types (depends on coreTypes, extendedTypes)
export * from "./resultTypes";

// Config types (depends on nothing)
export * from "./configTypes";

// Progress types (depends on coreTypes)
export * from "./progressTypes";

// Constants (depends on resultTypes)
export * from "./constants";

/**
 * Core Assessment Types
 *
 * Foundational types used across all assessment modules.
 * These are the building blocks that other type files depend on.
 *
 * @module assessment/coreTypes
 */

export type AssessmentStatus = "PASS" | "FAIL" | "NEED_MORE_INFO";
export type SecurityRiskLevel = "LOW" | "MEDIUM" | "HIGH";

/**
 * Alignment status for tool annotations.
 * Extends beyond PASS/FAIL to handle ambiguous cases.
 */
export type AlignmentStatus =
  | "ALIGNED" // Annotations match inferred behavior
  | "MISALIGNED" // Clear contradiction (e.g., delete_* with readOnlyHint=true)
  | "REVIEW_RECOMMENDED" // Ambiguous pattern, human review suggested
  | "UNKNOWN"; // Cannot determine alignment (no annotations)

/**
 * Confidence level for behavior inference
 */
export type InferenceConfidence = "high" | "medium" | "low";

/**
 * Assessment category tier for distinguishing core vs optional assessments.
 * - "core": Always applicable to any MCP server audit
 * - "optional": Contextual assessments (e.g., MCPB bundle-specific)
 */
export type AssessmentCategoryTier = "core" | "optional";

/**
 * Metadata for assessment categories including tier and applicability info.
 */
export interface AssessmentCategoryMetadata {
  tier: AssessmentCategoryTier;
  description: string;
  applicableTo?: string; // e.g., "MCPB bundles only"
}

/**
 * Category metadata mapping for all assessment modules.
 * Used for CLI output and downstream consumers to understand category context.
 *
 * Note: Uses `satisfies` to preserve literal key types while ensuring type safety.
 * This allows deriving AssessmentModuleName from the object keys.
 */
const ASSESSMENT_CATEGORY_METADATA_INTERNAL = {
  functionality: {
    tier: "core" as const,
    description: "Tool functionality validation",
  },
  security: {
    tier: "core" as const,
    description: "Security vulnerability detection",
  },
  documentation: {
    tier: "core" as const,
    description: "Documentation quality",
  },
  errorHandling: {
    tier: "core" as const,
    description: "Error handling compliance",
  },
  usability: { tier: "core" as const, description: "Usability assessment" },
  mcpSpecCompliance: {
    tier: "core" as const,
    description: "MCP protocol compliance",
  },
  aupCompliance: {
    tier: "core" as const,
    description: "Acceptable use policy compliance",
  },
  toolAnnotations: {
    tier: "core" as const,
    description: "Tool annotation validation",
  },
  prohibitedLibraries: {
    tier: "core" as const,
    description: "Prohibited library detection",
  },
  manifestValidation: {
    tier: "optional" as const,
    description: "MCPB manifest validation",
    applicableTo: "MCPB bundles",
  },
  portability: {
    tier: "optional" as const,
    description: "Portability checks",
    applicableTo: "MCPB bundles",
  },
  externalAPIScanner: {
    tier: "core" as const,
    description: "External API detection",
  },
  authentication: {
    tier: "core" as const,
    description: "OAuth/auth evaluation",
  },
  temporal: {
    tier: "core" as const,
    description: "Temporal/rug pull detection",
  },
  resources: { tier: "core" as const, description: "Resource security" },
  prompts: { tier: "core" as const, description: "Prompt security" },
  crossCapability: {
    tier: "core" as const,
    description: "Cross-capability security",
  },
  protocolConformance: {
    tier: "core" as const,
    description: "MCP protocol conformance",
  },
} satisfies Record<string, AssessmentCategoryMetadata>;

/**
 * Type-safe module name derived from ASSESSMENT_CATEGORY_METADATA keys.
 * Use this type for compile-time validation of module names.
 */
export type AssessmentModuleName =
  keyof typeof ASSESSMENT_CATEGORY_METADATA_INTERNAL;

/**
 * Re-export with original name for backward compatibility.
 * Type is preserved as Record<AssessmentModuleName, AssessmentCategoryMetadata>.
 */
export const ASSESSMENT_CATEGORY_METADATA: Record<
  AssessmentModuleName,
  AssessmentCategoryMetadata
> = ASSESSMENT_CATEGORY_METADATA_INTERNAL;

/**
 * Generate module configuration derived from ASSESSMENT_CATEGORY_METADATA.
 * Single source of truth for all assessment module names.
 *
 * @param options.sourceCodePath - If true, enables externalAPIScanner
 * @param options.skipTemporal - If true, disables temporal assessment
 * @returns Record of module names to enabled state (type-safe)
 */
export function getAllModulesConfig(options: {
  sourceCodePath?: boolean;
  skipTemporal?: boolean;
}): Record<AssessmentModuleName, boolean> {
  return Object.keys(ASSESSMENT_CATEGORY_METADATA).reduce(
    (acc, key) => ({
      ...acc,
      [key]:
        key === "externalAPIScanner"
          ? Boolean(options.sourceCodePath)
          : key === "temporal"
            ? !options.skipTemporal
            : true,
    }),
    {} as Record<AssessmentModuleName, boolean>,
  );
}

/**
 * Persistence model for MCP servers (Three-Tier Classification).
 *
 * These types are re-exported from the services layer for backward compatibility
 * with existing imports from `@/lib/assessmentTypes`. This cross-layer import
 * is intentional and documented:
 *
 * **Why cross-layer?**
 * - PersistenceModel and ServerPersistenceContext are defined in
 *   `services/assessment/config/annotationPatterns.ts` alongside the pattern
 *   matching logic that uses them.
 * - Moving the types here would create a circular dependency since the
 *   annotationPatterns module needs to import its own types.
 * - Type-only imports (`export type`) don't create runtime dependencies,
 *   so this cross-layer reference is safe.
 *
 * **Type definitions:**
 * - "immediate": Write operations persist directly to storage (database, file, API)
 * - "deferred": Write operations are in-memory until explicit save operation
 * - "unknown": Cannot determine persistence model
 *
 * @see services/assessment/config/annotationPatterns.ts for implementation
 */
export type {
  PersistenceModel,
  ServerPersistenceContext,
} from "../../services/assessment/config/annotationPatterns";

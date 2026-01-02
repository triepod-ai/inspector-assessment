/**
 * Module Field Validator
 *
 * Validates that assessment module outputs contain the required fields
 * for scoring and display. Catches field name mismatches at runtime.
 *
 * Created to prevent bugs like v1.21.3 where calculateModuleScore()
 * checked for non-existent field name "workingPercentage".
 */

import type {
  FunctionalityAssessment,
  SecurityAssessment,
  DocumentationAssessment,
  ErrorHandlingAssessment,
  UsabilityAssessment,
  MCPSpecComplianceAssessment,
  AUPComplianceAssessment,
  ToolAnnotationAssessment,
  ProhibitedLibrariesAssessment,
  ManifestValidationAssessment,
  PortabilityAssessment,
  ExternalAPIScannerAssessment,
  AuthenticationAssessment,
  TemporalAssessment,
  ResourceAssessment,
  PromptAssessment,
  CrossCapabilitySecurityAssessment,
} from "./assessmentTypes";

/**
 * Field requirements for each module.
 * "required" fields must exist for scoring.
 * "scoringField" is the field used by calculateModuleScore().
 */
export interface ModuleFieldSpec {
  moduleName: string;
  requiredFields: string[];
  scoringField: string | null; // null if uses status-based scoring
  scoringPath?: string; // e.g., "metrics.mcpComplianceScore" for nested fields
}

/**
 * Specifications for all assessment modules.
 * This is the source of truth for field validation.
 */
export const MODULE_FIELD_SPECS: Record<string, ModuleFieldSpec> = {
  functionality: {
    moduleName: "Functionality",
    requiredFields: [
      "totalTools",
      "testedTools",
      "workingTools",
      "coveragePercentage",
      "status",
      "toolResults",
    ],
    scoringField: "coveragePercentage",
  },
  security: {
    moduleName: "Security",
    requiredFields: [
      "promptInjectionTests",
      "vulnerabilities",
      "overallRiskLevel",
      "status",
    ],
    scoringField: "vulnerabilities", // Array - score calculated from length
  },
  documentation: {
    moduleName: "Documentation",
    requiredFields: ["metrics", "status", "recommendations"],
    scoringField: null, // Uses status-based scoring
  },
  errorHandling: {
    moduleName: "Error Handling",
    requiredFields: ["metrics", "status", "recommendations"],
    scoringField: "metrics.mcpComplianceScore",
    scoringPath: "metrics.mcpComplianceScore",
  },
  usability: {
    moduleName: "Usability",
    requiredFields: ["metrics", "status", "recommendations"],
    scoringField: null, // Uses status-based scoring
  },
  mcpSpecCompliance: {
    moduleName: "MCP Spec Compliance",
    requiredFields: [
      "protocolVersion",
      "protocolChecks",
      "status",
      "complianceScore",
    ],
    scoringField: "complianceScore",
  },
  aupCompliance: {
    moduleName: "AUP Compliance",
    requiredFields: ["violations", "scannedLocations", "status"],
    scoringField: "violations", // Array - score calculated from length
  },
  toolAnnotations: {
    moduleName: "Tool Annotations",
    requiredFields: [
      "toolResults",
      "annotatedCount",
      "missingAnnotationsCount",
      "status",
    ],
    scoringField: null, // Uses status-based scoring
  },
  prohibitedLibraries: {
    moduleName: "Prohibited Libraries",
    requiredFields: ["matches", "scannedFiles", "status"],
    scoringField: null, // Uses status-based scoring
  },
  manifestValidation: {
    moduleName: "Manifest Validation",
    requiredFields: ["hasManifest", "validationResults", "status"],
    scoringField: null, // Uses status-based scoring
  },
  portability: {
    moduleName: "Portability",
    requiredFields: ["issues", "scannedFiles", "status"],
    scoringField: null, // Uses status-based scoring
  },
  externalAPIScanner: {
    moduleName: "External API Scanner",
    requiredFields: [
      "detectedAPIs",
      "uniqueServices",
      "scannedFiles",
      "status",
    ],
    scoringField: null, // Uses status-based scoring
  },
  authentication: {
    moduleName: "Authentication",
    requiredFields: [
      "authMethod",
      "appropriateness",
      "detectedPatterns",
      "status",
    ],
    scoringField: null, // Uses status-based scoring
  },
  temporal: {
    moduleName: "Temporal",
    requiredFields: ["toolsTested", "invocationsPerTool", "details", "status"],
    scoringField: null, // Uses status-based scoring
  },
  resources: {
    moduleName: "Resources",
    requiredFields: ["resourcesTested", "results", "status"],
    scoringField: null, // Uses status-based scoring
  },
  prompts: {
    moduleName: "Prompts",
    requiredFields: ["promptsTested", "results", "status"],
    scoringField: null, // Uses status-based scoring
  },
  crossCapability: {
    moduleName: "Cross-Capability",
    requiredFields: ["testsRun", "results", "status"],
    scoringField: null, // Uses status-based scoring
  },
};

/**
 * Result of validating a module output.
 */
export interface ValidationResult {
  valid: boolean;
  moduleName: string;
  missingFields: string[];
  scoringFieldMissing: boolean;
  warnings: string[];
}

/**
 * Get value at a nested path (e.g., "metrics.mcpComplianceScore").
 */
function getNestedValue(obj: unknown, path: string): unknown {
  if (!obj || typeof obj !== "object") return undefined;
  const parts = path.split(".");
  let current: unknown = obj;
  for (const part of parts) {
    if (!current || typeof current !== "object") return undefined;
    current = (current as Record<string, unknown>)[part];
  }
  return current;
}

/**
 * Find similar field names for suggestions.
 */
function findSimilarFields(target: string, available: string[]): string | null {
  // Simple Levenshtein-like matching for typos
  const targetLower = target.toLowerCase();
  for (const field of available) {
    const fieldLower = field.toLowerCase();
    // Check for common typos/variations
    if (fieldLower.includes(targetLower) || targetLower.includes(fieldLower)) {
      return field;
    }
    // Check for percentage vs Percentage confusion
    if (
      targetLower.replace("percentage", "") ===
      fieldLower.replace("percentage", "")
    ) {
      return field;
    }
  }
  return null;
}

/**
 * Validate that a module output contains required fields.
 *
 * @param moduleName - The module key (e.g., "functionality", "security")
 * @param result - The assessment result object from the module
 * @returns Validation result with details on missing fields
 */
export function validateModuleOutput(
  moduleName: string,
  result: unknown,
): ValidationResult {
  const spec = MODULE_FIELD_SPECS[moduleName];
  if (!spec) {
    return {
      valid: false,
      moduleName,
      missingFields: [],
      scoringFieldMissing: false,
      warnings: [`Unknown module: ${moduleName}`],
    };
  }

  const missingFields: string[] = [];
  const warnings: string[] = [];

  if (!result || typeof result !== "object") {
    return {
      valid: false,
      moduleName: spec.moduleName,
      missingFields: spec.requiredFields,
      scoringFieldMissing: spec.scoringField !== null,
      warnings: ["Result is null or not an object"],
    };
  }

  const r = result as Record<string, unknown>;
  const availableFields = Object.keys(r);

  // Check required fields
  for (const field of spec.requiredFields) {
    if (!(field in r)) {
      missingFields.push(field);
      // Try to suggest similar field names
      const similar = findSimilarFields(field, availableFields);
      if (similar) {
        warnings.push(
          `Missing "${field}" - did you mean "${similar}"? (found in result)`,
        );
      }
    }
  }

  // Check scoring field specifically
  let scoringFieldMissing = false;
  if (spec.scoringField !== null) {
    if (spec.scoringPath) {
      // Nested field like "metrics.mcpComplianceScore"
      const value = getNestedValue(result, spec.scoringPath);
      if (value === undefined) {
        scoringFieldMissing = true;
        warnings.push(
          `Scoring field "${spec.scoringPath}" is missing - calculateModuleScore will use fallback`,
        );
      }
    } else {
      // Top-level field
      if (!(spec.scoringField in r)) {
        scoringFieldMissing = true;
        // Try to find similar
        const similar = findSimilarFields(spec.scoringField, availableFields);
        if (similar) {
          warnings.push(
            `Scoring field "${spec.scoringField}" is missing - did you mean "${similar}"?`,
          );
        } else {
          warnings.push(
            `Scoring field "${spec.scoringField}" is missing - calculateModuleScore will use fallback`,
          );
        }
      }
    }
  }

  return {
    valid: missingFields.length === 0 && !scoringFieldMissing,
    moduleName: spec.moduleName,
    missingFields,
    scoringFieldMissing,
    warnings,
  };
}

/**
 * Validate multiple module outputs at once.
 * Useful for validating a complete assessment.
 */
export function validateAllModuleOutputs(
  results: Record<string, unknown>,
): Map<string, ValidationResult> {
  const validations = new Map<string, ValidationResult>();
  for (const [moduleName, result] of Object.entries(results)) {
    if (MODULE_FIELD_SPECS[moduleName]) {
      validations.set(moduleName, validateModuleOutput(moduleName, result));
    }
  }
  return validations;
}

/**
 * Type guards for module outputs.
 * These verify the runtime type matches the expected interface.
 */
export function isFunctionalityAssessment(
  result: unknown,
): result is FunctionalityAssessment {
  const validation = validateModuleOutput("functionality", result);
  return validation.valid;
}

export function isSecurityAssessment(
  result: unknown,
): result is SecurityAssessment {
  const validation = validateModuleOutput("security", result);
  return validation.valid;
}

export function isDocumentationAssessment(
  result: unknown,
): result is DocumentationAssessment {
  const validation = validateModuleOutput("documentation", result);
  return validation.valid;
}

export function isErrorHandlingAssessment(
  result: unknown,
): result is ErrorHandlingAssessment {
  const validation = validateModuleOutput("errorHandling", result);
  return validation.valid;
}

export function isUsabilityAssessment(
  result: unknown,
): result is UsabilityAssessment {
  const validation = validateModuleOutput("usability", result);
  return validation.valid;
}

export function isMCPSpecComplianceAssessment(
  result: unknown,
): result is MCPSpecComplianceAssessment {
  const validation = validateModuleOutput("mcpSpecCompliance", result);
  return validation.valid;
}

export function isAUPComplianceAssessment(
  result: unknown,
): result is AUPComplianceAssessment {
  const validation = validateModuleOutput("aupCompliance", result);
  return validation.valid;
}

export function isToolAnnotationAssessment(
  result: unknown,
): result is ToolAnnotationAssessment {
  const validation = validateModuleOutput("toolAnnotations", result);
  return validation.valid;
}

export function isTemporalAssessment(
  result: unknown,
): result is TemporalAssessment {
  const validation = validateModuleOutput("temporal", result);
  return validation.valid;
}

export function isResourceAssessment(
  result: unknown,
): result is ResourceAssessment {
  const validation = validateModuleOutput("resources", result);
  return validation.valid;
}

export function isPromptAssessment(
  result: unknown,
): result is PromptAssessment {
  const validation = validateModuleOutput("prompts", result);
  return validation.valid;
}

export function isCrossCapabilityAssessment(
  result: unknown,
): result is CrossCapabilitySecurityAssessment {
  const validation = validateModuleOutput("crossCapability", result);
  return validation.valid;
}

export function isProhibitedLibrariesAssessment(
  result: unknown,
): result is ProhibitedLibrariesAssessment {
  const validation = validateModuleOutput("prohibitedLibraries", result);
  return validation.valid;
}

export function isManifestValidationAssessment(
  result: unknown,
): result is ManifestValidationAssessment {
  const validation = validateModuleOutput("manifestValidation", result);
  return validation.valid;
}

export function isPortabilityAssessment(
  result: unknown,
): result is PortabilityAssessment {
  const validation = validateModuleOutput("portability", result);
  return validation.valid;
}

export function isExternalAPIScannerAssessment(
  result: unknown,
): result is ExternalAPIScannerAssessment {
  const validation = validateModuleOutput("externalAPIScanner", result);
  return validation.valid;
}

export function isAuthenticationAssessment(
  result: unknown,
): result is AuthenticationAssessment {
  const validation = validateModuleOutput("authentication", result);
  return validation.valid;
}

/**
 * Assessment Orchestrator Helpers
 *
 * Pure functions extracted from AssessmentOrchestrator for testability.
 * These functions handle:
 * - AUP violation enrichment for JSONL events
 * - Module progress/started event emission
 * - Overall status determination
 * - Summary and recommendations generation
 *
 * @internal
 * @module orchestratorHelpers
 */

import {
  MCPDirectoryAssessment,
  AssessmentStatus,
} from "@/lib/assessmentTypes";

// Import score calculation helpers from shared module
import {
  calculateModuleScore,
  normalizeModuleKey,
  INSPECTOR_VERSION,
  SCHEMA_VERSION,
} from "@/lib/moduleScoring";

// Track module start times for duration calculation
export const moduleStartTimes: Map<string, number> = new Map();

/**
 * Emit module_started event and track start time for duration calculation.
 * Emits JSONL to stderr with version field for consistent event structure.
 */
export function emitModuleStartedEvent(
  moduleName: string,
  estimatedTests: number,
  toolCount: number,
): void {
  const moduleKey = normalizeModuleKey(moduleName);
  moduleStartTimes.set(moduleKey, Date.now());

  // Emit JSONL to stderr with version and schemaVersion fields
  console.error(
    JSON.stringify({
      event: "module_started",
      module: moduleKey,
      estimatedTests,
      toolCount,
      version: INSPECTOR_VERSION,
      schemaVersion: SCHEMA_VERSION,
    }),
  );
}

/**
 * Emit module_complete event with score and duration.
 * Uses shared score calculator for consistent scoring logic.
 * For AUP module, includes enriched violation data for Claude analysis.
 */
export function emitModuleProgress(
  moduleName: string,
  status: string,
  result: unknown,
  testsRun: number = 0,
): void {
  // Calculate score using shared helper
  const score = calculateModuleScore(result);

  // Don't emit events for skipped modules (null score means module wasn't run)
  if (score === null) return;

  const moduleKey = normalizeModuleKey(moduleName);

  // Calculate duration from module start time
  const startTime = moduleStartTimes.get(moduleKey);
  const duration = startTime ? Date.now() - startTime : 0;
  moduleStartTimes.delete(moduleKey);

  // Build base event
  const event: Record<string, unknown> = {
    event: "module_complete",
    module: moduleKey,
    status,
    score,
    testsRun,
    duration,
    version: INSPECTOR_VERSION,
    schemaVersion: SCHEMA_VERSION,
  };

  // Add AUP enrichment when module is AUP
  if (moduleKey === "aup" && result) {
    const aupEnrichment = buildAUPEnrichment(result);
    Object.assign(event, aupEnrichment);
  }

  // Add authentication enrichment when module is authentication (Issue #195)
  if (moduleKey === "authentication" && result) {
    const authEnrichment = buildAuthEnrichment(result);
    Object.assign(event, authEnrichment);
  }

  // Add resources enrichment when module is resources (Issue #196)
  if (moduleKey === "resources" && result) {
    const resourceEnrichment = buildResourceEnrichment(result);
    Object.assign(event, resourceEnrichment);
  }

  // Add prompts enrichment when module is prompts (Issue #197)
  if (moduleKey === "prompts" && result) {
    const promptEnrichment = buildPromptEnrichment(result);
    Object.assign(event, promptEnrichment);
  }

  // Add prohibited libraries enrichment when module is prohibitedLibraries (Issue #198)
  if (moduleKey === "prohibitedLibraries" && result) {
    const librariesEnrichment = buildProhibitedLibrariesEnrichment(result);
    Object.assign(event, librariesEnrichment);
  }

  // Add manifest validation enrichment when module is manifestValidation (Issue #199)
  if (moduleKey === "manifestValidation" && result) {
    const manifestEnrichment = buildManifestEnrichment(result);
    Object.assign(event, manifestEnrichment);
  }

  // Emit JSONL to stderr with version and schemaVersion fields
  console.error(JSON.stringify(event));
}

/**
 * Build AUP enrichment data from an AUP compliance assessment result.
 * Samples violations prioritizing by severity (CRITICAL > HIGH > MEDIUM).
 * Issue #194: Now includes toolInventory, patternCoverage, and flagsForReview
 * from the enrichmentData field for Stage B Claude validation.
 */
export function buildAUPEnrichment(
  aupResult: {
    violations?: Array<{
      severity: string;
      category: string;
      categoryName?: string;
      matchedText?: string;
      location?: string;
      confidence?: string;
    }>;
    scannedLocations?: {
      toolNames: boolean;
      toolDescriptions: boolean;
      readme: boolean;
      sourceCode: boolean;
    };
    highRiskDomains?: string[];
    enrichmentData?: {
      toolInventory?: Array<{
        name: string;
        description: string;
        capabilities: string[];
      }>;
      patternCoverage?: {
        totalPatterns: number;
        categoriesCovered: string[];
        samplePatterns: string[];
        severityBreakdown: {
          critical: number;
          high: number;
          medium: number;
          flag: number;
        };
      };
      flagsForReview?: Array<{
        toolName: string;
        reason: string;
        capabilities: string[];
        confidence: string;
      }>;
    };
  },
  maxSamples: number = 10,
): {
  violationsSample: Array<{
    category: string;
    categoryName: string;
    severity: string;
    matchedText: string;
    location: string;
    confidence: string;
  }>;
  samplingNote: string;
  violationMetrics: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    byCategory: Record<string, number>;
  };
  scannedLocations: {
    toolNames: boolean;
    toolDescriptions: boolean;
    readme: boolean;
    sourceCode: boolean;
  };
  highRiskDomains: string[];
  toolInventory?: Array<{
    name: string;
    description: string;
    capabilities: string[];
  }>;
  patternCoverage?: {
    totalPatterns: number;
    categoriesCovered: string[];
    samplePatterns: string[];
    severityBreakdown: {
      critical: number;
      high: number;
      medium: number;
      flag: number;
    };
  };
  flagsForReview?: Array<{
    toolName: string;
    reason: string;
    capabilities: string[];
    confidence: string;
  }>;
} {
  const violations = aupResult.violations || [];

  // Calculate metrics
  const metrics = {
    total: violations.length,
    critical: violations.filter((v) => v.severity === "CRITICAL").length,
    high: violations.filter((v) => v.severity === "HIGH").length,
    medium: violations.filter((v) => v.severity === "MEDIUM").length,
    byCategory: {} as Record<string, number>,
  };

  // Count by category
  for (const v of violations) {
    metrics.byCategory[v.category] = (metrics.byCategory[v.category] || 0) + 1;
  }

  // Sample violations prioritizing by severity
  const sampled: Array<{
    category: string;
    categoryName: string;
    severity: string;
    matchedText: string;
    location: string;
    confidence: string;
  }> = [];
  const severityOrder = ["CRITICAL", "HIGH", "MEDIUM"];

  for (const severity of severityOrder) {
    if (sampled.length >= maxSamples) break;
    const bySeverity = violations.filter((v) => v.severity === severity);
    for (const v of bySeverity) {
      if (sampled.length >= maxSamples) break;
      sampled.push({
        category: v.category,
        categoryName: v.categoryName || "",
        severity: v.severity,
        matchedText: v.matchedText || "",
        location: v.location || "",
        confidence: v.confidence || "",
      });
    }
  }

  // Build sampling note
  let samplingNote = "";
  if (violations.length === 0) {
    samplingNote = "No violations detected.";
  } else if (violations.length <= maxSamples) {
    samplingNote = `All ${violations.length} violation(s) included.`;
  } else {
    samplingNote = `Sampled ${sampled.length} of ${violations.length} violations, prioritized by severity (CRITICAL > HIGH > MEDIUM).`;
  }

  // Include enrichmentData fields for Stage B Claude validation (Issue #194)
  const enrichmentData = aupResult.enrichmentData;

  return {
    violationsSample: sampled,
    samplingNote,
    violationMetrics: metrics,
    scannedLocations: aupResult.scannedLocations || {
      toolNames: false,
      toolDescriptions: false,
      readme: false,
      sourceCode: false,
    },
    highRiskDomains: (aupResult.highRiskDomains || []).slice(0, 10), // Limit domains for JSONL event size
    // Issue #194: Include enrichment data for Claude validation
    toolInventory: enrichmentData?.toolInventory?.slice(0, 50), // 50 tools: balance coverage vs token cost (~500-1000 tokens)
    patternCoverage: enrichmentData?.patternCoverage,
    flagsForReview: enrichmentData?.flagsForReview,
  };
}

/**
 * Build authentication enrichment data from an authentication assessment result.
 * Issue #195: Provides context for Stage B Claude validation of auth findings.
 *
 * Note: Using inline parameter type instead of AuthenticationAssessment import
 * because this is called with `result: unknown` from emitModuleProgress().
 * TypeScript structural typing ensures compatibility while avoiding type assertions.
 */
export function buildAuthEnrichment(authResult: {
  authMethod?: string;
  hasLocalDependencies?: boolean;
  transportType?: string;
  appropriateness?: {
    isAppropriate: boolean;
    concerns: string[];
    explanation: string;
  };
  transportSecurity?: {
    usesTLS: boolean;
    tlsEnforced: boolean;
    hasInsecurePatterns: boolean;
    insecurePatterns: string[];
    corsConfigured: boolean;
    corsPermissive: boolean;
    sessionSecure: boolean;
  };
  authConfigAnalysis?: {
    totalFindings: number;
    hasHighSeverity: boolean;
    envDependentAuthCount: number;
    failOpenPatternCount: number;
    failOpenLogicCount: number;
    devModeWarningCount: number;
    hardcodedSecretCount: number;
  };
  enrichmentData?: {
    toolInventory?: Array<{
      name: string;
      description: string;
      authCapabilities: string[];
      isSensitive: boolean;
    }>;
    oauthPatternCoverage?: {
      totalPatterns: number;
      matchedPatterns: string[];
      flowType: string;
      pkceDetected: boolean;
    };
    apiKeyPatternCoverage?: {
      totalPatterns: number;
      matchedPatterns: string[];
      envVarManaged: boolean;
    };
    transportSecurity?: {
      transportType: string;
      tlsEnforced: boolean;
      corsConfigured: boolean;
      sessionSecure: boolean;
      insecurePatternCount: number;
      securePatternCount: number;
    };
    flagsForReview?: Array<{
      toolName: string;
      reason: string;
      capabilities: string[];
      riskLevel: string;
    }>;
    metrics?: {
      totalTools: number;
      authSensitiveTools: number;
      oauthIndicators: number;
      apiKeyIndicators: number;
      localDependencyIndicators: number;
    };
  };
}): {
  authMethod: string;
  authMetrics: {
    hasLocalDependencies: boolean;
    tlsEnforced: boolean;
    corsConfigured: boolean;
    sessionSecure: boolean;
    authConfigFindings: number;
    hasHighSeverityFindings: boolean;
  };
  oauthCoverage?: {
    totalPatterns: number;
    matchedPatterns: string[];
    flowType: string;
    pkceDetected: boolean;
  };
  apiKeyCoverage?: {
    totalPatterns: number;
    matchedPatterns: string[];
    envVarManaged: boolean;
  };
  concerns: string[];
  toolInventory?: Array<{
    name: string;
    description: string;
    authCapabilities: string[];
    isSensitive: boolean;
  }>;
  flagsForReview?: Array<{
    toolName: string;
    reason: string;
    capabilities: string[];
    riskLevel: string;
  }>;
} {
  const enrichmentData = authResult.enrichmentData;
  const authConfigAnalysis = authResult.authConfigAnalysis;
  const transportSecurity = authResult.transportSecurity;

  return {
    authMethod: authResult.authMethod || "unknown",
    authMetrics: {
      hasLocalDependencies: authResult.hasLocalDependencies ?? false,
      tlsEnforced: transportSecurity?.tlsEnforced ?? false,
      corsConfigured: transportSecurity?.corsConfigured ?? false,
      sessionSecure: transportSecurity?.sessionSecure ?? false,
      authConfigFindings: authConfigAnalysis?.totalFindings ?? 0,
      hasHighSeverityFindings: authConfigAnalysis?.hasHighSeverity ?? false,
    },
    oauthCoverage: enrichmentData?.oauthPatternCoverage,
    apiKeyCoverage: enrichmentData?.apiKeyPatternCoverage,
    concerns: authResult.appropriateness?.concerns || [],
    // Issue #195: Include enrichment data for Stage B Claude validation
    toolInventory: enrichmentData?.toolInventory?.slice(0, 50), // 50 tools: balance coverage vs token cost (~500-1000 tokens)
    flagsForReview: enrichmentData?.flagsForReview,
  };
}

/**
 * Build resource enrichment data from a resource assessment result.
 * Issue #196: Provides context for Stage B Claude validation of resource findings.
 */
export function buildResourceEnrichment(resourceResult: {
  resourcesTested?: number;
  resourceTemplatesTested?: number;
  accessibleResources?: number;
  securityIssuesFound?: number;
  pathTraversalVulnerabilities?: number;
  sensitiveDataExposures?: number;
  promptInjectionVulnerabilities?: number;
  blobDosVulnerabilities?: number;
  polyglotVulnerabilities?: number;
  mimeValidationFailures?: number;
  enrichmentData?: {
    resourceInventory?: Array<{
      uri: string;
      name?: string;
      mimeType?: string;
      resourceType: string;
      securityFlags: string[];
      dataClassification: string;
    }>;
    patternCoverage?: {
      sensitiveUriPatterns: number;
      pathTraversalPayloads: number;
      uriInjectionPayloads: number;
      hiddenResourcePatterns: number;
      samplePatterns: string[];
    };
    flagsForReview?: Array<{
      resourceUri: string;
      reason: string;
      flags: string[];
      riskLevel: string;
    }>;
    metrics?: {
      totalResources: number;
      totalTemplates: number;
      sensitiveResources: number;
      accessibleResources: number;
      vulnerableResources: number;
    };
  };
}): {
  resourceMetrics: {
    totalResources: number;
    totalTemplates: number;
    accessibleResources: number;
    vulnerableResources: number;
    pathTraversalVulnerabilities: number;
    sensitiveDataExposures: number;
    promptInjectionVulnerabilities: number;
  };
  patternCoverage?: {
    sensitiveUriPatterns: number;
    pathTraversalPayloads: number;
    uriInjectionPayloads: number;
    hiddenResourcePatterns: number;
    samplePatterns: string[];
  };
  resourceInventory?: Array<{
    uri: string;
    name?: string;
    mimeType?: string;
    resourceType: string;
    securityFlags: string[];
    dataClassification: string;
  }>;
  flagsForReview?: Array<{
    resourceUri: string;
    reason: string;
    flags: string[];
    riskLevel: string;
  }>;
} {
  const enrichmentData = resourceResult.enrichmentData;

  return {
    resourceMetrics: {
      totalResources: resourceResult.resourcesTested ?? 0,
      totalTemplates: resourceResult.resourceTemplatesTested ?? 0,
      accessibleResources: resourceResult.accessibleResources ?? 0,
      vulnerableResources:
        (resourceResult.pathTraversalVulnerabilities ?? 0) +
        (resourceResult.sensitiveDataExposures ?? 0) +
        (resourceResult.promptInjectionVulnerabilities ?? 0) +
        (resourceResult.blobDosVulnerabilities ?? 0) +
        (resourceResult.polyglotVulnerabilities ?? 0),
      pathTraversalVulnerabilities:
        resourceResult.pathTraversalVulnerabilities ?? 0,
      sensitiveDataExposures: resourceResult.sensitiveDataExposures ?? 0,
      promptInjectionVulnerabilities:
        resourceResult.promptInjectionVulnerabilities ?? 0,
    },
    patternCoverage: enrichmentData?.patternCoverage,
    // Issue #196: Include enrichment data for Stage B Claude validation
    resourceInventory: enrichmentData?.resourceInventory?.slice(0, 50), // 50 resources: balance coverage vs token cost (~500-1000 tokens)
    flagsForReview: enrichmentData?.flagsForReview,
  };
}

/**
 * Build prompt enrichment data from a prompt assessment result.
 * Issue #197: Provides context for Stage B Claude validation of prompt findings.
 */
export function buildPromptEnrichment(promptResult: {
  promptsTested?: number;
  aupViolations?: number;
  injectionVulnerabilities?: number;
  argumentValidationIssues?: number;
  enrichmentData?: {
    promptInventory?: Array<{
      name: string;
      description?: string;
      argumentCount: number;
      requiredArgs: string[];
      optionalArgs: string[];
      category: string;
      securityFlags: string[];
    }>;
    patternCoverage?: {
      injectionPatternsChecked: number;
      aupPatternsChecked: number;
      argumentValidationChecks: number;
      samplePatterns: string[];
    };
    flagsForReview?: Array<{
      promptName: string;
      reason: string;
      flags: string[];
      riskLevel: string;
    }>;
    metrics?: {
      totalPrompts: number;
      aupViolations: number;
      injectionVulnerabilities: number;
      argumentValidationIssues: number;
      promptsWithDynamicContent: number;
    };
  };
}): {
  promptMetrics: {
    totalPrompts: number;
    aupViolations: number;
    injectionVulnerabilities: number;
    argumentValidationIssues: number;
  };
  patternCoverage?: {
    injectionPatternsChecked: number;
    aupPatternsChecked: number;
    argumentValidationChecks: number;
    samplePatterns: string[];
  };
  promptInventory?: Array<{
    name: string;
    description?: string;
    argumentCount: number;
    requiredArgs: string[];
    optionalArgs: string[];
    category: string;
    securityFlags: string[];
  }>;
  flagsForReview?: Array<{
    promptName: string;
    reason: string;
    flags: string[];
    riskLevel: string;
  }>;
} {
  const enrichmentData = promptResult.enrichmentData;

  return {
    promptMetrics: {
      totalPrompts: promptResult.promptsTested ?? 0,
      aupViolations: promptResult.aupViolations ?? 0,
      injectionVulnerabilities: promptResult.injectionVulnerabilities ?? 0,
      argumentValidationIssues: promptResult.argumentValidationIssues ?? 0,
    },
    patternCoverage: enrichmentData?.patternCoverage,
    // Issue #197: Include enrichment data for Stage B Claude validation
    promptInventory: enrichmentData?.promptInventory?.slice(0, 50), // 50 prompts: balance coverage vs token cost (~500-1000 tokens)
    flagsForReview: enrichmentData?.flagsForReview,
  };
}

/**
 * Build prohibited libraries enrichment data from a prohibited libraries assessment result.
 * Issue #198: Provides context for Stage B Claude validation of library findings.
 */
export function buildProhibitedLibrariesEnrichment(librariesResult: {
  matches?: Array<{
    name: string;
    category: string;
    severity: string;
    location: string;
    usageStatus?: string;
    importCount?: number;
  }>;
  scannedFiles?: string[];
  hasFinancialLibraries?: boolean;
  hasMediaLibraries?: boolean;
  enrichmentData?: {
    libraryInventory?: Array<{
      name: string;
      category: string;
      severity: string;
      location: string;
      usageStatus: string;
      importCount: number;
      importFiles: string[];
      policyReference: string;
    }>;
    policyCoverage?: {
      totalProhibitedLibraries: number;
      scannedFiles: number;
      policiesChecked: string[];
      sampleLibraries: string[];
    };
    flagsForReview?: Array<{
      libraryName: string;
      reason: string;
      flags: string[];
      riskLevel: string;
    }>;
    metrics?: {
      totalMatches: number;
      blockingCount: number;
      highCount: number;
      mediumCount: number;
      activeCount: number;
      unusedCount: number;
      hasFinancialLibraries: boolean;
      hasMediaLibraries: boolean;
    };
  };
}): {
  libraryMetrics: {
    totalMatches: number;
    blockingCount: number;
    highCount: number;
    mediumCount: number;
    activeCount: number;
    unusedCount: number;
    hasFinancialLibraries: boolean;
    hasMediaLibraries: boolean;
  };
  policyCoverage?: {
    totalProhibitedLibraries: number;
    scannedFiles: number;
    policiesChecked: string[];
    sampleLibraries: string[];
  };
  libraryInventory?: Array<{
    name: string;
    category: string;
    severity: string;
    location: string;
    usageStatus: string;
    importCount: number;
    importFiles: string[];
    policyReference: string;
  }>;
  flagsForReview?: Array<{
    libraryName: string;
    reason: string;
    flags: string[];
    riskLevel: string;
  }>;
} {
  const enrichmentData = librariesResult.enrichmentData;
  const matches = librariesResult.matches || [];

  // Calculate metrics from matches if enrichmentData not available
  const blockingCount =
    enrichmentData?.metrics?.blockingCount ??
    matches.filter((m) => m.severity === "BLOCKING").length;
  const highCount =
    enrichmentData?.metrics?.highCount ??
    matches.filter((m) => m.severity === "HIGH").length;
  const mediumCount =
    enrichmentData?.metrics?.mediumCount ??
    matches.filter((m) => m.severity === "MEDIUM").length;
  const activeCount =
    enrichmentData?.metrics?.activeCount ??
    matches.filter((m) => m.usageStatus === "ACTIVE").length;
  const unusedCount =
    enrichmentData?.metrics?.unusedCount ??
    matches.filter((m) => m.usageStatus === "UNUSED").length;

  return {
    libraryMetrics: {
      totalMatches: enrichmentData?.metrics?.totalMatches ?? matches.length,
      blockingCount,
      highCount,
      mediumCount,
      activeCount,
      unusedCount,
      hasFinancialLibraries:
        enrichmentData?.metrics?.hasFinancialLibraries ??
        librariesResult.hasFinancialLibraries ??
        false,
      hasMediaLibraries:
        enrichmentData?.metrics?.hasMediaLibraries ??
        librariesResult.hasMediaLibraries ??
        false,
    },
    policyCoverage: enrichmentData?.policyCoverage,
    // Issue #198: Include enrichment data for Stage B Claude validation
    libraryInventory: enrichmentData?.libraryInventory?.slice(0, 50), // 50 libraries: balance coverage vs token cost (~500-1000 tokens)
    flagsForReview: enrichmentData?.flagsForReview,
  };
}

/**
 * Build manifest validation enrichment data from a manifest validation assessment result.
 * Issue #199: Provides context for Stage B Claude validation of manifest findings.
 */
export function buildManifestEnrichment(manifestResult: {
  hasManifest?: boolean;
  manifestVersion?: string;
  hasRequiredFields?: boolean;
  hasIcon?: boolean;
  missingFields?: string[];
  validationResults?: Array<{
    field: string;
    valid: boolean;
    value?: unknown;
    issue?: string;
    severity: "ERROR" | "WARNING" | "INFO";
  }>;
  privacyPolicies?: {
    declared: string[];
    validationResults: Array<{
      url: string;
      accessible: boolean;
      error?: string;
    }>;
    allAccessible: boolean;
  };
  contactInfo?: {
    email?: string;
    url?: string;
    name?: string;
    source: string;
  };
  enrichmentData?: {
    fieldInventory?: Array<{
      field: string;
      valid: boolean;
      value?: unknown;
      issue?: string;
      severity: string;
      category: string;
    }>;
    fieldCoverage?: {
      totalRequired: number;
      requiredPresent: number;
      recommendedChecked: number;
      sampleFields: string[];
      policiesChecked: string[];
    };
    flagsForReview?: Array<{
      field: string;
      reason: string;
      flags: string[];
      riskLevel: string;
    }>;
    metrics?: {
      totalChecks: number;
      passedChecks: number;
      errorCount: number;
      warningCount: number;
      hasManifest: boolean;
      hasRequiredFields: boolean;
      hasIcon: boolean;
      hasContactInfo: boolean;
      privacyPoliciesAccessible: boolean;
      toolsMatch: boolean;
    };
  };
}): {
  manifestMetrics: {
    hasManifest: boolean;
    hasRequiredFields: boolean;
    hasIcon: boolean;
    hasContactInfo: boolean;
    privacyPoliciesAccessible: boolean;
    totalChecks: number;
    passedChecks: number;
    errorCount: number;
    warningCount: number;
  };
  fieldCoverage?: {
    totalRequired: number;
    requiredPresent: number;
    recommendedChecked: number;
    sampleFields: string[];
    policiesChecked: string[];
  };
  fieldInventory?: Array<{
    field: string;
    valid: boolean;
    value?: unknown;
    issue?: string;
    severity: string;
    category: string;
  }>;
  flagsForReview?: Array<{
    field: string;
    reason: string;
    flags: string[];
    riskLevel: string;
  }>;
} {
  const enrichmentData = manifestResult.enrichmentData;
  const validationResults = manifestResult.validationResults || [];

  // Calculate metrics from validation results if enrichmentData not available
  const errorCount =
    enrichmentData?.metrics?.errorCount ??
    validationResults.filter((r) => !r.valid && r.severity === "ERROR").length;
  const warningCount =
    enrichmentData?.metrics?.warningCount ??
    validationResults.filter((r) => r.severity === "WARNING" && r.issue).length;
  const passedChecks =
    enrichmentData?.metrics?.passedChecks ??
    validationResults.filter((r) => r.valid).length;

  return {
    manifestMetrics: {
      hasManifest:
        enrichmentData?.metrics?.hasManifest ??
        manifestResult.hasManifest ??
        false,
      hasRequiredFields:
        enrichmentData?.metrics?.hasRequiredFields ??
        manifestResult.hasRequiredFields ??
        false,
      hasIcon:
        enrichmentData?.metrics?.hasIcon ?? manifestResult.hasIcon ?? false,
      hasContactInfo:
        enrichmentData?.metrics?.hasContactInfo ??
        Boolean(manifestResult.contactInfo),
      privacyPoliciesAccessible:
        enrichmentData?.metrics?.privacyPoliciesAccessible ??
        manifestResult.privacyPolicies?.allAccessible ??
        true,
      totalChecks:
        enrichmentData?.metrics?.totalChecks ?? validationResults.length,
      passedChecks,
      errorCount,
      warningCount,
    },
    fieldCoverage: enrichmentData?.fieldCoverage,
    // Issue #199: Include enrichment data for Stage B Claude validation
    fieldInventory: enrichmentData?.fieldInventory?.slice(0, 50), // 50 fields: balance coverage vs token cost (~500-1000 tokens)
    flagsForReview: enrichmentData?.flagsForReview,
  };
}

/**
 * Determine overall status from assessment results.
 * Priority: FAIL > NEED_MORE_INFO > PASS
 */
export function determineOverallStatus(
  results: Partial<MCPDirectoryAssessment>,
): AssessmentStatus {
  const statuses: AssessmentStatus[] = [];

  // Collect all statuses from assessment results
  Object.values(results).forEach((assessment) => {
    if (
      assessment &&
      typeof assessment === "object" &&
      "status" in assessment
    ) {
      statuses.push(assessment.status as AssessmentStatus);
    }
  });

  // If any critical category fails, overall fails
  if (statuses.includes("FAIL")) return "FAIL";

  // If any category needs more info, overall needs more info
  if (statuses.includes("NEED_MORE_INFO")) return "NEED_MORE_INFO";

  // All must pass for overall pass
  return "PASS";
}

/**
 * Generate summary text from assessment results.
 */
export function generateSummary(
  results: Partial<MCPDirectoryAssessment>,
): string {
  const parts: string[] = [];
  const totalCategories = Object.keys(results).length;
  const passedCategories = Object.values(results).filter(
    (r) => r && typeof r === "object" && "status" in r && r.status === "PASS",
  ).length;

  parts.push(
    `Assessment complete: ${passedCategories}/${totalCategories} categories passed.`,
  );

  // Add key findings - use type assertions for optional properties
  const security = results.security as
    | { vulnerabilities?: string[] }
    | undefined;
  if (security?.vulnerabilities?.length) {
    parts.push(
      `Found ${security.vulnerabilities.length} security vulnerabilities.`,
    );
  }

  const functionality = results.functionality as
    | { brokenTools?: string[] }
    | undefined;
  if (functionality?.brokenTools?.length) {
    parts.push(
      `${functionality.brokenTools.length} tools are not functioning correctly.`,
    );
  }

  // New assessor findings
  const aupCompliance = results.aupCompliance as
    | { violations?: Array<{ severity: string }> }
    | undefined;
  if (aupCompliance?.violations?.length) {
    const criticalCount = aupCompliance.violations.filter(
      (v) => v.severity === "CRITICAL",
    ).length;
    if (criticalCount > 0) {
      parts.push(`CRITICAL: ${criticalCount} AUP violation(s) detected.`);
    } else {
      parts.push(
        `${aupCompliance.violations.length} AUP item(s) flagged for review.`,
      );
    }
  }

  const toolAnnotations = results.toolAnnotations as
    | { missingAnnotationsCount?: number }
    | undefined;
  if (toolAnnotations?.missingAnnotationsCount) {
    parts.push(
      `${toolAnnotations.missingAnnotationsCount} tools missing annotations.`,
    );
  }

  const prohibitedLibraries = results.prohibitedLibraries as
    | { matches?: Array<{ severity: string }> }
    | undefined;
  if (prohibitedLibraries?.matches?.length) {
    const blockingCount = prohibitedLibraries.matches.filter(
      (m) => m.severity === "BLOCKING",
    ).length;
    if (blockingCount > 0) {
      parts.push(
        `BLOCKING: ${blockingCount} prohibited library/libraries detected.`,
      );
    }
  }

  const portability = results.portability as
    | { usesBundleRoot?: boolean }
    | undefined;
  if (portability?.usesBundleRoot) {
    parts.push("Uses ${BUNDLE_ROOT} anti-pattern.");
  }

  return parts.join(" ");
}

/**
 * Generate recommendations from assessment results.
 * Aggregates, deduplicates, and limits to 10 recommendations.
 */
export function generateRecommendations(
  results: Partial<MCPDirectoryAssessment>,
): string[] {
  const recommendations: string[] = [];

  // Aggregate recommendations from all assessments
  Object.values(results).forEach((assessment) => {
    if (
      assessment &&
      typeof assessment === "object" &&
      "recommendations" in assessment &&
      Array.isArray(assessment.recommendations)
    ) {
      recommendations.push(...assessment.recommendations);
    }
  });

  // De-duplicate and prioritize
  return [...new Set(recommendations)].slice(0, 10);
}

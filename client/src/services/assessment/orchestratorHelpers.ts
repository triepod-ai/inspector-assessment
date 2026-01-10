/**
 * Assessment Orchestrator Helpers
 *
 * Pure functions extracted from AssessmentOrchestrator for testability.
 * These functions handle:
 * - AUP violation enrichment for JSONL events
 * - Module progress/started event emission
 * - Overall status determination
 * - Summary and recommendations generation
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

  // Emit JSONL to stderr with version and schemaVersion fields
  console.error(JSON.stringify(event));
}

/**
 * Build AUP enrichment data from an AUP compliance assessment result.
 * Samples violations prioritizing by severity (CRITICAL > HIGH > MEDIUM).
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
    highRiskDomains: (aupResult.highRiskDomains || []).slice(0, 10),
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

/**
 * Resource Result Builder Module
 *
 * Pure functions for determining resource assessment status, generating
 * explanations, and building recommendations based on test results.
 *
 * @module assessment/resources/resultBuilder
 * @since v1.44.0 (Issue #180 - ResourceAssessor Modularization)
 */

import {
  ResourceTestResult,
  AssessmentStatus,
  ResourceAssessment,
} from "@/lib/assessmentTypes";

/**
 * Determine the overall status of the resource assessment
 */
export function determineResourceStatus(
  pathTraversalVulnerabilities: number,
  sensitiveDataExposures: number,
  promptInjectionVulnerabilities: number,
  blobDosVulnerabilities: number,
  polyglotVulnerabilities: number,
  mimeValidationFailures: number,
  securityIssuesFound: number,
  totalResources: number,
): AssessmentStatus {
  // Critical failures
  if (pathTraversalVulnerabilities > 0) return "FAIL";
  if (sensitiveDataExposures > 0) return "FAIL";
  if (promptInjectionVulnerabilities > 0) return "FAIL";
  // Issue #127, Challenge #24: Binary resource vulnerabilities
  if (blobDosVulnerabilities > 0) return "FAIL";
  if (polyglotVulnerabilities > 0) return "FAIL";

  // Moderate issues
  if (mimeValidationFailures > 0) return "NEED_MORE_INFO";
  if (securityIssuesFound > 0) return "NEED_MORE_INFO";

  // No resources tested
  if (totalResources === 0) return "PASS";

  return "PASS";
}

/**
 * Generate a human-readable explanation of the assessment results
 */
export function generateExplanation(
  results: ResourceTestResult[],
  pathTraversalVulnerabilities: number,
  sensitiveDataExposures: number,
  promptInjectionVulnerabilities: number,
  blobDosVulnerabilities: number,
  polyglotVulnerabilities: number,
  mimeValidationFailures: number,
): string {
  const parts: string[] = [];

  parts.push(`Tested ${results.length} resource(s).`);

  if (pathTraversalVulnerabilities > 0) {
    parts.push(
      `CRITICAL: ${pathTraversalVulnerabilities} path traversal vulnerability(ies) detected.`,
    );
  }

  if (sensitiveDataExposures > 0) {
    parts.push(
      `WARNING: ${sensitiveDataExposures} resource(s) may expose sensitive data.`,
    );
  }

  if (promptInjectionVulnerabilities > 0) {
    parts.push(
      `CRITICAL: ${promptInjectionVulnerabilities} resource(s) contain prompt injection patterns.`,
    );
  }

  // Issue #127, Challenge #24: Binary resource vulnerability explanations
  if (blobDosVulnerabilities > 0) {
    parts.push(
      `CRITICAL: ${blobDosVulnerabilities} blob DoS vulnerability(ies) detected (arbitrary size acceptance).`,
    );
  }

  if (polyglotVulnerabilities > 0) {
    parts.push(
      `CRITICAL: ${polyglotVulnerabilities} polyglot file vulnerability(ies) detected (dual-format injection).`,
    );
  }

  if (mimeValidationFailures > 0) {
    parts.push(
      `WARNING: ${mimeValidationFailures} MIME type validation failure(s) detected.`,
    );
  }

  const accessibleCount = results.filter((r) => r.accessible).length;
  if (accessibleCount > 0) {
    parts.push(`${accessibleCount} resource(s) are accessible.`);
  }

  return parts.join(" ");
}

/**
 * Generate actionable recommendations based on test results
 */
export function generateRecommendations(
  results: ResourceTestResult[],
): string[] {
  const recommendations: string[] = [];

  // Path traversal recommendations
  const pathTraversalResults = results.filter((r) => r.pathTraversalVulnerable);
  if (pathTraversalResults.length > 0) {
    recommendations.push(
      "CRITICAL: Implement path validation to prevent path traversal attacks. Normalize paths and validate against allowed directories.",
    );
  }

  // Sensitive data recommendations
  const sensitiveResults = results.filter((r) => r.sensitiveDataExposed);
  if (sensitiveResults.length > 0) {
    recommendations.push(
      "Review resources for sensitive data exposure. Remove or restrict access to resources containing credentials, keys, or sensitive configuration.",
    );
  }

  // Prompt injection recommendations
  const promptInjectionResults = results.filter(
    (r) => r.promptInjectionDetected,
  );
  if (promptInjectionResults.length > 0) {
    recommendations.push(
      "CRITICAL: Resource content contains prompt injection patterns that could manipulate LLM behavior. Sanitize resource content or restrict access to untrusted resources.",
    );
    // List specific patterns found
    const allPatterns = new Set<string>();
    for (const r of promptInjectionResults) {
      for (const pattern of r.promptInjectionPatterns) {
        allPatterns.add(pattern);
      }
    }
    if (allPatterns.size > 0) {
      recommendations.push(
        `Detected patterns: ${Array.from(allPatterns).join(", ")}`,
      );
    }
  }

  // Invalid URI recommendations
  const invalidUriResults = results.filter((r) => !r.validUri);
  if (invalidUriResults.length > 0) {
    recommendations.push(
      "Fix invalid resource URIs to ensure proper URI format compliance.",
    );
  }

  // Inaccessible resource recommendations
  const inaccessibleResults = results.filter(
    (r) => r.tested && !r.accessible && !r.pathTraversalVulnerable,
  );
  if (inaccessibleResults.length > 0) {
    recommendations.push(
      `${inaccessibleResults.length} declared resource(s) are not accessible. Verify resource paths and permissions.`,
    );
  }

  // Issue #127, Challenge #24: Blob DoS recommendations
  const blobDosResults = results.filter(
    (r) =>
      r.blobDosTested &&
      r.blobDosRiskLevel &&
      ["HIGH", "MEDIUM"].includes(r.blobDosRiskLevel),
  );
  if (blobDosResults.length > 0) {
    recommendations.push(
      "CRITICAL: Implement blob size limits and validation. Reject requests exceeding reasonable thresholds (e.g., 10MB max). (CWE-400, CWE-409)",
    );
  }

  // Issue #127, Challenge #24: Polyglot file recommendations
  const polyglotResults = results.filter(
    (r) => r.polyglotTested && r.securityIssues.length > 0,
  );
  if (polyglotResults.length > 0) {
    recommendations.push(
      "CRITICAL: Validate binary content matches declared MIME type. Block polyglot file generation that could be used for content-type confusion attacks. (CWE-434, CWE-436)",
    );
  }

  // Issue #127, Challenge #24: MIME validation recommendations
  const mimeResults = results.filter((r) => r.mimeTypeMismatch === true);
  if (mimeResults.length > 0) {
    recommendations.push(
      "Implement content-type validation using magic byte verification. Do not trust declared MIME types without verification. (CWE-436)",
    );
  }

  return recommendations;
}

/**
 * Create a response for when no resources are declared by the server
 */
export function createNoResourcesResponse(): ResourceAssessment {
  return {
    resourcesTested: 0,
    resourceTemplatesTested: 0,
    accessibleResources: 0,
    securityIssuesFound: 0,
    pathTraversalVulnerabilities: 0,
    sensitiveDataExposures: 0,
    promptInjectionVulnerabilities: 0,
    blobDosVulnerabilities: 0,
    polyglotVulnerabilities: 0,
    mimeValidationFailures: 0,
    results: [],
    status: "PASS",
    explanation:
      "No resources declared by server. Resource assessment skipped.",
    recommendations: [],
  };
}

/**
 * Calculate metrics from test results
 */
export interface ResourceMetrics {
  accessibleResources: number;
  securityIssuesFound: number;
  pathTraversalVulnerabilities: number;
  sensitiveDataExposures: number;
  promptInjectionVulnerabilities: number;
  blobDosVulnerabilities: number;
  polyglotVulnerabilities: number;
  mimeValidationFailures: number;
}

/**
 * Calculate all metrics from test results
 */
export function calculateMetrics(
  results: ResourceTestResult[],
): ResourceMetrics {
  return {
    accessibleResources: results.filter((r) => r.accessible).length,
    securityIssuesFound: results.filter((r) => r.securityIssues.length > 0)
      .length,
    pathTraversalVulnerabilities: results.filter(
      (r) => r.pathTraversalVulnerable,
    ).length,
    sensitiveDataExposures: results.filter((r) => r.sensitiveDataExposed)
      .length,
    promptInjectionVulnerabilities: results.filter(
      (r) => r.promptInjectionDetected,
    ).length,
    blobDosVulnerabilities: results.filter(
      (r) =>
        r.blobDosTested &&
        r.blobDosRiskLevel &&
        ["HIGH", "MEDIUM"].includes(r.blobDosRiskLevel),
    ).length,
    polyglotVulnerabilities: results.filter(
      (r) => r.polyglotTested && r.securityIssues.length > 0,
    ).length,
    mimeValidationFailures: results.filter((r) => r.mimeTypeMismatch === true)
      .length,
  };
}

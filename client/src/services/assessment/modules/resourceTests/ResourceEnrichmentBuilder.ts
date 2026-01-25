/**
 * Resource Enrichment Builder Module
 *
 * Builds Stage B enrichment data for Claude validation.
 * Provides context for Claude to validate resource assessment findings.
 *
 * @module assessment/resources/enrichmentBuilder
 * @since v1.44.0 (Issue #180 - ResourceAssessor Modularization)
 */

import {
  ResourceTestResult,
  ResourceEnrichmentData,
  ResourceInventoryItem,
  ResourceType,
  ResourceSecurityFlag,
  ResourcePatternCoverage,
  ResourceFlagForReview,
} from "@/lib/assessmentTypes";
import {
  truncateForTokens,
  MAX_DESCRIPTION_LENGTH,
} from "../../lib/moduleEnrichment";
import { AssessmentContext } from "../../AssessmentOrchestrator";
import {
  SENSITIVE_PATTERNS,
  PATH_TRAVERSAL_PAYLOADS,
  URI_INJECTION_PAYLOADS,
  HIDDEN_RESOURCE_PATTERNS,
} from "./ResourcePatterns";
import {
  isSensitiveUri,
  inferDataClassification,
} from "./ResourceUriValidator";

/**
 * Resource Enrichment Builder class
 *
 * Builds enrichment data for Stage B Claude validation
 */
export class ResourceEnrichmentBuilder {
  /**
   * Build enrichment data for Stage B Claude validation.
   * Provides context for Claude to validate resource assessment findings.
   */
  buildEnrichmentData(
    context: AssessmentContext,
    results: ResourceTestResult[],
  ): ResourceEnrichmentData {
    // Build resource inventory
    const resourceInventory = this.buildResourceInventory(context, results);

    // Build pattern coverage
    const patternCoverage = this.buildPatternCoverage(results);

    // Generate flags for review
    const flagsForReview = this.generateResourceFlags(results);

    // Calculate metrics
    const metrics = {
      totalResources: context.resources?.length ?? 0,
      totalTemplates: context.resourceTemplates?.length ?? 0,
      sensitiveResources: results.filter((r) => r.sensitiveDataExposed).length,
      accessibleResources: results.filter((r) => r.accessible).length,
      vulnerableResources: results.filter(
        (r) =>
          r.pathTraversalVulnerable ||
          r.promptInjectionDetected ||
          (r.blobDosTested &&
            r.blobDosRiskLevel &&
            ["HIGH", "MEDIUM"].includes(r.blobDosRiskLevel)) ||
          (r.polyglotTested && r.securityIssues.length > 0),
      ).length,
    };

    return {
      resourceInventory,
      patternCoverage,
      flagsForReview,
      metrics,
    };
  }

  /**
   * Build resource inventory with security analysis
   */
  private buildResourceInventory(
    context: AssessmentContext,
    results: ResourceTestResult[],
  ): ResourceInventoryItem[] {
    const inventory: ResourceInventoryItem[] = [];

    // Add declared resources
    for (const resource of context.resources || []) {
      const result = results.find((r) => r.resourceUri === resource.uri);
      const securityFlags = this.inferSecurityFlags(resource.uri, result);
      const resourceType = this.inferResourceType(
        resource.uri,
        resource.mimeType,
      );
      const dataClassification =
        result?.dataClassification || inferDataClassification(resource.uri);

      inventory.push({
        uri: truncateForTokens(resource.uri, 200),
        name: resource.name
          ? truncateForTokens(resource.name, MAX_DESCRIPTION_LENGTH)
          : undefined,
        mimeType: resource.mimeType,
        resourceType,
        securityFlags,
        dataClassification,
      });
    }

    // Add resource templates
    for (const template of context.resourceTemplates || []) {
      const relatedResults = results.filter(
        (r) =>
          r.resourceUri.includes(
            template.uriTemplate.replace(/\{[^}]+\}/g, ""),
          ) || r.resourceName?.includes(template.name || ""),
      );
      const securityFlags = this.inferTemplateSecurityFlags(
        template.uriTemplate,
        relatedResults,
      );

      inventory.push({
        uri: truncateForTokens(template.uriTemplate, 200),
        name: template.name
          ? truncateForTokens(template.name, MAX_DESCRIPTION_LENGTH)
          : undefined,
        mimeType: template.mimeType,
        resourceType: "template",
        securityFlags,
        dataClassification: inferDataClassification(template.uriTemplate),
      });
    }

    // Limit inventory size for token efficiency
    return inventory.slice(0, 50);
  }

  /**
   * Infer resource type from URI and MIME type
   */
  private inferResourceType(uri: string, mimeType?: string): ResourceType {
    const lowerUri = uri.toLowerCase();

    // Check for specific schemes
    if (lowerUri.startsWith("file://")) return "file";
    if (lowerUri.startsWith("http://") || lowerUri.startsWith("https://"))
      return "api";
    if (lowerUri.startsWith("db://") || lowerUri.startsWith("database://"))
      return "database";
    if (lowerUri.startsWith("blob://")) return "binary";

    // Check URI patterns
    if (/config|settings|\.ya?ml|\.json|\.ini|\.conf/i.test(lowerUri))
      return "config";
    if (/secret|credential|password|key|\.pem|\.key/i.test(lowerUri))
      return "credential";
    if (/\.exe|\.dll|\.so|\.bin|\.dat/i.test(lowerUri)) return "binary";
    if (/\/api\/|\/v\d+\/|\/rest\//i.test(lowerUri)) return "api";

    // Check MIME type
    if (mimeType) {
      if (
        mimeType.includes("application/json") ||
        mimeType.includes("application/xml")
      )
        return "config";
      if (mimeType.includes("application/octet-stream")) return "binary";
    }

    return "unknown";
  }

  /**
   * Infer security flags from resource URI and test result
   */
  private inferSecurityFlags(
    uri: string,
    result?: ResourceTestResult,
  ): ResourceSecurityFlag[] {
    const flags: ResourceSecurityFlag[] = [];

    // Check URI patterns
    if (isSensitiveUri(uri)) {
      flags.push("sensitive_uri");
    }

    // Check result flags
    if (result) {
      if (result.pathTraversalVulnerable) {
        flags.push("path_traversal_tested");
      }
      if (result.sensitiveDataExposed) {
        flags.push("sensitive_content");
      }
      if (result.promptInjectionDetected) {
        flags.push("prompt_injection");
      }
      if (result.hiddenResourceProbe && result.accessible) {
        flags.push("hidden_resource");
      }
      if (
        result.blobDosTested &&
        result.blobDosRiskLevel &&
        ["HIGH", "MEDIUM"].includes(result.blobDosRiskLevel)
      ) {
        flags.push("blob_dos_risk");
      }
      if (result.polyglotTested && result.securityIssues.length > 0) {
        flags.push("polyglot_risk");
      }
      if (result.mimeTypeMismatch) {
        flags.push("mime_mismatch");
      }
    }

    return flags;
  }

  /**
   * Infer security flags for resource templates
   */
  private inferTemplateSecurityFlags(
    uriTemplate: string,
    relatedResults: ResourceTestResult[],
  ): ResourceSecurityFlag[] {
    const flags: ResourceSecurityFlag[] = [];

    // Check URI template patterns
    if (isSensitiveUri(uriTemplate)) {
      flags.push("sensitive_uri");
    }

    // Aggregate flags from related test results
    for (const result of relatedResults) {
      if (
        result.pathTraversalVulnerable &&
        !flags.includes("path_traversal_tested")
      ) {
        flags.push("path_traversal_tested");
      }
      if (result.sensitiveDataExposed && !flags.includes("sensitive_content")) {
        flags.push("sensitive_content");
      }
      if (
        result.promptInjectionDetected &&
        !flags.includes("prompt_injection")
      ) {
        flags.push("prompt_injection");
      }
      if (
        result.blobDosTested &&
        result.blobDosRiskLevel &&
        ["HIGH", "MEDIUM"].includes(result.blobDosRiskLevel) &&
        !flags.includes("blob_dos_risk")
      ) {
        flags.push("blob_dos_risk");
      }
      if (
        result.polyglotTested &&
        result.securityIssues.length > 0 &&
        !flags.includes("polyglot_risk")
      ) {
        flags.push("polyglot_risk");
      }
      if (result.mimeTypeMismatch && !flags.includes("mime_mismatch")) {
        flags.push("mime_mismatch");
      }
    }

    return flags;
  }

  /**
   * Build pattern coverage showing what security tests were performed
   */
  private buildPatternCoverage(
    results: ResourceTestResult[],
  ): ResourcePatternCoverage {
    // Count unique patterns tested
    const pathTraversalCount = results.filter((r) =>
      r.resourceName?.includes("path traversal test"),
    ).length;

    const uriInjectionCount = results.filter(
      (r) => r.uriInjectionTested,
    ).length;

    const hiddenResourceCount = results.filter(
      (r) => r.hiddenResourceProbe,
    ).length;

    // Sample patterns for context
    const samplePatterns: string[] = [];
    if (SENSITIVE_PATTERNS.length > 0) {
      samplePatterns.push(
        `Sensitive URI patterns (${SENSITIVE_PATTERNS.length}): .env, .pem, password, etc.`,
      );
    }
    if (PATH_TRAVERSAL_PAYLOADS.length > 0) {
      samplePatterns.push(
        `Path traversal payloads (${PATH_TRAVERSAL_PAYLOADS.length}): ../../../etc/passwd, etc.`,
      );
    }
    if (URI_INJECTION_PAYLOADS.length > 0) {
      samplePatterns.push(
        `URI injection payloads (${URI_INJECTION_PAYLOADS.length}): SQL injection, SSRF, etc.`,
      );
    }
    if (HIDDEN_RESOURCE_PATTERNS.length > 0) {
      samplePatterns.push(
        `Hidden resource patterns (${HIDDEN_RESOURCE_PATTERNS.length}): internal://, .env, secrets.json, etc.`,
      );
    }

    return {
      sensitiveUriPatterns: SENSITIVE_PATTERNS.length,
      pathTraversalPayloads: pathTraversalCount,
      uriInjectionPayloads: uriInjectionCount,
      hiddenResourcePatterns: hiddenResourceCount,
      samplePatterns,
    };
  }

  /**
   * Generate flags for resources that warrant review
   */
  private generateResourceFlags(
    results: ResourceTestResult[],
  ): ResourceFlagForReview[] {
    const flags: ResourceFlagForReview[] = [];

    for (const result of results) {
      // Skip results without security concerns
      if (
        !result.pathTraversalVulnerable &&
        !result.sensitiveDataExposed &&
        !result.promptInjectionDetected &&
        !result.hiddenResourceProbe &&
        !(
          result.blobDosTested &&
          result.blobDosRiskLevel &&
          ["HIGH", "MEDIUM"].includes(result.blobDosRiskLevel)
        ) &&
        !(result.polyglotTested && result.securityIssues.length > 0) &&
        !result.mimeTypeMismatch
      ) {
        continue;
      }

      const resourceFlags = this.inferSecurityFlags(result.resourceUri, result);
      let riskLevel: "critical" | "high" | "medium" | "low" = "low";
      let reason = "";

      // Determine risk level and reason
      if (result.pathTraversalVulnerable) {
        riskLevel = "critical";
        reason = "Path traversal vulnerability detected";
      } else if (result.promptInjectionDetected) {
        riskLevel = "critical";
        reason = `Prompt injection patterns: ${result.promptInjectionPatterns.slice(0, 3).join(", ")}`;
      } else if (result.blobDosTested && result.blobDosRiskLevel === "HIGH") {
        riskLevel = "critical";
        reason = "Blob DoS vulnerability - accepts arbitrary large sizes";
      } else if (result.polyglotTested && result.securityIssues.length > 0) {
        riskLevel = "high";
        reason = `Polyglot file vulnerability: ${result.polyglotCombination || "unknown"}`;
      } else if (result.sensitiveDataExposed) {
        riskLevel = "high";
        reason = "Sensitive data exposure detected";
      } else if (result.hiddenResourceProbe && result.accessible) {
        riskLevel = "high";
        reason = "Hidden resource accessible without declaration";
      } else if (result.blobDosTested && result.blobDosRiskLevel === "MEDIUM") {
        riskLevel = "medium";
        reason = "Blob size validation could be bypassed";
      } else if (result.mimeTypeMismatch) {
        riskLevel = "medium";
        reason = `MIME mismatch: declared ${result.declaredMimeType}, actual ${result.expectedMimeType}`;
      }

      if (reason) {
        flags.push({
          resourceUri: truncateForTokens(result.resourceUri, 200),
          reason,
          flags: resourceFlags,
          riskLevel,
        });
      }
    }

    // Sort by risk level and limit
    const riskOrder = { critical: 0, high: 1, medium: 2, low: 3 };
    flags.sort((a, b) => riskOrder[a.riskLevel] - riskOrder[b.riskLevel]);

    return flags.slice(0, 20);
  }
}

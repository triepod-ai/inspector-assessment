/**
 * Resource Tester Module
 *
 * Core resource testing functionality including resource accessibility,
 * template testing, blob DoS testing, and polyglot file testing.
 *
 * @module assessment/resources/tester
 * @since v1.44.0 (Issue #180 - ResourceAssessor Modularization)
 */

import { ResourceTestResult } from "@/lib/assessmentTypes";
import { AssessmentContext } from "../../AssessmentOrchestrator";
import {
  PATH_TRAVERSAL_PAYLOADS,
  DOS_SIZE_PAYLOADS,
  POLYGLOT_COMBINATIONS,
} from "./ResourcePatterns";
import {
  detectSensitivePatterns,
  containsSensitiveContent,
  detectPromptInjection,
  validateMimeType,
  formatBytes,
  stringToBytes,
  startsWithBytes,
} from "./ResourceContentAnalyzer";
import {
  isValidUri,
  isValidUriTemplate,
  isSensitiveUri,
  inferAccessControls,
  inferDataClassification,
  injectPayloadIntoTemplate,
} from "./ResourceUriValidator";

/**
 * Logger interface for test execution
 */
export interface TestLogger {
  debug: (message: string, context?: Record<string, unknown>) => void;
  info: (message: string, context?: Record<string, unknown>) => void;
}

/**
 * Configuration for resource tester
 */
export interface ResourceTesterConfig {
  logger: TestLogger;
  executeWithTimeout: <T>(promise: Promise<T>, timeout: number) => Promise<T>;
  incrementTestCount: () => void;
  extractErrorMessage: (error: unknown) => string;
}

/**
 * Resource Tester class
 *
 * Handles core resource testing including accessibility checks,
 * path traversal testing, blob DoS, and polyglot detection.
 */
export class ResourceTester {
  private logger: TestLogger;
  private executeWithTimeout: <T>(
    promise: Promise<T>,
    timeout: number,
  ) => Promise<T>;
  private incrementTestCount: () => void;
  private extractErrorMessage: (error: unknown) => string;

  constructor(config: ResourceTesterConfig) {
    this.logger = config.logger;
    this.executeWithTimeout = config.executeWithTimeout;
    this.incrementTestCount = config.incrementTestCount;
    this.extractErrorMessage = config.extractErrorMessage;
  }

  /**
   * Test a single resource for accessibility and security issues
   */
  async testResource(
    resource: { uri: string; name?: string; mimeType?: string },
    context: AssessmentContext,
  ): Promise<ResourceTestResult> {
    const result: ResourceTestResult = {
      resourceUri: resource.uri,
      resourceName: resource.name,
      mimeType: resource.mimeType,
      tested: true,
      accessible: false,
      securityIssues: [],
      pathTraversalVulnerable: false,
      sensitiveDataExposed: false,
      promptInjectionDetected: false,
      promptInjectionPatterns: [],
      validUri: isValidUri(resource.uri),
      // NEW: Initialize enrichment fields (Issue #9)
      sensitivePatterns: [],
      accessControls: inferAccessControls(resource.uri),
      dataClassification: inferDataClassification(resource.uri),
    };

    // Check URI for sensitive patterns
    if (isSensitiveUri(resource.uri)) {
      result.securityIssues.push(
        `Resource URI matches sensitive file pattern: ${resource.uri}`,
      );
      result.sensitiveDataExposed = true;
      // Update classification if sensitive (only upgrade, don't downgrade from restricted)
      if (
        result.dataClassification !== "restricted" &&
        result.dataClassification !== "confidential"
      ) {
        result.dataClassification = "confidential";
      }
    }

    // Try to read the resource if readResource function is provided
    if (context.readResource) {
      try {
        const startTime = Date.now();
        const content = await this.executeWithTimeout(
          context.readResource(resource.uri),
          5000,
        );
        result.readTime = Date.now() - startTime;
        result.accessible = true;
        result.contentSizeBytes = content?.length || 0;

        // Check content for sensitive data
        if (content && containsSensitiveContent(content)) {
          result.securityIssues.push(
            "Resource content contains sensitive data patterns (credentials, keys, etc.)",
          );
          result.sensitiveDataExposed = true;
        }

        // NEW: Detect sensitive patterns with severity (Issue #9)
        if (content) {
          result.sensitivePatterns = detectSensitivePatterns(content);
          // Upgrade classification if patterns found (only upgrade, never downgrade)
          if (
            result.sensitivePatterns.some(
              (p) => p.detected && p.severity === "critical",
            )
          ) {
            result.dataClassification = "restricted";
          } else if (
            result.sensitivePatterns.some(
              (p) => p.detected && p.severity === "high",
            ) &&
            result.dataClassification !== "restricted"
          ) {
            result.dataClassification = "confidential";
          }
        }

        // Check content for prompt injection patterns
        if (content) {
          const injectionMatches = detectPromptInjection(content);
          if (injectionMatches.length > 0) {
            result.promptInjectionDetected = true;
            result.promptInjectionPatterns = injectionMatches;
            result.securityIssues.push(
              `Prompt injection patterns detected: ${injectionMatches.join(", ")}`,
            );
          }
        }

        // Issue #127, Challenge #24: MIME type validation
        if (content && resource.mimeType) {
          const mimeValidation = validateMimeType(content, resource.mimeType);
          result.mimeValidationPerformed = true;
          result.declaredMimeType = resource.mimeType;
          if (mimeValidation.expectedMimeType) {
            result.expectedMimeType = mimeValidation.expectedMimeType;
          }
          if (mimeValidation.mismatch) {
            result.mimeTypeMismatch = true;
            result.securityIssues.push(
              `MIME type mismatch: declared ${resource.mimeType} but content appears to be ${mimeValidation.expectedMimeType} (CWE-436)`,
            );
          }
        }
      } catch (error) {
        result.error = this.extractErrorMessage(error);
        result.accessible = false;
      }
    } else {
      result.tested = false;
      result.error = "readResource function not provided - skipping read test";
    }

    return result;
  }

  /**
   * Test a resource template with path traversal payloads
   */
  async testResourceTemplate(
    template: { uriTemplate: string; name?: string; mimeType?: string },
    context: AssessmentContext,
  ): Promise<ResourceTestResult[]> {
    const results: ResourceTestResult[] = [];

    // Test the template itself
    const templateResult: ResourceTestResult = {
      resourceUri: template.uriTemplate,
      resourceName: template.name,
      mimeType: template.mimeType,
      tested: true,
      accessible: false,
      securityIssues: [],
      pathTraversalVulnerable: false,
      sensitiveDataExposed: false,
      promptInjectionDetected: false,
      promptInjectionPatterns: [],
      validUri: isValidUriTemplate(template.uriTemplate),
      // Issue #9: Initialize enrichment fields for template results
      sensitivePatterns: [],
      accessControls: inferAccessControls(template.uriTemplate),
      dataClassification: inferDataClassification(template.uriTemplate),
    };

    // Check template for sensitive patterns
    if (isSensitiveUri(template.uriTemplate)) {
      templateResult.securityIssues.push(
        `Resource template matches sensitive file pattern: ${template.uriTemplate}`,
      );
      templateResult.sensitiveDataExposed = true;
    }

    results.push(templateResult);

    // Test path traversal vulnerabilities if readResource is available
    if (context.readResource) {
      for (const payload of PATH_TRAVERSAL_PAYLOADS) {
        this.incrementTestCount();
        const testUri = injectPayloadIntoTemplate(
          template.uriTemplate,
          payload,
        );

        const traversalResult: ResourceTestResult = {
          resourceUri: testUri,
          resourceName: `${template.name} (path traversal test)`,
          tested: true,
          accessible: false,
          securityIssues: [],
          pathTraversalVulnerable: false,
          sensitiveDataExposed: false,
          promptInjectionDetected: false,
          promptInjectionPatterns: [],
          validUri: false,
          // Issue #9: Initialize enrichment fields for traversal results
          sensitivePatterns: [],
          accessControls: inferAccessControls(template.uriTemplate),
          dataClassification: inferDataClassification(template.uriTemplate),
        };

        try {
          const content = await this.executeWithTimeout(
            context.readResource(testUri),
            3000,
          );

          // If we got content with a path traversal payload, it's vulnerable
          if (
            content &&
            (content.includes("root:") || content.includes("[fonts]"))
          ) {
            traversalResult.pathTraversalVulnerable = true;
            traversalResult.accessible = true;
            traversalResult.securityIssues.push(
              `Path traversal vulnerability: successfully accessed ${testUri}`,
            );
          }
        } catch (error) {
          // Expected - path traversal should be rejected
          this.logger.debug(
            `Path traversal correctly rejected for ${testUri}`,
            {
              error: error instanceof Error ? error.message : String(error),
            },
          );
          traversalResult.accessible = false;
        }

        results.push(traversalResult);
      }
    }

    return results;
  }

  /**
   * Issue #127, Challenge #24: Test blob resource templates for DoS vulnerabilities
   * Detects arbitrary size acceptance without validation/limits (CWE-400, CWE-409)
   */
  async testBlobDoS(
    template: { uriTemplate: string; name?: string },
    context: AssessmentContext,
  ): Promise<ResourceTestResult[]> {
    const results: ResourceTestResult[] = [];

    // Only test blob:// templates
    if (!template.uriTemplate.startsWith("blob://")) {
      return results;
    }

    if (!context.readResource) {
      return results;
    }

    const PROBE_DELAY_MS = 50;

    for (const sizePayload of DOS_SIZE_PAYLOADS) {
      this.incrementTestCount();

      // Construct URI: blob://{size}/{mime_base}/{mime_subtype}
      const testUri = template.uriTemplate
        .replace(/\{size\}/g, sizePayload)
        .replace(/\{mime_base\}/g, "application")
        .replace(/\{mime_subtype\}/g, "octet-stream");

      const dosResult: ResourceTestResult = {
        resourceUri: testUri,
        resourceName: `${template.name || "blob"} (DoS size test: ${sizePayload})`,
        tested: true,
        accessible: false,
        securityIssues: [],
        pathTraversalVulnerable: false,
        sensitiveDataExposed: false,
        promptInjectionDetected: false,
        promptInjectionPatterns: [],
        validUri: true,
        sensitivePatterns: [],
        accessControls: { requiresAuth: false },
        dataClassification: "internal",
        blobDosTested: true,
        blobRequestedSize: parseInt(sizePayload) || 0,
      };

      try {
        const content = await this.executeWithTimeout(
          context.readResource(testUri),
          2000, // Short timeout to avoid actual DoS
        );

        if (content) {
          dosResult.accessible = true;
          const requestedSize = parseInt(sizePayload);

          // Detect vulnerability: server accepted arbitrary large size
          if (!isNaN(requestedSize) && requestedSize > 1024 * 1024) {
            dosResult.blobDosRiskLevel =
              requestedSize > 100 * 1024 * 1024 ? "HIGH" : "MEDIUM";
            dosResult.securityIssues.push(
              `Blob DoS vulnerability: server accepted ${formatBytes(requestedSize)} request without size validation (CWE-400, CWE-409)`,
            );
          } else if (
            sizePayload === "-1" ||
            sizePayload === "NaN" ||
            sizePayload === "Infinity"
          ) {
            // Invalid values accepted = poor input validation
            dosResult.securityIssues.push(
              `Blob size validation bypass: server accepted invalid size "${sizePayload}"`,
            );
            dosResult.blobDosRiskLevel = "MEDIUM";
          } else {
            dosResult.blobDosRiskLevel = "LOW";
          }
        }
      } catch {
        // Expected - large sizes should be rejected
        this.logger.debug(`Blob DoS test correctly rejected for ${testUri}`);
        dosResult.blobDosRiskLevel = "NONE";
      }

      if (dosResult.securityIssues.length > 0) {
        results.push(dosResult);
      }

      await new Promise((resolve) => setTimeout(resolve, PROBE_DELAY_MS));
    }

    return results;
  }

  /**
   * Issue #127, Challenge #24: Test polyglot resource generation vulnerabilities
   * Detects dual-format file injection (CWE-434, CWE-436)
   */
  async testPolyglotResources(
    template: { uriTemplate: string; name?: string },
    context: AssessmentContext,
  ): Promise<ResourceTestResult[]> {
    const results: ResourceTestResult[] = [];

    // Only test polyglot:// templates
    if (!template.uriTemplate.startsWith("polyglot://")) {
      return results;
    }

    if (!context.readResource) {
      return results;
    }

    const PROBE_DELAY_MS = 50;

    for (const combo of POLYGLOT_COMBINATIONS) {
      this.incrementTestCount();

      const testUri = template.uriTemplate
        .replace(/\{base_type\}/g, combo.baseType)
        .replace(/\{hidden_type\}/g, combo.hiddenType);

      const polyglotResult: ResourceTestResult = {
        resourceUri: testUri,
        resourceName: `${template.name || "polyglot"} (${combo.baseType}/${combo.hiddenType})`,
        tested: true,
        accessible: false,
        securityIssues: [],
        pathTraversalVulnerable: false,
        sensitiveDataExposed: false,
        promptInjectionDetected: false,
        promptInjectionPatterns: [],
        validUri: true,
        sensitivePatterns: [],
        accessControls: { requiresAuth: false },
        dataClassification: "internal",
        polyglotTested: true,
        polyglotCombination: `${combo.baseType}/${combo.hiddenType}`,
      };

      try {
        const content = await this.executeWithTimeout(
          context.readResource(testUri),
          3000,
        );

        if (content) {
          polyglotResult.accessible = true;

          // Check for magic bytes first (primary detection method)
          // This ensures we detect polyglot content even if server doesn't self-report
          const contentBytes = stringToBytes(content);
          if (startsWithBytes(contentBytes, combo.magicBytes)) {
            polyglotResult.securityIssues.push(
              `Polyglot file vulnerability: response contains ${combo.baseType} magic bytes with potential ${combo.hiddenType} payload (CWE-434, CWE-436)`,
            );
          } else {
            // Check if response indicates polyglot generation (supplementary detection)
            // Only used when magic bytes aren't present but server self-reports
            try {
              const parsed = JSON.parse(content);
              if (
                parsed.vulnerable === true ||
                parsed.polyglot_known === true
              ) {
                polyglotResult.securityIssues.push(
                  `Polyglot file vulnerability: server generates ${combo.description} (CWE-434, CWE-436)`,
                );
              }
            } catch {
              // Expected for non-JSON content - no action needed
            }
          }
        }
      } catch {
        this.logger.debug(`Polyglot test correctly rejected for ${testUri}`);
      }

      if (polyglotResult.securityIssues.length > 0) {
        results.push(polyglotResult);
      }

      await new Promise((resolve) => setTimeout(resolve, PROBE_DELAY_MS));
    }

    return results;
  }
}

/**
 * Resource Probe Tester Module
 *
 * Handles hidden resource discovery and URI injection vulnerability testing.
 * Tests for undeclared resources and parameter injection attacks.
 *
 * @module assessment/resources/probeTester
 * @since v1.44.0 (Issue #180 - ResourceAssessor Modularization)
 */

import { ResourceTestResult } from "@/lib/assessmentTypes";
import { AssessmentContext } from "../../AssessmentOrchestrator";
import {
  URI_INJECTION_PAYLOADS,
  HIDDEN_RESOURCE_PATTERNS,
} from "./ResourcePatterns";
import {
  containsSensitiveContent,
  detectPromptInjection,
} from "./ResourceContentAnalyzer";
import {
  inferAccessControls,
  inferDataClassification,
  injectPayloadIntoTemplate,
} from "./ResourceUriValidator";

/**
 * Logger interface for test execution
 */
export interface TestLogger {
  debug: (message: string, context?: Record<string, unknown>) => void;
}

/**
 * Configuration for probe tester
 */
export interface ProbeTesterConfig {
  logger: TestLogger;
  executeWithTimeout: <T>(promise: Promise<T>, timeout: number) => Promise<T>;
  incrementTestCount: () => void;
}

/**
 * Resource Probe Tester class
 *
 * Tests for hidden resources and URI injection vulnerabilities
 */
export class ResourceProbeTester {
  private logger: TestLogger;
  private executeWithTimeout: <T>(
    promise: Promise<T>,
    timeout: number,
  ) => Promise<T>;
  private incrementTestCount: () => void;

  constructor(config: ProbeTesterConfig) {
    this.logger = config.logger;
    this.executeWithTimeout = config.executeWithTimeout;
    this.incrementTestCount = config.incrementTestCount;
  }

  /**
   * Issue #119, Challenge #14: Test URI injection vulnerabilities in resource templates
   * Injects malicious payloads into URI parameters and checks for sensitive content leakage
   */
  async testParameterizedUriInjection(
    template: { uriTemplate: string; name?: string },
    context: AssessmentContext,
  ): Promise<ResourceTestResult[]> {
    const results: ResourceTestResult[] = [];

    if (!context.readResource) {
      return results;
    }

    for (const payload of URI_INJECTION_PAYLOADS) {
      this.incrementTestCount();
      const testUri = injectPayloadIntoTemplate(template.uriTemplate, payload);

      const injectionResult: ResourceTestResult = {
        resourceUri: testUri,
        resourceName: `${template.name || "template"} (URI injection test)`,
        tested: true,
        accessible: false,
        securityIssues: [],
        pathTraversalVulnerable: false,
        sensitiveDataExposed: false,
        promptInjectionDetected: false,
        promptInjectionPatterns: [],
        validUri: false,
        sensitivePatterns: [],
        accessControls: inferAccessControls(template.uriTemplate),
        dataClassification: inferDataClassification(template.uriTemplate),
        // Issue #119: New URI injection fields
        uriInjectionTested: true,
        uriInjectionPayload: payload,
      };

      try {
        const content = await this.executeWithTimeout(
          context.readResource(testUri),
          3000,
        );

        if (content) {
          injectionResult.accessible = true;

          // Check if response contains sensitive content indicating vulnerability
          if (containsSensitiveContent(content)) {
            injectionResult.sensitiveDataExposed = true;
            injectionResult.securityIssues.push(
              `URI injection vulnerability: payload "${payload.substring(0, 50)}..." returned sensitive content`,
            );
          }

          // Check for injection indicators in response
          if (
            content.includes("process.env") ||
            content.includes("API_KEY") ||
            content.includes("root:") ||
            content.includes("env:") ||
            content.includes("DROP TABLE")
          ) {
            injectionResult.securityIssues.push(
              `URI injection may have executed: response contains injection indicators`,
            );
          }

          // Check for prompt injection echo-back
          const injectionMatches = detectPromptInjection(content);
          if (injectionMatches.length > 0) {
            injectionResult.promptInjectionDetected = true;
            injectionResult.promptInjectionPatterns = injectionMatches;
            injectionResult.securityIssues.push(
              `URI parameter reflected with prompt injection patterns: ${injectionMatches.join(", ")}`,
            );
          }
        }
      } catch (error) {
        // Expected - injection payloads should be rejected
        this.logger.debug(`URI injection correctly rejected for ${testUri}`, {
          error: error instanceof Error ? error.message : String(error),
        });
      }

      // Only add results with security issues to avoid noise
      if (injectionResult.securityIssues.length > 0) {
        results.push(injectionResult);
      }
    }

    return results;
  }

  /**
   * Issue #119, Challenge #14: Probe for hidden/undeclared resources
   * Tests common hidden resource patterns to find accessible but undeclared resources
   */
  async testHiddenResourceDiscovery(
    declaredResources: Array<{ uri: string }>,
    context: AssessmentContext,
  ): Promise<ResourceTestResult[]> {
    const results: ResourceTestResult[] = [];

    if (!context.readResource) {
      return results;
    }

    // Extract base schemes from declared resources
    const baseSchemes = new Set<string>();
    for (const resource of declaredResources) {
      const match = resource.uri.match(/^([a-z][a-z0-9+.-]*):\/\//i);
      if (match) {
        baseSchemes.add(match[1].toLowerCase());
      }
    }

    // Also try common schemes if none found
    if (baseSchemes.size === 0) {
      baseSchemes.add("file");
      baseSchemes.add("resource");
    }

    // Test hidden resource patterns with rate limiting to avoid overwhelming target
    const PROBE_DELAY_MS = 50; // 50ms delay between probes

    for (const pattern of HIDDEN_RESOURCE_PATTERNS) {
      // For patterns with their own scheme, test directly
      if (pattern.includes("://")) {
        this.incrementTestCount();
        const probeResult = await this.probeHiddenResource(
          pattern,
          pattern,
          context,
        );
        if (probeResult) {
          results.push(probeResult);
        }
        // Rate limit between probes
        await new Promise((resolve) => setTimeout(resolve, PROBE_DELAY_MS));
      } else {
        // For file paths, combine with discovered schemes
        for (const scheme of baseSchemes) {
          this.incrementTestCount();
          const testUri = `${scheme}://${pattern}`;
          const probeResult = await this.probeHiddenResource(
            testUri,
            pattern,
            context,
          );
          if (probeResult) {
            results.push(probeResult);
          }
          // Rate limit between probes
          await new Promise((resolve) => setTimeout(resolve, PROBE_DELAY_MS));
        }
      }
    }

    return results;
  }

  /**
   * Helper: Probe a single hidden resource URI
   */
  private async probeHiddenResource(
    testUri: string,
    pattern: string,
    context: AssessmentContext,
  ): Promise<ResourceTestResult | null> {
    const probeResult: ResourceTestResult = {
      resourceUri: testUri,
      resourceName: `Hidden resource probe: ${pattern}`,
      tested: true,
      accessible: false,
      securityIssues: [],
      pathTraversalVulnerable: false,
      sensitiveDataExposed: false,
      promptInjectionDetected: false,
      promptInjectionPatterns: [],
      validUri: true,
      sensitivePatterns: [],
      accessControls: { requiresAuth: true, authType: "unknown" },
      dataClassification: "restricted",
      // Issue #119: New hidden resource fields
      hiddenResourceProbe: true,
      probePattern: pattern,
    };

    try {
      const content = await this.executeWithTimeout(
        context.readResource!(testUri),
        2000,
      );

      if (content) {
        probeResult.accessible = true;
        probeResult.contentSizeBytes = content.length;
        probeResult.securityIssues.push(
          `Hidden resource accessible: ${testUri} (probed via ${pattern})`,
        );

        // Check for sensitive content
        if (containsSensitiveContent(content)) {
          probeResult.sensitiveDataExposed = true;
          probeResult.securityIssues.push(
            `Hidden resource contains sensitive data`,
          );
        }

        // Check for prompt injection in hidden resources
        const injectionMatches = detectPromptInjection(content);
        if (injectionMatches.length > 0) {
          probeResult.promptInjectionDetected = true;
          probeResult.promptInjectionPatterns = injectionMatches;
          probeResult.securityIssues.push(
            `Hidden resource contains prompt injection: ${injectionMatches.join(", ")}`,
          );
        }

        return probeResult;
      }
    } catch (error) {
      // Expected - hidden resources should not be accessible
      this.logger.debug(`Hidden resource probe rejected for ${testUri}`, {
        error: error instanceof Error ? error.message : String(error),
      });
    }

    return null; // Only return results for accessible hidden resources
  }
}

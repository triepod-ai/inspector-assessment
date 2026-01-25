/**
 * Resource Assessor Module
 *
 * Tests MCP server resources for accessibility, security, and compliance.
 * This module orchestrates resource testing using injected tester components.
 *
 * Tests include:
 * - Resource accessibility (can read declared resources)
 * - Path traversal vulnerabilities in resource URIs
 * - Sensitive data exposure detection
 * - URI validation and format compliance
 * - Hidden resource discovery (Issue #119)
 * - Blob DoS and polyglot vulnerabilities (Issue #127)
 *
 * @module assessment/resources
 * @since v1.44.0 (Issue #180 - Modularized to ~250 lines from 1907 lines)
 */

import { ResourceAssessment } from "@/lib/assessmentTypes";
import { BaseAssessor } from "./BaseAssessor";
import { AssessmentContext } from "../AssessmentOrchestrator";
import {
  createResourceTesters,
  type ResourceTesters,
  createNoResourcesResponse,
  calculateMetrics,
  determineResourceStatus,
  generateExplanation,
  generateRecommendations,
} from "./resourceTests";

/**
 * Resource Assessor
 *
 * Orchestrates resource security testing by delegating to specialized testers.
 * Uses factory-injected dependencies for testability and maintainability.
 *
 * @example
 * // Production usage
 * const assessor = new ResourceAssessor(config);
 * const results = await assessor.assess(context);
 *
 * // Testing with mock testers
 * const mockTesters = { resourceTester: mockTester, ... };
 * const assessor = new ResourceAssessor(config, mockTesters);
 */
export class ResourceAssessor extends BaseAssessor {
  private testers: ResourceTesters;

  constructor(
    config: import("@/lib/assessment/configTypes").AssessmentConfiguration,
    testers?: ResourceTesters,
  ) {
    super(config);

    // Create test logger adapter
    const testLogger = {
      info: (message: string, context?: Record<string, unknown>) =>
        this.logger.info(message, context),
      debug: (message: string, context?: Record<string, unknown>) =>
        this.logger.debug(message, context),
    };

    // Use provided testers or create via factory
    this.testers =
      testers ??
      createResourceTesters({
        assessmentConfig: config,
        logger: testLogger,
        executeWithTimeout: this.executeWithTimeout.bind(this),
        incrementTestCount: () => this.testCount++,
        extractErrorMessage: this.extractErrorMessage.bind(this),
      });
  }

  /**
   * Assess resources for security and compliance
   */
  async assess(context: AssessmentContext): Promise<ResourceAssessment> {
    // Check if resources are provided
    if (!context.resources && !context.resourceTemplates) {
      return createNoResourcesResponse();
    }

    const resources = context.resources || [];
    const templates = context.resourceTemplates || [];

    this.logger.info(
      `Testing ${resources.length} resources and ${templates.length} resource templates`,
    );

    // Collect all test results
    const results = await this.runAllTests(resources, templates, context);

    // Calculate metrics from results
    const metrics = calculateMetrics(results);

    // Determine status
    const status = determineResourceStatus(
      metrics.pathTraversalVulnerabilities,
      metrics.sensitiveDataExposures,
      metrics.promptInjectionVulnerabilities,
      metrics.blobDosVulnerabilities,
      metrics.polyglotVulnerabilities,
      metrics.mimeValidationFailures,
      metrics.securityIssuesFound,
      results.length,
    );

    // Generate explanation and recommendations
    const explanation = generateExplanation(
      results,
      metrics.pathTraversalVulnerabilities,
      metrics.sensitiveDataExposures,
      metrics.promptInjectionVulnerabilities,
      metrics.blobDosVulnerabilities,
      metrics.polyglotVulnerabilities,
      metrics.mimeValidationFailures,
    );
    const recommendations = generateRecommendations(results);

    // Build Stage B enrichment data for Claude validation
    const enrichmentData = this.testers.enrichmentBuilder.buildEnrichmentData(
      context,
      results,
    );

    return {
      resourcesTested: resources.length,
      resourceTemplatesTested: templates.length,
      accessibleResources: metrics.accessibleResources,
      securityIssuesFound: metrics.securityIssuesFound,
      pathTraversalVulnerabilities: metrics.pathTraversalVulnerabilities,
      sensitiveDataExposures: metrics.sensitiveDataExposures,
      promptInjectionVulnerabilities: metrics.promptInjectionVulnerabilities,
      blobDosVulnerabilities: metrics.blobDosVulnerabilities,
      polyglotVulnerabilities: metrics.polyglotVulnerabilities,
      mimeValidationFailures: metrics.mimeValidationFailures,
      results,
      status,
      explanation,
      recommendations,
      enrichmentData,
    };
  }

  /**
   * Run all resource tests and collect results
   */
  private async runAllTests(
    resources: Array<{ uri: string; name?: string; mimeType?: string }>,
    templates: Array<{ uriTemplate: string; name?: string; mimeType?: string }>,
    context: AssessmentContext,
  ) {
    const results: import("@/lib/assessmentTypes").ResourceTestResult[] = [];

    // Test each declared resource
    for (const resource of resources) {
      this.testCount++;
      const result = await this.testers.resourceTester.testResource(
        resource,
        context,
      );
      results.push(result);
    }

    // Test resource templates
    for (const template of templates) {
      this.testCount++;

      // Path traversal testing
      const templateResults =
        await this.testers.resourceTester.testResourceTemplate(
          template,
          context,
        );
      results.push(...templateResults);

      // Issue #119, Challenge #14: Test URI injection on templates
      const injectionResults =
        await this.testers.probeTester.testParameterizedUriInjection(
          template,
          context,
        );
      results.push(...injectionResults);

      // Issue #127, Challenge #24: Test blob DoS vulnerabilities
      const blobDosResults = await this.testers.resourceTester.testBlobDoS(
        template,
        context,
      );
      results.push(...blobDosResults);

      // Issue #127, Challenge #24: Test polyglot file vulnerabilities
      const polyglotResults =
        await this.testers.resourceTester.testPolyglotResources(
          template,
          context,
        );
      results.push(...polyglotResults);
    }

    // Issue #119, Challenge #14: Probe for hidden/undeclared resources
    const hiddenResourceResults =
      await this.testers.probeTester.testHiddenResourceDiscovery(
        resources,
        context,
      );
    results.push(...hiddenResourceResults);

    return results;
  }
}

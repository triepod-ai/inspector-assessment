/**
 * Security Assessor Module
 * Tests for backend API security vulnerabilities using 23 focused patterns
 *
 * BASIC MODE (5 patterns - enableDomainTesting=false):
 *   Command Injection, Calculator Injection, SQL Injection, Path Traversal, Unicode Bypass
 *
 * ADVANCED MODE (all 23 patterns - enableDomainTesting=true):
 *   - Critical Injection (6): Command, Calculator, SQL, Path Traversal, XXE, NoSQL
 *   - Input Validation (3): Type Safety, Boundary Testing, Required Fields
 *   - Protocol Compliance (2): MCP Error Format, Timeout Handling
 *   - Tool-Specific (6): SSRF, Nested Injection, Package Squatting,
 *                        Data Exfiltration, Configuration Drift, Tool Shadowing
 *   - Encoding Bypass (1): Unicode Bypass
 *   - Resource Exhaustion (1): DoS/Resource Exhaustion
 *   - Deserialization (1): Insecure Deserialization
 *
 * This module orchestrates security testing by coordinating:
 * - SecurityPayloadTester: Executes tests with payloads
 * - SecurityResponseAnalyzer: Analyzes responses for vulnerabilities
 * - SecurityPayloadGenerator: Creates test parameters
 */

import {
  SecurityAssessment,
  SecurityTestResult,
  SecurityRiskLevel,
  AssessmentStatus,
} from "@/lib/assessmentTypes";
import { BaseAssessor } from "./BaseAssessor";
import { AssessmentContext } from "../AssessmentOrchestrator";
import { Tool } from "@modelcontextprotocol/sdk/types.js";
import { ToolClassifier, ToolCategory } from "../ToolClassifier";
import { ProgressCallback } from "@/lib/assessment/progressTypes";
import {
  SecurityPayloadTester,
  SecurityPayloadGenerator,
} from "./securityTests";

export class SecurityAssessor extends BaseAssessor {
  private payloadTester: SecurityPayloadTester | null = null;
  private payloadGenerator = new SecurityPayloadGenerator();

  /**
   * Get or create the payload tester instance
   */
  private getPayloadTester(): SecurityPayloadTester {
    if (!this.payloadTester) {
      this.payloadTester = new SecurityPayloadTester(
        {
          enableDomainTesting: this.config.enableDomainTesting,
          maxParallelTests: this.config.maxParallelTests,
          securityTestTimeout: this.config.securityTestTimeout,
          selectedToolsForTesting: this.config.selectedToolsForTesting,
        },
        {
          log: (msg) => this.log(msg),
          logError: (msg, err) => this.logError(msg, err),
        },
        (promise, timeout) => this.executeWithTimeout(promise, timeout),
      );
    }
    return this.payloadTester;
  }

  async assess(context: AssessmentContext): Promise<SecurityAssessment> {
    // Select tools for testing first
    const toolsToTest = this.selectToolsForTesting(context.tools);

    // Create progress callback adapter
    const onProgress: ProgressCallback | undefined = context.onProgress
      ? (event) => context.onProgress!(event)
      : undefined;

    // Run universal security testing - test selected tools with ALL attack types
    const allTests = await this.getPayloadTester().runUniversalSecurityTests(
      toolsToTest,
      context.callTool,
      onProgress,
    );

    // Separate connection errors from valid tests
    const connectionErrors = allTests.filter((t) => t.connectionError === true);
    const validTests = allTests.filter((t) => !t.connectionError);

    // Log connection error warning
    if (connectionErrors.length > 0) {
      this.log(
        `⚠️ WARNING: ${connectionErrors.length} test${connectionErrors.length !== 1 ? "s" : ""} failed due to connection/server errors`,
      );
      this.log(
        `Connection errors: ${connectionErrors.map((e) => `${e.toolName}:${e.testName} (${e.errorType})`).join(", ")}`,
      );
    }

    // Count vulnerabilities from VALID tests only
    const vulnerabilities: string[] = [];
    let highRiskCount = 0;
    let mediumRiskCount = 0;

    for (const test of validTests) {
      if (test.vulnerable) {
        // Create confidence-aware vulnerability message
        let vulnerability: string;
        if (test.confidence === "high" || !test.confidence) {
          vulnerability = `${test.toolName} vulnerable to ${test.testName}`;
        } else if (test.confidence === "medium") {
          vulnerability = `${test.toolName} may have ${test.testName} issue`;
        } else {
          vulnerability = `${test.toolName} flagged for ${test.testName} (needs review)`;
        }

        if (!vulnerabilities.includes(vulnerability)) {
          vulnerabilities.push(vulnerability);
        }

        if (test.riskLevel === "HIGH") highRiskCount++;
        else if (test.riskLevel === "MEDIUM") mediumRiskCount++;
      }
    }

    // Additional security checks for new patterns (only on selected tools)
    const additionalVulnerabilities =
      await this.performAdditionalSecurityChecks(toolsToTest);
    vulnerabilities.push(...additionalVulnerabilities);

    // Determine overall risk level
    const overallRiskLevel = this.determineOverallRiskLevel(
      highRiskCount,
      mediumRiskCount,
      vulnerabilities.length,
    );

    // Determine status
    const status = this.determineSecurityStatus(
      validTests,
      vulnerabilities.length,
      validTests.length,
      connectionErrors.length,
    );

    // Generate explanation
    const explanation = this.generateSecurityExplanation(
      validTests,
      connectionErrors,
      vulnerabilities,
      overallRiskLevel,
    );

    return {
      promptInjectionTests: allTests,
      vulnerabilities,
      overallRiskLevel,
      status,
      explanation,
    };
  }

  /**
   * Select tools for testing based on configuration
   */
  private selectToolsForTesting(tools: Tool[]): Tool[] {
    if (this.config.selectedToolsForTesting !== undefined) {
      const selectedNames = new Set(this.config.selectedToolsForTesting);
      const selectedTools = tools.filter((tool) =>
        selectedNames.has(tool.name),
      );

      if (this.config.selectedToolsForTesting.length === 0) {
        this.log(`User selected 0 tools for security testing - skipping tests`);
        return [];
      }

      if (selectedTools.length === 0) {
        this.log(
          `Warning: No tools matched selection (${this.config.selectedToolsForTesting.join(", ")})`,
        );
        return [];
      }

      this.log(
        `Testing ${selectedTools.length} selected tools out of ${tools.length} for security`,
      );
      return selectedTools;
    }

    this.log(`Testing all ${tools.length} tools for security`);
    return tools;
  }

  /**
   * Perform additional security checks
   */
  private async performAdditionalSecurityChecks(
    tools: Tool[],
  ): Promise<string[]> {
    const vulnerabilities: string[] = [];
    const classifier = new ToolClassifier();

    for (const tool of tools) {
      const toolText = `${tool.name} ${tool.description || ""}`.toLowerCase();

      const classification = classifier.classify(tool.name, tool.description);
      if (
        classification.categories.includes(ToolCategory.READ_ONLY_INFO) ||
        classification.categories.includes(ToolCategory.SEARCH_RETRIEVAL) ||
        classification.categories.includes(ToolCategory.CRUD_CREATION)
      ) {
        continue;
      }

      if (
        /key|secret|credential|password|token|auth/.test(toolText) &&
        !this.payloadGenerator.hasInputParameters(tool)
      ) {
        vulnerabilities.push(
          `${tool.name} may expose sensitive data (security-related tool with no input validation)`,
        );
      }
    }

    return vulnerabilities;
  }

  /**
   * Determine overall risk level
   */
  private determineOverallRiskLevel(
    highRiskCount: number,
    mediumRiskCount: number,
    totalVulnerabilities: number,
  ): SecurityRiskLevel {
    if (highRiskCount > 0) return "HIGH";
    if (mediumRiskCount > 2) return "HIGH";
    if (mediumRiskCount > 0) return "MEDIUM";
    if (totalVulnerabilities > 0) return "LOW";
    return "LOW";
  }

  /**
   * Determine security status based on confidence levels
   */
  private determineSecurityStatus(
    tests: SecurityTestResult[],
    vulnerabilityCount: number,
    testCount: number,
    connectionErrorCount: number = 0,
  ): AssessmentStatus {
    if (connectionErrorCount > 0) return "FAIL";
    if (testCount === 0) return "NEED_MORE_INFO";
    if (vulnerabilityCount === 0) return "PASS";

    const hasHighConfidence = tests.some(
      (t) => t.vulnerable && (!t.confidence || t.confidence === "high"),
    );

    if (hasHighConfidence) return "FAIL";

    return "NEED_MORE_INFO";
  }

  /**
   * Generate security explanation
   */
  private generateSecurityExplanation(
    validTests: SecurityTestResult[],
    connectionErrors: SecurityTestResult[],
    vulnerabilities: string[],
    riskLevel: SecurityRiskLevel,
  ): string {
    const vulnCount = vulnerabilities.length;
    const testCount = validTests.length;
    const errorCount = connectionErrors.length;

    let explanation = "";

    if (errorCount > 0) {
      explanation += `⚠️ ${errorCount} test${errorCount !== 1 ? "s" : ""} failed due to connection/server errors. `;
    }

    if (testCount === 0 && errorCount > 0) {
      return (
        explanation +
        `No valid tests completed. Check server connectivity and retry assessment.`
      );
    }

    if (testCount === 0 && errorCount === 0) {
      return `No tools selected for security testing. Select tools to run security assessments.`;
    }

    if (vulnCount === 0) {
      return (
        explanation +
        `Tested ${testCount} security patterns across selected tools. No vulnerabilities detected. All tools properly handle malicious inputs.`
      );
    }

    const highConfidenceCount = validTests.filter(
      (t) => t.vulnerable && (!t.confidence || t.confidence === "high"),
    ).length;
    const mediumConfidenceCount = validTests.filter(
      (t) => t.vulnerable && t.confidence === "medium",
    ).length;
    const lowConfidenceCount = validTests.filter(
      (t) => t.vulnerable && t.confidence === "low",
    ).length;

    if (highConfidenceCount > 0) {
      return (
        explanation +
        `Found ${highConfidenceCount} confirmed vulnerability${highConfidenceCount !== 1 ? "s" : ""} across ${testCount} security tests. Risk level: ${riskLevel}. Tools may execute malicious commands or leak sensitive data.`
      );
    } else if (mediumConfidenceCount > 0) {
      return (
        explanation +
        `Detected ${mediumConfidenceCount} potential security concern${mediumConfidenceCount !== 1 ? "s" : ""} across ${testCount} security tests requiring manual review. Tools showed suspicious behavior that needs verification.`
      );
    } else {
      return (
        explanation +
        `Flagged ${lowConfidenceCount} uncertain detection${lowConfidenceCount !== 1 ? "s" : ""} across ${testCount} security tests. Manual verification needed to confirm if these are actual vulnerabilities or false positives.`
      );
    }
  }
}

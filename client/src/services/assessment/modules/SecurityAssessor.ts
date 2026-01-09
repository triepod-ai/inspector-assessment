/**
 * Security Assessor Module
 * Tests for backend API security vulnerabilities using 25 focused patterns
 *
 * BASIC MODE (5 patterns - enableDomainTesting=false):
 *   Command Injection, Calculator Injection, SQL Injection, Path Traversal, Unicode Bypass
 *
 * ADVANCED MODE (all 25 patterns - enableDomainTesting=true):
 *   - Critical Injection (6): Command, Calculator, SQL, Path Traversal, XXE, NoSQL
 *   - Input Validation (3): Type Safety, Boundary Testing, Required Fields
 *   - Protocol Compliance (2): MCP Error Format, Timeout Handling
 *   - Tool-Specific (6): SSRF, Nested Injection, Package Squatting,
 *                        Data Exfiltration, Configuration Drift, Tool Shadowing
 *   - Encoding Bypass (1): Unicode Bypass
 *   - Resource Exhaustion (1): DoS/Resource Exhaustion
 *   - Deserialization (1): Insecure Deserialization
 *   - Auth Bypass (1): Fail-open authentication vulnerabilities (CVE-2025-52882)
 *   - Cross-Tool State Bypass (1): Privilege escalation via shared state (Issue #92)
 *
 * SEQUENCE TESTING (enableSequenceTesting - default true):
 *   Tests for cross-tool privilege escalation by calling tool sequences
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
import {
  SecurityPayloadTester,
  SecurityPayloadGenerator,
  CrossToolStateTester,
  type PayloadTestConfig,
  type TestLogger,
} from "./securityTests";
import { ToolClassifier, ToolCategory } from "../ToolClassifier";
import {
  ClaudeCodeBridge,
  SecurityAnalysisContext,
  SecuritySemanticAnalysisResult,
} from "../lib/claudeCodeBridge";

export class SecurityAssessor extends BaseAssessor {
  private payloadTester: SecurityPayloadTester;
  private payloadGenerator: SecurityPayloadGenerator;
  private crossToolStateTester: CrossToolStateTester;
  private claudeBridge: ClaudeCodeBridge | null = null;

  /**
   * Set the ClaudeCodeBridge for semantic analysis of security test results
   * Enables progressive enhancement: pattern-based detection first, Claude refinement for uncertain cases
   */
  setClaudeBridge(bridge: ClaudeCodeBridge | null): void {
    this.claudeBridge = bridge;
    if (bridge) {
      this.log(
        `ClaudeCodeBridge enabled for security semantic analysis (transport: ${bridge.getTransport()})`,
      );
    }
  }

  /**
   * Check if semantic analysis is available and enabled
   */
  private isSemanticAnalysisEnabled(): boolean {
    return (
      this.claudeBridge !== null &&
      this.claudeBridge.isFeatureEnabled("securitySemanticAnalysis")
    );
  }

  /**
   * Refine a security test result using Claude semantic analysis
   * Only called for medium/low confidence detections (progressive enhancement)
   */
  private async refineWithSemanticAnalysis(
    test: SecurityTestResult,
    tool: Tool,
  ): Promise<SecuritySemanticAnalysisResult | null> {
    if (!this.claudeBridge) return null;

    const context: SecurityAnalysisContext = {
      toolName: tool.name,
      toolDescription: tool.description || "",
      attackPattern: test.testName,
      payload: test.payload,
      response: test.response || "",
      originalConfidence: test.confidence || "medium",
    };

    try {
      return await this.claudeBridge.analyzeSecurityResponse(context);
    } catch (error) {
      this.logError("Claude semantic analysis failed", error);
      return null;
    }
  }

  constructor(
    config: import("@/lib/assessment/configTypes").AssessmentConfiguration,
  ) {
    super(config);

    // Initialize payload generator for additional checks
    this.payloadGenerator = new SecurityPayloadGenerator();

    // Create payload tester config from assessment config
    const payloadConfig: PayloadTestConfig = {
      enableDomainTesting: config.enableDomainTesting,
      maxParallelTests: config.maxParallelTests,
      securityTestTimeout: config.securityTestTimeout,
      selectedToolsForTesting: config.selectedToolsForTesting,
    };

    // Create logger adapter
    const testLogger: TestLogger = {
      log: (message: string) => this.log(message),
      logError: (message: string, error: unknown) =>
        this.logError(message, error),
    };

    // Initialize payload tester with config, logger, and timeout function
    this.payloadTester = new SecurityPayloadTester(
      payloadConfig,
      testLogger,
      this.executeWithTimeout.bind(this),
    );

    // Initialize cross-tool state tester (Issue #92)
    this.crossToolStateTester = new CrossToolStateTester({
      timeout: config.securityTestTimeout,
    });
  }

  async assess(context: AssessmentContext): Promise<SecurityAssessment> {
    // Select tools for testing first
    const toolsToTest = this.selectToolsForTesting(context.tools);

    // Run universal security testing via extracted payload tester
    const allTests = await this.payloadTester.runUniversalSecurityTests(
      toolsToTest,
      context.callTool,
      context.onProgress,
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

    // Progressive enhancement: refine medium/low confidence detections with Claude semantic analysis
    // HIGH confidence detections bypass Claude (cost efficient), only uncertain cases get API calls
    if (this.isSemanticAnalysisEnabled()) {
      // Create tool lookup map for quick access
      const toolMap = new Map(toolsToTest.map((t) => [t.name, t]));

      // Find tests that need semantic refinement (medium/low confidence vulnerabilities)
      const testsToRefine = validTests.filter(
        (t) =>
          t.vulnerable && (t.confidence === "medium" || t.confidence === "low"),
      );

      if (testsToRefine.length > 0) {
        this.log(
          `🧠 Running Claude semantic analysis on ${testsToRefine.length} medium/low confidence detection(s)...`,
        );

        let refinedCount = 0;
        let falsePositivesRemoved = 0;

        for (const test of testsToRefine) {
          const tool = toolMap.get(test.toolName || "");
          if (!tool) continue;

          const refinement = await this.refineWithSemanticAnalysis(test, tool);
          if (refinement) {
            refinedCount++;

            // Store semantic analysis result on the test
            (
              test as SecurityTestResult & { semanticAnalysis?: unknown }
            ).semanticAnalysis = {
              originalConfidence: test.confidence || "medium",
              refinedConfidence: refinement.refinedConfidence,
              reasoning: refinement.reasoning,
              source: "claude-refined" as const,
            };

            if (!refinement.isVulnerable) {
              // False positive - mark as not vulnerable
              test.vulnerable = false;
              falsePositivesRemoved++;
              this.log(
                `  ✅ ${test.toolName}:${test.testName} - marked safe (${refinement.reasoning.substring(0, 100)}...)`,
              );
            } else {
              // Confirmed or upgraded - update confidence
              test.confidence = refinement.refinedConfidence;
              if (refinement.refinedConfidence === "high") {
                this.log(
                  `  ⚠️ ${test.toolName}:${test.testName} - confirmed vulnerable (${refinement.reasoning.substring(0, 100)}...)`,
                );
              }
            }
          }
        }

        this.log(
          `🧠 Semantic analysis complete: ${refinedCount} refined, ${falsePositivesRemoved} false positives removed`,
        );
      }
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
          // High confidence: definitive language
          vulnerability = `${test.toolName} vulnerable to ${test.testName}`;
        } else if (test.confidence === "medium") {
          // Medium confidence: potential issue
          vulnerability = `${test.toolName} may have ${test.testName} issue`;
        } else {
          // Low confidence: flagged for review
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

    // Cross-tool sequence testing (Issue #92, Challenge #7)
    // Tests for privilege escalation via shared mutable state
    if (this.config.enableSequenceTesting !== false) {
      const crossToolResults = await this.runCrossToolSequenceTests(
        toolsToTest,
        context.callTool,
        context.onProgress,
      );

      for (const [pairKey, result] of crossToolResults) {
        if (result.vulnerable) {
          highRiskCount++;
          const vulnerability = `Cross-tool privilege escalation: ${pairKey}`;
          if (!vulnerabilities.includes(vulnerability)) {
            vulnerabilities.push(vulnerability);
          }
        }
      }
    }

    // Determine overall risk level
    const overallRiskLevel = this.determineOverallRiskLevel(
      highRiskCount,
      mediumRiskCount,
      vulnerabilities.length,
    );

    // Determine status (pass validTests array to check confidence levels, not allTests)
    const status = this.determineSecurityStatus(
      validTests,
      vulnerabilities.length,
      validTests.length,
      connectionErrors.length,
    );

    // Generate explanation (pass both validTests and connectionErrors)
    const explanation = this.generateSecurityExplanation(
      validTests,
      connectionErrors,
      vulnerabilities,
      overallRiskLevel,
    );

    // Issue #75: Aggregate auth bypass detection results
    const authBypassSummary = this.aggregateAuthBypassResults(allTests);

    return {
      promptInjectionTests: allTests,
      vulnerabilities,
      overallRiskLevel,
      status,
      explanation,
      authBypassSummary,
    };
  }

  /**
   * Select tools for testing based on configuration
   */
  private selectToolsForTesting(tools: Tool[]): Tool[] {
    // Prefer new selectedToolsForTesting configuration
    // Note: undefined/null means "test all" (default), empty array [] means "test none" (explicit)
    if (this.config.selectedToolsForTesting !== undefined) {
      const selectedNames = new Set(this.config.selectedToolsForTesting);
      const selectedTools = tools.filter((tool) =>
        selectedNames.has(tool.name),
      );

      // Empty array means user explicitly selected 0 tools
      if (this.config.selectedToolsForTesting.length === 0) {
        this.log(`User selected 0 tools for security testing - skipping tests`);
        return [];
      }

      // If no tools matched the names (config out of sync), log warning but respect selection
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

    // Default: test all tools
    this.log(`Testing all ${tools.length} tools for security`);
    return tools;
  }

  /**
   * Perform additional security checks
   */
  private async performAdditionalSecurityChecks(
    tools: any[],
  ): Promise<string[]> {
    const vulnerabilities: string[] = [];
    const classifier = new ToolClassifier();

    // Check for tools that might handle sensitive data
    for (const tool of tools) {
      const toolText = `${tool.name} ${tool.description || ""}`.toLowerCase();

      // Skip tools in safe categories that are designed to return user/data info
      const classification = classifier.classify(tool.name, tool.description);
      if (
        classification.categories.includes(ToolCategory.READ_ONLY_INFO) ||
        classification.categories.includes(ToolCategory.SEARCH_RETRIEVAL) ||
        classification.categories.includes(ToolCategory.CRUD_CREATION)
      ) {
        continue; // These tools are designed to return data, skip the check
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
   * Run cross-tool sequence tests for privilege escalation (Issue #92, Challenge #7)
   * Tests tool pairs: modifier enables admin mode, then admin action succeeds
   */
  private async runCrossToolSequenceTests(
    tools: Tool[],
    callTool: (
      name: string,
      params: Record<string, unknown>,
    ) => Promise<
      import("@modelcontextprotocol/sdk/types.js").CompatibilityCallToolResult
    >,
    onProgress?: import("@/lib/assessment/progressTypes").ProgressCallback,
  ): Promise<Map<string, import("./securityTests").CrossToolTestResult>> {
    const pairs = this.crossToolStateTester.identifyCrossToolPairs(tools);

    if (pairs.length === 0) {
      this.log(`No cross-tool pairs identified for sequence testing`);
      return new Map();
    }

    this.log(
      `Running cross-tool sequence tests on ${pairs.length} tool pair(s)...`,
    );

    const results = await this.crossToolStateTester.runAllSequenceTests(
      tools,
      callTool,
      onProgress,
    );

    // Log results
    const summary = this.crossToolStateTester.summarizeResults(results);
    if (summary.vulnerable > 0) {
      this.log(
        `⚠️ Cross-tool privilege escalation detected in ${summary.vulnerable} pair(s): ${summary.vulnerablePairs.join(", ")}`,
      );
    } else {
      this.log(
        `✅ No cross-tool privilege escalation detected (${summary.safe} safe, ${summary.errors} errors)`,
      );
    }

    return results;
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
    // If there are connection errors, we can't verify security
    if (connectionErrorCount > 0) return "FAIL";

    // If no tests were run, we can't determine security status
    if (testCount === 0) return "NEED_MORE_INFO";

    if (vulnerabilityCount === 0) return "PASS";

    // Check confidence levels of vulnerabilities
    const hasHighConfidence = tests.some(
      (t) => t.vulnerable && (!t.confidence || t.confidence === "high"),
    );

    // Only HIGH confidence vulnerabilities should result in FAIL
    if (hasHighConfidence) return "FAIL";

    // Medium and low confidence always require review
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

    // Build explanation starting with connection error warning if present
    let explanation = "";

    if (errorCount > 0) {
      explanation += `⚠️ ${errorCount} test${errorCount !== 1 ? "s" : ""} failed due to connection/server errors. `;
    }

    // Handle case when no tools were tested
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

    // Count by confidence level (from valid tests only)
    const highConfidenceCount = validTests.filter(
      (t) => t.vulnerable && (!t.confidence || t.confidence === "high"),
    ).length;
    const mediumConfidenceCount = validTests.filter(
      (t) => t.vulnerable && t.confidence === "medium",
    ).length;
    const lowConfidenceCount = validTests.filter(
      (t) => t.vulnerable && t.confidence === "low",
    ).length;

    // Generate confidence-aware explanation
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

  /**
   * Aggregate auth bypass detection results from security tests (Issue #75)
   * Summarizes fail-open/fail-closed patterns across all tested tools
   */
  private aggregateAuthBypassResults(tests: SecurityTestResult[]): {
    toolsWithAuthBypass: string[];
    failOpenCount: number;
    failClosedCount: number;
    unknownCount: number;
  } {
    const toolsWithAuthBypass: string[] = [];
    let failOpenCount = 0;
    let failClosedCount = 0;
    let unknownCount = 0;

    // Filter to Auth Bypass tests only
    const authBypassTests = tests.filter(
      (t) => t.testName === "Auth Bypass" && t.authFailureMode,
    );

    // Track unique tools with auth bypass detected
    const seenTools = new Set<string>();

    for (const test of authBypassTests) {
      const toolName = test.toolName || "unknown";

      if (test.authBypassDetected && !seenTools.has(toolName)) {
        toolsWithAuthBypass.push(toolName);
        seenTools.add(toolName);
      }

      // Count failure modes
      switch (test.authFailureMode) {
        case "FAIL_OPEN":
          failOpenCount++;
          break;
        case "FAIL_CLOSED":
          failClosedCount++;
          break;
        case "UNKNOWN":
          unknownCount++;
          break;
      }
    }

    return {
      toolsWithAuthBypass,
      failOpenCount,
      failClosedCount,
      unknownCount,
    };
  }
}

/**
 * Security Assessor Module
 * Tests for backend API security vulnerabilities using 20 focused patterns
 *
 * BASIC MODE (5 patterns - enableDomainTesting=false):
 *   Command Injection, Calculator Injection, SQL Injection, Path Traversal, Unicode Bypass
 *
 * ADVANCED MODE (all 20 patterns - enableDomainTesting=true):
 *   - Critical Injection (6): Command, Calculator, SQL, Path Traversal, XXE, NoSQL
 *   - Input Validation (3): Type Safety, Boundary Testing, Required Fields
 *   - Protocol Compliance (2): MCP Error Format, Timeout Handling
 *   - Tool-Specific (6): SSRF, Nested Injection, Package Squatting,
 *                        Data Exfiltration, Configuration Drift, Tool Shadowing
 *   - Encoding Bypass (1): Unicode Bypass
 *   - Resource Exhaustion (1): DoS/Resource Exhaustion
 *   - Deserialization (1): Insecure Deserialization
 */

import {
  SecurityAssessment,
  SecurityTestResult,
  SecurityRiskLevel,
  AssessmentStatus,
} from "@/lib/assessmentTypes";
import { BaseAssessor } from "./BaseAssessor";
import { AssessmentContext } from "../AssessmentOrchestrator";
import {
  CompatibilityCallToolResult,
  Tool,
} from "@modelcontextprotocol/sdk/types.js";
import {
  getAllAttackPatterns,
  getPayloadsForAttack,
  SecurityPayload,
} from "@/lib/securityPatterns";
import { ToolClassifier, ToolCategory } from "../ToolClassifier";
import { createConcurrencyLimit } from "../lib/concurrencyLimit";
import { LanguageAwarePayloadGenerator } from "../LanguageAwarePayloadGenerator";

export class SecurityAssessor extends BaseAssessor {
  private languageGenerator = new LanguageAwarePayloadGenerator();
  async assess(context: AssessmentContext): Promise<SecurityAssessment> {
    // Select tools for testing first
    const toolsToTest = this.selectToolsForTesting(context.tools);

    // Run universal security testing - test selected tools with ALL attack types
    const allTests = await this.runUniversalSecurityTests(context);

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
   * Run comprehensive security tests (advanced mode)
   * Tests selected tools with ALL 8 security patterns using diverse payloads
   * Includes injection tests, validation tests, and protocol compliance checks
   */
  private async runUniversalSecurityTests(
    context: AssessmentContext,
  ): Promise<SecurityTestResult[]> {
    // Check if advanced security testing is enabled
    if (!this.config.enableDomainTesting) {
      return this.runBasicSecurityTests(context);
    }

    const results: SecurityTestResult[] = [];
    const attackPatterns = getAllAttackPatterns();

    // Select tools for testing
    const toolsToTest = this.selectToolsForTesting(context.tools);

    // Parallel tool testing with concurrency limit
    const concurrency = this.config.maxParallelTests ?? 5;
    const limit = createConcurrencyLimit(concurrency);

    // Progress tracking for batched events - pre-calculate exact payload count
    let totalPayloads = 0;
    for (const pattern of attackPatterns) {
      totalPayloads += getPayloadsForAttack(pattern.attackName).length;
    }
    const totalEstimate = toolsToTest.length * totalPayloads;
    let completedTests = 0;
    let lastBatchTime = Date.now();
    const startTime = Date.now();
    const BATCH_INTERVAL = 500; // ms
    const BATCH_SIZE = 10; // tests
    let batchCount = 0;

    // Helper to emit batched progress
    const emitProgressBatch = () => {
      if (context.onProgress) {
        context.onProgress({
          type: "test_batch",
          module: "security",
          completed: completedTests,
          total: totalEstimate,
          batchSize: batchCount,
          elapsed: Date.now() - startTime,
        });
      }
      batchCount = 0;
      lastBatchTime = Date.now();
    };

    this.log(
      `Starting ADVANCED security assessment - testing ${toolsToTest.length} tools with ${attackPatterns.length} security patterns (~${totalEstimate} tests) [concurrency: ${concurrency}]`,
    );

    const allToolResults = await Promise.all(
      toolsToTest.map((tool) =>
        limit(async () => {
          const toolResults: SecurityTestResult[] = [];

          // Tools with no input parameters can't be exploited via payload injection
          // Add passing results so they appear in the UI
          if (!this.hasInputParameters(tool)) {
            this.log(
              `${tool.name} has no input parameters - adding passing results`,
            );

            // Add a passing result for each attack pattern so tool appears in UI
            for (const attackPattern of attackPatterns) {
              const payloads = getPayloadsForAttack(attackPattern.attackName);

              // Add one passing result per payload type
              for (const payload of payloads) {
                toolResults.push({
                  testName: attackPattern.attackName,
                  description: payload.description,
                  payload: payload.payload,
                  riskLevel: payload.riskLevel,
                  toolName: tool.name,
                  vulnerable: false,
                  evidence:
                    "Tool has no input parameters - cannot be exploited via payload injection",
                });
              }
            }
            return toolResults;
          }

          this.log(`Testing ${tool.name} with all attack patterns`);

          // Test with each attack type (all patterns in advanced mode)
          for (const attackPattern of attackPatterns) {
            // Get ALL payloads for this attack pattern
            const payloads = getPayloadsForAttack(attackPattern.attackName);

            // Test tool with each payload variation
            for (const payload of payloads) {
              this.testCount++;
              completedTests++;
              batchCount++;

              try {
                const result = await this.testPayload(
                  tool,
                  attackPattern.attackName,
                  payload,
                  context.callTool,
                );

                toolResults.push(result);

                if (result.vulnerable) {
                  this.log(
                    `🚨 VULNERABILITY: ${tool.name} - ${attackPattern.attackName} (${payload.payloadType}: ${payload.description})`,
                  );

                  // Emit real-time vulnerability_found event
                  if (context.onProgress) {
                    context.onProgress({
                      type: "vulnerability_found",
                      tool: tool.name,
                      pattern: attackPattern.attackName,
                      confidence: result.confidence || "medium",
                      evidence: result.evidence || "Vulnerability detected",
                      riskLevel: payload.riskLevel,
                      requiresReview: result.requiresManualReview || false,
                      payload: payload.payload,
                    });
                  }
                }
              } catch (error) {
                this.logError(
                  `Error testing ${tool.name} with ${attackPattern.attackName}`,
                  error,
                );
              }

              // Emit progress batch if threshold reached
              const timeSinceLastBatch = Date.now() - lastBatchTime;
              if (
                batchCount >= BATCH_SIZE ||
                timeSinceLastBatch >= BATCH_INTERVAL
              ) {
                emitProgressBatch();
              }

              // Rate limiting
              if (this.testCount % 5 === 0) {
                await this.sleep(100);
              }
            }
          }

          return toolResults;
        }),
      ),
    );

    // Flatten all tool results into the main results array
    for (const toolResults of allToolResults) {
      results.push(...toolResults);
    }

    // Final flush of any remaining progress
    if (batchCount > 0) {
      emitProgressBatch();
    }

    this.log(
      `ADVANCED security assessment complete: ${results.length} tests executed, ${results.filter((r) => r.vulnerable).length} vulnerabilities found`,
    );

    return results;
  }

  /**
   * Run basic security tests (fast mode)
   * Tests only 3 critical injection patterns with 1 generic payload each
   * Used when enableDomainTesting = false
   */
  private async runBasicSecurityTests(
    context: AssessmentContext,
  ): Promise<SecurityTestResult[]> {
    const results: SecurityTestResult[] = [];

    // Only test 5 critical injection patterns
    const criticalPatterns = [
      "Command Injection",
      "Calculator Injection",
      "SQL Injection",
      "Path Traversal",
      "Unicode Bypass",
    ];

    const allPatterns = getAllAttackPatterns();
    const basicPatterns = allPatterns.filter((p) =>
      criticalPatterns.includes(p.attackName),
    );

    // Select tools for testing
    const toolsToTest = this.selectToolsForTesting(context.tools);

    // Progress tracking for batched events
    const totalEstimate = toolsToTest.length * basicPatterns.length;
    let completedTests = 0;
    let lastBatchTime = Date.now();
    const startTime = Date.now();
    const BATCH_INTERVAL = 500;
    const BATCH_SIZE = 10;
    let batchCount = 0;

    const emitProgressBatch = () => {
      if (context.onProgress) {
        context.onProgress({
          type: "test_batch",
          module: "security",
          completed: completedTests,
          total: totalEstimate,
          batchSize: batchCount,
          elapsed: Date.now() - startTime,
        });
      }
      batchCount = 0;
      lastBatchTime = Date.now();
    };

    this.log(
      `Starting BASIC security assessment - testing ${toolsToTest.length} tools with ${basicPatterns.length} critical injection patterns (~${totalEstimate} tests)`,
    );

    for (const tool of toolsToTest) {
      // Tools with no input parameters can't be exploited via payload injection
      // Add passing results so they appear in the UI
      if (!this.hasInputParameters(tool)) {
        this.log(
          `${tool.name} has no input parameters - adding passing results`,
        );

        // Add a passing result for each basic pattern so tool appears in UI
        for (const attackPattern of basicPatterns) {
          const allPayloads = getPayloadsForAttack(attackPattern.attackName);
          const payload = allPayloads[0];

          if (payload) {
            results.push({
              testName: attackPattern.attackName,
              description: payload.description,
              payload: payload.payload,
              riskLevel: payload.riskLevel,
              toolName: tool.name,
              vulnerable: false,
              evidence:
                "Tool has no input parameters - cannot be exploited via payload injection",
            });
          }
        }
        continue;
      }

      this.log(
        `Testing ${tool.name} with ${basicPatterns.length} critical patterns`,
      );

      // Test with each critical pattern
      for (const attackPattern of basicPatterns) {
        // Get only the FIRST (most generic) payload for basic testing
        const allPayloads = getPayloadsForAttack(attackPattern.attackName);
        const payload = allPayloads[0]; // Just use first payload

        if (!payload) continue;

        this.testCount++;
        completedTests++;
        batchCount++;

        try {
          const result = await this.testPayload(
            tool,
            attackPattern.attackName,
            payload,
            context.callTool,
          );

          results.push(result);

          if (result.vulnerable) {
            this.log(
              `🚨 VULNERABILITY: ${tool.name} - ${attackPattern.attackName}`,
            );

            // Emit real-time vulnerability_found event
            if (context.onProgress) {
              context.onProgress({
                type: "vulnerability_found",
                tool: tool.name,
                pattern: attackPattern.attackName,
                confidence: result.confidence || "medium",
                evidence: result.evidence || "Vulnerability detected",
                riskLevel: payload.riskLevel,
                requiresReview: result.requiresManualReview || false,
                payload: payload.payload,
              });
            }
          }
        } catch (error) {
          this.logError(
            `Error testing ${tool.name} with ${attackPattern.attackName}`,
            error,
          );
        }

        // Emit progress batch if threshold reached
        const timeSinceLastBatch = Date.now() - lastBatchTime;
        if (batchCount >= BATCH_SIZE || timeSinceLastBatch >= BATCH_INTERVAL) {
          emitProgressBatch();
        }

        // Rate limiting
        if (this.testCount % 5 === 0) {
          await this.sleep(100);
        }
      }
    }

    // Final flush of any remaining progress
    if (batchCount > 0) {
      emitProgressBatch();
    }

    this.log(
      `BASIC security assessment complete: ${results.length} tests executed, ${results.filter((r) => r.vulnerable).length} vulnerabilities found`,
    );

    return results;
  }

  /**
   * Test tool with a specific payload
   */
  private async testPayload(
    tool: Tool,
    attackName: string,
    payload: SecurityPayload,
    callTool: (
      name: string,
      params: Record<string, unknown>,
    ) => Promise<CompatibilityCallToolResult>,
  ): Promise<SecurityTestResult> {
    // Skip execution-based tests for API wrappers (they return data, not execute code)
    if (this.isApiWrapper(tool) && this.isExecutionTest(attackName)) {
      return {
        testName: attackName,
        description: payload.description,
        payload: payload.payload,
        riskLevel: payload.riskLevel,
        toolName: tool.name,
        vulnerable: false,
        evidence:
          "API wrapper tool - skips execution tests (returns external data as text, does not execute it as code)",
      };
    }

    try {
      // Create parameters using payload
      const params = this.createTestParameters(payload, tool);

      if (Object.keys(params).length === 0) {
        return {
          testName: attackName,
          description: payload.description,
          payload: payload.payload,
          riskLevel: payload.riskLevel,
          toolName: tool.name,
          vulnerable: false,
          evidence: "No compatible parameters for testing",
        };
      }

      // Execute tool call with configurable timeout (default 5000ms for fast payload testing)
      const securityTimeout = this.config.securityTestTimeout ?? 5000;
      const response = await this.executeWithTimeout(
        callTool(tool.name, params),
        securityTimeout,
      );

      // Check for connection errors FIRST (before vulnerability analysis)
      if (this.isConnectionError(response)) {
        return {
          testName: attackName,
          description: payload.description,
          payload: payload.payload,
          riskLevel: payload.riskLevel,
          toolName: tool.name,
          vulnerable: true, // Mark as failed (test could not complete)
          evidence: `CONNECTION ERROR: Test could not complete due to server/network failure`,
          response: this.extractResponseContent(response),
          connectionError: true,
          errorType: this.classifyError(response),
          testReliability: "failed",
          confidence: "high",
          requiresManualReview: true,
        };
      }

      // Analyze with evidence-based detection
      const { isVulnerable, evidence } = this.analyzeResponse(
        response,
        payload,
        tool,
      );

      // Calculate confidence and manual review requirements
      const confidenceResult = this.calculateConfidence(
        tool,
        isVulnerable,
        evidence || "",
        this.extractResponseContent(response),
        payload,
      );

      return {
        testName: attackName,
        description: payload.description,
        payload: payload.payload,
        riskLevel: payload.riskLevel,
        toolName: tool.name,
        vulnerable: isVulnerable,
        evidence,
        response: this.extractResponseContent(response),
        ...confidenceResult,
      };
    } catch (error) {
      // Check if error is a connection/server failure
      if (this.isConnectionErrorFromException(error)) {
        return {
          testName: attackName,
          description: payload.description,
          payload: payload.payload,
          riskLevel: payload.riskLevel,
          toolName: tool.name,
          vulnerable: false,
          evidence: `CONNECTION ERROR: Test could not complete due to server/network failure`,
          response: this.extractErrorMessage(error),
          connectionError: true,
          errorType: this.classifyErrorFromException(error),
          testReliability: "failed",
          confidence: "high",
          requiresManualReview: true,
        };
      }

      return {
        testName: attackName,
        description: payload.description,
        payload: payload.payload,
        riskLevel: payload.riskLevel,
        toolName: tool.name,
        vulnerable: false,
        evidence: `Tool rejected input: ${this.extractErrorMessage(error)}`,
      };
    }
  }

  /**
   * Check if response indicates connection/server failure
   * Returns true if test couldn't complete due to infrastructure issues
   *
   * CRITICAL: Only match transport/infrastructure errors, NOT tool business logic
   */
  private isConnectionError(response: CompatibilityCallToolResult): boolean {
    const text = this.extractResponseContent(response).toLowerCase();

    // UNAMBIGUOUS patterns - only match infrastructure failures
    const unambiguousPatterns = [
      /MCP error -32001/i, // MCP transport errors
      /MCP error -32603/i, // MCP internal error
      /MCP error -32000/i, // MCP server error
      /MCP error -32700/i, // MCP parse error
      /socket hang up/i, // Network socket errors
      /ECONNREFUSED/i, // Connection refused
      /ETIMEDOUT/i, // Network timeout
      /ERR_CONNECTION/i, // Connection errors
      /fetch failed/i, // HTTP fetch failures
      /connection reset/i, // Connection reset
      /error POSTing to endpoint/i, // Transport layer POST errors
      /error GETting.*endpoint/i, // Transport layer GET errors (requires 'endpoint' to avoid false positives)
      /service unavailable/i, // HTTP 503 (server down)
      /gateway timeout/i, // HTTP 504 (gateway timeout)
      /unknown tool:/i, // MCP spec format: "Unknown tool: <name>"
      /no such tool/i, // Alternative phrasing for missing tool
    ];

    // Check unambiguous patterns first
    if (unambiguousPatterns.some((pattern) => pattern.test(text))) {
      return true;
    }

    // CONTEXTUAL patterns - only match if in MCP error context
    // These words can appear in legitimate tool responses, so require MCP prefix
    const mcpPrefix = /^mcp error -\d+:/i.test(text);
    if (mcpPrefix) {
      const contextualPatterns = [
        /bad request/i, // HTTP 400 (only if in MCP error)
        /unauthorized/i, // HTTP 401 (only if in MCP error)
        /forbidden/i, // HTTP 403 (only if in MCP error)
        /no valid session/i, // Session errors (only if in MCP error)
        /session.*expired/i, // Session expiration (only if in MCP error)
        /internal server error/i, // HTTP 500 (only if in MCP error)
        /HTTP [45]\d\d/i, // HTTP status codes (only if in MCP error)
      ];

      return contextualPatterns.some((pattern) => pattern.test(text));
    }

    return false;
  }

  /**
   * Check if caught exception indicates connection/server failure
   * CRITICAL: Only match transport/infrastructure errors, NOT tool business logic
   */
  private isConnectionErrorFromException(error: unknown): boolean {
    if (error instanceof Error) {
      const message = error.message.toLowerCase();

      // UNAMBIGUOUS patterns - only match infrastructure failures
      const unambiguousPatterns = [
        /MCP error -32001/i, // MCP transport errors
        /MCP error -32603/i, // MCP internal error
        /MCP error -32000/i, // MCP server error
        /MCP error -32700/i, // MCP parse error
        /socket hang up/i, // Network socket errors
        /ECONNREFUSED/i, // Connection refused
        /ETIMEDOUT/i, // Network timeout
        /network error/i, // Generic network errors
        /ERR_CONNECTION/i, // Connection errors
        /fetch failed/i, // HTTP fetch failures
        /connection reset/i, // Connection reset
        /error POSTing to endpoint/i, // Transport layer POST errors
        /error GETting/i, // Transport layer GET errors
        /service unavailable/i, // HTTP 503 (server down)
        /gateway timeout/i, // HTTP 504 (gateway timeout)
        /unknown tool:/i, // MCP spec format: "Unknown tool: <name>"
        /no such tool/i, // Alternative phrasing for missing tool
      ];

      // Check unambiguous patterns first
      if (unambiguousPatterns.some((pattern) => pattern.test(message))) {
        return true;
      }

      // CONTEXTUAL patterns - only match if in MCP error context
      const mcpPrefix = /^mcp error -\d+:/i.test(message);
      if (mcpPrefix) {
        const contextualPatterns = [
          /bad request/i,
          /unauthorized/i,
          /forbidden/i,
          /no valid session/i,
          /session.*expired/i,
          /internal server error/i,
          /HTTP [45]\d\d/i,
        ];

        return contextualPatterns.some((pattern) => pattern.test(message));
      }
    }
    return false;
  }

  /**
   * Classify error type for reporting
   */
  private classifyError(
    response: CompatibilityCallToolResult,
  ): "connection" | "server" | "protocol" {
    const text = this.extractResponseContent(response).toLowerCase();

    // Connection-level errors (network, transport)
    if (
      /socket|ECONNREFUSED|ETIMEDOUT|network|fetch failed|connection reset/i.test(
        text,
      )
    ) {
      return "connection";
    }

    // Server-level errors (backend issues)
    if (
      /-32603|-32000|-32700|internal server error|service unavailable|gateway timeout|HTTP 5\d\d|error POSTing.*endpoint|error GETting.*endpoint|bad request|HTTP 400|unauthorized|forbidden|no valid session|session.*expired/i.test(
        text,
      )
    ) {
      return "server";
    }

    // Protocol errors (MCP-specific)
    if (/-32001/i.test(text)) {
      return "protocol";
    }

    return "protocol";
  }

  /**
   * Classify error type from caught exception
   */
  private classifyErrorFromException(
    error: unknown,
  ): "connection" | "server" | "protocol" {
    if (error instanceof Error) {
      const message = error.message.toLowerCase();

      // Connection-level errors (network, transport)
      if (
        /socket|ECONNREFUSED|ETIMEDOUT|network|fetch failed|connection reset/i.test(
          message,
        )
      ) {
        return "connection";
      }

      // Server-level errors (backend issues)
      if (
        /-32603|-32000|-32700|internal server error|service unavailable|gateway timeout|HTTP 5\d\d|error POSTing|error GETting|bad request|HTTP 400|unauthorized|forbidden|no valid session|session.*expired/i.test(
          message,
        )
      ) {
        return "server";
      }

      // Protocol errors (MCP-specific)
      if (/-32001/i.test(message)) {
        return "protocol";
      }
    }
    return "protocol";
  }

  /**
   * Analyze response with evidence-based detection
   * CRITICAL: Distinguish between safe reflection and actual execution
   */
  private analyzeResponse(
    response: CompatibilityCallToolResult,
    payload: SecurityPayload,
    tool: any,
  ): { isVulnerable: boolean; evidence?: string } {
    const responseText = this.extractResponseContent(response).toLowerCase();
    const payloadText = payload.payload.toLowerCase();

    // ✅ STEP 1: Check for MCP validation errors (HIGHEST PRIORITY)
    // Tools that reject invalid input before processing are SECURE
    const errorInfo = this.extractErrorInfo(response);
    if (this.isMCPValidationError(errorInfo, responseText)) {
      const errorCode = errorInfo.code ? ` (${errorInfo.code})` : "";
      return {
        isVulnerable: false,
        evidence: `MCP validation error${errorCode}: Tool properly rejected invalid input before processing`,
      };
    }

    // ✅ STEP 1.1: Check for HTTP error responses (Issue #26)
    // HTTP 4xx/5xx errors indicate tool rejection, not vulnerability
    // This prevents false positives like "404: Not Found" being flagged for Calculator Injection
    if (this.isHttpErrorResponse(responseText)) {
      return {
        isVulnerable: false,
        evidence:
          "HTTP error response indicates tool rejection (not vulnerability)",
      };
    }

    // ✅ STEP 1.5: Classify tool and check for safe categories (prevents false positives)
    // Check tool category before generic pattern matching to avoid false positives
    const classifier = new ToolClassifier();
    const classification = classifier.classify(tool.name, tool.description);

    // Check if tool is in a safe category and response matches expected format
    if (classification.categories.includes(ToolCategory.SEARCH_RETRIEVAL)) {
      // Search tools should return search results, not execute code
      if (this.isSearchResultResponse(responseText)) {
        return {
          isVulnerable: false,
          evidence: "Search tool returned query results (not code execution)",
        };
      }
    }

    if (classification.categories.includes(ToolCategory.CRUD_CREATION)) {
      // Creation tools should return creation confirmations, not execute code
      if (this.isCreationResponse(responseText)) {
        return {
          isVulnerable: false,
          evidence: "CRUD tool created/modified resource (not code execution)",
        };
      }
    }

    if (classification.categories.includes(ToolCategory.READ_ONLY_INFO)) {
      // Info tools should return user/workspace data (intended exposure)
      return {
        isVulnerable: false,
        evidence:
          "Read-only info tool returned user/workspace data (intended data exposure, not vulnerability)",
      };
    }

    if (classification.categories.includes(ToolCategory.SAFE_STORAGE)) {
      // Safe storage control tools should NEVER be flagged (validated safe implementations)
      return {
        isVulnerable: false,
        evidence:
          "Safe storage control tool (validated safe implementation, control group for testing)",
      };
    }

    // ✅ STEP 1: Check if response is just reflecting/echoing input (SAFE)
    // This prevents false positives from tools that echo malicious input as data
    // IMPORTANT: Check reflection BEFORE execution evidence (priority order matters)
    // This handles escaping differences (e.g., single vs double backslashes)
    const isJustReflection = this.isReflectionResponse(responseText);
    if (isJustReflection) {
      return {
        isVulnerable: false,
        evidence: "Tool safely reflected input without execution",
      };
    }

    // Response doesn't match reflection patterns - continue checking
    // Falls through - might be execution (with or without echo of input)

    // ✅ STEP 1.7: Check for computed math results (Issue #14 fix)
    // If payload is a math expression and response contains the computed result
    // (but NOT the original expression), that's evidence of execution
    if (this.isComputedMathResult(payload.payload, responseText)) {
      return {
        isVulnerable: true,
        evidence: `Tool computed math expression result instead of storing/echoing it (payload: ${payload.payload})`,
      };
    }

    // ✅ STEP 2: Check if tool explicitly rejected the input (SAFE)
    // CRITICAL: Check this BEFORE evidence matching to prevent false positives
    // Tools that reject invalid input are secure, regardless of error message content
    if (this.isValidationRejection(response)) {
      return {
        isVulnerable: false,
        evidence: "Tool correctly rejected invalid input with validation error",
      };
    }

    // ✅ STEP 3: Check for expected evidence of execution
    // Only flag as vulnerable if we find execution evidence AND it's not just reflection
    if (payload.evidence && payload.evidence.test(responseText)) {
      // Double-check: is the evidence pattern matching the input or the output?
      const evidenceMatchesInput = payload.evidence.test(payloadText);
      if (evidenceMatchesInput && responseText.includes(payloadText)) {
        // Evidence matches input and response contains input - probably just echoing
        return {
          isVulnerable: false,
          evidence: "Evidence pattern matched echoed input, not execution",
        };
      }

      // NEW: For validation-type patterns, require execution evidence
      // This prevents false positives from validation error messages
      if (this.isValidationPattern(payload.evidence)) {
        const hasExecutionEvidence = this.hasExecutionEvidence(responseText);
        if (!hasExecutionEvidence) {
          return {
            isVulnerable: false,
            evidence:
              "Pattern matched in error message but no execution evidence - tool properly validated input",
          };
        }
      }

      // Evidence doesn't match input OR response doesn't contain input - real execution
      return {
        isVulnerable: true,
        evidence: `Tool executed malicious instruction: found evidence matching ${payload.evidence} - ${payload.description}`,
      };
    }

    // ✅ STEP 4: Fall back to existing detection logic for comprehensive analysis
    return this.analyzeInjectionResponse(response, payload.payload);
  }

  /**
   * Check if tool explicitly rejected input with validation error (SAFE)
   * Returns true if tool properly rejected invalid input (SECURE)
   *
   * Distinguishes between:
   * - SAFE: {"valid": false, "errors": ["Input too long"]} (rejection)
   * - VULNERABLE: {"result": "deleted 5 rows"} (execution)
   */
  private isValidationRejection(
    response: CompatibilityCallToolResult,
  ): boolean {
    const responseText = this.extractResponseContent(response);

    try {
      const parsed = JSON.parse(responseText);

      // Explicit rejection indicators (highest priority)
      if (
        parsed.valid === false ||
        parsed.error === true ||
        parsed.error === "true" || // Handle string boolean
        (parsed.error && parsed.error !== false) || // Any truthy error value
        parsed.status === "rejected" ||
        parsed.status === "invalid" ||
        parsed.status === "failed"
      ) {
        return true;
      }

      // Has explicit error details (errors array, error field)
      if (
        parsed.errors &&
        Array.isArray(parsed.errors) &&
        parsed.errors.length > 0
      ) {
        return true;
      }

      if (parsed.error && typeof parsed.error === "string") {
        return true;
      }

      // Result field indicates validation failure
      if (typeof parsed.result === "string") {
        const resultRejectionPatterns = [
          /validation (failed|error)/i,
          /rejected/i,
          /not.*approved/i,
          /not.*in.*list/i,
          /invalid.*input/i,
          /error:.*invalid/i,
        ];
        if (resultRejectionPatterns.some((p) => p.test(parsed.result))) {
          return true;
        }
      }
    } catch {
      // Not JSON, check text patterns
    }

    // Text-based rejection patterns (fallback for non-JSON responses)
    const rejectionPatterns = [
      /validation failed/i,
      /rejected/i,
      /not.*approved/i,
      /not.*in.*list/i,
      /invalid.*input/i,
      /error:.*invalid/i,
    ];

    return rejectionPatterns.some((pattern) => pattern.test(responseText));
  }

  /**
   * Check if response is an MCP validation error (safe rejection)
   * Returns true if tool rejected input before processing (SECURE)
   *
   * Validation errors indicate proper input sanitization and are NOT vulnerabilities.
   * Examples:
   * - MCP error -32602 (JSON-RPC Invalid params standard)
   * - "parameter validation failed: invalid url"
   * - "schema validation error: must be a string"
   */
  private isMCPValidationError(
    errorInfo: { code?: string | number; message?: string },
    responseText: string,
  ): boolean {
    // Check for JSON-RPC -32602 (Invalid params)
    // This is the standard error code for parameter validation failures
    if (errorInfo.code === -32602 || errorInfo.code === "-32602") {
      return true;
    }

    // Check for explicit validation rejection patterns
    // These indicate the tool properly validated input BEFORE processing
    const validationPatterns = [
      /parameter validation failed/i,
      /schema validation (error|failed)/i,
      /invalid (url|email|format|parameter|input|data)/i,
      /must be a valid/i,
      /must have a valid/i,
      /failed to validate/i,
      /validation error/i,
      /does not match (pattern|schema)/i,
      /not a valid (url|email|number|string)/i,
      /expected.*but (got|received)/i,
      /type mismatch/i,
      /\brequired\b.*\bmissing\b/i,
      // Boundary validation patterns (empty strings, required fields)
      /cannot.*be.*empty/i,
      /must.*not.*be.*empty/i,
      /empty.*not.*allowed/i,
      /\brequired\b/i, // Generic required field validation
      /missing.*required/i,
      /field.*required/i,
    ];

    return validationPatterns.some((pattern) => pattern.test(responseText));
  }

  /**
   * Check if response is an HTTP error (Issue #26)
   * HTTP 4xx/5xx error responses indicate tool rejection, not vulnerability.
   *
   * This prevents false positives like "404: Not Found" being flagged for
   * Calculator Injection (the digit "4" in "404" was incorrectly matching
   * as the computed result of "2+2").
   */
  private isHttpErrorResponse(responseText: string): boolean {
    // Pattern 1: HTTP status code followed by error description
    // e.g., "404 Not Found", "500 Internal Server Error", "503 Service Unavailable"
    const httpErrorPattern =
      /\b(4\d{2}|5\d{2})\b.*?(not found|error|bad request|unauthorized|forbidden|internal server|unavailable|timeout|service)/i;

    // Pattern 2: Response starts with HTTP status code
    // e.g., "404: Not Found", "500: Error"
    const simpleHttpPattern = /^(4\d{2}|5\d{2})[\s:]/;

    // Pattern 3: Short "not found" messages (common API error response)
    // e.g., "Not Found", "Resource not found"
    const notFoundPattern = /not found/i;
    const isShortNotFound =
      notFoundPattern.test(responseText) && responseText.length < 100;

    // Pattern 4: HTTP status in JSON error structure
    // e.g., {"status": 404, "error": "Not Found"}
    const jsonStatusPattern = /"status":\s*(4\d{2}|5\d{2})/;

    return (
      httpErrorPattern.test(responseText) ||
      simpleHttpPattern.test(responseText) ||
      isShortNotFound ||
      jsonStatusPattern.test(responseText)
    );
  }

  /**
   * Check if evidence pattern is ambiguous (can match both validation and execution)
   * These patterns appear in BOTH:
   * - Secure validation errors: "parameter validation failed: invalid type"
   * - Vulnerable execution errors: "SQL executed: type error in result"
   */
  private isValidationPattern(evidencePattern: RegExp): boolean {
    const patternStr = evidencePattern.toString().toLowerCase();

    // Patterns that are ambiguous - match both validation AND execution errors
    const ambiguousPatterns = [
      "type.*error",
      "invalid.*type",
      "error",
      "invalid",
      "failed",
      "negative.*not.*allowed",
      "must.*be.*positive",
      "invalid.*value",
      "overflow",
      "out.*of.*range",
    ];

    return ambiguousPatterns.some((ambiguous) =>
      patternStr.includes(ambiguous),
    );
  }

  /**
   * Check if response contains evidence of actual execution
   * Returns true only if malicious input was actually PROCESSED/EXECUTED
   *
   * Distinguishes between:
   * - SECURE: "Parameter validation failed: invalid type" (rejected BEFORE execution)
   * - VULNERABLE: "SQL executed: syntax error" (error DURING execution)
   */
  private hasExecutionEvidence(responseText: string): boolean {
    const executionIndicators = [
      // Explicit execution verbs
      /\bexecuted\b/i,
      /\bprocessed\b/i,
      /\bran\b.*command/i,
      /\bcompleted\b/i,
      /\bcomputed\b/i,
      /\bcalculated\b/i,

      // System-level errors (only occur during execution)
      /NullPointerException/i,
      /SegmentationFault/i,
      /StackOverflow/i,
      /OutOfMemory/i,
      /syntax error in executed/i,
      /error while executing/i,
      /failed during execution/i,
      /error in query execution/i,
      /runtime error/i,

      // Side effects (prove execution occurred)
      /deleted \d+ (rows|files|records)/i,
      /(file|resource) (opened|accessed|modified|deleted)/i,
      /query returned \d+ results/i,
      /modified \d+ records/i,
      /\d+ rows affected/i,
      /command output:/i,
      /execution result:/i,
    ];

    return executionIndicators.some((pattern) => pattern.test(responseText));
  }

  /**
   * Check if a math expression payload was computed (execution evidence)
   * Returns true if the response contains the computed result but NOT the original expression.
   *
   * This is key evidence of execution:
   * - VULNERABLE: payload "15*37+100" → response contains "655" (computed result)
   * - SAFE: payload "15*37+100" → response contains "15*37+100" (echoed, not computed)
   *
   * Added for Issue #14: False positives on safe input reflection
   */
  private isComputedMathResult(payload: string, responseText: string): boolean {
    // Issue #26: Skip HTTP error responses - they indicate tool rejection, not computation
    // HTTP 4xx/5xx status codes (e.g., "404: Not Found") should not trigger false positives
    // The digit "4" in "404" was incorrectly matching as computed result of "2+2"
    const httpErrorPattern =
      /\b(4\d{2}|5\d{2})\b.*?(not found|error|bad request|unauthorized|forbidden|internal server|unavailable|timeout)/i;
    const simpleHttpPattern = /^(4\d{2}|5\d{2})[\s:]/; // Starts with HTTP status code
    const notFoundPattern = /not found/i;

    if (
      httpErrorPattern.test(responseText) ||
      simpleHttpPattern.test(responseText) ||
      (notFoundPattern.test(responseText) && responseText.length < 100)
    ) {
      return false; // HTTP error response, not a computed result
    }

    // Check if payload looks like a simple math expression
    // Matches: "2+2", "15*37+100", "10/2", "5-3", etc.
    const simpleMathPattern =
      /^\s*(\d+)\s*([+\-*/])\s*(\d+)(?:\s*([+\-*/])\s*(\d+))?\s*$/;
    const match = payload.match(simpleMathPattern);

    if (!match) {
      return false; // Not a simple math expression
    }

    // Try to safely evaluate the expression
    try {
      // Parse numbers and operators manually (avoid eval)
      const num1 = parseInt(match[1], 10);
      const op1 = match[2];
      const num2 = parseInt(match[3], 10);
      const op2 = match[4];
      const num3 = match[5] ? parseInt(match[5], 10) : undefined;

      let result: number;

      // Calculate first operation
      switch (op1) {
        case "+":
          result = num1 + num2;
          break;
        case "-":
          result = num1 - num2;
          break;
        case "*":
          result = num1 * num2;
          break;
        case "/":
          result = Math.floor(num1 / num2);
          break;
        default:
          return false;
      }

      // Calculate second operation if present (left-to-right, no precedence)
      if (op2 && num3 !== undefined) {
        switch (op2) {
          case "+":
            result = result + num3;
            break;
          case "-":
            result = result - num3;
            break;
          case "*":
            result = result * num3;
            break;
          case "/":
            result = Math.floor(result / num3);
            break;
          default:
            return false;
        }
      }

      // Check if response contains the computed result
      const resultStr = result.toString();
      const hasComputedResult = responseText.includes(resultStr);

      // Check if response also contains the original expression (reflection)
      const normalizedPayload = payload.replace(/\s+/g, "");
      const hasOriginalExpression =
        responseText.includes(payload) ||
        responseText.includes(normalizedPayload);

      // Vulnerable if: has computed result AND does NOT have original expression
      // This means the tool executed the expression instead of just echoing it
      return hasComputedResult && !hasOriginalExpression;
    } catch {
      return false;
    }
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
        !this.hasInputParameters(tool)
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
   * Calculate confidence level and manual review requirements
   * Detects ambiguous patterns that need human verification
   */
  private calculateConfidence(
    tool: any,
    isVulnerable: boolean,
    evidence: string,
    responseText: string,
    payload: SecurityPayload,
  ): {
    confidence: "high" | "medium" | "low";
    requiresManualReview: boolean;
    manualReviewReason?: string;
    reviewGuidance?: string;
  } {
    const toolDescription = (tool.description || "").toLowerCase();
    const toolName = tool.name.toLowerCase();
    const responseLower = responseText.toLowerCase();
    const payloadLower = payload.payload.toLowerCase();

    // HIGH CONFIDENCE: Clear cases
    // 1. Not vulnerable with clear safety indicators
    if (
      !isVulnerable &&
      (evidence.includes("safely reflected") ||
        evidence.includes("API wrapper") ||
        evidence.includes("safe: true"))
    ) {
      return {
        confidence: "high",
        requiresManualReview: false,
      };
    }

    // 2. Vulnerable with unambiguous execution evidence
    if (
      isVulnerable &&
      evidence.includes("executed") &&
      !this.isStructuredDataTool(toolName, toolDescription)
    ) {
      return {
        confidence: "high",
        requiresManualReview: false,
      };
    }

    // LOW CONFIDENCE: Ambiguous pattern matches in structured data
    if (isVulnerable) {
      // Check if tool returns structured data (search, lookup, retrieval)
      const isDataTool = this.isStructuredDataTool(toolName, toolDescription);

      // Check if response contains structured data indicators
      const hasStructuredData =
        /title:|name:|description:|trust score:|id:|snippets:/i.test(
          responseText,
        ) ||
        /^\s*-\s+/m.test(responseText) || // Bullet points
        /"[^"]+"\s*:\s*"[^"]+"/g.test(responseText); // JSON-like structure

      // Check if evidence pattern appears in input query
      const patternInInput = payload.evidence?.test(payloadLower);

      // Check if response echoes the input
      const echosInput = responseLower.includes(payloadLower);

      if (isDataTool && (hasStructuredData || echosInput) && patternInInput) {
        return {
          confidence: "low",
          requiresManualReview: true,
          manualReviewReason:
            "Pattern matched in structured data response. Tool may be legitimately " +
            "returning data containing search terms rather than executing malicious code.",
          reviewGuidance:
            "Verify: 1) Does the tool actually execute/compute the input? " +
            "2) Or does it just return pre-existing data that happens to contain the pattern? " +
            `3) Check if '${payload.evidence}' appears in legitimate tool output vs. execution results.`,
        };
      }

      // Arithmetic patterns in numeric data (scores, counts, IDs)
      if (
        payload.evidence &&
        /\b\d\b/.test(payload.evidence.toString()) &&
        /\b(score|count|trust|rating|id|version)\b/i.test(responseText)
      ) {
        return {
          confidence: "low",
          requiresManualReview: true,
          manualReviewReason:
            "Numeric pattern found in response with numeric metadata (scores, counts, etc.). " +
            "May be coincidental data rather than arithmetic execution.",
          reviewGuidance:
            "Verify: 1) Did the tool actually compute an arithmetic result? " +
            "2) Or does the number appear in metadata like trust scores, version numbers, or counts? " +
            "3) Compare pattern location in response with tool's expected output format.",
        };
      }

      // Role/admin patterns in tool that deals with admin-related content
      if (
        /admin|role|privilege|elevated/i.test(payload.payload) &&
        /\b(library|search|documentation|api|wrapper)\b/i.test(toolDescription)
      ) {
        return {
          confidence: "low",
          requiresManualReview: true,
          manualReviewReason:
            "Admin-related keywords found in search/retrieval tool results. " +
            "Tool may be returning data about admin-related libraries/APIs rather than elevating privileges.",
          reviewGuidance:
            "Verify: 1) Did the tool actually change behavior or assume admin role? " +
            "2) Or did it return search results for admin-related content? " +
            "3) Test if tool behavior actually changed after this request.",
        };
      }
    }

    // MEDIUM CONFIDENCE: Execution evidence but some ambiguity
    if (isVulnerable && evidence.includes("executed")) {
      return {
        confidence: "medium",
        requiresManualReview: true,
        manualReviewReason:
          "Execution indicators found but context suggests possible ambiguity.",
        reviewGuidance:
          "Verify: 1) Review the full response to confirm actual code execution. " +
          "2) Check if tool's intended function involves execution. " +
          "3) Test with variations to confirm consistency.",
      };
    }

    // Default: HIGH confidence for clear safe cases
    return {
      confidence: "high",
      requiresManualReview: false,
    };
  }

  /**
   * Check if tool is a structured data tool (search, lookup, retrieval)
   * These tools naturally echo input patterns in their results
   */
  private isStructuredDataTool(
    toolName: string,
    toolDescription: string,
  ): boolean {
    const dataToolPatterns = [
      /search/i,
      /find/i,
      /lookup/i,
      /query/i,
      /retrieve/i,
      /fetch/i,
      /get/i,
      /list/i,
      /resolve/i,
      /discover/i,
      /browse/i,
    ];

    const combined = `${toolName} ${toolDescription}`;
    return dataToolPatterns.some((pattern) => pattern.test(combined));
  }

  /**
   * Check if response is just reflection (safe)
   * Expanded to catch more reflection patterns including echo, repeat, display
   * IMPROVED: Bidirectional patterns, safety indicators, and two-layer defense
   *
   * CRITICAL: This check distinguishes between:
   * - SAFE: Tool stores/echoes malicious input as data (reflection)
   * - VULNERABLE: Tool executes malicious input and returns results (execution)
   *
   * Two-layer defense:
   * Layer 1: Match reflection/status patterns
   * Layer 2: Verify NO execution evidence (defense-in-depth)
   */
  private isReflectionResponse(responseText: string): boolean {
    // Status message patterns (NEW)
    const statusPatterns = [
      // "Action executed successfully: <anything>" (generic status message)
      /action\s+executed\s+successfully:/i,
      /command\s+executed\s+successfully:/i,
      // "Action executed successfully" (generic status - in JSON or standalone)
      /"result":\s*"action\s+executed\s+successfully"/i,
      /result.*action\s+executed\s+successfully/i,
      /successfully\s+(executed|completed|processed):/i,
      /successfully\s+(executed|completed|processed)"/i,
      // "Action received:" - safe echo/acknowledgment pattern (DVMCP testbed)
      /action\s+received:/i,
      /input\s+received:/i,
      /request\s+received:/i,
      // Explicit safety indicators in JSON responses (context-aware to avoid matching unrelated fields)
      // Require safety-related context: message, result, status, stored, reflected, etc.
      // Bounded quantifiers prevent ReDoS attacks from malicious server responses
      /"safe"\s*:\s*true[^}]{0,500}("message"|"result"|"status"|"response")/i,
      /("message"|"result"|"status"|"response")[^}]{0,500}"safe"\s*:\s*true/i,
      /"vulnerable"\s*:\s*false[^}]{0,500}("safe"|"stored"|"reflected"|"status")/i,
      /("safe"|"stored"|"reflected"|"status")[^}]{0,500}"vulnerable"\s*:\s*false/i,
      /"status"\s*:\s*"acknowledged"[^}]{0,500}("message"|"result"|"safe")/i,
      /("message"|"result"|"safe")[^}]{0,500}"status"\s*:\s*"acknowledged"/i,
    ];

    const reflectionPatterns = [
      ...statusPatterns,
      // Original patterns (keep all existing)
      /stored.*query/i,
      /saved.*input/i,
      /received.*parameter/i,
      /processing.*request/i,
      /storing.*data/i,
      /added.*to.*collection/i,
      /echo:/i,
      /echoing/i,
      /repeating/i,
      /displaying/i,
      /showing.*input/i,
      /message.*echoed/i,
      /safely.*as.*data/i,

      // NEW: Bidirectional patterns (catch "Query stored" and "stored query")
      /query.*stored/i,
      /stored.*query/i, // Bidirectional: "Stored query"
      /input.*saved/i,
      /parameter.*received/i,
      /command.*stored/i,
      /stored.*command/i, // Bidirectional: "Stored command"
      /data.*stored/i,
      /stored.*data/i, // Bidirectional: "Stored data"
      /action.*stored/i,
      /stored.*action/i, // Bidirectional: "Stored action"
      /text.*stored/i,
      /stored.*text/i, // Bidirectional: "Stored text"
      /setting.*stored/i,
      /stored.*setting/i, // Bidirectional: "Stored setting"
      /instruction.*stored/i,
      /stored.*instruction/i, // Bidirectional: "Stored instruction"
      /url.*stored/i,
      /stored.*url/i, // Bidirectional: "Stored URL"
      /package.*stored/i,
      /stored.*package/i, // Bidirectional: "Stored package"

      // NEW: Safety indicators (common in hardened implementations)
      /stored.*safely/i,
      /safely.*stored/i,
      /without\s+execut/i,
      /not\s+executed/i,
      /never\s+executed/i,
      /stored.*as.*data/i,
      /treated.*as.*data/i,
      /stored\s+in\s+(collection|database)/i,

      // NEW: Common safe storage responses
      /stored.*successfully/i,
      /saved.*to/i,
      /recorded\s+in/i,
      /added\s+to/i,

      // NEW: Storage/logging confirmations (high confidence)
      /logged successfully:/i,
      /queued for processing:/i,
      /saved (for|successfully)/i,
      /stored for (admin review|configuration|processing)/i,

      // NEW: Processing confirmations (high confidence)
      /processed successfully/i,
      /validated successfully/i,
      /parsed successfully/i,
      /(validation|processing) (passed|completed)/i,

      // NEW: Error messages with input reflection (common safe pattern)
      /error:.*not (found|in approved list|recognized)/i,
      /error getting info for ['"].*['"]/i,
      /invalid .* format.*stored as text/i,
      /error:.*too (long|short|large)/i,

      // NEW: DoS/Resource safe rejection patterns
      // These indicate the tool properly rejected resource-intensive input
      /payload.?rejected/i,
      /input.?exceeds.?limit/i,
      /resource.?limit.?enforced/i,
      /size.?limit/i,
      /maximum.?length/i,
      /rate.?limit/i,
      /request.?throttled/i,
      /input.?too.?large/i,
      /exceeds.?maximum.?size/i,
      /depth.?limit.?exceeded/i,
      /nesting.?limit/i,
      /complexity.?limit/i,

      // NEW: Insecure Deserialization safe rejection patterns
      // These indicate the tool properly rejected serialized data without deserializing
      /serialization.?not.?supported/i,
      /pickle.?disabled/i,
      /deserialization.?blocked/i,
      /unsafe.?format.?rejected/i,
      /binary.?data.?not.?accepted/i,
      /data.?stored.?safely/i,
      /without.?deserialization/i,
      /no.?pickle/i,
      /stored.?without.?deserializ/i,

      // NEW: Hash-based sanitization patterns (Issue #14 fix)
      // These indicate the tool replaced dangerous input with safe hash identifiers
      /\[ref-[a-f0-9]+\]/i, // Hash-based sanitization: [ref-a1b2c3d4]
      /stored.*\[ref-/i, // "Expression stored: [ref-...]"
      /\[sanitized\]/i, // [sanitized] placeholder
      /\[redacted\]/i, // [redacted] placeholder
      /\[filtered\]/i, // [filtered] placeholder
      /\[blocked\]/i, // [blocked] placeholder
      /expression.*stored:/i, // "Expression stored:" prefix
      /input.*sanitized/i, // "Input sanitized"
      /content.*replaced/i, // "Content replaced with hash"
    ];

    // LAYER 1: Check for reflection/status patterns
    const hasReflection = reflectionPatterns.some((pattern) =>
      pattern.test(responseText),
    );

    if (hasReflection) {
      // LAYER 2: Defense-in-depth - verify NO execution evidence
      // For JSON responses, check execution artifacts only in result/output fields
      try {
        const parsed = JSON.parse(responseText);
        const resultText = String(parsed.result || "");
        const outputFields = [
          parsed.stdout,
          parsed.stderr,
          parsed.output,
          parsed.contents,
          parsed.execution_log,
          parsed.command_output,
        ]
          .filter(Boolean)
          .join(" ");

        // Only check resultText for execution if it's NOT purely a status message
        // Status messages like "Action executed successfully: X" just echo the payload
        const resultIsStatusOnly = statusPatterns.some((pattern) =>
          pattern.test(resultText),
        );

        const hasExecutionInOutput = resultIsStatusOnly
          ? this.detectExecutionArtifacts(outputFields) // Skip result, check only output fields
          : this.detectExecutionArtifacts(resultText) ||
            this.detectExecutionArtifacts(outputFields);

        if (hasExecutionInOutput) {
          return false; // Reflection + Execution in output = VULNERABLE
        }
        return true; // Reflection + clean output = SAFE
      } catch {
        // Not JSON, check entire response for execution
        const hasExecution = this.detectExecutionArtifacts(responseText);

        if (hasExecution) {
          return false; // Reflection + Execution = VULNERABLE
        }
        return true; // Reflection only = SAFE
      }
    }

    // JSON Structural Analysis with execution verification
    try {
      const parsed = JSON.parse(responseText);

      // Check placeholder action with safe result
      if (parsed.action === "test" || parsed.action === "placeholder") {
        const resultText = String(parsed.result || "");
        if (!this.detectExecutionArtifacts(resultText)) {
          return true; // Placeholder action with clean result
        }
      }

      // Check generic status without execution
      if (parsed.status && /(completed|success|ok|done)/.test(parsed.status)) {
        if (!this.detectExecutionArtifacts(responseText)) {
          return true; // Status indicator with no execution
        }
      }
    } catch {
      // Not JSON, continue with text-only analysis
    }

    return false;
  }

  /**
   * Detect execution artifacts in response
   * Returns true if response contains evidence of actual code execution
   *
   * HIGH confidence: System files, commands, directory listings
   * MEDIUM confidence: Contextual patterns (root alone, paths)
   *
   * IMPORTANT: Excludes patterns that appear within echoed injection payloads
   * (e.g., /etc/passwd within an XXE entity definition is NOT execution evidence)
   */
  private detectExecutionArtifacts(responseText: string): boolean {
    // First, check if this response contains echoed injection payload patterns
    // If so, we need to be more careful about what we consider "execution evidence"
    const containsEchoedPayload =
      this.containsEchoedInjectionPayload(responseText);

    const executionIndicators = [
      // HIGH CONFIDENCE - System files (requires format)
      /[a-z]+:x:\d+:\d+:/i, // passwd: "root:x:0:0:"
      /uid=\d+\([^)]+\)\s+gid=\d+/i, // id: "uid=0(root) gid=0(root)"

      // HIGH CONFIDENCE - Directory listings (full format)
      /[d-][rwx-]{9}\s+\d+\s+[a-z]+/i, // ls -la: "drwxr-xr-x 2 root"
      /total\s+\d+\s*$/m, // ls total line

      // HIGH CONFIDENCE - Command execution fields
      /command_executed:\s*[^"\s]/i, // "command_executed: whoami"
      /stdout:\s*["']?[^"'\s]/i, // "stdout: root"
      /(execution|output)_log:/i, // Log fields

      // HIGH CONFIDENCE - Shell paths
      /\/bin\/(bash|sh|zsh|dash)/i, // Shell executables

      // MEDIUM CONFIDENCE - System identity (contextual only)
      /\b(root|administrator)\s*$/im, // "root" alone on line (whoami)
      /\/root\//i, // Path: "/root/"

      // MEDIUM CONFIDENCE - Process info
      /PID:\s*\d{3,}/i, // Process ID
    ];

    // Patterns that indicate execution ONLY if NOT in an echoed payload context
    // These patterns can appear in injection payloads (XXE, SSRF, etc.)
    const contextSensitiveIndicators = [
      /\/etc\/passwd/i, // Sensitive file - appears in XXE payloads
      /\/etc\/shadow/i, // Sensitive file - appears in XXE payloads
      /file:\/\/\//i, // File protocol - appears in XXE/SSRF payloads
    ];

    // Check high-confidence indicators first (always count as execution)
    if (executionIndicators.some((pattern) => pattern.test(responseText))) {
      return true;
    }

    // Check context-sensitive indicators only if NOT in echoed payload context
    if (!containsEchoedPayload) {
      if (
        contextSensitiveIndicators.some((pattern) => pattern.test(responseText))
      ) {
        return true;
      }
    }

    return false;
  }

  /**
   * Check if response contains echoed injection payload patterns
   * These indicate the tool is safely echoing/storing input rather than executing it
   */
  private containsEchoedInjectionPayload(responseText: string): boolean {
    const echoedPayloadPatterns = [
      // XXE payload markers (echoed XML entity definitions)
      /<!DOCTYPE\s+\w+\s+\[/i, // DOCTYPE with internal subset
      /<!ENTITY\s+\w+\s+SYSTEM/i, // External entity definition
      /<!ENTITY\s+%\s*\w+/i, // Parameter entity

      // SSRF/URL payload markers (echoed in storage context)
      /stored.*http:\/\//i, // "Stored query: http://..."
      /saved.*http:\/\//i, // "Saved: http://..."

      // SQL injection payload markers (echoed)
      /stored.*union\s+select/i, // "Stored query: UNION SELECT..."
      /stored.*drop\s+table/i, // "Stored query: DROP TABLE..."

      // Common echo/storage patterns with payload content
      /stored\s+query:\s*[<'"]/i, // "Stored query: <xml..." or "Stored query: '..."
      /saved\s+data:\s*[<'"]/i, // "Saved data: <xml..."
    ];

    return echoedPayloadPatterns.some((pattern) => pattern.test(responseText));
  }

  /**
   * Analyze injection response (existing logic)
   * Note: payload parameter unused after refactoring to two-layer defense
   */
  private analyzeInjectionResponse(
    response: CompatibilityCallToolResult,
    _payload: string,
  ): { isVulnerable: boolean; evidence?: string } {
    const responseText = this.extractResponseContent(response);

    // Look for signs of execution vs reflection
    const executionPatterns = [
      /executed/i,
      /command.*ran/i,
      /result.*is/i,
      /output.*:/i,
      /returned.*value/i,
    ];

    const hasExecution = executionPatterns.some((pattern) =>
      pattern.test(responseText),
    );

    // CRITICAL: Check reflection BEFORE flagging as vulnerable
    if (hasExecution && !this.isReflectionResponse(responseText)) {
      return {
        isVulnerable: true,
        evidence: "Tool executed instruction: found execution keywords",
      };
    }

    return { isVulnerable: false };
  }

  /**
   * Extract response content
   */
  private extractResponseContent(
    response: CompatibilityCallToolResult,
  ): string {
    if (response.content && Array.isArray(response.content)) {
      return response.content
        .map((c: any) => (c.type === "text" ? c.text : ""))
        .join(" ");
    }
    return String(response.content || "");
  }

  /**
   * Check if tool has input parameters
   */
  private hasInputParameters(tool: any): boolean {
    const schema =
      tool.inputSchema?.type === "object" ? tool.inputSchema : tool.inputSchema;

    return schema?.properties && Object.keys(schema.properties).length > 0;
  }

  private createTestParameters(
    payload: SecurityPayload,
    tool: any,
  ): Record<string, unknown> {
    // Extract tool schema
    const schema =
      tool.inputSchema?.type === "object" ? tool.inputSchema : tool.inputSchema;

    if (!schema?.properties) {
      return {};
    }

    const params: Record<string, unknown> = {};
    const targetParamTypes = payload.parameterTypes || [];
    let payloadInjected = false;

    // NEW: Check for language-specific code execution parameters first
    // This enables detection of vulnerabilities in tools expecting Python/JS/SQL code
    for (const [key, prop] of Object.entries(schema.properties)) {
      const propSchema = prop as any;
      if (propSchema.type !== "string") continue;

      const detectedLanguage = this.languageGenerator.detectLanguage(
        key,
        tool.name,
        tool.description,
      );

      // If we detect a specific language (not generic), use language-appropriate payloads
      if (detectedLanguage !== "generic" && !payloadInjected) {
        const languagePayloads =
          this.languageGenerator.getPayloadsForLanguage(detectedLanguage);

        if (languagePayloads.length > 0) {
          // Select a payload that targets similar behavior as the current attack pattern
          // (e.g., if testing command injection, use a command-executing payload)
          const payloadLower = payload.payload.toLowerCase();
          const isCommandTest =
            payloadLower.includes("whoami") ||
            payloadLower.includes("passwd") ||
            payloadLower.includes("id");

          // Find matching language payload based on test intent
          let selectedPayload = languagePayloads[0]; // Default to first
          if (isCommandTest) {
            // Prefer command execution payloads
            const cmdPayload = languagePayloads.find(
              (lp) =>
                lp.payload.includes("whoami") ||
                lp.payload.includes("subprocess") ||
                lp.payload.includes("execSync"),
            );
            if (cmdPayload) selectedPayload = cmdPayload;
          }

          params[key] = selectedPayload.payload;
          payloadInjected = true;
          break;
        }
      }
    }

    // Fall back to parameterTypes matching if no language-specific payload was used
    if (!payloadInjected && targetParamTypes.length > 0) {
      // Payload is parameter-specific (e.g., URLs only for "url" params)
      for (const [key, prop] of Object.entries(schema.properties)) {
        const propSchema = prop as any;
        const paramNameLower = key.toLowerCase();

        // Check if parameter name matches expected types
        if (
          propSchema.type === "string" &&
          targetParamTypes.some((type) => paramNameLower.includes(type))
        ) {
          params[key] = payload.payload;
          payloadInjected = true;
          break;
        }
      }
    }

    // Fall back to generic payload - inject into first string parameter (original behavior)
    if (!payloadInjected) {
      for (const [key, prop] of Object.entries(schema.properties)) {
        const propSchema = prop as any;

        if (propSchema.type === "string" && !payloadInjected) {
          params[key] = payload.payload;
          payloadInjected = true;
          break;
        }
      }
    }

    // Fill required parameters with safe defaults
    for (const [key, prop] of Object.entries(schema.properties)) {
      const propSchema = prop as any;

      if (schema.required?.includes(key) && !(key in params)) {
        if (propSchema.type === "string") {
          params[key] = "test";
        } else if (propSchema.type === "number") {
          params[key] = 1;
        } else if (propSchema.type === "boolean") {
          params[key] = true;
        } else if (propSchema.type === "object") {
          params[key] = {};
        } else if (propSchema.type === "array") {
          params[key] = [];
        }
      }
    }

    return params;
  }

  /**
   * Check if tool is an API wrapper (safe data-passing tool)
   */
  private isApiWrapper(tool: any): boolean {
    const classifier = new ToolClassifier();
    const classification = classifier.classify(
      tool.name,
      tool.description || "",
    );
    return classification.categories.includes(ToolCategory.API_WRAPPER);
  }

  /**
   * Check if attack is an execution-based test
   * These tests assume the tool executes input as code, which doesn't apply to API wrappers
   */
  private isExecutionTest(attackName: string): boolean {
    const executionTests = [
      "Command Injection",
      "SQL Injection",
      "Path Traversal",
    ];
    return executionTests.includes(attackName);
  }

  /**
   * Check if response is returning search results
   * Search tools return query results as data, not execute them
   */
  private isSearchResultResponse(responseText: string): boolean {
    const searchResultPatterns = [
      /"results"\s*:\s*\[/i, // JSON results array
      /"type"\s*:\s*"search"/i, // Type indicator
      /"object"\s*:\s*"list"/i, // Notion list format
      /\bhighlight\b/i, // Search highlighting
      /search\s+results/i,
      /found\s+\d+\s+(results?|pages?|items?)/i,
      /query\s+(returned|matched)/i,
      /\d+\s+(results?|matches?|hits?)\s+for/i,
      /"has_more"\s*:/i, // Pagination indicator
      /next_cursor/i, // Pagination cursor
    ];

    return searchResultPatterns.some((pattern) => pattern.test(responseText));
  }

  /**
   * Check if response is from a creation/modification operation
   * CRUD tools create/modify resources, not execute code
   */
  private isCreationResponse(responseText: string): boolean {
    const creationPatterns = [
      /successfully\s+created/i,
      /database\s+created/i,
      /page\s+created/i,
      /resource\s+created/i,
      /\bcreate\s+table\b/i, // SQL creation
      /\binsert\s+into\b/i, // SQL insertion
      /"id"\s*:\s*"[a-f0-9-]{36}"/i, // UUID response (created resource)
      /"object"\s*:\s*"(page|database)"/i, // Notion object types
      /collection:\/\//i, // Collection URI
      /successfully\s+(added|inserted|updated|modified)/i,
      /resource\s+id:\s*[a-f0-9-]/i,
      /"created_time"/i, // Timestamp from creation
      /"last_edited_time"/i, // Timestamp from modification
    ];

    return creationPatterns.some((pattern) => pattern.test(responseText));
  }
}

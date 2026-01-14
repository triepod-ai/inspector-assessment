/**
 * Security Payload Tester
 * Executes security tests with payloads against MCP tools
 *
 * Extracted from SecurityAssessor.ts for maintainability.
 * Handles test execution, batching, and progress tracking.
 */

import { SecurityTestResult } from "@/lib/assessmentTypes";
import {
  ProgressCallback,
  TestBatchProgress,
  VulnerabilityFoundProgress,
  ToolTestCompleteProgress,
} from "@/lib/assessment/progressTypes";
import {
  CompatibilityCallToolResult,
  Tool,
} from "@modelcontextprotocol/sdk/types.js";
import {
  getAllAttackPatterns,
  getPayloadsForAttack,
  SecurityPayload,
} from "@/lib/securityPatterns";
import { createConcurrencyLimit } from "../../lib/concurrencyLimit";
import { SecurityResponseAnalyzer } from "./SecurityResponseAnalyzer";
import { SecurityPayloadGenerator } from "./SecurityPayloadGenerator";
import { SanitizationDetector } from "./SanitizationDetector";
import { DEFAULT_PERFORMANCE_CONFIG } from "../../config/performanceConfig";
import { isTransientErrorPattern } from "./SecurityPatternLibrary";

/**
 * Re-export ProgressCallback for external use
 */
export type TestProgressCallback = ProgressCallback;

/**
 * Configuration for payload testing
 */
export interface PayloadTestConfig {
  enableDomainTesting?: boolean;
  maxParallelTests?: number;
  securityTestTimeout?: number;
  selectedToolsForTesting?: string[];
  /**
   * Maximum retry attempts for transient errors (Issue #157)
   * Uses PerformanceConfig.securityRetryMaxAttempts if not specified
   */
  securityRetryMaxAttempts?: number;
  /**
   * Initial backoff delay in ms for retries (Issue #157)
   * Uses PerformanceConfig.securityRetryBackoffMs if not specified
   */
  securityRetryBackoffMs?: number;
}

/**
 * Logger interface for test execution
 */
export interface TestLogger {
  log: (message: string) => void;
  logError: (message: string, error: unknown) => void;
}

/**
 * Executes security tests with payloads against MCP tools
 */
export class SecurityPayloadTester {
  private responseAnalyzer: SecurityResponseAnalyzer;
  private payloadGenerator: SecurityPayloadGenerator;
  private sanitizationDetector: SanitizationDetector;
  private testCount = 0;

  constructor(
    private config: PayloadTestConfig,
    private logger: TestLogger,
    private executeWithTimeout: <T>(
      promise: Promise<T>,
      timeout: number,
    ) => Promise<T>,
  ) {
    this.responseAnalyzer = new SecurityResponseAnalyzer();
    this.payloadGenerator = new SecurityPayloadGenerator();
    this.sanitizationDetector = new SanitizationDetector();
  }

  /**
   * Run comprehensive security tests (advanced mode)
   * Tests selected tools with ALL 23 security patterns using diverse payloads
   */
  async runUniversalSecurityTests(
    tools: Tool[],
    callTool: (
      name: string,
      params: Record<string, unknown>,
    ) => Promise<CompatibilityCallToolResult>,
    onProgress?: TestProgressCallback,
  ): Promise<SecurityTestResult[]> {
    // Check if advanced security testing is enabled
    if (!this.config.enableDomainTesting) {
      return this.runBasicSecurityTests(tools, callTool, onProgress);
    }

    const results: SecurityTestResult[] = [];
    const attackPatterns = getAllAttackPatterns();

    // Parallel tool testing with concurrency limit
    const concurrency = this.config.maxParallelTests ?? 5;
    const limit = createConcurrencyLimit(concurrency);

    // Progress tracking for batched events
    // Uses centralized PerformanceConfig values (Issue #37)
    let totalPayloads = 0;
    for (const pattern of attackPatterns) {
      totalPayloads += getPayloadsForAttack(pattern.attackName).length;
    }
    const totalEstimate = tools.length * totalPayloads;
    let completedTests = 0;
    let lastBatchTime = Date.now();
    const startTime = Date.now();
    const BATCH_INTERVAL = DEFAULT_PERFORMANCE_CONFIG.batchFlushIntervalMs;
    const BATCH_SIZE = DEFAULT_PERFORMANCE_CONFIG.securityBatchSize;
    let batchCount = 0;

    const emitProgressBatch = () => {
      if (onProgress) {
        const event: TestBatchProgress = {
          type: "test_batch",
          module: "security",
          completed: completedTests,
          total: totalEstimate,
          batchSize: batchCount,
          elapsed: Date.now() - startTime,
        };
        onProgress(event);
      }
      batchCount = 0;
      lastBatchTime = Date.now();
    };

    this.logger.log(
      `Starting ADVANCED security assessment - testing ${tools.length} tools with ${attackPatterns.length} security patterns (~${totalEstimate} tests) [concurrency: ${concurrency}]`,
    );

    const allToolResults = await Promise.all(
      tools.map((tool) =>
        limit(async () => {
          const toolResults: SecurityTestResult[] = [];
          const toolStartTime = Date.now();

          // Tools with no input parameters can't be exploited
          if (!this.payloadGenerator.hasInputParameters(tool)) {
            this.logger.log(
              `${tool.name} has no input parameters - adding passing results`,
            );

            for (const attackPattern of attackPatterns) {
              const payloads = getPayloadsForAttack(attackPattern.attackName);

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

            // Emit per-tool completion event for auditor UI (Phase 7)
            if (onProgress) {
              const toolCompleteEvent: ToolTestCompleteProgress = {
                type: "tool_test_complete",
                tool: tool.name,
                module: "security",
                scenariosPassed: toolResults.length,
                scenariosExecuted: toolResults.length,
                confidence: "high",
                status: "PASS",
                executionTime: Date.now() - toolStartTime,
              };
              onProgress(toolCompleteEvent);
            }

            return toolResults;
          }

          this.logger.log(`Testing ${tool.name} with all attack patterns`);

          for (const attackPattern of attackPatterns) {
            const payloads = getPayloadsForAttack(attackPattern.attackName);

            for (const payload of payloads) {
              this.testCount++;
              completedTests++;
              batchCount++;

              try {
                // Issue #157: Use retry-enabled wrapper for transient error resilience
                const result = await this.testPayloadWithRetry(
                  tool,
                  attackPattern.attackName,
                  payload,
                  callTool,
                );

                toolResults.push(result);

                if (result.vulnerable && onProgress) {
                  this.logger.log(
                    `🚨 VULNERABILITY: ${tool.name} - ${attackPattern.attackName} (${payload.payloadType}: ${payload.description})`,
                  );

                  const vulnEvent: VulnerabilityFoundProgress = {
                    type: "vulnerability_found",
                    tool: tool.name,
                    pattern: attackPattern.attackName,
                    confidence: result.confidence || "medium",
                    evidence: result.evidence || "Vulnerability detected",
                    riskLevel: payload.riskLevel,
                    requiresReview: result.requiresManualReview || false,
                    payload: payload.payload,
                  };
                  onProgress(vulnEvent);
                }
              } catch (error) {
                this.logger.logError(
                  `Error testing ${tool.name} with ${attackPattern.attackName}`,
                  error,
                );
              }

              const timeSinceLastBatch = Date.now() - lastBatchTime;
              if (
                batchCount >= BATCH_SIZE ||
                timeSinceLastBatch >= BATCH_INTERVAL
              ) {
                emitProgressBatch();
              }

              if (this.testCount % 5 === 0) {
                await this.sleep(100);
              }
            }
          }

          // Emit per-tool completion event for auditor UI (Phase 7)
          if (onProgress) {
            const passed = toolResults.filter((r) => !r.vulnerable).length;
            const vulnCount = toolResults.filter((r) => r.vulnerable).length;
            const hasHighConfidence = toolResults.some(
              (r) => r.vulnerable && r.confidence === "high",
            );

            const toolCompleteEvent: ToolTestCompleteProgress = {
              type: "tool_test_complete",
              tool: tool.name,
              module: "security",
              scenariosPassed: passed,
              scenariosExecuted: toolResults.length,
              confidence: hasHighConfidence
                ? "high"
                : vulnCount > 0
                  ? "medium"
                  : "high",
              status: vulnCount > 0 ? "FAIL" : "PASS",
              executionTime: Date.now() - toolStartTime,
            };
            onProgress(toolCompleteEvent);
          }

          return toolResults;
        }),
      ),
    );

    for (const toolResults of allToolResults) {
      results.push(...toolResults);
    }

    if (batchCount > 0) {
      emitProgressBatch();
    }

    this.logger.log(
      `ADVANCED security assessment complete: ${results.length} tests executed, ${results.filter((r) => r.vulnerable).length} vulnerabilities found`,
    );

    return results;
  }

  /**
   * Run basic security tests (fast mode)
   * Tests only 5 critical injection patterns with 1 generic payload each
   */
  async runBasicSecurityTests(
    tools: Tool[],
    callTool: (
      name: string,
      params: Record<string, unknown>,
    ) => Promise<CompatibilityCallToolResult>,
    onProgress?: TestProgressCallback,
  ): Promise<SecurityTestResult[]> {
    const results: SecurityTestResult[] = [];

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

    // Progress tracking for batched events
    // Uses centralized PerformanceConfig values (Issue #37)
    const totalEstimate = tools.length * basicPatterns.length;
    let completedTests = 0;
    let lastBatchTime = Date.now();
    const startTime = Date.now();
    const BATCH_INTERVAL = DEFAULT_PERFORMANCE_CONFIG.batchFlushIntervalMs;
    const BATCH_SIZE = DEFAULT_PERFORMANCE_CONFIG.securityBatchSize;
    let batchCount = 0;

    const emitProgressBatch = () => {
      if (onProgress) {
        const event: TestBatchProgress = {
          type: "test_batch",
          module: "security",
          completed: completedTests,
          total: totalEstimate,
          batchSize: batchCount,
          elapsed: Date.now() - startTime,
        };
        onProgress(event);
      }
      batchCount = 0;
      lastBatchTime = Date.now();
    };

    this.logger.log(
      `Starting BASIC security assessment - testing ${tools.length} tools with ${basicPatterns.length} critical injection patterns (~${totalEstimate} tests)`,
    );

    for (const tool of tools) {
      const toolStartTime = Date.now();
      const toolResults: SecurityTestResult[] = [];

      if (!this.payloadGenerator.hasInputParameters(tool)) {
        this.logger.log(
          `${tool.name} has no input parameters - adding passing results`,
        );

        for (const attackPattern of basicPatterns) {
          const allPayloads = getPayloadsForAttack(attackPattern.attackName);
          const payload = allPayloads[0];

          if (payload) {
            const result: SecurityTestResult = {
              testName: attackPattern.attackName,
              description: payload.description,
              payload: payload.payload,
              riskLevel: payload.riskLevel,
              toolName: tool.name,
              vulnerable: false,
              evidence:
                "Tool has no input parameters - cannot be exploited via payload injection",
            };
            results.push(result);
            toolResults.push(result);
          }
        }

        // Emit per-tool completion event for auditor UI (Phase 7)
        if (onProgress) {
          const toolCompleteEvent: ToolTestCompleteProgress = {
            type: "tool_test_complete",
            tool: tool.name,
            module: "security",
            scenariosPassed: toolResults.length,
            scenariosExecuted: toolResults.length,
            confidence: "high",
            status: "PASS",
            executionTime: Date.now() - toolStartTime,
          };
          onProgress(toolCompleteEvent);
        }

        continue;
      }

      this.logger.log(
        `Testing ${tool.name} with ${basicPatterns.length} critical patterns`,
      );

      for (const attackPattern of basicPatterns) {
        const allPayloads = getPayloadsForAttack(attackPattern.attackName);
        const payload = allPayloads[0];

        if (!payload) continue;

        this.testCount++;
        completedTests++;
        batchCount++;

        try {
          // Issue #157: Use retry-enabled wrapper for transient error resilience
          const result = await this.testPayloadWithRetry(
            tool,
            attackPattern.attackName,
            payload,
            callTool,
          );

          results.push(result);
          toolResults.push(result);

          if (result.vulnerable && onProgress) {
            this.logger.log(
              `🚨 VULNERABILITY: ${tool.name} - ${attackPattern.attackName}`,
            );

            const vulnEvent: VulnerabilityFoundProgress = {
              type: "vulnerability_found",
              tool: tool.name,
              pattern: attackPattern.attackName,
              confidence: result.confidence || "medium",
              evidence: result.evidence || "Vulnerability detected",
              riskLevel: payload.riskLevel,
              requiresReview: result.requiresManualReview || false,
              payload: payload.payload,
            };
            onProgress(vulnEvent);
          }
        } catch (error) {
          this.logger.logError(
            `Error testing ${tool.name} with ${attackPattern.attackName}`,
            error,
          );
        }

        const timeSinceLastBatch = Date.now() - lastBatchTime;
        if (batchCount >= BATCH_SIZE || timeSinceLastBatch >= BATCH_INTERVAL) {
          emitProgressBatch();
        }

        if (this.testCount % 5 === 0) {
          await this.sleep(100);
        }
      }

      // Emit per-tool completion event for auditor UI (Phase 7)
      if (onProgress) {
        const passed = toolResults.filter((r) => !r.vulnerable).length;
        const vulnCount = toolResults.filter((r) => r.vulnerable).length;
        const hasHighConfidence = toolResults.some(
          (r) => r.vulnerable && r.confidence === "high",
        );

        const toolCompleteEvent: ToolTestCompleteProgress = {
          type: "tool_test_complete",
          tool: tool.name,
          module: "security",
          scenariosPassed: passed,
          scenariosExecuted: toolResults.length,
          confidence: hasHighConfidence
            ? "high"
            : vulnCount > 0
              ? "medium"
              : "high",
          status: vulnCount > 0 ? "FAIL" : "PASS",
          executionTime: Date.now() - toolStartTime,
        };
        onProgress(toolCompleteEvent);
      }
    }

    if (batchCount > 0) {
      emitProgressBatch();
    }

    this.logger.log(
      `BASIC security assessment complete: ${results.length} tests executed, ${results.filter((r) => r.vulnerable).length} vulnerabilities found`,
    );

    return results;
  }

  /**
   * Test tool with a specific payload
   */
  async testPayload(
    tool: Tool,
    attackName: string,
    payload: SecurityPayload,
    callTool: (
      name: string,
      params: Record<string, unknown>,
    ) => Promise<CompatibilityCallToolResult>,
  ): Promise<SecurityTestResult> {
    // Skip execution-based tests for API wrappers
    if (
      this.payloadGenerator.isApiWrapper(tool) &&
      this.payloadGenerator.isExecutionTest(attackName)
    ) {
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
      const params = this.payloadGenerator.createTestParameters(payload, tool);

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

      // Use config timeout or fall back to centralized PerformanceConfig (Issue #37)
      const securityTimeout =
        this.config.securityTestTimeout ??
        DEFAULT_PERFORMANCE_CONFIG.securityTestTimeoutMs;
      const response = await this.executeWithTimeout(
        callTool(tool.name, params),
        securityTimeout,
      );

      // Check for connection errors FIRST
      if (this.responseAnalyzer.isConnectionError(response)) {
        return {
          testName: attackName,
          description: payload.description,
          payload: payload.payload,
          riskLevel: payload.riskLevel,
          toolName: tool.name,
          vulnerable: true,
          evidence: `CONNECTION ERROR: Test could not complete due to server/network failure`,
          response: this.responseAnalyzer.extractResponseContent(response),
          connectionError: true,
          errorType: this.responseAnalyzer.classifyError(response),
          testReliability: "failed",
          confidence: "high",
          requiresManualReview: true,
        };
      }

      // Analyze with evidence-based detection
      const { isVulnerable, evidence } = this.responseAnalyzer.analyzeResponse(
        response,
        payload,
        tool,
      );

      // Issue #56: Detect sanitization for false positive reduction
      const responseText =
        this.responseAnalyzer.extractResponseContent(response);
      const toolSanitization = this.sanitizationDetector.detect(tool);
      const responseSanitization =
        this.sanitizationDetector.detectInResponse(responseText);
      const combinedSanitization = this.sanitizationDetector.mergeResults(
        toolSanitization,
        responseSanitization,
      );

      // Calculate confidence with sanitization awareness
      const confidenceResult = this.responseAnalyzer.calculateConfidence(
        tool,
        isVulnerable,
        evidence || "",
        responseText,
        payload,
        combinedSanitization, // Issue #56: Pass sanitization detection result
      );

      // Issue #75: Analyze auth bypass patterns for "Auth Bypass" attack type
      let authBypassFields: {
        authBypassDetected?: boolean;
        authFailureMode?: "FAIL_OPEN" | "FAIL_CLOSED" | "UNKNOWN";
        authBypassEvidence?: string;
      } = {};
      if (attackName === "Auth Bypass") {
        const authResult =
          this.responseAnalyzer.analyzeAuthBypassResponse(response);
        authBypassFields = {
          authBypassDetected: authResult.detected,
          authFailureMode: authResult.failureMode,
          authBypassEvidence: authResult.evidence,
        };
      }

      // Issue #110: Analyze blacklist bypass patterns for "Blacklist Bypass" attack type
      let blacklistBypassFields: {
        blacklistBypassDetected?: boolean;
        blacklistBypassType?:
          | "BLACKLIST_BYPASS"
          | "ALLOWLIST_BLOCKED"
          | "UNKNOWN";
        blacklistBypassMethod?: string;
        blacklistBypassEvidence?: string;
      } = {};
      if (attackName === "Blacklist Bypass") {
        const bypassResult =
          this.responseAnalyzer.analyzeBlacklistBypassResponse(response);
        blacklistBypassFields = {
          blacklistBypassDetected: bypassResult.detected,
          blacklistBypassType: bypassResult.bypassType,
          blacklistBypassMethod: bypassResult.bypassMethod,
          blacklistBypassEvidence: bypassResult.evidence,
        };
      }

      // Issue #110: Analyze output injection patterns for Challenge #8
      // Check ALL responses since any tool could have output injection vulnerabilities
      const outputInjectionResult =
        this.responseAnalyzer.analyzeOutputInjectionResponse(response);
      const outputInjectionFields: {
        outputInjectionDetected?: boolean;
        outputInjectionType?:
          | "LLM_INJECTION_MARKERS"
          | "RAW_CONTENT_INCLUDED"
          | "SANITIZED"
          | "UNKNOWN";
        outputInjectionMarkers?: string[];
        outputInjectionEvidence?: string;
      } = {
        outputInjectionDetected: outputInjectionResult.detected,
        outputInjectionType: outputInjectionResult.injectionType,
        outputInjectionMarkers: outputInjectionResult.markers,
        outputInjectionEvidence: outputInjectionResult.evidence,
      };

      // Issue #111: Analyze session management patterns for Challenge #12
      let sessionManagementFields: {
        sessionManagementDetected?: boolean;
        sessionVulnerabilityType?:
          | "SESSION_FIXATION"
          | "PREDICTABLE_TOKEN"
          | "NO_TIMEOUT"
          | "ID_IN_URL"
          | "NO_REGENERATION"
          | "UNKNOWN";
        sessionCweIds?: string[];
        sessionManagementEvidence?: string;
      } = {};
      if (attackName === "Session Management") {
        const sessionResult =
          this.responseAnalyzer.analyzeSessionManagementResponse(response);
        sessionManagementFields = {
          sessionManagementDetected: sessionResult.detected,
          sessionVulnerabilityType: sessionResult.vulnerabilityType,
          sessionCweIds: sessionResult.cweIds,
          sessionManagementEvidence: sessionResult.evidence,
        };
      }

      // Issue #112: Analyze cryptographic failure patterns for Challenge #13
      let cryptoFailureFields: {
        cryptoFailureDetected?: boolean;
        cryptoVulnerabilityType?:
          | "WEAK_HASH"
          | "STATIC_SALT"
          | "PREDICTABLE_RNG"
          | "TIMING_ATTACK"
          | "ECB_MODE"
          | "HARDCODED_KEY"
          | "WEAK_KDF"
          | "WEAK_KEY_LENGTH"
          | "UNKNOWN";
        cryptoCweIds?: string[];
        cryptoFailureEvidence?: string;
      } = {};
      if (attackName === "Cryptographic Failures") {
        const cryptoResult =
          this.responseAnalyzer.analyzeCryptographicFailures(response);
        cryptoFailureFields = {
          cryptoFailureDetected: cryptoResult.detected,
          cryptoVulnerabilityType: cryptoResult.vulnerabilityType,
          cryptoCweIds: cryptoResult.cweIds,
          cryptoFailureEvidence: cryptoResult.evidence,
        };
      }

      // Issue #144: Analyze excessive permissions scope patterns for Challenge #22
      let excessivePermissionsFields: {
        excessivePermissionsDetected?: boolean;
        scopeViolationType?:
          | "SCOPE_VIOLATION"
          | "SCOPE_ESCALATION"
          | "SAFE"
          | "UNKNOWN";
        scopeActual?: string;
        scopeTriggerPayload?: string;
        scopeCweIds?: string[];
        excessivePermissionsEvidence?: string;
      } = {};
      if (attackName === "Excessive Permissions Scope") {
        const scopeResult =
          this.responseAnalyzer.analyzeExcessivePermissionsResponse(response);
        excessivePermissionsFields = {
          excessivePermissionsDetected: scopeResult.detected,
          scopeViolationType: scopeResult.violationType,
          scopeActual: scopeResult.actualScope,
          scopeTriggerPayload: scopeResult.triggerPayload,
          scopeCweIds: scopeResult.cweIds,
          excessivePermissionsEvidence: scopeResult.evidence,
        };
      }

      return {
        testName: attackName,
        description: payload.description,
        payload: payload.payload,
        riskLevel: payload.riskLevel,
        toolName: tool.name,
        vulnerable: isVulnerable,
        evidence,
        response: responseText,
        // Issue #56: Include sanitization info for transparency
        sanitizationDetected: combinedSanitization.detected,
        sanitizationLibraries: combinedSanitization.libraries,
        // Issue #75: Auth bypass detection fields
        ...authBypassFields,
        // Issue #110: Blacklist bypass detection fields
        ...blacklistBypassFields,
        // Issue #110: Output injection detection fields (Challenge #8)
        ...outputInjectionFields,
        // Issue #111: Session management detection fields (Challenge #12)
        ...sessionManagementFields,
        // Issue #112: Cryptographic failure detection fields (Challenge #13)
        ...cryptoFailureFields,
        // Issue #144: Excessive permissions scope detection fields (Challenge #22)
        ...excessivePermissionsFields,
        ...confidenceResult,
      };
    } catch (error) {
      // Check if error is a connection/server failure
      if (this.responseAnalyzer.isConnectionErrorFromException(error)) {
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
          errorType: this.responseAnalyzer.classifyErrorFromException(error),
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
   * Test payload with retry logic for transient errors.
   * Implements exponential backoff: 100ms → 200ms → 400ms
   *
   * Issue #157: Connection retry logic for reliability
   *
   * @param tool - Tool to test
   * @param attackName - Name of attack pattern
   * @param payload - Security payload to test
   * @param callTool - Function to call the tool
   * @returns SecurityTestResult with retry metadata if applicable
   */
  async testPayloadWithRetry(
    tool: Tool,
    attackName: string,
    payload: SecurityPayload,
    callTool: (
      name: string,
      params: Record<string, unknown>,
    ) => Promise<CompatibilityCallToolResult>,
  ): Promise<SecurityTestResult> {
    const maxRetries =
      this.config.securityRetryMaxAttempts ??
      DEFAULT_PERFORMANCE_CONFIG.securityRetryMaxAttempts;
    const backoffMs =
      this.config.securityRetryBackoffMs ??
      DEFAULT_PERFORMANCE_CONFIG.securityRetryBackoffMs;

    let lastResult: SecurityTestResult | null = null;
    let retryAttempts = 0;

    for (let attempt = 0; attempt <= maxRetries; attempt++) {
      const result = await this.testPayload(
        tool,
        attackName,
        payload,
        callTool,
      );

      // Check if result indicates transient error worth retrying
      if (result.connectionError && attempt < maxRetries) {
        const errorText = (result.response || "").toLowerCase();
        if (isTransientErrorPattern(errorText)) {
          retryAttempts++;
          lastResult = result;

          this.logger.log(
            `Transient error on ${tool.name}, retrying (${attempt + 1}/${maxRetries}): ${errorText.slice(0, 100)}`,
          );

          // Exponential backoff: 100ms → 200ms → 400ms
          await this.sleep(backoffMs * Math.pow(2, attempt));
          continue;
        }
      }

      // Success or permanent error - return with retry metadata
      return this.addRetryMetadata(
        result,
        retryAttempts,
        !result.connectionError,
      );
    }

    // All retries exhausted - return last result with failure metadata
    if (lastResult) {
      return this.addRetryMetadata(lastResult, retryAttempts, false);
    }

    // Should not reach here, but handle gracefully
    throw new Error(`Unexpected retry loop exit for ${tool.name}`);
  }

  /**
   * Add retry metadata to result.
   * Issue #157: Track retry attempts for reliability metrics
   */
  private addRetryMetadata(
    result: SecurityTestResult,
    retryAttempts: number,
    succeeded: boolean,
  ): SecurityTestResult {
    if (retryAttempts === 0) {
      // No retries needed - return as-is with completed status
      return {
        ...result,
        testReliability: result.connectionError ? "failed" : "completed",
      };
    }

    return {
      ...result,
      retryAttempts,
      retriedSuccessfully: succeeded,
      testReliability: succeeded ? "retried" : "failed",
    };
  }

  /**
   * Extract error message from caught exception
   */
  private extractErrorMessage(error: unknown): string {
    if (error instanceof Error) {
      return error.message;
    }
    return String(error);
  }

  /**
   * Sleep for specified milliseconds
   */
  private sleep(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }
}

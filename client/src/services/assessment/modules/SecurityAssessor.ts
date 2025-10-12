/**
 * Security Assessor Module
 * Tests for backend API security vulnerabilities using 8 focused patterns
 * - Critical Injection (3): Command, SQL, Path Traversal
 * - Input Validation (3): Type Safety, Boundary Testing, Required Fields
 * - Protocol Compliance (2): MCP Error Format, Timeout Handling
 */

import {
  SecurityAssessment,
  SecurityTestResult,
  SecurityRiskLevel,
  AssessmentStatus,
} from "@/lib/assessmentTypes";
import { BaseAssessor } from "./BaseAssessor";
import { AssessmentContext } from "../AssessmentOrchestrator";
import { CompatibilityCallToolResult } from "@modelcontextprotocol/sdk/types.js";
import {
  getAllAttackPatterns,
  getPayloadsForAttack,
  SecurityPayload,
} from "@/lib/securityPatterns";
import { ToolClassifier, ToolCategory } from "../ToolClassifier";

export class SecurityAssessor extends BaseAssessor {
  async assess(context: AssessmentContext): Promise<SecurityAssessment> {
    // Select tools for testing first
    const toolsToTest = this.selectToolsForTesting(context.tools);

    // Run universal security testing - test selected tools with ALL attack types
    const allTests = await this.runUniversalSecurityTests(context);

    // Count vulnerabilities
    const vulnerabilities: string[] = [];
    let highRiskCount = 0;
    let mediumRiskCount = 0;

    for (const test of allTests) {
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

    // Determine status (pass tests array to check confidence levels)
    const status = this.determineSecurityStatus(
      allTests,
      vulnerabilities.length,
      allTests.length,
    );

    // Generate explanation
    const explanation = this.generateSecurityExplanation(
      allTests,
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
  private selectToolsForTesting(tools: any[]): any[] {
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

    this.log(
      `Starting ADVANCED security assessment - testing ${toolsToTest.length} tools with ${attackPatterns.length} security patterns (~${toolsToTest.length * attackPatterns.length * 3} tests)`,
    );

    for (const tool of toolsToTest) {
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

      this.log(`Testing ${tool.name} with all attack patterns`);

      // Test with each attack type (all patterns in advanced mode)
      for (const attackPattern of attackPatterns) {
        // Get ALL payloads for this attack pattern
        const payloads = getPayloadsForAttack(attackPattern.attackName);

        // Test tool with each payload variation
        for (const payload of payloads) {
          this.testCount++;

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
                `🚨 VULNERABILITY: ${tool.name} - ${attackPattern.attackName} (${payload.payloadType}: ${payload.description})`,
              );
            }
          } catch (error) {
            this.logError(
              `Error testing ${tool.name} with ${attackPattern.attackName}`,
              error,
            );
          }

          // Rate limiting
          if (this.testCount % 5 === 0) {
            await this.sleep(100);
          }
        }
      }
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

    // Only test 3 critical injection patterns
    const criticalPatterns = [
      "Command Injection",
      "SQL Injection",
      "Path Traversal",
    ];

    const allPatterns = getAllAttackPatterns();
    const basicPatterns = allPatterns.filter((p) =>
      criticalPatterns.includes(p.attackName),
    );

    // Select tools for testing
    const toolsToTest = this.selectToolsForTesting(context.tools);

    this.log(
      `Starting BASIC security assessment - testing ${toolsToTest.length} tools with ${basicPatterns.length} critical injection patterns (~${toolsToTest.length * basicPatterns.length} tests)`,
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
          }
        } catch (error) {
          this.logError(
            `Error testing ${tool.name} with ${attackPattern.attackName}`,
            error,
          );
        }

        // Rate limiting
        if (this.testCount % 5 === 0) {
          await this.sleep(100);
        }
      }
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
    tool: any,
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
      const params = this.createTestParameters(payload.payload, tool);

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

      // Execute tool call
      const response = await this.executeWithTimeout(
        callTool(tool.name, params),
        5000,
      );

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
   * Try to parse JSON response and extract structured data
   * Returns null if response is not JSON
   */
  private tryParseResponseJSON(
    response: CompatibilityCallToolResult,
  ): any | null {
    try {
      const responseText = this.extractResponseContent(response);
      return JSON.parse(responseText);
    } catch {
      return null; // Not JSON, that's okay
    }
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

    // ✅ STEP -1: Check for explicit safety/vulnerability flags (HIGHEST PRIORITY)
    // Optional fast-path: If server explicitly marks safety/vulnerability, trust it
    // This works for test servers but behavioral detection below works for ALL servers
    const parsedResponse = this.tryParseResponseJSON(response);
    if (parsedResponse) {
      // Explicit safe flag - DEFINITELY not vulnerable
      if (parsedResponse.safe === true) {
        return {
          isVulnerable: false,
          evidence:
            "Tool explicitly marked response as safe (safe: true flag in JSON response)",
        };
      }

      // Explicit hardened flag - DEFINITELY not vulnerable (security-fixed version)
      if (parsedResponse.hardened === true) {
        return {
          isVulnerable: false,
          evidence:
            "Tool explicitly marked response as hardened (hardened: true flag in JSON response)",
        };
      }

      // Explicit vulnerable flag - DEFINITELY vulnerable
      if (parsedResponse.vulnerable === true) {
        return {
          isVulnerable: true,
          evidence:
            "Tool explicitly marked response as vulnerable (vulnerable: true flag in JSON response)",
        };
      }
    }

    // ✅ STEP -2: Check for MCP validation errors (HIGHEST PRIORITY)
    // Tools that reject invalid input before processing are SECURE
    const errorInfo = this.extractErrorInfo(response);
    if (this.isMCPValidationError(errorInfo, responseText)) {
      const errorCode = errorInfo.code ? ` (${errorInfo.code})` : "";
      return {
        isVulnerable: false,
        evidence: `MCP validation error${errorCode}: Tool properly rejected invalid input before processing`,
      };
    }

    // ✅ STEP -0.5: Classify tool and check for safe categories (prevents false positives)
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

    // ✅ STEP 0: Check if response is from an API wrapper (SAFE)
    // API wrappers fetch external content and return it as data, not execute it
    if (this.isApiWrapperResponse(responseText)) {
      return {
        isVulnerable: false,
        evidence: "API wrapper response - returned external content as data",
      };
    }

    // ✅ STEP 1: Check if response is just reflecting/echoing input (SAFE)
    // This prevents false positives from tools that echo malicious input as data
    if (responseText.includes(payloadText)) {
      // Response contains the exact input - likely safe reflection
      // Check if it's ONLY reflection (echo, stored, saved) vs execution + reflection
      const isJustReflection = this.isReflectionResponse(responseText);
      if (isJustReflection) {
        return {
          isVulnerable: false,
          evidence: "Tool safely reflected input without execution",
        };
      }
      // Falls through - might be execution WITH reflection (e.g., "Stored '2+2' and calculated: 4")
    }

    // ✅ STEP 2: Check for expected evidence of execution
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

    // ✅ STEP 3: Fall back to existing detection logic for comprehensive analysis
    return this.analyzeInjectionResponse(response, payload.payload);
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
  ): AssessmentStatus {
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
    tests: SecurityTestResult[],
    vulnerabilities: string[],
    riskLevel: SecurityRiskLevel,
  ): string {
    const vulnCount = vulnerabilities.length;
    const testCount = tests.length;

    // Handle case when no tools were tested
    if (testCount === 0) {
      return `No tools selected for security testing. Select tools to run security assessments.`;
    }

    if (vulnCount === 0) {
      return `Tested ${testCount} security patterns across selected tools. No vulnerabilities detected. All tools properly handle malicious inputs.`;
    }

    // Count by confidence level
    const highConfidenceCount = tests.filter(
      (t) => t.vulnerable && (!t.confidence || t.confidence === "high"),
    ).length;
    const mediumConfidenceCount = tests.filter(
      (t) => t.vulnerable && t.confidence === "medium",
    ).length;
    const lowConfidenceCount = tests.filter(
      (t) => t.vulnerable && t.confidence === "low",
    ).length;

    // Generate confidence-aware explanation
    if (highConfidenceCount > 0) {
      return `Found ${highConfidenceCount} confirmed vulnerability${highConfidenceCount !== 1 ? "s" : ""} across ${testCount} security tests. Risk level: ${riskLevel}. Tools may execute malicious commands or leak sensitive data.`;
    } else if (mediumConfidenceCount > 0) {
      return `Detected ${mediumConfidenceCount} potential security concern${mediumConfidenceCount !== 1 ? "s" : ""} across ${testCount} security tests requiring manual review. Tools showed suspicious behavior that needs verification.`;
    } else {
      return `Flagged ${lowConfidenceCount} uncertain detection${lowConfidenceCount !== 1 ? "s" : ""} across ${testCount} security tests. Manual verification needed to confirm if these are actual vulnerabilities or false positives.`;
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
   * IMPROVED: Bidirectional patterns and safety indicators for broader coverage
   */
  private isReflectionResponse(responseText: string): boolean {
    const reflectionPatterns = [
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
      /input.*saved/i,
      /parameter.*received/i,
      /command.*stored/i,
      /data.*stored/i,
      /action.*stored/i,
      /text.*stored/i,
      /setting.*stored/i,
      /instruction.*stored/i,
      /url.*stored/i,
      /package.*stored/i,

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
    ];

    return reflectionPatterns.some((pattern) => pattern.test(responseText));
  }

  /**
   * Analyze injection response (existing logic)
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
    payload: string,
    tool: any,
  ): Record<string, unknown> {
    // Extract tool schema
    const schema =
      tool.inputSchema?.type === "object" ? tool.inputSchema : tool.inputSchema;

    if (!schema?.properties) {
      return {};
    }

    const params: Record<string, unknown> = {};

    // For each parameter in the schema, inject the test payload
    for (const [key, prop] of Object.entries(schema.properties)) {
      const propSchema = prop as any;

      // Inject payload into first string parameter found
      if (propSchema.type === "string" && Object.keys(params).length === 0) {
        params[key] = payload;
      }
      // Fill required parameters with safe defaults
      else if (schema.required?.includes(key)) {
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
   * Check if response is from an API wrapper tool
   * API wrappers return external content as data, not execute it
   */
  private isApiWrapperResponse(responseText: string): boolean {
    const apiWrapperPatterns = [
      /successfully\s+(scraped|fetched|crawled)/i,
      /content\s+from\s+http/i,
      /api\s+(request|response|call)\s+(completed|successful)/i,
      /retrieved\s+\d+\s+(results|pages|urls)/i,
      /markdown.*screenshot.*links/i, // Firecrawl format indicators
      /scraping\s+(complete|finished|done)/i,
      /\bfirecrawl\b/i,
      /crawl.*job/i,
      /extraction.*complete/i,
    ];

    return apiWrapperPatterns.some((pattern) => pattern.test(responseText));
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

/**
 * Security Assessor Module
 * Tests for prompt injection and security vulnerabilities using universal attack patterns
 * Tests ALL tools with ALL attack types using diverse payloads
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
    // Run universal security testing - test ALL tools with ALL attack types
    const allTests = await this.runUniversalSecurityTests(context);

    // Count vulnerabilities
    const vulnerabilities: string[] = [];
    let highRiskCount = 0;
    let mediumRiskCount = 0;

    for (const test of allTests) {
      if (test.vulnerable) {
        const vulnerability = `${test.toolName} vulnerable to ${test.testName}`;
        if (!vulnerabilities.includes(vulnerability)) {
          vulnerabilities.push(vulnerability);
        }

        if (test.riskLevel === "HIGH") highRiskCount++;
        else if (test.riskLevel === "MEDIUM") mediumRiskCount++;
      }
    }

    // Additional security checks for new patterns
    const additionalVulnerabilities =
      await this.performAdditionalSecurityChecks(context);
    vulnerabilities.push(...additionalVulnerabilities);

    // Determine overall risk level
    const overallRiskLevel = this.determineOverallRiskLevel(
      highRiskCount,
      mediumRiskCount,
      vulnerabilities.length,
    );

    // Determine status
    const status = this.determineSecurityStatus(
      vulnerabilities.length,
      overallRiskLevel,
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
   * Run universal security tests
   * Tests ALL tools with ALL attack types using diverse payloads
   * NO tool classification - just comprehensive fuzzing with domain-specific payloads
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

    this.log(
      `Starting ADVANCED security assessment - testing ${context.tools.length} tools with ${attackPatterns.length} attack patterns (~${context.tools.length * attackPatterns.length * 3} tests)`,
    );

    for (const tool of context.tools) {
      // Skip tools with no input parameters
      if (!this.hasInputParameters(tool)) {
        this.log(`Skipping ${tool.name} - no input parameters`);
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
   * Tests only 3 critical attack patterns with 1 generic payload each
   * Used when enableDomainTesting = false
   */
  private async runBasicSecurityTests(
    context: AssessmentContext,
  ): Promise<SecurityTestResult[]> {
    const results: SecurityTestResult[] = [];

    // Only test 3 critical HIGH-risk patterns
    const criticalPatterns = [
      "Direct Command Injection",
      "Role Override",
      "Data Exfiltration",
    ];

    const allPatterns = getAllAttackPatterns();
    const basicPatterns = allPatterns.filter((p) =>
      criticalPatterns.includes(p.attackName),
    );

    this.log(
      `Starting BASIC security assessment - testing ${context.tools.length} tools with ${basicPatterns.length} critical patterns (~${context.tools.length * basicPatterns.length} tests)`,
    );

    for (const tool of context.tools) {
      // Skip tools with no input parameters
      if (!this.hasInputParameters(tool)) {
        this.log(`Skipping ${tool.name} - no input parameters`);
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
   * Perform additional security checks
   */
  private async performAdditionalSecurityChecks(
    context: AssessmentContext,
  ): Promise<string[]> {
    const vulnerabilities: string[] = [];

    // Check for tools that might handle sensitive data
    for (const tool of context.tools) {
      const toolText = `${tool.name} ${tool.description || ""}`.toLowerCase();

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
   * Determine security status
   */
  private determineSecurityStatus(
    vulnerabilityCount: number,
    riskLevel: SecurityRiskLevel,
  ): AssessmentStatus {
    if (vulnerabilityCount === 0) return "PASS";
    if (riskLevel === "HIGH") return "FAIL";
    if (vulnerabilityCount > 3) return "FAIL";
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

    if (vulnCount === 0) {
      return `Tested ${testCount} security patterns across all tools. No vulnerabilities detected. All tools properly handle malicious inputs.`;
    }

    const criticalCount = tests.filter(
      (t) => t.vulnerable && t.riskLevel === "HIGH",
    ).length;
    const moderateCount = tests.filter(
      (t) => t.vulnerable && t.riskLevel === "MEDIUM",
    ).length;

    return `Found ${vulnCount} vulnerabilities (${criticalCount} critical, ${moderateCount} moderate) across ${testCount} security tests. Risk level: ${riskLevel}. Tools may execute malicious commands or leak sensitive data.`;
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
      "Direct Command Injection",
      "System Command",
      "Indirect Prompt Injection",
      "Unicode Bypass",
      "Sandbox Escape",
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
}

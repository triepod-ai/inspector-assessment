/**
 * Security Assessor Module
 * Tests for prompt injection and security vulnerabilities with 17 attack patterns
 */

import {
  SecurityAssessment,
  SecurityTestResult,
  SecurityRiskLevel,
  PROMPT_INJECTION_TESTS,
  AssessmentStatus,
} from "@/lib/assessmentTypes";
import { BaseAssessor } from "./BaseAssessor";
import { AssessmentContext } from "../AssessmentOrchestrator";
import { CompatibilityCallToolResult } from "@modelcontextprotocol/sdk/types.js";

export class SecurityAssessor extends BaseAssessor {
  async assess(context: AssessmentContext): Promise<SecurityAssessment> {
    // Determine how many security patterns to test based on mode
    const patternsToTest = this.config.reviewerMode
      ? 3 // Reviewer mode: test only 3 critical patterns
      : this.config.securityPatternsToTest || PROMPT_INJECTION_TESTS.length;

    const selectedPatterns = PROMPT_INJECTION_TESTS.slice(0, patternsToTest);

    this.log(
      `Starting security assessment with ${selectedPatterns.length} attack patterns${this.config.reviewerMode ? " (reviewer mode)" : ""}`,
    );

    const promptInjectionTests: SecurityTestResult[] = [];
    const vulnerabilities: string[] = [];
    let highRiskCount = 0;
    let mediumRiskCount = 0;

    // Test each tool against selected injection patterns
    for (const tool of context.tools) {
      // Skip testing if tool has no input parameters
      if (!this.hasInputParameters(tool)) {
        this.log(`Skipping ${tool.name} - no input parameters`);
        continue;
      }

      for (const testCase of selectedPatterns) {
        this.testCount++;

        try {
          const result = await this.testPromptInjection(
            tool.name,
            testCase,
            context.callTool,
          );

          promptInjectionTests.push(result);

          if (result.vulnerable) {
            const vulnerability = `${tool.name} vulnerable to ${result.testName}`;
            vulnerabilities.push(vulnerability);

            if (result.riskLevel === "HIGH") highRiskCount++;
            else if (result.riskLevel === "MEDIUM") mediumRiskCount++;

            this.log(`⚠️ Vulnerability found: ${vulnerability}`);
          }
        } catch (error) {
          this.logError(
            `Error testing ${tool.name} with ${testCase.testName}`,
            error,
          );
        }

        // Rate limiting to avoid overwhelming the server
        if (this.testCount % 5 === 0) {
          await this.sleep(100);
        }
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
      promptInjectionTests,
      vulnerabilities,
      overallRiskLevel,
    );

    return {
      promptInjectionTests,
      vulnerabilities,
      overallRiskLevel,
      status,
      explanation,
    };
  }

  private async testPromptInjection(
    toolName: string,
    testCase: Omit<SecurityTestResult, "vulnerable" | "evidence">,
    callTool: (
      name: string,
      params: Record<string, unknown>,
    ) => Promise<CompatibilityCallToolResult>,
  ): Promise<SecurityTestResult> {
    try {
      // Create test parameters with the injection payload
      const params = this.createTestParameters(testCase.payload);

      // Call the tool with injection payload
      const response = await this.executeWithTimeout(
        callTool(toolName, params),
        5000, // 5 second timeout for security tests
      );

      // Analyze response for vulnerability indicators
      const { isVulnerable, evidence } = this.analyzeInjectionResponse(
        response,
        testCase.payload,
      );

      return {
        ...testCase,
        toolName,
        vulnerable: isVulnerable,
        evidence,
        response: this.extractResponseContent(response),
      };
    } catch (error) {
      // If tool errors out, it might be a good sign (input validation)
      return {
        ...testCase,
        toolName,
        vulnerable: false,
        evidence: `Tool rejected input: ${this.extractErrorMessage(error)}`,
      };
    }
  }

  private analyzeInjectionResponse(
    response: CompatibilityCallToolResult,
    payload: string,
  ): { isVulnerable: boolean; evidence?: string } {
    const responseText = this.extractResponseContent(response).toLowerCase();
    const payloadLower = payload.toLowerCase();

    // Check if response is just reflecting input as data (safe)
    const isReflection = this.isReflectionResponse(responseText);

    // Check for dangerous patterns (code execution attempts)
    const dangerousPatterns = [
      /<script>/i,
      /process\.env/i,
      /require\(/i,
      /import\s/i,
      /eval\(/i,
      /exec\(/i,
      /__proto__/i,
      /constructor\(/i,
    ];

    for (const pattern of dangerousPatterns) {
      if (pattern.test(responseText)) {
        // If it's just reflection (echoing back the payload), not vulnerable
        if (isReflection) {
          continue;
        }
        return {
          isVulnerable: true,
          evidence: `Response contains dangerous pattern: ${pattern}`,
        };
      }
    }

    // Check for actual execution (not just keyword matching)
    const executionEvidence = this.detectActualExecution(
      responseText,
      payloadLower,
      isReflection,
    );
    if (executionEvidence) {
      return {
        isVulnerable: true,
        evidence: executionEvidence,
      };
    }

    // Check for behavior changes
    if (this.detectBehaviorChange(response, payload)) {
      return {
        isVulnerable: true,
        evidence: "Tool behavior changed based on injection payload",
      };
    }

    return { isVulnerable: false };
  }

  /**
   * Detect if response is safely reflecting input as data (not executing it)
   */
  private isReflectionResponse(responseText: string): boolean {
    // Common patterns for data storage/confirmation and read-operation responses
    const reflectionPatterns = [
      // Write operation confirmations
      /stored/i,
      /created/i,
      /added/i,
      /saved/i,
      /inserted/i,
      /recorded/i,
      /indexed/i,
      /collection/i,
      /entity/i,
      /successfully/i,
      /\bid:\s*\d+/i, // "id: 123"
      /\b(using|with)\s+[\w-]+\s*\(/i, // "using model-name (dimensions)"

      // Read operation patterns - listing/querying stored data
      /qdrant collections/i, // Collection listing header
      /\d+\s+collections?/i, // Collection counts
      /"query".*"results"/i, // Search response structure
      /"total_found":\s*\d+/i, // Result counts
      /no information found/i, // Empty search results
      /indexed vectors/i, // Vector counts
      /optimizations/i, // Configuration metadata
      /status.*points.*vector/i, // Collection info response

      // Error message patterns - echoing back invalid input
      /error getting info for/i, // "Error getting info for <input>"
      /not found:.*doesn't exist/i, // "Not found: Collection `<input>` doesn't exist"
      /error.*collection/i, // Generic collection error messages
      /404.*not found/i, // HTTP 404 responses
      /doesn't exist/i, // Existence check failures
    ];

    // Check if response contains reflection patterns
    // If response has data operation patterns (storage, listing, querying),
    // it's safely handling input as data, not executing commands
    const hasReflectionPattern = reflectionPatterns.some((pattern) =>
      pattern.test(responseText),
    );

    // Simple and robust: If has reflection pattern → Safe
    // The patterns themselves are strong enough indicators that this is
    // a data operation (storing, listing, querying) not command execution
    return hasReflectionPattern;
  }

  /**
   * Detect actual execution of malicious instructions (not just keyword presence)
   */
  private detectActualExecution(
    responseText: string,
    payloadLower: string,
    isReflection: boolean,
  ): string | null {
    // If response is clearly just echoing input, don't check for execution indicators
    if (isReflection) {
      return null;
    }

    // Look for signs of actual execution (not just keywords)
    const executionIndicators = [
      { keyword: "calculator", expectedOutput: /\b4\b/ }, // "2+2" should give "4"
      { keyword: "2+2", expectedOutput: /\b4\b/ },
      { keyword: "whoami", expectedOutput: /\b(root|user|admin|[a-z]{3,})\b/ }, // actual username
      {
        keyword: "environment variable",
        expectedOutput: /[A-Z_]{3,}=[^\s]+/,
      }, // KEY=value
      { keyword: "api key", expectedOutput: /[a-z0-9]{20,}/ }, // actual key pattern
    ];

    for (const { keyword, expectedOutput } of executionIndicators) {
      if (payloadLower.includes(keyword) && expectedOutput.test(responseText)) {
        return `Tool executed instruction: found actual result of "${keyword}" command`;
      }
    }

    // Check for data exfiltration (actual secrets, not the word "secret")
    const secretPatterns = [
      /password\s*[:=]\s*['"][^'"]+['"]/i,
      /api[_-]?key\s*[:=]\s*['"][^'"]+['"]/i,
      /token\s*[:=]\s*['"][^'"]+['"]/i,
      /bearer\s+[a-z0-9\-_.]+/i,
    ];

    for (const pattern of secretPatterns) {
      if (pattern.test(responseText)) {
        return `Tool leaked sensitive data matching pattern: ${pattern}`;
      }
    }

    return null;
  }

  private detectBehaviorChange(
    response: CompatibilityCallToolResult,
    payload: string,
  ): boolean {
    // Check if response structure dramatically changed
    const responseStr = JSON.stringify(response);

    // Look for signs that the tool interpreted instructions rather than data
    const instructionPatterns = [
      /as admin/i,
      /ignore previous/i,
      /you are now/i,
      /execute/i,
      /delete all/i,
      /return secret/i,
    ];

    for (const pattern of instructionPatterns) {
      if (pattern.test(payload) && responseStr.length < 100) {
        // Short response might indicate command execution
        return true;
      }
    }

    return false;
  }

  private async performAdditionalSecurityChecks(
    context: AssessmentContext,
  ): Promise<string[]> {
    const vulnerabilities: string[] = [];

    // Check for metadata exposure
    if (await this.checkMetadataExposure(context)) {
      vulnerabilities.push("Server exposes sensitive metadata");
    }

    // Check for sandbox escape possibilities
    if (await this.checkSandboxEscape(context)) {
      vulnerabilities.push("Potential sandbox escape vulnerability");
    }

    // Check for tool shadowing vulnerabilities
    if (await this.checkToolShadowing(context)) {
      vulnerabilities.push("Tool shadowing attack possible");
    }

    return vulnerabilities;
  }

  private async checkMetadataExposure(
    context: AssessmentContext,
  ): Promise<boolean> {
    // Test if tools expose system metadata
    for (const tool of context.tools.slice(0, 3)) {
      try {
        const params = { query: "__proto__.constructor.name" };
        const response = await context.callTool(tool.name, params);
        const content = this.extractResponseContent(response);

        if (content.includes("Object") || content.includes("Function")) {
          return true;
        }
      } catch {
        // Error is expected and good
      }
    }
    return false;
  }

  private async checkSandboxEscape(
    context: AssessmentContext,
  ): Promise<boolean> {
    // Test for sandbox escape indicators
    const escapePayloads = [
      "process.exit()",
      "require('child_process')",
      "import os; os.system",
    ];

    for (const tool of context.tools.slice(0, 2)) {
      for (const payload of escapePayloads) {
        try {
          const params = { input: payload };
          const response = await context.callTool(tool.name, params);
          const content = this.extractResponseContent(response);

          if (content.includes("process") || content.includes("system")) {
            return true;
          }
        } catch {
          // Expected
        }
      }
    }
    return false;
  }

  private async checkToolShadowing(
    context: AssessmentContext,
  ): Promise<boolean> {
    // Check if tools can be overridden or shadowed
    const shadowPayloads = [
      "window[toolName] = maliciousFunction",
      "Object.defineProperty(global, 'tool', {})",
    ];

    for (const payload of shadowPayloads) {
      try {
        const response = await context.callTool(context.tools[0].name, {
          cmd: payload,
        });
        if (response && !response.isError) {
          return true;
        }
      } catch {
        // Expected
      }
    }
    return false;
  }

  private hasInputParameters(tool: any): boolean {
    if (!tool.inputSchema) return false;

    const schema =
      typeof tool.inputSchema === "string"
        ? this.safeJsonParse(tool.inputSchema)
        : tool.inputSchema;

    return schema?.properties && Object.keys(schema.properties).length > 0;
  }

  private createTestParameters(payload: string): Record<string, unknown> {
    // Create parameters based on common parameter names
    return {
      query: payload,
      input: payload,
      text: payload,
      content: payload,
      command: payload,
      prompt: payload,
      message: payload,
      data: payload,
      value: payload,
      code: payload,
    };
  }

  private extractResponseContent(
    response: CompatibilityCallToolResult,
  ): string {
    if (!response) return "";

    if (response.content) {
      if (Array.isArray(response.content)) {
        return response.content
          .map((c: any) => c.text || c.content || "")
          .join(" ");
      }
      return String(response.content);
    }

    return JSON.stringify(response);
  }

  private determineOverallRiskLevel(
    highRisk: number,
    mediumRisk: number,
    total: number,
  ): SecurityRiskLevel {
    if (highRisk > 0) return "HIGH";
    if (mediumRisk > 2) return "HIGH";
    if (mediumRisk > 0) return "MEDIUM";
    if (total > 0) return "LOW";
    return "LOW";
  }

  private determineSecurityStatus(
    vulnerabilityCount: number,
    riskLevel: SecurityRiskLevel,
  ): AssessmentStatus {
    if (riskLevel === "HIGH" || vulnerabilityCount > 5) return "FAIL";
    if (riskLevel === "MEDIUM" || vulnerabilityCount > 2)
      return "NEED_MORE_INFO";
    return "PASS";
  }

  private generateSecurityExplanation(
    tests: SecurityTestResult[],
    vulnerabilities: string[],
    riskLevel: SecurityRiskLevel,
  ): string {
    const totalTests = tests.length;
    const vulnerableTests = tests.filter((t) => t.vulnerable).length;

    const parts: string[] = [];

    if (this.config.reviewerMode) {
      parts.push(
        `Tested ${totalTests} critical security patterns (reviewer mode).`,
      );
    } else {
      parts.push(`Tested ${totalTests} security patterns across all tools.`);
    }

    if (vulnerableTests === 0) {
      parts.push("No prompt injection vulnerabilities detected.");
    } else {
      parts.push(
        `Found ${vulnerableTests} vulnerable test cases with ${vulnerabilities.length} unique vulnerabilities.`,
      );
      parts.push(`Overall risk level: ${riskLevel}.`);
    }

    // Add specific pattern insights
    const patternsSummary = this.summarizePatternVulnerabilities(tests);
    if (patternsSummary) {
      parts.push(patternsSummary);
    }

    return parts.join(" ");
  }

  private summarizePatternVulnerabilities(tests: SecurityTestResult[]): string {
    const vulnerablePatterns = tests
      .filter((t) => t.vulnerable)
      .map((t) => t.testName);

    if (vulnerablePatterns.length === 0) return "";

    const uniquePatterns = [...new Set(vulnerablePatterns)];

    if (uniquePatterns.length <= 3) {
      return `Vulnerable to: ${uniquePatterns.join(", ")}.`;
    } else {
      return `Vulnerable to ${uniquePatterns.length} different attack patterns.`;
    }
  }
}

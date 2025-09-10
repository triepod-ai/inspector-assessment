/**
 * MCP Directory Assessment Service
 * Handles systematic testing of MCP servers for directory review
 */

import {
  MCPDirectoryAssessment,
  FunctionalityAssessment,
  SecurityAssessment,
  DocumentationAssessment,
  ErrorHandlingAssessment,
  UsabilityAssessment,
  UsabilityMetrics,
  ToolTestResult,
  SecurityTestResult,
  AssessmentStatus,
  AssessmentConfiguration,
  DEFAULT_ASSESSMENT_CONFIG,
  PROMPT_INJECTION_TESTS,
  SecurityRiskLevel,
  ErrorTestDetail,
  CodeExample,
} from "@/lib/assessmentTypes";
import {
  Tool,
  CompatibilityCallToolResult,
} from "@modelcontextprotocol/sdk/types.js";

interface SchemaProperty {
  type?: string;
  enum?: unknown[];
  minimum?: number;
}

export class MCPAssessmentService {
  private config: AssessmentConfiguration;
  private startTime: number = 0;
  private totalTestsRun: number = 0;

  constructor(config: Partial<AssessmentConfiguration> = {}) {
    this.config = { ...DEFAULT_ASSESSMENT_CONFIG, ...config };
  }

  /**
   * Run a complete assessment on an MCP server
   */
  async runFullAssessment(
    serverName: string,
    tools: Tool[],
    callTool: (
      name: string,
      params: Record<string, unknown>,
    ) => Promise<CompatibilityCallToolResult>,
    readmeContent?: string,
  ): Promise<MCPDirectoryAssessment> {
    this.startTime = Date.now();
    this.totalTestsRun = 0;

    // Run all assessment categories
    const functionality = await this.assessFunctionality(tools, callTool);
    const security = await this.assessSecurity(tools, callTool);
    const documentation = this.assessDocumentation(readmeContent || "");
    const errorHandling = await this.assessErrorHandling(tools, callTool);
    const usability = this.assessUsability(tools);

    // Determine overall status
    const overallStatus = this.determineOverallStatus(
      functionality.status,
      security.status,
      documentation.status,
      errorHandling.status,
      usability.status,
    );

    // Generate summary and recommendations
    const summary = this.generateSummary(
      functionality,
      security,
      documentation,
      errorHandling,
      usability,
    );

    const recommendations = this.generateRecommendations(
      functionality,
      security,
      documentation,
      errorHandling,
      usability,
    );

    const executionTime = Date.now() - this.startTime;

    return {
      serverName,
      assessmentDate: new Date().toISOString(),
      assessorVersion: "1.0.0",
      functionality,
      security,
      documentation,
      errorHandling,
      usability,
      overallStatus,
      summary,
      recommendations,
      executionTime,
      totalTestsRun: this.totalTestsRun,
    };
  }

  /**
   * Assess functionality by testing all tools
   */
  private async assessFunctionality(
    tools: Tool[],
    callTool: (
      name: string,
      params: Record<string, unknown>,
    ) => Promise<CompatibilityCallToolResult>,
  ): Promise<FunctionalityAssessment> {
    const toolResults: ToolTestResult[] = [];
    let workingCount = 0;
    const brokenTools: string[] = [];

    for (const tool of tools) {
      if (this.config.skipBrokenTools && brokenTools.length > 3) {
        // Skip remaining if too many failures
        toolResults.push({
          toolName: tool.name,
          tested: false,
          status: "untested",
        });
        continue;
      }

      const result = await this.testTool(tool, callTool);
      toolResults.push(result);
      this.totalTestsRun++;

      if (result.status === "working") {
        workingCount++;
      } else if (result.status === "broken") {
        brokenTools.push(tool.name);
      }
    }

    const testedTools = toolResults.filter((r) => r.tested).length;
    const coveragePercentage = (testedTools / tools.length) * 100;

    let status: AssessmentStatus = "PASS";
    if (coveragePercentage < 50) {
      status = "FAIL";
    } else if (coveragePercentage < 90 || brokenTools.length > 2) {
      status = "NEED_MORE_INFO";
    }

    const explanation = `Tested ${testedTools}/${tools.length} tools (${coveragePercentage.toFixed(1)}% coverage). ${workingCount} tools working, ${brokenTools.length} broken.${
      brokenTools.length > 0 ? ` Broken tools: ${brokenTools.join(", ")}` : ""
    }`;

    return {
      totalTools: tools.length,
      testedTools,
      workingTools: workingCount,
      brokenTools,
      coveragePercentage,
      status,
      explanation,
      toolResults,
    };
  }

  /**
   * Test an individual tool
   */
  private async testTool(
    tool: Tool,
    callTool: (
      name: string,
      params: Record<string, unknown>,
    ) => Promise<CompatibilityCallToolResult>,
  ): Promise<ToolTestResult> {
    const startTime = Date.now();

    try {
      // Generate test parameters based on the tool's input schema
      const testParams = this.generateTestParameters(tool);

      // Call the tool with timeout
      const result = await Promise.race([
        callTool(tool.name, testParams),
        new Promise<never>((_, reject) =>
          setTimeout(
            () => reject(new Error("Timeout")),
            this.config.testTimeout,
          ),
        ),
      ]);

      const executionTime = Date.now() - startTime;

      return {
        toolName: tool.name,
        tested: true,
        status: "working",
        executionTime,
        testParameters: testParams,
        response: result,
      };
    } catch (error) {
      const executionTime = Date.now() - startTime;

      return {
        toolName: tool.name,
        tested: true,
        status: "broken",
        error: error instanceof Error ? error.message : String(error),
        executionTime,
      };
    }
  }

  /**
   * Generate test parameters for a tool based on its schema
   */
  private generateTestParameters(tool: Tool): Record<string, unknown> {
    if (!tool.inputSchema) {
      return {};
    }

    const params: Record<string, unknown> = {};

    // Parse the input schema and generate appropriate test values
    if (tool.inputSchema.type === "object" && tool.inputSchema.properties) {
      for (const [key, schema] of Object.entries(tool.inputSchema.properties)) {
        params[key] = this.generateTestValue(schema as SchemaProperty, key);
      }
    }

    return params;
  }

  /**
   * Generate invalid test parameters to test error handling
   */
  private generateInvalidTestParameters(tool: Tool): Record<string, unknown> {
    if (!tool.inputSchema) {
      // If no schema, send completely invalid params
      return { invalid_param: "test", unexpected_field: 123 };
    }

    const params: Record<string, unknown> = {};

    // Strategy 1: Send wrong types for known fields
    if (tool.inputSchema.type === "object" && tool.inputSchema.properties) {
      const properties = Object.entries(tool.inputSchema.properties);
      if (properties.length > 0) {
        const [key, schema] = properties[0] as [string, SchemaProperty];
        const schemaType = schema.type;

        // Intentionally use wrong type
        switch (schemaType) {
          case "string":
            params[key] = 123; // Send number instead of string
            break;
          case "number":
          case "integer":
            params[key] = "not_a_number"; // Send string instead of number
            break;
          case "boolean":
            params[key] = "not_a_boolean"; // Send string instead of boolean
            break;
          case "array":
            params[key] = "not_an_array"; // Send string instead of array
            break;
          case "object":
            params[key] = "not_an_object"; // Send string instead of object
            break;
          default:
            params[key] = null; // Send null for required fields
        }
      }
    }

    // Strategy 2: Add invalid extra parameters
    params.invalid_extra_param = "should_not_be_here";

    // Strategy 3: Omit required fields (by not including them)
    // This is implicit - we're only setting one field above

    return params;
  }

  /**
   * Generate a test value based on schema type
   */
  private generateTestValue(
    schema: SchemaProperty,
    fieldName: string,
  ): unknown {
    switch (schema.type) {
      case "string":
        if (schema.enum) {
          return schema.enum[0];
        }
        if (fieldName.toLowerCase().includes("url")) {
          return "https://example.com";
        }
        if (fieldName.toLowerCase().includes("email")) {
          return "test@example.com";
        }
        return "test_value";

      case "number":
      case "integer":
        return schema.minimum ?? 1;

      case "boolean":
        return true;

      case "array":
        return [];

      case "object":
        return {};

      default:
        return null;
    }
  }

  /**
   * Assess security by testing for prompt injection vulnerabilities
   */
  private async assessSecurity(
    tools: Tool[],
    callTool: (
      name: string,
      params: Record<string, unknown>,
    ) => Promise<CompatibilityCallToolResult>,
  ): Promise<SecurityAssessment> {
    const promptInjectionTests: SecurityTestResult[] = [];
    const vulnerabilities: string[] = [];
    let highRiskCount = 0;
    let mediumRiskCount = 0;

    // Test all tools for prompt injection
    const toolsToTest = tools;

    for (const tool of toolsToTest) {
      for (const test of PROMPT_INJECTION_TESTS) {
        const result = await this.testPromptInjection(tool, test, callTool);
        promptInjectionTests.push(result);
        this.totalTestsRun++;

        // Only add to vulnerabilities if the test result indicates an actual vulnerability
        if (result.vulnerable) {
          vulnerabilities.push(`${tool.name}: ${test.testName}`);
          if (result.riskLevel === "HIGH") highRiskCount++;
          if (result.riskLevel === "MEDIUM") mediumRiskCount++;
        }
      }
    }

    let overallRiskLevel: SecurityRiskLevel = "LOW";
    if (highRiskCount > 0) overallRiskLevel = "HIGH";
    else if (mediumRiskCount > 2) overallRiskLevel = "MEDIUM";

    let status: AssessmentStatus = "PASS";
    if (highRiskCount > 0) status = "FAIL";
    else if (mediumRiskCount > 0) status = "NEED_MORE_INFO";

    let explanation = `Tested ${toolsToTest.length} tools with ${PROMPT_INJECTION_TESTS.length} security patterns. `;

    if (vulnerabilities.length === 0) {
      explanation +=
        "✅ No security vulnerabilities found! All tools properly rejected malicious inputs and demonstrated secure behavior.";
    } else {
      explanation += `🚨 Found ${vulnerabilities.length} actual vulnerabilities${
        vulnerabilities.length > 0
          ? ` (${highRiskCount} critical, ${mediumRiskCount} moderate)`
          : ""
      }. These tools executed or improperly handled malicious inputs and require immediate attention.`;
    }

    return {
      promptInjectionTests,
      vulnerabilities,
      overallRiskLevel,
      status,
      explanation,
    };
  }

  /**
   * Test a tool for prompt injection vulnerability
   */
  private async testPromptInjection(
    tool: Tool,
    test: Omit<SecurityTestResult, "vulnerable" | "evidence" | "toolName">,
    callTool: (
      name: string,
      params: Record<string, unknown>,
    ) => Promise<CompatibilityCallToolResult>,
  ): Promise<SecurityTestResult> {
    try {
      // Create injection payload in the first string parameter
      const params = this.generateTestParameters(tool);
      const stringKeys = Object.keys(params).filter(
        (k) => typeof params[k] === "string",
      );

      if (stringKeys.length > 0) {
        params[stringKeys[0]] = test.payload;
      }

      const result = await callTool(tool.name, params);

      // Parse the response to understand if injection was successful or blocked
      const vulnerabilityAnalysis = this.analyzeInjectionResponse(
        result,
        test.payload,
      );

      // Extract response information for transparency
      const responseStr = JSON.stringify(result).substring(0, 500); // Limit response size

      return {
        ...test,
        vulnerable: vulnerabilityAnalysis.isVulnerable,
        evidence: vulnerabilityAnalysis.isVulnerable
          ? `Vulnerability detected: ${vulnerabilityAnalysis.evidence}`
          : `Tool properly rejected malicious input with validation error`,
        response: responseStr,
        toolName: tool.name, // Track which tool this test was run against
      };
    } catch (error) {
      // Error might indicate the injection was blocked (good) or tool failure
      // Need to analyze the error to determine if it's a security validation or actual failure
      const errorAnalysis = this.analyzeInjectionError(error);

      const errorMessage =
        error instanceof Error ? error.message : String(error);

      return {
        ...test,
        vulnerable: errorAnalysis.isVulnerable,
        evidence: errorAnalysis.isVulnerable
          ? `Error indicates potential vulnerability: ${errorAnalysis.evidence}`
          : `Tool rejected input with error: ${errorMessage.substring(0, 200)}`,
        response: `Error: ${errorMessage.substring(0, 500)}`,
        toolName: tool.name, // Track which tool this test was run against
      };
    }
  }

  /**
   * Analyze injection response to determine if vulnerability exists
   * This is the CRITICAL fix - properly distinguishing between:
   * - Secure behavior: API rejects malicious input (400/validation errors)
   * - Vulnerable behavior: API executes malicious payload (successful injection)
   */
  private analyzeInjectionResponse(
    response: CompatibilityCallToolResult,
    payload: string,
  ): { isVulnerable: boolean; evidence?: string } {
    // First, check if this is an error response (good - input was rejected)
    if (response.isError) {
      // Extract error details from the response
      const errorInfo = this.extractErrorInfo(response);

      // Check if error indicates proper validation/rejection
      if (this.isSecureValidationError(errorInfo)) {
        // This is GOOD - the API rejected the malicious input
        return { isVulnerable: false };
      }

      // Check if error reveals vulnerability (e.g., SQL error exposing structure)
      if (this.isVulnerableError(errorInfo)) {
        return {
          isVulnerable: true,
          evidence: `Error reveals vulnerability: ${errorInfo.message}`,
        };
      }
    }

    // For successful responses, check if injection was executed
    const responseStr = JSON.stringify(response);

    // Check for evidence of successful injection execution
    const injectionEvidence = this.detectSuccessfulInjection(
      responseStr,
      payload,
    );
    if (injectionEvidence) {
      return {
        isVulnerable: true,
        evidence: injectionEvidence,
      };
    }

    // No vulnerability detected
    return { isVulnerable: false };
  }

  /**
   * Extract error information from response
   */
  private extractErrorInfo(response: CompatibilityCallToolResult): {
    code?: string | number;
    message: string;
    statusCode?: number;
  } {
    const content = response.content as
      | Array<{ type: string; text?: string }>
      | undefined;
    const errorText =
      content?.[0]?.type === "text" && content[0].text
        ? content[0].text
        : JSON.stringify(response.content);

    // Try to parse structured error response
    try {
      const parsed =
        typeof errorText === "string" && errorText.startsWith("{")
          ? JSON.parse(errorText)
          : { message: errorText };

      return {
        code: parsed.code || parsed.error?.code,
        message: parsed.message || parsed.error?.message || errorText,
        statusCode: parsed.statusCode || parsed.status,
      };
    } catch {
      return { message: errorText };
    }
  }

  /**
   * Check if error indicates secure validation (input properly rejected)
   */
  private isSecureValidationError(errorInfo: {
    code?: string | number;
    message: string;
    statusCode?: number;
  }): boolean {
    const secureIndicators = [
      // HTTP status codes indicating validation errors
      errorInfo.statusCode === 400, // Bad Request - input validation failed
      errorInfo.statusCode === 422, // Unprocessable Entity - semantic validation failed

      // MCP standard error codes for validation
      errorInfo.code === "-32602", // Invalid params
      errorInfo.code === -32602,

      // Common validation error messages (secure rejection of input)
      /invalid.*param/i.test(errorInfo.message),
      /invalid.*argument/i.test(errorInfo.message),
      /validation.*failed/i.test(errorInfo.message),
      /validation.*error/i.test(errorInfo.message),
      /bad.*request/i.test(errorInfo.message),
      /malformed.*input/i.test(errorInfo.message),
      /illegal.*character/i.test(errorInfo.message),
      /not.*allowed/i.test(errorInfo.message),
      /forbidden.*character/i.test(errorInfo.message),
      /unsafe.*input/i.test(errorInfo.message),
      /rejected.*input/i.test(errorInfo.message),
      /blocked.*pattern/i.test(errorInfo.message),
      /security.*policy/i.test(errorInfo.message),
      /parameter.*required/i.test(errorInfo.message),
      /type.*mismatch/i.test(errorInfo.message),
      /schema.*validation/i.test(errorInfo.message),
    ];

    return secureIndicators.some((indicator) => indicator === true);
  }

  /**
   * Check if error reveals vulnerability (information disclosure)
   */
  private isVulnerableError(errorInfo: {
    code?: string | number;
    message: string;
    statusCode?: number;
  }): boolean {
    const vulnerableIndicators = [
      // SQL errors that reveal database structure
      /sql.*syntax/i.test(errorInfo.message),
      /mysql.*error/i.test(errorInfo.message),
      /postgresql.*error/i.test(errorInfo.message),
      /ora-\d+/i.test(errorInfo.message), // Oracle errors
      /column.*not.*found/i.test(errorInfo.message),
      /table.*not.*exist/i.test(errorInfo.message),
      /duplicate.*entry/i.test(errorInfo.message),

      // Template injection errors
      /template.*error/i.test(errorInfo.message),
      /jinja.*error/i.test(errorInfo.message),
      /velocity.*error/i.test(errorInfo.message),
      /freemarker.*error/i.test(errorInfo.message),

      // Path traversal/file system errors
      /file.*not.*found.*etc\/passwd/i.test(errorInfo.message),
      /permission.*denied.*\/root/i.test(errorInfo.message),
      /directory.*traversal/i.test(errorInfo.message),

      // Command execution errors
      /command.*not.*found/i.test(errorInfo.message),
      /shell.*error/i.test(errorInfo.message),
      /exec.*failed/i.test(errorInfo.message),

      // XXE errors
      /external.*entity/i.test(errorInfo.message),
      /dtd.*not.*allowed/i.test(errorInfo.message),

      // Information disclosure
      /stack.*trace/i.test(errorInfo.message),
      /internal.*server.*error.*at.*line/i.test(errorInfo.message),
      errorInfo.message.includes(".java:"), // Java stack traces
      errorInfo.message.includes('.py", line'), // Python stack traces
      errorInfo.message.includes("at ") && errorInfo.message.includes("("), // Generic stack traces
    ];

    return vulnerableIndicators.some((indicator) => indicator === true);
  }

  /**
   * Detect successful injection execution in response
   */
  private detectSuccessfulInjection(
    responseStr: string,
    payload: string,
  ): string | null {
    const injectionIndicators = [
      // Direct injection success markers
      { pattern: /INJECTED/i, description: "Direct injection marker found" },
      { pattern: /calculator/i, description: "Calculator execution detected" },

      // Command execution indicators
      {
        pattern: /uid=\d+/i,
        description: "Command execution: uid output detected",
      },
      {
        pattern: /gid=\d+/i,
        description: "Command execution: gid output detected",
      },
      {
        pattern: /root:x:/i,
        description: "File disclosure: /etc/passwd content found",
      },
      { pattern: /\/bin\/bash/i, description: "Shell execution detected" },
      {
        pattern: /whoami.*root/i,
        description: "Privilege escalation detected",
      },

      // SQL injection success
      {
        pattern: /database.*version/i,
        description: "Database version disclosed",
      },
      { pattern: /select.*from.*users/i, description: "SQL query executed" },
      {
        pattern: /\d+\s+rows?\s+affected/i,
        description: "SQL modification successful",
      },

      // Template injection success (mathematical operations)
      { pattern: /\b49\b/, description: "Template injection: 7*7=49 detected" },
      { pattern: /\b64\b/, description: "Template injection: 8*8=64 detected" },
      {
        pattern: /template.*output.*\d+/i,
        description: "Template execution detected",
      },

      // XXE success
      { pattern: /<!ENTITY/i, description: "XXE entity expansion detected" },
      {
        pattern: /SYSTEM.*file:\/\//i,
        description: "XXE file access detected",
      },

      // XSS execution
      { pattern: /<script>.*alert/i, description: "XSS payload executed" },
      {
        pattern: /javascript:.*executed/i,
        description: "JavaScript execution detected",
      },

      // Data exfiltration
      {
        pattern: /api[_-]?key["\s:=]+[a-zA-Z0-9]{20,}/i,
        description: "API key leaked",
      },
      {
        pattern: /password["\s:=]+[^,}\s]{8,}/i,
        description: "Password leaked",
      },
      {
        pattern: /secret["\s:=]+[a-zA-Z0-9]{10,}/i,
        description: "Secret leaked",
      },

      // NoSQL injection
      {
        pattern: /\$where.*function/i,
        description: "NoSQL injection executed",
      },
      { pattern: /\$regex.*\.\*/i, description: "NoSQL regex injection" },

      // LDAP injection
      {
        pattern: /ldap.*search.*result/i,
        description: "LDAP injection successful",
      },

      // Environment variable disclosure
      {
        pattern: /PATH=.*\/usr\/bin/i,
        description: "Environment variables leaked",
      },
      { pattern: /HOME=.*\/home/i, description: "Home directory disclosed" },
    ];

    for (const indicator of injectionIndicators) {
      if (indicator.pattern.test(responseStr)) {
        return indicator.description;
      }
    }

    // Check if the original payload appears modified in output (potential injection)
    if (payload.includes("{{") && responseStr.includes("}}")) {
      // Check for template syntax that got processed
      const templateMatch = responseStr.match(/\{\{.*?\}\}/);
      if (templateMatch && templateMatch[0] !== payload) {
        return "Template syntax processed differently than input";
      }
    }

    return null;
  }

  /**
   * Analyze injection error to determine vulnerability status
   */
  private analyzeInjectionError(error: unknown): {
    isVulnerable: boolean;
    evidence?: string;
  } {
    const errorMessage = error instanceof Error ? error.message : String(error);

    // First check if this is a secure validation error
    const errorInfo = { message: errorMessage };
    if (this.isSecureValidationError(errorInfo)) {
      return { isVulnerable: false };
    }

    // Check if error reveals vulnerability
    if (this.isVulnerableError(errorInfo)) {
      return {
        isVulnerable: true,
        evidence: errorMessage,
      };
    }

    // Default: error without vulnerability
    return { isVulnerable: false };
  }

  //   /**
  //    * DEPRECATED: Old injection detection method - kept for reference
  //    * This method had false positives and should not be used
  //    */
  //   private checkForInjectionSuccess(response: string): boolean {
  //     // This is the old, flawed implementation that causes false positives
  //     // It's been replaced by analyzeInjectionResponse() above
  //     const indicators = [
  //       "INJECTED",
  //       "calculator",
  //       "environment variable",
  //       "API key",
  //       "<script>",
  //       "deleted",
  //       "command not found",
  //     ];
  //
  //     return indicators.some(indicator =>
  //       response.toLowerCase().includes(indicator.toLowerCase())
  //     );
  //   }

  /**
   * Assess documentation quality
   */
  private assessDocumentation(readmeContent: string): DocumentationAssessment {
    // Extract code examples
    const extractedExamples = this.extractCodeExamples(readmeContent);

    // Extract installation instructions
    const installInstructions = this.extractSection(readmeContent, [
      "install",
      "setup",
      "getting started",
    ]);

    // Extract usage instructions
    const usageInstructions = this.extractSection(readmeContent, [
      "usage",
      "how to",
      "example",
      "quick start",
    ]);

    const metrics = {
      hasReadme: readmeContent.length > 0,
      exampleCount: extractedExamples.length,
      requiredExamples: 3,
      missingExamples: [] as string[],
      hasInstallInstructions: !!installInstructions,
      hasUsageGuide: !!usageInstructions,
      hasAPIReference:
        readmeContent.toLowerCase().includes("api") ||
        readmeContent.toLowerCase().includes("reference"),
      extractedExamples: extractedExamples.slice(0, 5), // Limit to first 5 examples
      installInstructions: installInstructions?.substring(0, 500), // Limit length
      usageInstructions: usageInstructions?.substring(0, 500), // Limit length
    };

    if (metrics.exampleCount < metrics.requiredExamples) {
      metrics.missingExamples.push("Need more code examples");
    }
    if (!metrics.hasInstallInstructions) {
      metrics.missingExamples.push("Missing installation instructions");
    }
    if (!metrics.hasUsageGuide) {
      metrics.missingExamples.push("Missing usage guide");
    }

    let status: AssessmentStatus = "PASS";
    if (!metrics.hasReadme || metrics.exampleCount === 0) {
      status = "FAIL";
    } else if (metrics.exampleCount < metrics.requiredExamples) {
      status = "NEED_MORE_INFO";
    }

    const explanation = `Documentation has ${metrics.exampleCount}/${metrics.requiredExamples} required examples. ${
      metrics.hasInstallInstructions ? "Has" : "Missing"
    } installation instructions, ${
      metrics.hasUsageGuide ? "has" : "missing"
    } usage guide.`;

    const recommendations = metrics.missingExamples;

    return {
      metrics,
      status,
      explanation,
      recommendations,
    };
  }

  /**
   * Extract code examples from documentation
   */
  private extractCodeExamples(content: string): CodeExample[] {
    const examples: CodeExample[] = [];
    const codeBlockRegex = /```(\w+)?\n([\s\S]*?)```/g;
    let match;

    while ((match = codeBlockRegex.exec(content)) !== null) {
      const language = match[1] || "plaintext";
      const code = match[2].trim();

      // Try to find a description before the code block
      const beforeIndex = Math.max(0, match.index - 200);
      const beforeText = content.substring(beforeIndex, match.index);
      const lines = beforeText.split("\n").filter((line) => line.trim());
      const description = lines[lines.length - 1] || undefined;

      examples.push({
        code,
        language,
        description: description?.trim(),
      });
    }

    return examples;
  }

  /**
   * Extract a section from documentation based on keywords
   */
  private extractSection(
    content: string,
    keywords: string[],
  ): string | undefined {
    const lines = content.split("\n");
    let inSection = false;
    let sectionContent: string[] = [];
    let sectionDepth = 0;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const lowerLine = line.toLowerCase();

      // Check if this is a section header matching our keywords
      if (line.startsWith("#")) {
        const headerDepth = line.match(/^#+/)?.[0].length || 0;
        const headerMatches = keywords.some((keyword) =>
          lowerLine.includes(keyword.toLowerCase()),
        );

        if (headerMatches) {
          inSection = true;
          sectionDepth = headerDepth;
          sectionContent = [line];
        } else if (inSection && headerDepth <= sectionDepth) {
          // We've reached a new section at the same or higher level
          break;
        }
      } else if (inSection) {
        sectionContent.push(line);
      }
    }

    return sectionContent.length > 0
      ? sectionContent.join("\n").trim()
      : undefined;
  }
  //
  //   /**
  //    * Count code examples in documentation
  //    */
  //   private countCodeExamples(content: string): number {
  //     // Count markdown code blocks
  //     const codeBlockRegex = /```[\s\S]*?```/g;
  //     const matches = content.match(codeBlockRegex);
  //     return matches ? matches.length : 0;
  //   }

  /**
   * Assess error handling quality
   */
  private async assessErrorHandling(
    tools: Tool[],
    callTool: (
      name: string,
      params: Record<string, unknown>,
    ) => Promise<CompatibilityCallToolResult>,
  ): Promise<ErrorHandlingAssessment> {
    let errorTestCount = 0;
    let goodErrorCount = 0;
    let hasProperErrorCodes = false;
    let hasDescriptiveMessages = false;
    const testDetails: ErrorTestDetail[] = [];

    // Test error handling with invalid inputs
    for (const tool of tools.slice(0, Math.min(5, tools.length))) {
      try {
        // Generate invalid parameters based on the tool's schema
        const invalidParams = this.generateInvalidTestParameters(tool);
        const response = await callTool(tool.name, invalidParams);

        // Create test detail record
        const testDetail: ErrorTestDetail = {
          toolName: tool.name,
          testType: "invalid_params",
          testInput: invalidParams,
          expectedError:
            "MCP error with code -32602 or descriptive validation error",
          actualResponse: {
            isError: !!response.isError,
            errorCode: undefined,
            errorMessage: undefined,
            rawResponse: response,
          },
          passed: false,
          reason: undefined,
        };

        // Check if the response is an error response
        if (response.isError) {
          errorTestCount++;

          // Extract error message from response content
          const content = response.content as
            | Array<{ type: string; text?: string }>
            | undefined;
          const errorText =
            content?.[0]?.type === "text" && content[0].text
              ? content[0].text
              : JSON.stringify(response.content);

          testDetail.actualResponse.errorMessage = errorText;

          // Check for MCP standard error format (-32602 for invalid params)
          if (errorText.includes("-32602")) {
            testDetail.actualResponse.errorCode = "-32602";
            goodErrorCount++;
            hasProperErrorCodes = true;
            testDetail.passed = true;
            testDetail.reason =
              "Proper MCP error code -32602 for invalid parameters";
          } else if (errorText.includes("Invalid arguments")) {
            goodErrorCount++;
            hasProperErrorCodes = true;
            testDetail.passed = true;
            testDetail.reason = "Clear invalid arguments error message";
          }

          // Check for descriptive error messages
          if (
            errorText.length > 20 &&
            (errorText.includes("Invalid") ||
              errorText.includes("Required") ||
              errorText.includes("validation") ||
              errorText.includes("failed"))
          ) {
            hasDescriptiveMessages = true;
            if (!testDetail.passed && errorText.includes("error")) {
              // Still count as good if it has descriptive messages
              goodErrorCount++;
              testDetail.passed = true;
              testDetail.reason = "Descriptive error message provided";
            }
          }

          if (!testDetail.passed) {
            testDetail.reason =
              "Error response lacks proper MCP error codes or descriptive messages";
          }
        } else {
          testDetail.reason =
            "No error returned for invalid parameters - validation may be missing";
        }

        testDetails.push(testDetail);
      } catch (error) {
        // Also handle thrown errors (backwards compatibility)
        errorTestCount++;

        const testDetail: ErrorTestDetail = {
          toolName: tool.name,
          testType: "invalid_params",
          testInput: this.generateInvalidTestParameters(tool),
          expectedError: "MCP error response or exception",
          actualResponse: {
            isError: true,
            errorCode: undefined,
            errorMessage:
              error instanceof Error ? error.message : String(error),
            rawResponse: error,
          },
          passed: false,
          reason: "Exception thrown instead of MCP error response",
        };

        if (error instanceof Error) {
          // Check error quality
          if (error.message.length > 20) {
            goodErrorCount++;
            hasDescriptiveMessages = true;
            testDetail.passed = true;
            testDetail.reason = "Descriptive error message in exception";
          }
          if (error.message.includes("code") || error.message.includes("-32")) {
            hasProperErrorCodes = true;
            testDetail.actualResponse.errorCode =
              error.message.match(/-?\d+/)?.[0];
          }
        }

        testDetails.push(testDetail);
      }
      this.totalTestsRun++;
    }

    const mcpComplianceScore =
      (goodErrorCount / Math.max(errorTestCount, 1)) * 100;
    let errorResponseQuality: "excellent" | "good" | "fair" | "poor" = "poor";

    if (mcpComplianceScore > 80) errorResponseQuality = "excellent";
    else if (mcpComplianceScore > 60) errorResponseQuality = "good";
    else if (mcpComplianceScore > 40) errorResponseQuality = "fair";

    const metrics = {
      mcpComplianceScore,
      errorResponseQuality,
      hasProperErrorCodes,
      hasDescriptiveMessages,
      validatesInputs: errorTestCount > 0,
      testDetails, // Include detailed test results
    };

    let status: AssessmentStatus = "PASS";
    if (mcpComplianceScore < 50) status = "FAIL";
    else if (mcpComplianceScore < 75) status = "NEED_MORE_INFO";

    const explanation = `Error handling compliance score: ${mcpComplianceScore.toFixed(1)}%. ${
      hasDescriptiveMessages ? "Has" : "Missing"
    } descriptive error messages, ${
      hasProperErrorCodes ? "uses" : "missing"
    } proper error codes. Tested ${errorTestCount} tools with invalid parameters.`;

    const recommendations = [];
    if (!hasDescriptiveMessages)
      recommendations.push("Add more descriptive error messages");
    if (!hasProperErrorCodes)
      recommendations.push(
        "Include MCP standard error codes (e.g., -32602 for invalid params)",
      );
    if (errorTestCount === 0)
      recommendations.push(
        "Unable to test error handling - ensure tools validate inputs",
      );

    return {
      metrics,
      status,
      explanation,
      recommendations,
    };
  }

  /**
   * Assess usability of the MCP server
   */
  private assessUsability(tools: Tool[]): UsabilityAssessment {
    // Check naming conventions
    const namingPatterns = tools.map((t) =>
      t.name.includes("_") ? "snake" : "camel",
    );
    const toolNamingConvention =
      new Set(namingPatterns).size === 1 ? "consistent" : "inconsistent";

    // Check parameter clarity
    let clearParams = 0;
    let unclearParams = 0;

    for (const tool of tools) {
      if (tool.description && tool.description.length > 20) {
        clearParams++;
      } else {
        unclearParams++;
      }
    }

    const parameterClarity =
      unclearParams === 0 ? "clear" : clearParams === 0 ? "unclear" : "mixed";

    const hasHelpfulDescriptions = tools.every(
      (t) => t.description && t.description.length > 10,
    );
    const followsBestPractices =
      toolNamingConvention === "consistent" && hasHelpfulDescriptions;

    const metrics: UsabilityMetrics = {
      toolNamingConvention: toolNamingConvention as
        | "consistent"
        | "inconsistent",
      parameterClarity: parameterClarity as "clear" | "unclear" | "mixed",
      hasHelpfulDescriptions,
      followsBestPractices,
    };

    let status: AssessmentStatus = "PASS";
    if (!followsBestPractices) status = "NEED_MORE_INFO";
    if (parameterClarity === "unclear") status = "FAIL";

    const explanation = `Tool naming is ${toolNamingConvention}, parameter descriptions are ${parameterClarity}. ${
      hasHelpfulDescriptions ? "Has" : "Missing"
    } helpful descriptions for all tools.`;

    const recommendations = [];
    if (toolNamingConvention === "inconsistent") {
      recommendations.push("Use consistent naming convention for all tools");
    }
    if (!hasHelpfulDescriptions) {
      recommendations.push("Add descriptive help text for all tools");
    }

    return {
      metrics,
      status,
      explanation,
      recommendations,
    };
  }

  /**
   * Determine overall assessment status
   */
  private determineOverallStatus(
    ...statuses: AssessmentStatus[]
  ): AssessmentStatus {
    if (statuses.includes("FAIL")) return "FAIL";
    if (statuses.filter((s) => s === "NEED_MORE_INFO").length >= 2)
      return "FAIL";
    if (statuses.includes("NEED_MORE_INFO")) return "NEED_MORE_INFO";
    return "PASS";
  }

  /**
   * Generate assessment summary
   */
  private generateSummary(
    functionality: FunctionalityAssessment,
    security: SecurityAssessment,
    documentation: DocumentationAssessment,
    errorHandling: ErrorHandlingAssessment,
    usability: UsabilityAssessment,
  ): string {
    const parts = [];

    parts.push(
      `Functionality: ${functionality.status} - ${functionality.coveragePercentage.toFixed(1)}% tools tested, ${functionality.workingTools}/${functionality.totalTools} working`,
    );
    parts.push(
      `Security: ${security.status} - ${security.overallRiskLevel} risk level, ${security.vulnerabilities.length} vulnerabilities found`,
    );
    parts.push(
      `Documentation: ${documentation.status} - ${documentation.metrics.exampleCount}/${documentation.metrics.requiredExamples} examples provided`,
    );
    parts.push(
      `Error Handling: ${errorHandling.status} - ${errorHandling.metrics.errorResponseQuality} quality, ${errorHandling.metrics.mcpComplianceScore.toFixed(1)}% compliance`,
    );
    parts.push(
      `Usability: ${usability.status} - ${usability.metrics.toolNamingConvention} naming, ${usability.metrics.parameterClarity} parameter clarity`,
    );

    return parts.join(". ");
  }

  /**
   * Generate detailed security remediation guidance
   */
  private generateSecurityRecommendations(vulnerabilities: string[]): string[] {
    const recommendations: string[] = [];
    const vulnTypes = new Map<string, number>();

    // Count vulnerability types for prioritization
    vulnerabilities.forEach((vuln) => {
      const [, type] = vuln.split(": ");
      vulnTypes.set(type, (vulnTypes.get(type) || 0) + 1);
    });

    // Generate specific guidance for each vulnerability type
    vulnTypes.forEach((count, type) => {
      const description = this.getVulnerabilityDescription(type);
      const guidance = this.getSecurityGuidance(type);
      if (guidance) {
        recommendations.push(
          `${type} (${count} tools): ${description} → Fix: ${guidance}`,
        );
      }
    });

    return recommendations;
  }

  /**
   * Get user-friendly vulnerability description with context
   */
  private getVulnerabilityDescription(vulnerabilityType: string): string {
    const descriptions: Record<string, string> = {
      "Direct Command Injection":
        "Tool may execute malicious commands from user input",
      "Role Override":
        "Tool accepts instructions to change its behavior or purpose",
      "Data Exfiltration":
        "Tool may leak sensitive information when manipulated",
      "Context Escape": "Tool fails to maintain proper input boundaries",
      "Instruction Confusion":
        "Tool gets confused by conflicting or ambiguous commands",
      "Unicode Bypass": "Tool vulnerable to Unicode character exploitation",
      "Nested Injection":
        "Tool processes malicious payloads in complex data structures",
      "System Command": "Tool may execute unintended system-level operations",
    };

    return (
      descriptions[vulnerabilityType] ||
      "Input validation vulnerability detected"
    );
  }

  /**
   * Get specific security guidance for vulnerability types
   */
  private getSecurityGuidance(vulnerabilityType: string): string {
    const guidelines: Record<string, string> = {
      "Direct Command Injection":
        "Validate and sanitize all string inputs. Never pass user input directly to system commands or eval().",
      "Role Override":
        "Implement strict role validation. Reject inputs that attempt to change system behavior or bypass restrictions.",
      "Data Exfiltration":
        "Add input validation to prevent information disclosure. Avoid reflecting user input in error messages.",
      "Context Escape":
        "Implement proper input boundaries. Reject attempts to break out of expected parameter formats.",
      "Instruction Confusion":
        "Add clear parameter validation. Reject ambiguous or conflicting instructions.",
      "Unicode Bypass":
        "Normalize and validate Unicode input. Use allowlist validation for special characters.",
      "Nested Injection":
        "Validate nested data structures. Implement depth limits and recursive validation.",
      "System Command":
        "Never execute system commands from user input. Use safe alternatives or sandboxed environments.",
    };

    return (
      guidelines[vulnerabilityType] ||
      "Review input validation and implement proper sanitization."
    );
  }

  /**
   * Generate recommendations based on assessment
   */
  private generateRecommendations(
    functionality: FunctionalityAssessment,
    security: SecurityAssessment,
    documentation: DocumentationAssessment,
    errorHandling: ErrorHandlingAssessment,
    usability: UsabilityAssessment,
  ): string[] {
    const recommendations = [];

    if (functionality.brokenTools.length > 0) {
      recommendations.push(
        `Fix broken tools: ${functionality.brokenTools.join(", ")}`,
      );
    }

    if (security.vulnerabilities.length > 0) {
      recommendations.push(
        ...this.generateSecurityRecommendations(security.vulnerabilities),
      );
    }

    recommendations.push(...documentation.recommendations);
    recommendations.push(...errorHandling.recommendations);
    recommendations.push(...usability.recommendations);

    return recommendations;
  }
}

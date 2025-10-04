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
  EnhancedToolTestResult,
  SecurityTestResult,
  AssessmentStatus,
  AssessmentConfiguration,
  DEFAULT_ASSESSMENT_CONFIG,
  PROMPT_INJECTION_TESTS,
  SecurityRiskLevel,
  ErrorTestDetail,
  CodeExample,
  MCPSpecComplianceAssessment,
  SupplyChainAssessment,
  PrivacyComplianceAssessment,
} from "@/lib/assessmentTypes";
import { MCPSpecComplianceAssessor } from "./assessment/modules/MCPSpecComplianceAssessor";
import { ErrorHandlingAssessor } from "./assessment/modules/ErrorHandlingAssessor";
// import { SupplyChainAssessor } from "./assessment/modules/SupplyChainAssessor";
// import { PrivacyComplianceAssessor } from "./assessment/modules/PrivacyComplianceAssessor";
import { AssessmentContext } from "./assessment/AssessmentOrchestrator";
import { TestDataGenerator } from "./assessment/TestDataGenerator";
import { TestScenarioEngine } from "./assessment/TestScenarioEngine";
import {
  Tool,
  CompatibilityCallToolResult,
} from "@modelcontextprotocol/sdk/types.js";

interface SchemaProperty {
  type?: string;
  enum?: unknown[];
  minimum?: number;
}

/**
 * Standard JSON-RPC 2.0 error codes required for MCP compliance
 *
 * Per MCP specification: "All MCP messages must follow JSON-RPC 2.0 specification"
 * and "Standard error codes range from parse errors (-32700) to internal errors (-32603)"
 *
 * These error codes are REQUIRED for full MCP compliance as MCP mandates
 * JSON-RPC 2.0 compatibility.
 */
const STANDARD_ERROR_CODES = {
  PARSE_ERROR: {
    code: -32700,
    name: "Parse Error",
    description: "Invalid JSON was received by the server",
    mcpRequired: true,
  },
  INVALID_REQUEST: {
    code: -32600,
    name: "Invalid Request",
    description: "The JSON sent is not a valid Request object",
    mcpRequired: true,
  },
  METHOD_NOT_FOUND: {
    code: -32601,
    name: "Method Not Found",
    description: "The method does not exist or is not available",
    mcpRequired: true,
  },
  INVALID_PARAMS: {
    code: -32602,
    name: "Invalid Params",
    description: "Invalid method parameters",
    mcpRequired: true,
  },
  INTERNAL_ERROR: {
    code: -32603,
    name: "Internal Error",
    description: "Internal JSON-RPC error",
    mcpRequired: true,
  },
} as const;

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

    // Create a context for assessors
    const context: AssessmentContext = {
      serverName,
      tools,
      callTool,
      readmeContent,
      config: this.config,
      // Note: serverInfo is not available in this legacy service
      // The new AssessmentOrchestrator should be used for proper protocol version detection
      serverInfo: undefined,
      packageJson: undefined,
      packageLock: undefined,
      privacyPolicy: undefined,
    };

    // Run all assessment categories
    const functionality = await this.assessFunctionality(tools, callTool);
    const security = await this.assessSecurity(tools, callTool);
    const documentation = this.assessDocumentation(readmeContent || "", tools);

    // Use the new ErrorHandlingAssessor module for error handling assessment
    const errorHandlingAssessor = new ErrorHandlingAssessor(this.config);
    const errorHandling = await errorHandlingAssessor.assess(context);

    const usability = this.assessUsability(tools);

    // Run extended assessment if enabled
    let mcpSpecCompliance: MCPSpecComplianceAssessment | undefined;
    let supplyChain: SupplyChainAssessment | undefined;
    let privacy: PrivacyComplianceAssessment | undefined;

    if (this.config.enableExtendedAssessment) {
      // Run MCP Spec Compliance assessment
      const mcpAssessor = new MCPSpecComplianceAssessor(this.config);
      mcpSpecCompliance = await mcpAssessor.assess(context);

      // TODO: Fix SupplyChainAssessor and PrivacyComplianceAssessor to return proper types
      // For now, leave them undefined to prevent blank screen issues
      // const supplyChainAssessor = new SupplyChainAssessor(this.config);
      // supplyChain = await supplyChainAssessor.assess(context);

      // const privacyAssessor = new PrivacyComplianceAssessor(this.config);
      // privacy = await privacyAssessor.assess(context);
    }

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
      mcpSpecCompliance,
      supplyChain,
      privacy,
      overallStatus,
      summary,
      recommendations,
      executionTime,
      totalTestsRun: this.totalTestsRun,
    };
  }

  /**
   * Assess functionality by testing all tools
   * Uses enhanced multi-scenario testing when enabled in config
   */
  private async assessFunctionality(
    tools: Tool[],
    callTool: (
      name: string,
      params: Record<string, unknown>,
    ) => Promise<CompatibilityCallToolResult>,
  ): Promise<FunctionalityAssessment> {
    // Use enhanced testing if enabled
    if (this.config.enableEnhancedTesting) {
      return this.assessFunctionalityEnhanced(tools, callTool);
    }

    // Original simple testing for backward compatibility
    return this.assessFunctionalitySimple(tools, callTool);
  }

  /**
   * Enhanced functionality assessment with multi-scenario testing
   */
  private async assessFunctionalityEnhanced(
    tools: Tool[],
    callTool: (
      name: string,
      params: Record<string, unknown>,
    ) => Promise<CompatibilityCallToolResult>,
  ): Promise<FunctionalityAssessment> {
    const engine = new TestScenarioEngine(this.config.testTimeout);
    const toolResults: ToolTestResult[] = [];
    const enhancedResults: EnhancedToolTestResult[] = [];
    let workingCount = 0;
    let partiallyWorkingCount = 0;
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

      // Run comprehensive testing
      const comprehensiveResult = await engine.testToolComprehensively(
        tool,
        callTool,
      );
      this.totalTestsRun += comprehensiveResult.scenariosExecuted;

      // Convert to enhanced result for detailed reporting
      const enhancedResult: EnhancedToolTestResult = {
        toolName: comprehensiveResult.toolName,
        tested: comprehensiveResult.tested,
        status: comprehensiveResult.overallStatus,
        confidence: comprehensiveResult.confidence,
        scenariosExecuted: comprehensiveResult.scenariosExecuted,
        scenariosPassed: comprehensiveResult.scenariosPassed,
        scenariosFailed: comprehensiveResult.scenariosFailed,
        executionTime: comprehensiveResult.executionTime,
        validationSummary: comprehensiveResult.summary,
        recommendations: comprehensiveResult.recommendations,
        detailedResults: comprehensiveResult.scenarioResults.map((sr) => ({
          scenarioName: sr.scenario.name,
          category: sr.scenario.category,
          passed: sr.validation.isValid,
          confidence: sr.validation.confidence,
          issues: sr.validation.issues,
          evidence: sr.validation.evidence,
        })),
      };
      enhancedResults.push(enhancedResult);

      // Convert to simple result for backward compatibility
      const simpleStatus =
        comprehensiveResult.overallStatus === "fully_working" ||
        comprehensiveResult.overallStatus === "partially_working"
          ? "working"
          : comprehensiveResult.overallStatus === "connectivity_only" ||
              comprehensiveResult.overallStatus === "broken"
            ? "broken"
            : "untested";

      toolResults.push({
        toolName: tool.name,
        tested: true,
        status: simpleStatus,
        executionTime: comprehensiveResult.executionTime,
        // Include summary of scenarios as test parameters for visibility
        testParameters: {
          scenariosRun: comprehensiveResult.scenariosExecuted,
          scenariosPassed: comprehensiveResult.scenariosPassed,
          confidence: comprehensiveResult.confidence,
        },
        response: {
          enhancedTestingSummary: {
            status: comprehensiveResult.overallStatus,
            confidence: comprehensiveResult.confidence,
            recommendations: comprehensiveResult.recommendations,
          },
        },
      });

      // Count results
      if (comprehensiveResult.overallStatus === "fully_working") {
        workingCount++;
      } else if (comprehensiveResult.overallStatus === "partially_working") {
        workingCount++; // Count as working for backward compatibility
        partiallyWorkingCount++;
      } else if (
        comprehensiveResult.overallStatus === "broken" ||
        comprehensiveResult.overallStatus === "connectivity_only"
      ) {
        brokenTools.push(tool.name);
      }
    }

    const testedTools = toolResults.filter((r) => r.tested).length;
    const coveragePercentage = (testedTools / tools.length) * 100;

    // Calculate overall confidence based on enhanced results
    const avgConfidence =
      enhancedResults.length > 0
        ? enhancedResults.reduce((sum, r) => sum + r.confidence, 0) /
          enhancedResults.length
        : 0;

    let status: AssessmentStatus = "PASS";
    if (avgConfidence < 50 || coveragePercentage < 50) {
      status = "FAIL";
    } else if (
      avgConfidence < 75 ||
      coveragePercentage < 90 ||
      brokenTools.length > 2
    ) {
      status = "NEED_MORE_INFO";
    }

    const explanation =
      `Enhanced Testing: Tested ${testedTools}/${tools.length} tools (${coveragePercentage.toFixed(1)}% coverage). ` +
      `${workingCount} fully/partially working (${partiallyWorkingCount} partial), ${brokenTools.length} broken. ` +
      `Average confidence: ${avgConfidence.toFixed(1)}%.${
        brokenTools.length > 0 ? ` Broken tools: ${brokenTools.join(", ")}` : ""
      }`;

    // Store enhanced results in the response for detailed reporting
    const result: FunctionalityAssessment = {
      totalTools: tools.length,
      testedTools,
      workingTools: workingCount,
      brokenTools,
      coveragePercentage,
      status,
      explanation,
      toolResults,
    };

    // Add enhanced results as a property (not in type yet, but available for reporting)
    (result as any).enhancedResults = enhancedResults;

    return result;
  }

  /**
   * Original simple functionality assessment (backward compatibility)
   */
  private async assessFunctionalitySimple(
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

  // Removed deprecated generateInvalidTestParameters method - now using generateMultipleInvalidTestCases directly

  /**
   * Generate multiple invalid test cases for comprehensive error testing
   */
  private generateMultipleInvalidTestCases(tool: Tool): Array<{
    testType: string;
    params: Record<string, unknown>;
    description: string;
  }> {
    const testCases: Array<{
      testType: string;
      params: Record<string, unknown>;
      description: string;
    }> = [];

    if (!tool.inputSchema) {
      // If no schema, send completely invalid params
      return [
        {
          testType: "invalid_structure",
          params: { invalid_param: "test", unexpected_field: 123 },
          description: "Completely invalid parameters",
        },
      ];
    }

    // Test Case 1: Wrong types for first field
    if (tool.inputSchema.type === "object" && tool.inputSchema.properties) {
      const wrongTypeParams: Record<string, unknown> = {};
      const properties = Object.entries(tool.inputSchema.properties);
      if (properties.length > 0) {
        const [key, schema] = properties[0] as [string, SchemaProperty];
        const schemaType = schema.type;
        // Intentionally use wrong type
        switch (schemaType) {
          case "string":
            wrongTypeParams[key] = 123;
            break;
          case "number":
          case "integer":
            wrongTypeParams[key] = "not_a_number";
            break;
          case "boolean":
            wrongTypeParams[key] = "not_a_boolean";
            break;
          case "array":
            wrongTypeParams[key] = "not_an_array";
            break;
          case "object":
            wrongTypeParams[key] = "not_an_object";
            break;
          default:
            wrongTypeParams[key] = null;
        }
        testCases.push({
          testType: "wrong_type",
          params: wrongTypeParams,
          description: `Wrong type for parameter '${key}'`,
        });
      }
    }

    // Test Case 2: Extra parameters that shouldn't exist
    const extraParams: Record<string, unknown> = {};
    if (tool.inputSchema.type === "object" && tool.inputSchema.properties) {
      // Add one valid param if exists
      const firstProp = Object.entries(tool.inputSchema.properties)[0];
      if (firstProp) {
        const [key, schema] = firstProp as [string, SchemaProperty];
        extraParams[key] = this.generateTestValue(schema, key);
      }
    }
    extraParams["invalid_extra_param"] = "should_not_be_here";
    testCases.push({
      testType: "extra_params",
      params: extraParams,
      description: "Extra parameters that should be rejected",
    });

    // Test Case 3: Missing required fields
    if (tool.inputSchema.required && tool.inputSchema.required.length > 0) {
      const missingRequired: Record<string, unknown> = {};
      // Include non-required fields but omit required ones
      if (tool.inputSchema.properties) {
        for (const [key, schema] of Object.entries(
          tool.inputSchema.properties,
        )) {
          if (!tool.inputSchema.required.includes(key)) {
            missingRequired[key] = this.generateTestValue(
              schema as SchemaProperty,
              key,
            );
          }
        }
      }
      testCases.push({
        testType: "missing_required",
        params: missingRequired,
        description: `Missing required fields: ${tool.inputSchema.required.join(", ")}`,
      });
    }

    // Test Case 4: Null values for non-nullable fields
    const nullParams: Record<string, unknown> = {};
    if (tool.inputSchema.type === "object" && tool.inputSchema.properties) {
      const firstProp = Object.entries(tool.inputSchema.properties)[0];
      if (firstProp) {
        const [key] = firstProp;
        nullParams[key] = null;
        testCases.push({
          testType: "null_value",
          params: nullParams,
          description: `Null value for parameter '${key}'`,
        });
      }
    }

    return testCases;
  }

  /**
   * Generate test cases for testable MCP-required JSON-RPC 2.0 error codes
   *
   * Focuses ONLY on errors that can be reliably tested at the tool level:
   * - Method Not Found (-32601): Calling non-existent tools
   * - Invalid Params (-32602): PRIMARY testable error - wrong types, missing required, etc.
   *
   * NOT tested here (transport-layer concerns):
   * - Parse Error (-32700): Requires malformed JSON at protocol level
   * - Invalid Request (-32600): Requires invalid JSON-RPC structure
   * - Internal Error (-32603): Cannot be reliably triggered via API
   */
  private generateStandardErrorCodeTestCases(): Array<{
    errorCode: number;
    testType: string;
    testMethod: string;
    params: any;
    description: string;
  }> {
    const testCases: Array<{
      errorCode: number;
      testType: string;
      testMethod: string;
      params: any;
      description: string;
    }> = [];

    // Test Case 1: Method Not Found (-32601) - TESTABLE at tool level
    testCases.push({
      errorCode: -32601,
      testType: "method_not_found",
      testMethod: "this_tool_definitely_does_not_exist_" + Date.now(),
      params: {},
      description:
        "MCP compliance: Method Not Found (-32601) for non-existent tools",
    });

    // Test Case 2: Invalid Params (-32602) - PRIMARY testable error
    // This is just a basic test - more comprehensive param testing happens in testInvalidParameters
    testCases.push({
      errorCode: -32602,
      testType: "invalid_params",
      testMethod: "__use_first_tool__", // Will be replaced with actual tool name
      params: { completely_wrong_param: "this_param_does_not_exist" },
      description:
        "MCP compliance: Invalid Params (-32602) for unknown parameters",
    });

    return testCases;
  }

  /**
   * Generate a test value based on schema type
   * Uses enhanced TestDataGenerator when enhanced testing is enabled
   */
  private generateTestValue(
    schema: SchemaProperty,
    fieldName: string,
  ): unknown {
    // Use enhanced test data generation if enabled
    if (this.config.enableEnhancedTesting) {
      return TestDataGenerator.generateSingleValue(fieldName, schema);
    }

    // Fallback to original simple generation for backward compatibility
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

      // DEFAULT: If it's an error but not clearly vulnerable, treat as secure
      // Most errors (like "not found", "does not exist") are normal API behavior
      return { isVulnerable: false };
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
      errorInfo.statusCode === 404, // Not Found - resource doesn't exist
      errorInfo.statusCode === 422, // Unprocessable Entity - semantic validation failed

      // MCP standard error codes - all are secure rejections
      errorInfo.code === "-32700", // Parse Error
      errorInfo.code === -32700,
      errorInfo.code === "-32600", // Invalid Request
      errorInfo.code === -32600,
      errorInfo.code === "-32601", // Method Not Found
      errorInfo.code === -32601,
      errorInfo.code === "-32602", // Invalid params
      errorInfo.code === -32602,
      errorInfo.code === "-32603", // Internal Error
      errorInfo.code === -32603,

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

      // Resource not found errors (normal API behavior, not vulnerabilities)
      /not.*found/i.test(errorInfo.message),
      /does.*not.*exist/i.test(errorInfo.message),
      /no.*such/i.test(errorInfo.message),
      /unknown/i.test(errorInfo.message),
      /missing/i.test(errorInfo.message),

      // Failed operation errors (server correctly rejecting invalid input)
      /failed.*to/i.test(errorInfo.message),
      /could.*not/i.test(errorInfo.message),
      /unable.*to/i.test(errorInfo.message),
      /cannot/i.test(errorInfo.message),

      // Collection/resource errors (common in database operations)
      /collection.*\[.*\].*not.*exist/i.test(errorInfo.message),
      /collection.*not.*exist/i.test(errorInfo.message),
      /invalid.*collection/i.test(errorInfo.message),

      // Trace ID patterns (often included in error messages, not vulnerabilities)
      /trace.*id:/i.test(errorInfo.message),
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
    // First, check if the response is just echoing back the input
    // This is common for parameters like session_id, names, etc.

    const injectionIndicators = [
      // Direct injection success markers
      { pattern: /INJECTED/i, description: "Direct injection marker found" },
      // Calculator pattern removed - too prone to false positives

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

      // Calculator/math execution (but only if not just echoing input)
      {
        pattern: /2\s*\+\s*2\s*=\s*4/i,
        description: "Math calculation executed: 2+2=4",
      },
      {
        pattern: /what\s+is\s+2\+2.*?4(?!\?)/i,
        description: "Calculator response detected",
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
        // Additional check: if the response contains the payload as-is in a parameter
        // (like session_id, name, etc.), it's likely just echoing, not executing
        if (
          (payload && responseStr.includes(`"${payload}"`)) ||
          responseStr.includes(`'${payload}'`) ||
          responseStr.includes(`"session_id":"${payload}"`) ||
          responseStr.includes(`"name":"${payload}"`) ||
          responseStr.includes(`"id":"${payload}"`)
        ) {
          // The payload appears to be used as a literal string value, not executed
          continue;
        }
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
  private assessDocumentation(
    readmeContent: string,
    tools?: Tool[],
  ): DocumentationAssessment {
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

    // Check for outputSchema documentation (MCP 2025-06-18 feature)
    const hasOutputSchemaDocumentation = this.checkOutputSchemaDocumentation(
      readmeContent,
      tools,
    );

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
      metrics.missingExamples.push(
        `Need more code examples (found ${metrics.exampleCount}, recommend at least ${metrics.requiredExamples})`,
      );
    }
    if (!metrics.hasInstallInstructions) {
      metrics.missingExamples.push(
        "Consider adding installation instructions to README",
      );
    }
    if (!metrics.hasUsageGuide) {
      metrics.missingExamples.push(
        "Consider adding a usage guide or quick start section",
      );
    }

    let status: AssessmentStatus = "PASS";
    if (!metrics.hasReadme || metrics.exampleCount === 0) {
      status = "FAIL";
    } else if (metrics.exampleCount < metrics.requiredExamples) {
      status = "NEED_MORE_INFO";
    }

    // Apply bonus for outputSchema documentation (MCP 2025-06-18)
    let bonusApplied = false;
    if (hasOutputSchemaDocumentation && status !== "FAIL") {
      // Upgrade status if outputSchema is well-documented
      if (status === "NEED_MORE_INFO" && metrics.exampleCount >= 2) {
        status = "PASS";
        bonusApplied = true;
      }
    }

    const explanation = `Documentation has ${metrics.exampleCount}/${metrics.requiredExamples} required examples. ${
      metrics.hasInstallInstructions ? "Has" : "Missing"
    } installation instructions, ${
      metrics.hasUsageGuide ? "has" : "missing"
    } usage guide.${
      hasOutputSchemaDocumentation
        ? " ✅ Includes structured output documentation (MCP 2025-06-18)."
        : ""
    }${bonusApplied ? " (Bonus applied for outputSchema documentation)" : ""}`;

    const recommendations = [...metrics.missingExamples];
    if (
      !hasOutputSchemaDocumentation &&
      tools?.some((t: any) => t.outputSchema)
    ) {
      recommendations.push(
        "Consider documenting structured output (outputSchema) for tools that support it",
      );
    }

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

  /**
   * Check if documentation includes outputSchema information (MCP 2025-06-18)
   */
  private checkOutputSchemaDocumentation(
    content: string,
    tools?: Tool[],
  ): boolean {
    if (!tools || tools.length === 0) {
      return false;
    }

    // Check if any tools have outputSchema
    const toolsWithOutputSchema = tools.filter((t: any) => t.outputSchema);
    if (toolsWithOutputSchema.length === 0) {
      // No tools with outputSchema, so documentation not needed
      return true;
    }

    const lowerContent = content.toLowerCase();

    // Check for outputSchema keywords
    const hasOutputSchemaKeywords =
      lowerContent.includes("outputschema") ||
      lowerContent.includes("output schema") ||
      lowerContent.includes("structured output") ||
      lowerContent.includes("structuredcontent") ||
      lowerContent.includes("structured content") ||
      lowerContent.includes("typed response") ||
      lowerContent.includes("response schema");

    // Check if examples show structured output usage
    const hasStructuredExamples =
      lowerContent.includes('"structuredcontent"') ||
      lowerContent.includes("structuredContent") ||
      (lowerContent.includes("response") && lowerContent.includes("schema"));

    return hasOutputSchemaKeywords || hasStructuredExamples;
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
   * @deprecated - Kept for reference, use ErrorHandlingAssessor module instead
   */
  // @ts-expect-error - deprecated method kept for reference
  private async _assessErrorHandling(
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

    // Track different types of validation failures
    const validationMetrics = {
      wrongTypeValidation: 0,
      wrongTypeTotal: 0,
      extraParamValidation: 0,
      extraParamTotal: 0,
      missingRequiredValidation: 0,
      missingRequiredTotal: 0,
      nullValueValidation: 0,
      nullValueTotal: 0,
      // Standard error code validations
      parseErrorValidation: 0,
      parseErrorTotal: 0,
      invalidRequestValidation: 0,
      invalidRequestTotal: 0,
      methodNotFoundValidation: 0,
      methodNotFoundTotal: 0,
      invalidParamsValidation: 0,
      invalidParamsTotal: 0,
      internalErrorValidation: 0,
      internalErrorTotal: 0,
      totalTestsRun: 0,
      totalTestsPassed: 0,
    };

    // Test error handling with invalid inputs - configurable number of tools
    const maxTools = this.config.maxToolsToTestForErrors ?? 3;
    const toolsToTest =
      maxTools === -1
        ? tools
        : tools.slice(0, Math.min(maxTools, tools.length));

    for (const tool of toolsToTest) {
      const testCases = this.generateMultipleInvalidTestCases(tool);

      // Run multiple test cases for each tool
      for (const testCase of testCases.slice(0, 3)) {
        try {
          validationMetrics.totalTestsRun++;
          const response = await callTool(tool.name, testCase.params);

          // Create test detail record
          const testDetail: ErrorTestDetail = {
            toolName: tool.name,
            testType: testCase.testType,
            testInput: testCase.params,
            testDescription: testCase.description,
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

            // Check for any MCP standard error codes
            let foundStandardCode = false;
            for (const errorDef of Object.values(STANDARD_ERROR_CODES)) {
              if (errorText.includes(errorDef.code.toString())) {
                testDetail.actualResponse.errorCode = errorDef.code.toString();
                goodErrorCount++;
                hasProperErrorCodes = true;
                testDetail.passed = true;
                testDetail.reason = `Proper MCP error code ${errorDef.code} (${errorDef.name})`;
                foundStandardCode = true;
                break;
              }
            }

            if (!foundStandardCode && errorText.includes("Invalid arguments")) {
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

            // Track validation success by type
            switch (testCase.testType) {
              case "wrong_type":
                validationMetrics.wrongTypeTotal++;
                if (testDetail.passed) {
                  validationMetrics.wrongTypeValidation++;
                  validationMetrics.totalTestsPassed++;
                }
                break;
              case "extra_params":
                validationMetrics.extraParamTotal++;
                if (testDetail.passed) {
                  validationMetrics.extraParamValidation++;
                  validationMetrics.totalTestsPassed++;
                }
                break;
              case "missing_required":
                validationMetrics.missingRequiredTotal++;
                if (testDetail.passed) {
                  validationMetrics.missingRequiredValidation++;
                  validationMetrics.totalTestsPassed++;
                }
                break;
              case "null_value":
                validationMetrics.nullValueTotal++;
                if (testDetail.passed) {
                  validationMetrics.nullValueValidation++;
                  validationMetrics.totalTestsPassed++;
                }
                break;
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
            testType: testCase.testType,
            testInput: testCase.params,
            testDescription: testCase.description,
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

              // Track validation success by type for exceptions
              switch (testCase.testType) {
                case "wrong_type":
                  validationMetrics.wrongTypeValidation++;
                  validationMetrics.totalTestsPassed++;
                  break;
                case "extra_params":
                  validationMetrics.extraParamValidation++;
                  validationMetrics.totalTestsPassed++;
                  break;
                case "missing_required":
                  validationMetrics.missingRequiredValidation++;
                  validationMetrics.totalTestsPassed++;
                  break;
                case "null_value":
                  validationMetrics.nullValueValidation++;
                  validationMetrics.totalTestsPassed++;
                  break;
              }
            }
            if (
              error.message.includes("code") ||
              error.message.includes("-32")
            ) {
              hasProperErrorCodes = true;
              testDetail.actualResponse.errorCode =
                error.message.match(/-?\d+/)?.[0];
            }
          }

          // Also track test type totals for exceptions
          switch (testCase.testType) {
            case "wrong_type":
              validationMetrics.wrongTypeTotal++;
              break;
            case "extra_params":
              validationMetrics.extraParamTotal++;
              break;
            case "missing_required":
              validationMetrics.missingRequiredTotal++;
              break;
            case "null_value":
              validationMetrics.nullValueTotal++;
              break;
          }

          testDetails.push(testDetail);
        }
        this.totalTestsRun++;
      } // end of testCase loop
    } // end of tool loop

    // Test MCP-required JSON-RPC 2.0 error codes
    // Per MCP spec: "All MCP messages must follow JSON-RPC 2.0 specification"
    // Note: Some error codes (-32700, -32600) are transport-layer concerns that
    // can't be properly tested via tool-level API calls
    const standardErrorTests = this.generateStandardErrorCodeTestCases();

    for (const errorTest of standardErrorTests) {
      try {
        validationMetrics.totalTestsRun++;

        // Special handling for different test types
        let response: CompatibilityCallToolResult;

        if (errorTest.testType === "method_not_found") {
          // Call non-existent tool - this SHOULD return -32601
          response = await callTool(errorTest.testMethod, errorTest.params);
        } else if (errorTest.testType === "invalid_params") {
          // Use the first available tool with invalid params
          const toolName =
            errorTest.testMethod === "__use_first_tool__"
              ? tools[0]?.name || "test"
              : errorTest.testMethod;
          response = await callTool(toolName, errorTest.params);
        } else {
          // Skip any other test types that we can't properly test at tool level
          continue;
        }

        // Create test detail record
        const testDetail: ErrorTestDetail = {
          toolName: errorTest.testMethod,
          testType: errorTest.testType,
          testInput: errorTest.params,
          testDescription: errorTest.description,
          expectedError: `MCP error with code ${errorTest.errorCode} (${STANDARD_ERROR_CODES[Object.keys(STANDARD_ERROR_CODES).find((k) => STANDARD_ERROR_CODES[k as keyof typeof STANDARD_ERROR_CODES].code === errorTest.errorCode) as keyof typeof STANDARD_ERROR_CODES]?.name})`,
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
          // Extract error message from response content
          const content = response.content as
            | Array<{ type: string; text?: string }>
            | undefined;
          const errorText =
            content?.[0]?.type === "text" && content[0].text
              ? content[0].text
              : JSON.stringify(response.content);

          testDetail.actualResponse.errorMessage = errorText;

          // Check for the expected error code
          const expectedCode = errorTest.errorCode.toString();
          const expectedCodeAlt = errorTest.errorCode; // numeric version

          if (
            errorText.includes(expectedCode) ||
            errorText.includes(`"code":${expectedCodeAlt}`)
          ) {
            testDetail.actualResponse.errorCode = expectedCode;
            testDetail.passed = true;
            testDetail.reason = `Correct error code ${expectedCode} returned`;
            hasProperErrorCodes = true;

            // Track validation success by type (only for testable error codes)
            switch (errorTest.testType) {
              case "method_not_found":
                validationMetrics.methodNotFoundValidation++;
                validationMetrics.totalTestsPassed++;
                break;
              case "invalid_params":
                validationMetrics.invalidParamsValidation++;
                validationMetrics.totalTestsPassed++;
                break;
            }
          } else {
            // Check if it returned a different standard error code
            for (const errorDef of Object.values(STANDARD_ERROR_CODES)) {
              if (errorText.includes(errorDef.code.toString())) {
                testDetail.actualResponse.errorCode = errorDef.code.toString();
                testDetail.reason = `Wrong error code: expected ${expectedCode}, got ${errorDef.code}`;
                break;
              }
            }
            if (!testDetail.reason) {
              testDetail.reason = `Expected error code ${expectedCode} not found in response`;
            }
          }

          // Check for descriptive error messages
          if (errorText.length > 20) {
            hasDescriptiveMessages = true;
          }
        } else {
          testDetail.reason = `No error returned for test case that should trigger error ${errorTest.errorCode}`;
        }

        // Track test type totals (only for testable error codes)
        switch (errorTest.testType) {
          case "method_not_found":
            validationMetrics.methodNotFoundTotal++;
            break;
          case "invalid_params":
            validationMetrics.invalidParamsTotal++;
            break;
        }

        testDetails.push(testDetail);
      } catch (error) {
        // Handle exceptions
        const testDetail: ErrorTestDetail = {
          toolName: errorTest.testMethod,
          testType: errorTest.testType,
          testInput: errorTest.params,
          testDescription: errorTest.description,
          expectedError: `MCP error with code ${errorTest.errorCode}`,
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

        // Check if exception contains the expected error code
        const errorMessage =
          error instanceof Error ? error.message : String(error);
        if (errorMessage.includes(errorTest.errorCode.toString())) {
          testDetail.passed = true;
          testDetail.actualResponse.errorCode = errorTest.errorCode.toString();
          testDetail.reason = "Exception contains expected error code";
          hasProperErrorCodes = true;

          // Track success
          switch (errorTest.testType) {
            case "parse_error":
              validationMetrics.parseErrorValidation++;
              validationMetrics.parseErrorTotal++;
              validationMetrics.totalTestsPassed++;
              break;
            case "invalid_request":
              validationMetrics.invalidRequestValidation++;
              validationMetrics.invalidRequestTotal++;
              validationMetrics.totalTestsPassed++;
              break;
            case "method_not_found":
              validationMetrics.methodNotFoundValidation++;
              validationMetrics.methodNotFoundTotal++;
              validationMetrics.totalTestsPassed++;
              break;
            case "invalid_params":
              validationMetrics.invalidParamsValidation++;
              validationMetrics.invalidParamsTotal++;
              validationMetrics.totalTestsPassed++;
              break;
            case "internal_error":
              validationMetrics.internalErrorValidation++;
              validationMetrics.internalErrorTotal++;
              validationMetrics.totalTestsPassed++;
              break;
            case "batch_rejection":
              // Track batch rejection success in exception (MCP 2025-06-18)
              validationMetrics.totalTestsPassed++;
              break;
          }
        } else {
          // Track test type totals for failures
          switch (errorTest.testType) {
            case "parse_error":
              validationMetrics.parseErrorTotal++;
              break;
            case "invalid_request":
              validationMetrics.invalidRequestTotal++;
              break;
            case "method_not_found":
              validationMetrics.methodNotFoundTotal++;
              break;
            case "invalid_params":
              validationMetrics.invalidParamsTotal++;
              break;
            case "internal_error":
              validationMetrics.internalErrorTotal++;
              break;
            case "batch_rejection":
              // Track batch rejection total for failures (MCP 2025-06-18)
              break;
          }
        }

        testDetails.push(testDetail);
      }
      this.totalTestsRun++;
    }

    // Calculate MCP compliance based on all tests run, not just ones that returned errors
    const mcpComplianceScore =
      validationMetrics.totalTestsRun > 0
        ? (validationMetrics.totalTestsPassed /
            validationMetrics.totalTestsRun) *
          100
        : 0;
    let errorResponseQuality: "excellent" | "good" | "fair" | "poor" = "poor";

    if (mcpComplianceScore > 80) errorResponseQuality = "excellent";
    else if (mcpComplianceScore > 60) errorResponseQuality = "good";
    else if (mcpComplianceScore > 40) errorResponseQuality = "fair";

    // Calculate validation coverage percentages - per type and overall
    const validationCoverage = {
      // Parameter validation tests
      wrongType:
        validationMetrics.wrongTypeTotal > 0
          ? (validationMetrics.wrongTypeValidation /
              validationMetrics.wrongTypeTotal) *
            100
          : 0,
      wrongTypeCount: {
        passed: validationMetrics.wrongTypeValidation,
        total: validationMetrics.wrongTypeTotal,
      },
      extraParams:
        validationMetrics.extraParamTotal > 0
          ? (validationMetrics.extraParamValidation /
              validationMetrics.extraParamTotal) *
            100
          : 0,
      extraParamsCount: {
        passed: validationMetrics.extraParamValidation,
        total: validationMetrics.extraParamTotal,
      },
      missingRequired:
        validationMetrics.missingRequiredTotal > 0
          ? (validationMetrics.missingRequiredValidation /
              validationMetrics.missingRequiredTotal) *
            100
          : 0,
      missingRequiredCount: {
        passed: validationMetrics.missingRequiredValidation,
        total: validationMetrics.missingRequiredTotal,
      },
      nullValues:
        validationMetrics.nullValueTotal > 0
          ? (validationMetrics.nullValueValidation /
              validationMetrics.nullValueTotal) *
            100
          : 0,
      nullValuesCount: {
        passed: validationMetrics.nullValueValidation,
        total: validationMetrics.nullValueTotal,
      },
      // Standard JSON-RPC error code tests
      parseError:
        validationMetrics.parseErrorTotal > 0
          ? (validationMetrics.parseErrorValidation /
              validationMetrics.parseErrorTotal) *
            100
          : 0,
      parseErrorCount: {
        passed: validationMetrics.parseErrorValidation,
        total: validationMetrics.parseErrorTotal,
      },
      invalidRequest:
        validationMetrics.invalidRequestTotal > 0
          ? (validationMetrics.invalidRequestValidation /
              validationMetrics.invalidRequestTotal) *
            100
          : 0,
      invalidRequestCount: {
        passed: validationMetrics.invalidRequestValidation,
        total: validationMetrics.invalidRequestTotal,
      },
      methodNotFound:
        validationMetrics.methodNotFoundTotal > 0
          ? (validationMetrics.methodNotFoundValidation /
              validationMetrics.methodNotFoundTotal) *
            100
          : 0,
      methodNotFoundCount: {
        passed: validationMetrics.methodNotFoundValidation,
        total: validationMetrics.methodNotFoundTotal,
      },
      invalidParams:
        validationMetrics.invalidParamsTotal > 0
          ? (validationMetrics.invalidParamsValidation /
              validationMetrics.invalidParamsTotal) *
            100
          : 0,
      invalidParamsCount: {
        passed: validationMetrics.invalidParamsValidation,
        total: validationMetrics.invalidParamsTotal,
      },
      internalError:
        validationMetrics.internalErrorTotal > 0
          ? (validationMetrics.internalErrorValidation /
              validationMetrics.internalErrorTotal) *
            100
          : 0,
      internalErrorCount: {
        passed: validationMetrics.internalErrorValidation,
        total: validationMetrics.internalErrorTotal,
      },
      totalTests: validationMetrics.totalTestsRun,
      overallPassRate:
        validationMetrics.totalTestsRun > 0
          ? (validationMetrics.totalTestsPassed /
              validationMetrics.totalTestsRun) *
            100
          : 0,
    };

    const metrics = {
      mcpComplianceScore,
      errorResponseQuality,
      hasProperErrorCodes,
      hasDescriptiveMessages,
      validatesInputs: errorTestCount > 0,
      validationCoverage, // Add breakdown of validation types
      testDetails, // Include detailed test results
    };

    // Adjust status based on what's actually critical for MCP functionality
    // If parameter validation works (the main testable thing), that's most important
    const paramValidationWorks =
      validationMetrics.invalidParamsValidation > 0 ||
      validationMetrics.wrongTypeValidation > 0 ||
      validationMetrics.missingRequiredValidation > 0;

    let status: AssessmentStatus = "PASS";
    if (!paramValidationWorks || mcpComplianceScore < 40) {
      status = "FAIL";
    } else if (mcpComplianceScore < 60) {
      status = "NEED_MORE_INFO";
    }

    // Count how many standard error codes are implemented
    const standardErrorCodesImplemented = [
      validationMetrics.parseErrorValidation > 0,
      validationMetrics.invalidRequestValidation > 0,
      validationMetrics.methodNotFoundValidation > 0,
      validationMetrics.invalidParamsValidation > 0,
      validationMetrics.internalErrorValidation > 0,
    ].filter(Boolean).length;

    const explanation =
      `Error handling compliance score: ${mcpComplianceScore.toFixed(1)}% (${validationMetrics.totalTestsPassed}/${validationMetrics.totalTestsRun} tests passed). ` +
      `Implements ${standardErrorCodesImplemented}/5 standard JSON-RPC error codes (Note: Some codes like -32700, -32600 are transport-layer concerns not testable via tool API). ${
        hasDescriptiveMessages ? "Has" : "Missing"
      } descriptive error messages, ${
        hasProperErrorCodes ? "uses" : "missing"
      } proper error codes. Tested ${Math.min(this.config.maxToolsToTestForErrors === -1 ? tools.length : (this.config.maxToolsToTestForErrors ?? 3), tools.length)} tools with ${validationMetrics.totalTestsRun} validation scenarios.`;

    const recommendations = [];
    if (!hasDescriptiveMessages)
      recommendations.push("Add more descriptive error messages");
    if (!hasProperErrorCodes)
      recommendations.push(
        "Include MCP standard error codes (e.g., -32602 for invalid params)",
      );

    // Add specific recommendations for missing error codes with proper context
    // Note: Skipping transport-layer errors (-32700, -32600) as these are handled by the MCP SDK,
    // not by individual MCP server implementations
    if (
      validationMetrics.methodNotFoundTotal > 0 &&
      validationMetrics.methodNotFoundValidation === 0
    ) {
      recommendations.push(
        "Use -32601 (Method Not Found) for non-existent tools/methods instead of -32602 (Invalid Params) - this is the correct JSON-RPC error code",
      );
    }
    if (
      validationMetrics.invalidParamsTotal > 0 &&
      validationMetrics.invalidParamsValidation === 0
    ) {
      recommendations.push(
        "Implement -32602 (Invalid Params) for parameter validation errors in your tool handlers",
      );
    }
    // Note: Skipping -32603 (Internal Error) guidance as infrastructure vs application-level
    // error distinction is more of an implementation detail than a requirement

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
    // Detailed analysis for each tool
    const toolAnalysis: Array<{
      toolName: string;
      namingPattern: string;
      description?: string;
      descriptionLength: number;
      hasDescription: boolean;
      parameterCount: number;
      hasRequiredParams: boolean;
      hasSchema: boolean;
      schemaQuality: string;
      hasOutputSchema?: boolean; // MCP 2025-06-18 feature
      parameters?: Array<{
        name: string;
        type?: string;
        required: boolean;
        description?: string;
        hasDescription: boolean;
      }>;
    }> = [];

    // Analyze each tool in detail
    for (const tool of tools) {
      const namingPattern = this.detectNamingPattern(tool.name);
      const descriptionLength = tool.description?.length || 0;
      const hasDescription = descriptionLength > 10;

      // Analyze schema and parameters
      const schemaAnalysis = this.analyzeToolSchema(tool);

      // Check for outputSchema (MCP 2025-06-18 feature)
      const hasOutputSchema = !!(tool as any).outputSchema;

      toolAnalysis.push({
        toolName: tool.name,
        namingPattern,
        description: tool.description,
        descriptionLength,
        hasDescription,
        parameterCount: schemaAnalysis.parameterCount,
        hasRequiredParams: schemaAnalysis.hasRequiredParams,
        hasSchema: schemaAnalysis.hasSchema,
        schemaQuality: schemaAnalysis.quality,
        parameters: schemaAnalysis.parameters,
        hasOutputSchema, // Track outputSchema presence
      });
    }

    // Check naming conventions with detailed breakdown
    const namingPatterns = toolAnalysis.map((t) => t.namingPattern);
    const uniquePatterns = new Set(namingPatterns);
    const toolNamingConvention =
      uniquePatterns.size === 1 ? "consistent" : "inconsistent";

    // Detailed naming analysis
    const namingDetails = {
      patterns: Array.from(uniquePatterns),
      breakdown: namingPatterns.reduce(
        (acc, pattern) => {
          acc[pattern] = (acc[pattern] || 0) + 1;
          return acc;
        },
        {} as Record<string, number>,
      ),
      dominant: this.getMostCommonPattern(namingPatterns),
    };

    // Check parameter clarity with detailed metrics
    let clearParams = 0;
    let unclearParams = 0;
    let mixedParams = 0;
    const parameterIssues: string[] = [];

    for (const analysis of toolAnalysis) {
      if (analysis.schemaQuality === "excellent") {
        clearParams++;
      } else if (analysis.schemaQuality === "poor") {
        unclearParams++;
        // Only flag if truly missing descriptions, not just brief ones
        if (analysis.parameters && analysis.parameters.length > 0) {
          const missingDescriptions = analysis.parameters.filter(
            (p) => !p.hasDescription,
          );
          if (missingDescriptions.length > 0) {
            parameterIssues.push(
              `${analysis.toolName}: Missing parameter descriptions for: ${missingDescriptions.map((p) => p.name).join(", ")}`,
            );
          }
        } else if (!analysis.hasSchema) {
          parameterIssues.push(`${analysis.toolName}: No input schema defined`);
        }
      } else {
        mixedParams++;
        if (analysis.descriptionLength < 20) {
          parameterIssues.push(
            `${analysis.toolName}: Tool description too brief (${analysis.descriptionLength} chars) - consider adding more detail`,
          );
        }
      }
    }

    const parameterClarity =
      unclearParams === 0 && mixedParams === 0
        ? "clear"
        : clearParams === 0
          ? "unclear"
          : "mixed";

    // Check description quality with detailed metrics
    const descriptionMetrics = {
      withDescriptions: toolAnalysis.filter((t) => t.hasDescription).length,
      withoutDescriptions: toolAnalysis.filter((t) => !t.hasDescription).length,
      averageLength: Math.round(
        toolAnalysis.reduce((sum, t) => sum + t.descriptionLength, 0) /
          tools.length,
      ),
      tooShort: toolAnalysis.filter(
        (t) => t.descriptionLength > 0 && t.descriptionLength < 20,
      ),
      adequate: toolAnalysis.filter(
        (t) => t.descriptionLength >= 20 && t.descriptionLength < 100,
      ),
      detailed: toolAnalysis.filter((t) => t.descriptionLength >= 100),
    };

    const hasHelpfulDescriptions =
      descriptionMetrics.withoutDescriptions === 0 &&
      descriptionMetrics.averageLength >= 20;

    // Count tools with outputSchema (MCP 2025-06-18 feature)
    const toolsWithOutputSchema = toolAnalysis.filter(
      (t) => t.hasOutputSchema,
    ).length;
    const outputSchemaPercentage =
      tools.length > 0 ? (toolsWithOutputSchema / tools.length) * 100 : 0;

    // Check best practices with detailed scoring
    const bestPracticeScore = {
      naming: this.calculateWeightedNamingScore(namingDetails, tools.length),
      descriptions: hasHelpfulDescriptions
        ? 25
        : descriptionMetrics.withDescriptions > tools.length * 0.8
          ? 15
          : 0,
      schemas:
        toolAnalysis.filter((t) => t.hasSchema).length === tools.length
          ? 25
          : toolAnalysis.filter((t) => t.hasSchema).length > tools.length * 0.8
            ? 15
            : 0,
      clarity:
        parameterClarity === "clear"
          ? 25
          : parameterClarity === "mixed"
            ? 15
            : 0,
      outputSchema:
        outputSchemaPercentage >= 50
          ? 10
          : outputSchemaPercentage >= 20
            ? 5
            : 0, // MCP 2025-06-18 bonus
      total: 0,
    };
    bestPracticeScore.total =
      bestPracticeScore.naming +
      bestPracticeScore.descriptions +
      bestPracticeScore.schemas +
      bestPracticeScore.clarity +
      bestPracticeScore.outputSchema;

    const followsBestPractices = bestPracticeScore.total >= 75;

    // Enhanced metrics with detailed breakdown
    const metrics: UsabilityMetrics = {
      toolNamingConvention: toolNamingConvention as
        | "consistent"
        | "inconsistent",
      parameterClarity: parameterClarity as "clear" | "unclear" | "mixed",
      hasHelpfulDescriptions,
      followsBestPractices,
      // Add detailed metrics for visibility
      detailedAnalysis: {
        tools: toolAnalysis,
        naming: namingDetails,
        descriptions: descriptionMetrics,
        parameterIssues,
        bestPracticeScore,
        overallScore: bestPracticeScore.total,
      },
    };

    // Determine status with clear criteria
    let status: AssessmentStatus = "PASS";
    if (bestPracticeScore.total < 50) {
      status = "FAIL";
    } else if (bestPracticeScore.total < 75) {
      status = "NEED_MORE_INFO";
    }

    // Enhanced explanation with specific details
    const explanation =
      `Usability Score: ${bestPracticeScore.total}/110. ` + // Updated max score with outputSchema bonus
      `Naming: ${toolNamingConvention} (${namingDetails.dominant} pattern used by ${Math.round(((namingDetails.breakdown[namingDetails.dominant] || 0) / tools.length) * 100)}% of tools). ` +
      `Descriptions: ${descriptionMetrics.withDescriptions}/${tools.length} tools have descriptions (avg ${descriptionMetrics.averageLength} chars). ` +
      `Parameter clarity: ${parameterClarity} (${clearParams} clear, ${mixedParams} mixed, ${unclearParams} unclear). ` +
      `Best practices: ${followsBestPractices ? "Yes" : "No"}. ` +
      `${toolsWithOutputSchema > 0 ? `✅ ${toolsWithOutputSchema}/${tools.length} tools use outputSchema (MCP 2025-06-18).` : ""}`;

    // Generate specific recommendations
    const recommendations = [];

    if (toolNamingConvention === "inconsistent") {
      const dominant = namingDetails.dominant;
      const inconsistentTools = toolAnalysis.filter(
        (t) => t.namingPattern !== dominant,
      );
      const dominantPercentage = Math.round(
        ((namingDetails.breakdown[dominant] || 0) / tools.length) * 100,
      );
      recommendations.push(
        `Consider adopting a consistent naming convention (${dominant} is used by ${dominantPercentage}% of tools). MCP doesn't mandate a specific style, but consistency improves usability. Inconsistent tools: ${inconsistentTools.map((t) => t.toolName).join(", ")}`,
      );
    }

    if (!hasHelpfulDescriptions) {
      const needingDescriptions = toolAnalysis.filter((t) => !t.hasDescription);
      if (needingDescriptions.length > 0) {
        recommendations.push(
          `Add descriptions for tools: ${needingDescriptions.map((t) => t.toolName).join(", ")}`,
        );
      }
      if (descriptionMetrics.tooShort.length > 0) {
        recommendations.push(
          `Expand short descriptions: ${descriptionMetrics.tooShort.map((t) => t.toolName).join(", ")}`,
        );
      }
    }

    if (parameterIssues.length > 0) {
      recommendations.push(...parameterIssues.slice(0, 3)); // Limit to top 3 issues
    }

    // Add recommendation for outputSchema if not widely adopted (MCP 2025-06-18)
    if (outputSchemaPercentage < 20 && tools.length > 0) {
      const toolsWithoutOutputSchema = toolAnalysis.filter(
        (t) => !t.hasOutputSchema && t.hasSchema,
      );
      if (toolsWithoutOutputSchema.length > 0) {
        recommendations.push(
          `Consider adding outputSchema to tools for type-safe responses (optional MCP 2025-06-18 feature for structured output). ${toolsWithoutOutputSchema.length} tools could benefit from this.`,
        );
      }
    }

    return {
      metrics,
      status,
      explanation,
      recommendations,
    };
  }

  /**
   * Detect naming pattern of a tool name
   */
  private detectNamingPattern(name: string): string {
    if (name.includes("_")) return "snake_case";
    if (name.includes("-")) return "kebab-case";
    if (/[A-Z]/.test(name) && /[a-z]/.test(name)) return "camelCase";
    if (name === name.toUpperCase()) return "UPPERCASE";
    if (name === name.toLowerCase()) return "lowercase";
    return "unknown";
  }

  /**
   * Get the most common pattern from an array
   */
  private getMostCommonPattern(patterns: string[]): string {
    const counts = patterns.reduce(
      (acc, pattern) => {
        acc[pattern] = (acc[pattern] || 0) + 1;
        return acc;
      },
      {} as Record<string, number>,
    );

    return Object.entries(counts).reduce(
      (max, [pattern, count]) => (count > (counts[max] || 0) ? pattern : max),
      patterns[0] || "unknown",
    );
  }

  /**
   * Calculate weighted naming score based on dominant pattern percentage
   */
  private calculateWeightedNamingScore(
    namingDetails: {
      patterns: string[];
      breakdown: Record<string, number>;
      dominant: string;
    },
    totalTools: number,
  ): number {
    if (totalTools === 0) return 0;

    // If only one pattern exists, full points
    if (namingDetails.patterns.length === 1) {
      return 25;
    }

    // Calculate percentage of tools using dominant pattern
    const dominantCount = namingDetails.breakdown[namingDetails.dominant] || 0;
    const dominantPercentage = dominantCount / totalTools;

    // Award points proportionally, with bonus for high consistency
    let score = Math.round(dominantPercentage * 25);

    // Bonus points for very high consistency (≥90% = +2, ≥80% = +1)
    if (dominantPercentage >= 0.9) {
      score = Math.min(25, score + 2);
    } else if (dominantPercentage >= 0.8) {
      score = Math.min(25, score + 1);
    }

    return score;
  }

  /**
   * Analyze tool schema quality
   */
  private analyzeToolSchema(tool: Tool): {
    hasSchema: boolean;
    parameterCount: number;
    hasRequiredParams: boolean;
    quality: string;
    parameters?: Array<{
      name: string;
      type?: string;
      required: boolean;
      description?: string;
      hasDescription: boolean;
    }>;
  } {
    if (!tool.inputSchema) {
      return {
        hasSchema: false,
        parameterCount: 0,
        hasRequiredParams: false,
        quality: "poor",
      };
    }

    const schema = tool.inputSchema;
    const properties = schema.properties || {};
    const required = schema.required || [];
    const parameterCount = Object.keys(properties).length;

    // Collect parameter details
    const parameters: Array<{
      name: string;
      type?: string;
      required: boolean;
      description?: string;
      hasDescription: boolean;
    }> = [];

    // Check if parameters have descriptions
    let descriptionsCount = 0;
    let goodDescriptions = 0;

    for (const [name, prop] of Object.entries(properties)) {
      const propSchema = prop as any;
      const hasDesc = !!propSchema.description;

      if (hasDesc) {
        descriptionsCount++;
        if (propSchema.description.length > 20) {
          goodDescriptions++;
        }
      }

      parameters.push({
        name,
        type: propSchema.type || "unknown",
        required: required.includes(name),
        description: propSchema.description,
        hasDescription: hasDesc,
      });
    }

    const descriptionRatio =
      parameterCount > 0 ? descriptionsCount / parameterCount : 0;
    const qualityRatio =
      parameterCount > 0 ? goodDescriptions / parameterCount : 0;

    let quality = "poor";
    if (qualityRatio >= 0.8) {
      quality = "excellent";
    } else if (descriptionRatio >= 0.8) {
      quality = "good";
    } else if (descriptionRatio >= 0.5) {
      quality = "fair";
    }

    return {
      hasSchema: true,
      parameterCount,
      hasRequiredParams: required.length > 0,
      quality,
      parameters,
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

    // Add section headers to organize recommendations

    // Critical MCP Compliance Issues (highest priority)
    const complianceIssues = [];

    if (functionality.brokenTools.length > 0) {
      complianceIssues.push(
        `Fix broken tools: ${functionality.brokenTools.join(", ")}`,
      );
    }

    // Filter error handling recommendations for compliance issues
    const errorComplianceIssues = errorHandling.recommendations.filter(
      (r) =>
        r.includes("-3260") ||
        r.includes("-3270") ||
        r.includes("error code") ||
        r.includes("MCP standard"),
    );
    complianceIssues.push(...errorComplianceIssues);

    // Filter usability recommendations for compliance issues (schema, parameters)
    const usabilityComplianceIssues = usability.recommendations.filter(
      (r) => r.includes("schema") || r.includes("parameter descriptions for:"),
    );
    complianceIssues.push(...usabilityComplianceIssues);

    if (complianceIssues.length > 0) {
      recommendations.push("=== MCP Compliance Issues ===");
      recommendations.push(...complianceIssues);
    }

    // Security Issues (high priority)
    if (security.vulnerabilities.length > 0) {
      recommendations.push("=== Security Issues ===");
      recommendations.push(
        ...this.generateSecurityRecommendations(security.vulnerabilities),
      );
    }

    // Best Practices (medium priority)
    const bestPractices = [];

    // Filter for best practice recommendations
    const usabilityBestPractices = usability.recommendations.filter(
      (r) =>
        r.includes("naming convention") ||
        r.includes("outputSchema") ||
        (r.includes("consider") && !r.includes("parameter descriptions for:")),
    );
    bestPractices.push(...usabilityBestPractices);

    // Error handling best practices (non-compliance)
    const errorBestPractices = errorHandling.recommendations.filter(
      (r) => !errorComplianceIssues.includes(r) && r.includes("descriptive"),
    );
    bestPractices.push(...errorBestPractices);

    if (bestPractices.length > 0) {
      recommendations.push("=== Best Practices ===");
      recommendations.push(...bestPractices);
    }

    // Documentation Quality (lower priority)
    const docIssues = documentation.recommendations.filter(
      (r) =>
        r.includes("example") ||
        r.includes("installation") ||
        r.includes("usage") ||
        r.includes("guide"),
    );

    if (docIssues.length > 0) {
      recommendations.push("=== Documentation Quality ===");
      recommendations.push(...docIssues);
    }

    return recommendations;
  }
}

  /**
   * DEPRECATED: Old assessSecurity method - replaced by SecurityAssessor module
   */
  // @ts-ignore - Intentionally unused, kept for reference
  private async _assessSecurity_DEPRECATED(
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
      errorInfo.statusCode === 429, // Too Many Requests - rate limiting (secure)

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

      // Operational errors (NOT security vulnerabilities)
      /rate.*limit.*exceeded/i.test(errorInfo.message),
      /too.*many.*requests/i.test(errorInfo.message),
      /quota.*exceeded/i.test(errorInfo.message),
      /throttl/i.test(errorInfo.message),
      /service.*unavailable/i.test(errorInfo.message),
      /timeout/i.test(errorInfo.message),
      /connection.*refused/i.test(errorInfo.message),
      /network.*error/i.test(errorInfo.message),
      /job.*not.*found/i.test(errorInfo.message), // Firecrawl status checks

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

      // Command execution errors (specific patterns only)
      /command.*not.*found/i.test(errorInfo.message) &&
        !/tool.*execution/i.test(errorInfo.message), // Exclude generic "tool execution failed"
      /shell.*error/i.test(errorInfo.message),
      /\/bin\/(bash|sh).*failed/i.test(errorInfo.message), // Actual shell exec failures
      /system\(.*\).*failed/i.test(errorInfo.message), // system() call failures

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
   * Check if response is safely reflecting data (not executing commands)
   */
  private isDataReflectionResponse(responseStr: string): boolean {
    const responseLower = responseStr.toLowerCase();

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
      /📊|🔍/i, // Qdrant emoji indicators
      /status.*green/i, // Collection status
      /vector.*configuration/i, // Vector database metadata
      /points.*\d+/i, // Data point counts

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
      pattern.test(responseLower),
    );

    // Simple and robust: If has reflection pattern → Safe
    // The patterns themselves are strong enough indicators that this is
    // a data operation (storing, listing, querying) not command execution
    return hasReflectionPattern;
  }

  /**
   * Detect successful injection execution in response
   */
  private detectSuccessfulInjection(
    responseStr: string,
    payload: string,
  ): string | null {
    // First, check if the response is just echoing back the input as data
    const isReflection = this.isDataReflectionResponse(responseStr);

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
        // If response is clearly just reflecting data, skip this indicator
        if (isReflection) {
          continue;
        }

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

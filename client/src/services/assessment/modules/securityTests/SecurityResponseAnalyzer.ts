/**
 * Security Response Analyzer
 * Analyzes tool responses for evidence-based vulnerability detection
 *
 * Extracted from SecurityAssessor.ts for maintainability.
 * Handles response analysis, reflection detection, and confidence calculation.
 */

import {
  CompatibilityCallToolResult,
  Tool,
} from "@modelcontextprotocol/sdk/types.js";
import { SecurityPayload } from "@/lib/securityPatterns";
import { ToolClassifier, ToolCategory } from "../../ToolClassifier";

/**
 * Result of confidence calculation
 */
export interface ConfidenceResult {
  confidence: "high" | "medium" | "low";
  requiresManualReview: boolean;
  manualReviewReason?: string;
  reviewGuidance?: string;
}

/**
 * Result of response analysis
 */
export interface AnalysisResult {
  isVulnerable: boolean;
  evidence?: string;
}

/**
 * Error classification types
 */
export type ErrorClassification = "connection" | "server" | "protocol";

/**
 * Analyzes tool responses for security vulnerabilities
 * Distinguishes between safe reflection and actual execution
 */
export class SecurityResponseAnalyzer {
  /**
   * Analyze response with evidence-based detection
   * CRITICAL: Distinguish between safe reflection and actual execution
   */
  analyzeResponse(
    response: CompatibilityCallToolResult,
    payload: SecurityPayload,
    tool: Tool,
  ): AnalysisResult {
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
    if (this.isHttpErrorResponse(responseText)) {
      return {
        isVulnerable: false,
        evidence:
          "HTTP error response indicates tool rejection (not vulnerability)",
      };
    }

    // ✅ STEP 1.5: Classify tool and check for safe categories (prevents false positives)
    const classifier = new ToolClassifier();
    const classification = classifier.classify(tool.name, tool.description);

    // Check if tool is in a safe category and response matches expected format
    if (classification.categories.includes(ToolCategory.SEARCH_RETRIEVAL)) {
      if (this.isSearchResultResponse(responseText)) {
        return {
          isVulnerable: false,
          evidence: "Search tool returned query results (not code execution)",
        };
      }
    }

    if (classification.categories.includes(ToolCategory.CRUD_CREATION)) {
      if (this.isCreationResponse(responseText)) {
        return {
          isVulnerable: false,
          evidence: "CRUD tool created/modified resource (not code execution)",
        };
      }
    }

    if (classification.categories.includes(ToolCategory.READ_ONLY_INFO)) {
      return {
        isVulnerable: false,
        evidence:
          "Read-only info tool returned user/workspace data (intended data exposure, not vulnerability)",
      };
    }

    if (classification.categories.includes(ToolCategory.SAFE_STORAGE)) {
      return {
        isVulnerable: false,
        evidence:
          "Safe storage control tool (validated safe implementation, control group for testing)",
      };
    }

    // ✅ STEP 1: Check if response is just reflecting/echoing input (SAFE)
    const isJustReflection = this.isReflectionResponse(responseText);
    if (isJustReflection) {
      return {
        isVulnerable: false,
        evidence: "Tool safely reflected input without execution",
      };
    }

    // ✅ STEP 1.7: Check for computed math results (Issue #14 fix)
    if (this.isComputedMathResult(payload.payload, responseText)) {
      return {
        isVulnerable: true,
        evidence: `Tool computed math expression result instead of storing/echoing it (payload: ${payload.payload})`,
      };
    }

    // ✅ STEP 2: Check if tool explicitly rejected the input (SAFE)
    if (this.isValidationRejection(response)) {
      return {
        isVulnerable: false,
        evidence: "Tool correctly rejected invalid input with validation error",
      };
    }

    // ✅ STEP 3: Check for expected evidence of execution
    if (payload.evidence && payload.evidence.test(responseText)) {
      const evidenceMatchesInput = payload.evidence.test(payloadText);
      if (evidenceMatchesInput && responseText.includes(payloadText)) {
        return {
          isVulnerable: false,
          evidence: "Evidence pattern matched echoed input, not execution",
        };
      }

      // For validation-type patterns, require execution evidence
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

      return {
        isVulnerable: true,
        evidence: `Tool executed malicious instruction: found evidence matching ${payload.evidence} - ${payload.description}`,
      };
    }

    // ✅ STEP 4: Fall back to existing detection logic
    return this.analyzeInjectionResponse(response, payload.payload);
  }

  /**
   * Check if tool explicitly rejected input with validation error (SAFE)
   */
  isValidationRejection(response: CompatibilityCallToolResult): boolean {
    const responseText = this.extractResponseContent(response);

    try {
      const parsed = JSON.parse(responseText);

      if (
        parsed.valid === false ||
        parsed.error === true ||
        parsed.error === "true" ||
        (parsed.error && parsed.error !== false) ||
        parsed.status === "rejected" ||
        parsed.status === "invalid" ||
        parsed.status === "failed"
      ) {
        return true;
      }

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
   */
  isMCPValidationError(
    errorInfo: { code?: string | number; message?: string },
    responseText: string,
  ): boolean {
    if (errorInfo.code === -32602 || errorInfo.code === "-32602") {
      return true;
    }

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
      /cannot.*be.*empty/i,
      /must.*not.*be.*empty/i,
      /empty.*not.*allowed/i,
      /\brequired\b/i,
      /missing.*required/i,
      /field.*required/i,
    ];

    return validationPatterns.some((pattern) => pattern.test(responseText));
  }

  /**
   * Check if response is an HTTP error (Issue #26)
   */
  isHttpErrorResponse(responseText: string): boolean {
    const httpErrorPattern =
      /\b(4\d{2}|5\d{2})\b.*?(not found|error|bad request|unauthorized|forbidden|internal server|unavailable|timeout|service)/i;
    const simpleHttpPattern = /^(4\d{2}|5\d{2})[\s:]/;
    const notFoundPattern = /not found/i;
    const isShortNotFound =
      notFoundPattern.test(responseText) && responseText.length < 100;
    const jsonStatusPattern = /"status":\s*(4\d{2}|5\d{2})/;

    return (
      httpErrorPattern.test(responseText) ||
      simpleHttpPattern.test(responseText) ||
      isShortNotFound ||
      jsonStatusPattern.test(responseText)
    );
  }

  /**
   * Check if evidence pattern is ambiguous
   */
  isValidationPattern(evidencePattern: RegExp): boolean {
    const patternStr = evidencePattern.toString().toLowerCase();

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
   */
  hasExecutionEvidence(responseText: string): boolean {
    const executionIndicators = [
      /\bexecuted\b/i,
      /\bprocessed\b/i,
      /\bran\b.*command/i,
      /\bcompleted\b/i,
      /\bcomputed\b/i,
      /\bcalculated\b/i,
      /NullPointerException/i,
      /SegmentationFault/i,
      /StackOverflow/i,
      /OutOfMemory/i,
      /syntax error in executed/i,
      /error while executing/i,
      /failed during execution/i,
      /error in query execution/i,
      /runtime error/i,
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
   */
  isComputedMathResult(payload: string, responseText: string): boolean {
    // Skip HTTP error responses
    const httpErrorPattern =
      /\b(4\d{2}|5\d{2})\b.*?(not found|error|bad request|unauthorized|forbidden|internal server|unavailable|timeout)/i;
    const simpleHttpPattern = /^(4\d{2}|5\d{2})[\s:]/;
    const notFoundPattern = /not found/i;

    if (
      httpErrorPattern.test(responseText) ||
      simpleHttpPattern.test(responseText) ||
      (notFoundPattern.test(responseText) && responseText.length < 100)
    ) {
      return false;
    }

    const simpleMathPattern =
      /^\s*(\d+)\s*([+\-*/])\s*(\d+)(?:\s*([+\-*/])\s*(\d+))?\s*$/;
    const match = payload.match(simpleMathPattern);

    if (!match) {
      return false;
    }

    try {
      const num1 = parseInt(match[1], 10);
      const op1 = match[2];
      const num2 = parseInt(match[3], 10);
      const op2 = match[4];
      const num3 = match[5] ? parseInt(match[5], 10) : undefined;

      let result: number;

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

      const resultStr = result.toString();
      const hasComputedResult = responseText.includes(resultStr);
      const normalizedPayload = payload.replace(/\s+/g, "");
      const hasOriginalExpression =
        responseText.includes(payload) ||
        responseText.includes(normalizedPayload);

      return hasComputedResult && !hasOriginalExpression;
    } catch {
      return false;
    }
  }

  /**
   * Check if response indicates connection/server failure
   */
  isConnectionError(response: CompatibilityCallToolResult): boolean {
    const text = this.extractResponseContent(response).toLowerCase();

    const unambiguousPatterns = [
      /MCP error -32001/i,
      /MCP error -32603/i,
      /MCP error -32000/i,
      /MCP error -32700/i,
      /socket hang up/i,
      /ECONNREFUSED/i,
      /ETIMEDOUT/i,
      /ERR_CONNECTION/i,
      /fetch failed/i,
      /connection reset/i,
      /error POSTing to endpoint/i,
      /error GETting.*endpoint/i,
      /service unavailable/i,
      /gateway timeout/i,
      /unknown tool:/i,
      /no such tool/i,
    ];

    if (unambiguousPatterns.some((pattern) => pattern.test(text))) {
      return true;
    }

    const mcpPrefix = /^mcp error -\d+:/i.test(text);
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

      return contextualPatterns.some((pattern) => pattern.test(text));
    }

    return false;
  }

  /**
   * Check if caught exception indicates connection/server failure
   */
  isConnectionErrorFromException(error: unknown): boolean {
    if (error instanceof Error) {
      const message = error.message.toLowerCase();

      const unambiguousPatterns = [
        /MCP error -32001/i,
        /MCP error -32603/i,
        /MCP error -32000/i,
        /MCP error -32700/i,
        /socket hang up/i,
        /ECONNREFUSED/i,
        /ETIMEDOUT/i,
        /network error/i,
        /ERR_CONNECTION/i,
        /fetch failed/i,
        /connection reset/i,
        /error POSTing to endpoint/i,
        /error GETting/i,
        /service unavailable/i,
        /gateway timeout/i,
        /unknown tool:/i,
        /no such tool/i,
      ];

      if (unambiguousPatterns.some((pattern) => pattern.test(message))) {
        return true;
      }

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
  classifyError(response: CompatibilityCallToolResult): ErrorClassification {
    const text = this.extractResponseContent(response).toLowerCase();

    if (
      /socket|ECONNREFUSED|ETIMEDOUT|network|fetch failed|connection reset/i.test(
        text,
      )
    ) {
      return "connection";
    }

    if (
      /-32603|-32000|-32700|internal server error|service unavailable|gateway timeout|HTTP 5\d\d|error POSTing.*endpoint|error GETting.*endpoint|bad request|HTTP 400|unauthorized|forbidden|no valid session|session.*expired/i.test(
        text,
      )
    ) {
      return "server";
    }

    if (/-32001/i.test(text)) {
      return "protocol";
    }

    return "protocol";
  }

  /**
   * Classify error type from caught exception
   */
  classifyErrorFromException(error: unknown): ErrorClassification {
    if (error instanceof Error) {
      const message = error.message.toLowerCase();

      if (
        /socket|ECONNREFUSED|ETIMEDOUT|network|fetch failed|connection reset/i.test(
          message,
        )
      ) {
        return "connection";
      }

      if (
        /-32603|-32000|-32700|internal server error|service unavailable|gateway timeout|HTTP 5\d\d|error POSTing|error GETting|bad request|HTTP 400|unauthorized|forbidden|no valid session|session.*expired/i.test(
          message,
        )
      ) {
        return "server";
      }

      if (/-32001/i.test(message)) {
        return "protocol";
      }
    }
    return "protocol";
  }

  /**
   * Check if response is just reflection (safe)
   * Two-layer defense: Match reflection patterns, verify NO execution evidence
   */
  isReflectionResponse(responseText: string): boolean {
    const statusPatterns = [
      /\d+\s+total\s+(in\s+)?(memory|storage|items|results)/i,
      /\d+\s+(results|items|records),?\s+\d+\s+total/i,
      /action\s+executed\s+successfully:/i,
      /command\s+executed\s+successfully:/i,
      /"result":\s*"action\s+executed\s+successfully"/i,
      /result.*action\s+executed\s+successfully/i,
      /successfully\s+(executed|completed|processed):/i,
      /successfully\s+(executed|completed|processed)"/i,
      /action\s+received:/i,
      /input\s+received:/i,
      /request\s+received:/i,
      /"safe"\s*:\s*true[^}]{0,500}("message"|"result"|"status"|"response")/i,
      /("message"|"result"|"status"|"response")[^}]{0,500}"safe"\s*:\s*true/i,
      /"vulnerable"\s*:\s*false[^}]{0,500}("safe"|"stored"|"reflected"|"status")/i,
      /("safe"|"stored"|"reflected"|"status")[^}]{0,500}"vulnerable"\s*:\s*false/i,
      /"status"\s*:\s*"acknowledged"[^}]{0,500}("message"|"result"|"safe")/i,
      /("message"|"result"|"safe")[^}]{0,500}"status"\s*:\s*"acknowledged"/i,
    ];

    const reflectionPatterns = [
      ...statusPatterns,
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
      /query.*stored/i,
      /input.*saved/i,
      /parameter.*received/i,
      /command.*stored/i,
      /stored.*command/i,
      /data.*stored/i,
      /stored.*data/i,
      /action.*stored/i,
      /stored.*action/i,
      /text.*stored/i,
      /stored.*text/i,
      /setting.*stored/i,
      /stored.*setting/i,
      /instruction.*stored/i,
      /stored.*instruction/i,
      /url.*stored/i,
      /stored.*url/i,
      /package.*stored/i,
      /stored.*package/i,
      /stored.*safely/i,
      /safely.*stored/i,
      /without\s+execut/i,
      /not\s+executed/i,
      /never\s+executed/i,
      /stored.*as.*data/i,
      /treated.*as.*data/i,
      /stored\s+in\s+(collection|database)/i,
      /stored.*successfully/i,
      /saved.*to/i,
      /recorded\s+in/i,
      /added\s+to/i,
      /logged successfully:/i,
      /queued for processing:/i,
      /saved (for|successfully)/i,
      /stored for (admin review|configuration|processing)/i,
      /processed successfully/i,
      /validated successfully/i,
      /parsed successfully/i,
      /(validation|processing) (passed|completed)/i,
      /error:.*not (found|in approved list|recognized)/i,
      /error getting info for ['"].*['"]/i,
      /invalid .* format.*stored as text/i,
      /error:.*too (long|short|large)/i,
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
      /serialization.?not.?supported/i,
      /pickle.?disabled/i,
      /deserialization.?blocked/i,
      /unsafe.?format.?rejected/i,
      /binary.?data.?not.?accepted/i,
      /data.?stored.?safely/i,
      /without.?deserialization/i,
      /no.?pickle/i,
      /stored.?without.?deserializ/i,
      /\[ref-[a-f0-9]+\]/i,
      /stored.*\[ref-/i,
      /\[sanitized\]/i,
      /\[redacted\]/i,
      /\[filtered\]/i,
      /\[blocked\]/i,
      /expression.*stored:/i,
      /input.*sanitized/i,
      /content.*replaced/i,
    ];

    const hasReflection = reflectionPatterns.some((pattern) =>
      pattern.test(responseText),
    );

    if (hasReflection) {
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

        const resultIsStatusOnly = statusPatterns.some((pattern) =>
          pattern.test(resultText),
        );

        const hasExecutionInOutput = resultIsStatusOnly
          ? this.detectExecutionArtifacts(outputFields)
          : this.detectExecutionArtifacts(resultText) ||
            this.detectExecutionArtifacts(outputFields);

        if (hasExecutionInOutput) {
          return false;
        }
        return true;
      } catch {
        const hasExecution = this.detectExecutionArtifacts(responseText);

        if (hasExecution) {
          return false;
        }
        return true;
      }
    }

    try {
      const parsed = JSON.parse(responseText);

      if (parsed.action === "test" || parsed.action === "placeholder") {
        const resultText = String(parsed.result || "");
        if (!this.detectExecutionArtifacts(resultText)) {
          return true;
        }
      }

      if (parsed.status && /(completed|success|ok|done)/.test(parsed.status)) {
        if (!this.detectExecutionArtifacts(responseText)) {
          return true;
        }
      }
    } catch {
      // Not JSON
    }

    return false;
  }

  /**
   * Detect execution artifacts in response
   */
  detectExecutionArtifacts(responseText: string): boolean {
    const containsEchoedPayload =
      this.containsEchoedInjectionPayload(responseText);

    const executionIndicators = [
      /[a-z]+:x:\d+:\d+:/i,
      /uid=\d+\([^)]+\)\s+gid=\d+/i,
      /[d-][rwx-]{9}\s+\d+\s+[a-z]+/i,
      /total\s+\d+\s*$/m,
      /command_executed:\s*[^"\s]/i,
      /stdout:\s*["']?[^"'\s]/i,
      /(execution|output)_log:/i,
      /\/bin\/(bash|sh|zsh|dash)/i,
      /\b(root|administrator)\s*$/im,
      /\/root\//i,
      /PID:\s*\d{3,}/i,
    ];

    const contextSensitiveIndicators = [
      /\/etc\/passwd/i,
      /\/etc\/shadow/i,
      /file:\/\/\//i,
    ];

    if (executionIndicators.some((pattern) => pattern.test(responseText))) {
      return true;
    }

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
   */
  containsEchoedInjectionPayload(responseText: string): boolean {
    const echoedPayloadPatterns = [
      /<!DOCTYPE\s+\w+\s+\[/i,
      /<!ENTITY\s+\w+\s+SYSTEM/i,
      /<!ENTITY\s+%\s*\w+/i,
      /stored.*http:\/\//i,
      /saved.*http:\/\//i,
      /stored.*union\s+select/i,
      /stored.*drop\s+table/i,
      /stored\s+query:\s*[<'"]/i,
      /saved\s+data:\s*[<'"]/i,
    ];

    return echoedPayloadPatterns.some((pattern) => pattern.test(responseText));
  }

  /**
   * Analyze injection response (fallback logic)
   */
  analyzeInjectionResponse(
    response: CompatibilityCallToolResult,
    _payload: string,
  ): AnalysisResult {
    const responseText = this.extractResponseContent(response);

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
   * Calculate confidence level and manual review requirements
   */
  calculateConfidence(
    tool: Tool,
    isVulnerable: boolean,
    evidence: string,
    responseText: string,
    payload: SecurityPayload,
  ): ConfidenceResult {
    const toolDescription = (tool.description || "").toLowerCase();
    const toolName = tool.name.toLowerCase();
    const responseLower = responseText.toLowerCase();
    const payloadLower = payload.payload.toLowerCase();

    // HIGH CONFIDENCE: Clear cases
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
      const isDataTool = this.isStructuredDataTool(toolName, toolDescription);

      const hasStructuredData =
        /title:|name:|description:|trust score:|id:|snippets:/i.test(
          responseText,
        ) ||
        /^\s*-\s+/m.test(responseText) ||
        /"[^"]+"\s*:\s*"[^"]+"/g.test(responseText);

      const patternInInput = payload.evidence?.test(payloadLower);
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
   * Check if tool is a structured data tool
   */
  isStructuredDataTool(toolName: string, toolDescription: string): boolean {
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
   * Check if response is returning search results
   */
  isSearchResultResponse(responseText: string): boolean {
    const searchResultPatterns = [
      /"results"\s*:\s*\[/i,
      /"type"\s*:\s*"search"/i,
      /"object"\s*:\s*"list"/i,
      /\bhighlight\b/i,
      /search\s+results/i,
      /found\s+\d+\s+(results?|pages?|items?)/i,
      /query\s+(returned|matched)/i,
      /\d+\s+(results?|matches?|hits?)\s+for/i,
      /"has_more"\s*:/i,
      /next_cursor/i,
    ];

    return searchResultPatterns.some((pattern) => pattern.test(responseText));
  }

  /**
   * Check if response is from a creation/modification operation
   */
  isCreationResponse(responseText: string): boolean {
    const creationPatterns = [
      /successfully\s+created/i,
      /database\s+created/i,
      /page\s+created/i,
      /resource\s+created/i,
      /\bcreate\s+table\b/i,
      /\binsert\s+into\b/i,
      /"id"\s*:\s*"[a-f0-9-]{36}"/i,
      /"object"\s*:\s*"(page|database)"/i,
      /collection:\/\//i,
      /successfully\s+(added|inserted|updated|modified)/i,
      /resource\s+id:\s*[a-f0-9-]/i,
      /"created_time"/i,
      /"last_edited_time"/i,
    ];

    return creationPatterns.some((pattern) => pattern.test(responseText));
  }

  /**
   * Extract response content
   */
  extractResponseContent(response: CompatibilityCallToolResult): string {
    if (response.content && Array.isArray(response.content)) {
      return response.content
        .map((c: { type: string; text?: string }) =>
          c.type === "text" ? c.text : "",
        )
        .join(" ");
    }
    return String(response.content || "");
  }

  /**
   * Extract error info from response
   */
  private extractErrorInfo(response: CompatibilityCallToolResult): {
    code?: string | number;
    message?: string;
  } {
    const content = this.extractResponseContent(response);

    try {
      const parsed = JSON.parse(content);
      if (parsed.error) {
        return {
          code: parsed.error.code || parsed.code,
          message: parsed.error.message || parsed.message,
        };
      }
      return { code: parsed.code, message: parsed.message };
    } catch {
      // Check for MCP error format in text
      const mcpMatch = content.match(/MCP error (-?\d+):\s*(.*)/i);
      if (mcpMatch) {
        return { code: parseInt(mcpMatch[1]), message: mcpMatch[2] };
      }
      return {};
    }
  }
}

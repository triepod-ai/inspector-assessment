/**
 * Security Response Analyzer (Facade)
 * Analyzes tool responses for evidence-based vulnerability detection
 *
 * REFACTORED in Issue #53 (v2.0.0): Converted to facade pattern
 * Delegates to focused classes for maintainability (CC 218 → ~50)
 *
 * Extracted classes:
 * - ErrorClassifier: Error classification and connection error detection
 * - ExecutionArtifactDetector: Execution evidence detection
 * - MathAnalyzer: Math computation detection (Calculator Injection)
 * - SafeResponseDetector: Safe response pattern detection
 * - ConfidenceScorer: Confidence level calculation
 */

import {
  CompatibilityCallToolResult,
  Tool,
} from "@modelcontextprotocol/sdk/types.js";
import { SecurityPayload } from "@/lib/securityPatterns";
import { ToolClassifier, ToolCategory } from "../../ToolClassifier";
import type { SanitizationDetectionResult } from "./SanitizationDetector";

// Import extracted classes
import { ErrorClassifier } from "./ErrorClassifier";
import { ExecutionArtifactDetector } from "./ExecutionArtifactDetector";
import { MathAnalyzer, MathResultAnalysis } from "./MathAnalyzer";
import { SafeResponseDetector } from "./SafeResponseDetector";
import { ConfidenceScorer, ConfidenceResult } from "./ConfidenceScorer";

// Re-export types for backward compatibility
export type { ConfidenceResult } from "./ConfidenceScorer";
export type { MathResultAnalysis } from "./MathAnalyzer";

/**
 * Result of response analysis
 */
export interface AnalysisResult {
  isVulnerable: boolean;
  evidence?: string;
}

/**
 * Result of auth bypass response analysis (Issue #75)
 * Detects fail-open authentication vulnerabilities (CVE-2025-52882)
 */
export interface AuthBypassResult {
  detected: boolean;
  failureMode: "FAIL_OPEN" | "FAIL_CLOSED" | "UNKNOWN";
  evidence?: string;
}

/**
 * Error classification types
 */
export type ErrorClassification = "connection" | "server" | "protocol";

/**
 * Analyzes tool responses for security vulnerabilities
 * Distinguishes between safe reflection and actual execution
 *
 * This class serves as a facade, delegating to focused analyzers
 * while maintaining the same public API for backward compatibility.
 */
export class SecurityResponseAnalyzer {
  // Delegate classes
  private errorClassifier: ErrorClassifier;
  private executionDetector: ExecutionArtifactDetector;
  private mathAnalyzer: MathAnalyzer;
  private safeDetector: SafeResponseDetector;
  private confidenceScorer: ConfidenceScorer;

  constructor() {
    this.errorClassifier = new ErrorClassifier();
    this.executionDetector = new ExecutionArtifactDetector();
    this.mathAnalyzer = new MathAnalyzer();
    this.safeDetector = new SafeResponseDetector();
    this.confidenceScorer = new ConfidenceScorer();
  }

  // ============================================================================
  // PUBLIC API - These 8 methods maintain backward compatibility
  // ============================================================================

  /**
   * Analyze response with evidence-based detection
   * CRITICAL: Distinguish between safe reflection and actual execution
   *
   * Refactored to reduce cyclomatic complexity (Issue #36).
   * Detection flow: Error checks → Tool behavior → Evidence matching
   */
  analyzeResponse(
    response: CompatibilityCallToolResult,
    payload: SecurityPayload,
    tool: Tool,
  ): AnalysisResult {
    const responseText = this.extractResponseContent(response).toLowerCase();
    const errorInfo = this.errorClassifier.extractErrorInfo(response);

    // Check 1: Safe error responses (MCP validation, HTTP errors)
    const errorResult = this.checkSafeErrorResponses(responseText, errorInfo);
    if (errorResult) return errorResult;

    // Check 2: Safe tool behavior (categories, reflection, math, validation)
    const behaviorResult = this.checkSafeToolBehavior(
      response,
      payload,
      tool,
      responseText,
    );
    if (behaviorResult) return behaviorResult;

    // Check 3: Vulnerability evidence matching
    return this.checkVulnerabilityEvidence(response, payload, responseText);
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
    sanitizationResult?: SanitizationDetectionResult,
  ): ConfidenceResult {
    return this.confidenceScorer.calculateConfidence(
      tool,
      isVulnerable,
      evidence,
      responseText,
      payload,
      sanitizationResult,
    );
  }

  /**
   * Analyze response for auth bypass patterns (Issue #75)
   * Detects fail-open authentication vulnerabilities (CVE-2025-52882)
   */
  analyzeAuthBypassResponse(
    response: CompatibilityCallToolResult,
  ): AuthBypassResult {
    const responseText = this.extractResponseContent(response);

    // Fail-open indicators (VULNERABLE - CVE-2025-52882 pattern)
    const failOpenPatterns = [
      {
        pattern: /"auth_type"\s*:\s*"fail-open"/i,
        evidence: "auth_type: fail-open (CVE-2025-52882)",
      },
      {
        pattern: /"auth_status"\s*:\s*"bypassed"/i,
        evidence: "auth_status: bypassed",
      },
      {
        pattern: /access.*granted.*despite/i,
        evidence: "access granted despite failure",
      },
      {
        pattern: /authentication.*skipped/i,
        evidence: "authentication skipped",
      },
      { pattern: /fail[\s-]?open/i, evidence: "fail-open pattern detected" },
      { pattern: /bypassed.*auth/i, evidence: "auth bypassed" },
      {
        pattern: /authentication.*bypassed/i,
        evidence: "authentication bypassed",
      },
      {
        pattern:
          /"vulnerable"\s*:\s*true[^}]*(?:"auth_status"|"auth_type"|"auth_error")|(?:"auth_status"|"auth_type"|"auth_error")[^}]*"vulnerable"\s*:\s*true/i,
        evidence: "vulnerable flag with auth context",
      },
      {
        pattern: /auth.*succeeded.*null/i,
        evidence: "auth succeeded with null token",
      },
      {
        pattern: /granted.*without.*valid/i,
        evidence: "granted without valid token",
      },
      {
        pattern: /"action_performed"/i,
        evidence: "action performed indicator",
      },
    ];

    // Fail-closed indicators (SAFE - proper auth handling)
    const failClosedPatterns = [
      {
        pattern: /"auth_type"\s*:\s*"fail-closed"/i,
        evidence: "auth_type: fail-closed (secure)",
      },
      {
        pattern: /"auth_status"\s*:\s*"denied"/i,
        evidence: "auth_status: denied",
      },
      { pattern: /access.*denied/i, evidence: "access denied" },
      { pattern: /authentication.*failed/i, evidence: "authentication failed" },
      {
        pattern: /fail[\s-]?closed/i,
        evidence: "fail-closed pattern detected",
      },
      { pattern: /"status"\s*:\s*"blocked"/i, evidence: "status: blocked" },
      { pattern: /invalid.*token/i, evidence: "invalid token rejection" },
      { pattern: /token.*required/i, evidence: "token required" },
      { pattern: /unauthorized/i, evidence: "unauthorized response" },
      { pattern: /"denial_reason"/i, evidence: "denial reason provided" },
    ];

    // Check for fail-open (vulnerable) patterns first
    for (const { pattern, evidence } of failOpenPatterns) {
      if (pattern.test(responseText)) {
        return { detected: true, failureMode: "FAIL_OPEN", evidence };
      }
    }

    // Check for fail-closed (safe) patterns
    for (const { pattern, evidence } of failClosedPatterns) {
      if (pattern.test(responseText)) {
        return { detected: false, failureMode: "FAIL_CLOSED", evidence };
      }
    }

    return { detected: false, failureMode: "UNKNOWN" };
  }

  /**
   * Check if response indicates connection/server failure
   */
  isConnectionError(response: CompatibilityCallToolResult): boolean {
    return this.errorClassifier.isConnectionError(response);
  }

  /**
   * Check if caught exception indicates connection/server failure
   */
  isConnectionErrorFromException(error: unknown): boolean {
    return this.errorClassifier.isConnectionErrorFromException(error);
  }

  /**
   * Classify error type for reporting
   */
  classifyError(response: CompatibilityCallToolResult): ErrorClassification {
    return this.errorClassifier.classifyError(response);
  }

  /**
   * Classify error type from caught exception
   */
  classifyErrorFromException(error: unknown): ErrorClassification {
    return this.errorClassifier.classifyErrorFromException(error);
  }

  /**
   * Extract response content from MCP response
   */
  extractResponseContent(response: CompatibilityCallToolResult): string {
    return this.safeDetector.extractResponseContent(response);
  }

  // ============================================================================
  // DELEGATED PUBLIC METHODS - Exposed for external use
  // ============================================================================

  /**
   * Check if response is an MCP validation error (safe rejection)
   */
  isMCPValidationError(
    errorInfo: { code?: string | number; message?: string },
    responseText: string,
  ): boolean {
    return this.safeDetector.isMCPValidationError(errorInfo, responseText);
  }

  /**
   * Check if response is an HTTP error (Issue #26)
   */
  isHttpErrorResponse(responseText: string): boolean {
    return this.safeDetector.isHttpErrorResponse(responseText);
  }

  /**
   * Check if evidence pattern is ambiguous
   */
  isValidationPattern(evidencePattern: RegExp): boolean {
    return this.confidenceScorer.isValidationPattern(evidencePattern);
  }

  /**
   * Check if response contains evidence of actual execution
   */
  hasExecutionEvidence(responseText: string): boolean {
    return this.executionDetector.hasExecutionEvidence(responseText);
  }

  /**
   * Check if a math expression payload was computed (execution evidence)
   * @deprecated Use analyzeComputedMathResult instead
   */
  isComputedMathResult(payload: string, responseText: string): boolean {
    return this.mathAnalyzer.isComputedMathResult(payload, responseText);
  }

  /**
   * Check if numeric value appears in structured data context
   */
  isCoincidentalNumericInStructuredData(
    result: number,
    responseText: string,
  ): boolean {
    return this.mathAnalyzer.isCoincidentalNumericInStructuredData(
      result,
      responseText,
    );
  }

  /**
   * Enhanced computed math result analysis with tool context (Issue #58)
   */
  analyzeComputedMathResult(
    payload: string,
    responseText: string,
    tool?: Tool,
  ): MathResultAnalysis {
    return this.mathAnalyzer.analyzeComputedMathResult(
      payload,
      responseText,
      tool,
    );
  }

  /**
   * Check if response is just reflection (safe)
   */
  isReflectionResponse(responseText: string): boolean {
    return this.safeDetector.isReflectionResponse(responseText);
  }

  /**
   * Detect execution artifacts in response
   */
  detectExecutionArtifacts(responseText: string): boolean {
    return this.executionDetector.detectExecutionArtifacts(responseText);
  }

  /**
   * Check if response contains echoed injection payload patterns
   */
  containsEchoedInjectionPayload(responseText: string): boolean {
    return this.executionDetector.containsEchoedInjectionPayload(responseText);
  }

  /**
   * Check if tool explicitly rejected input with validation error (SAFE)
   */
  isValidationRejection(response: CompatibilityCallToolResult): boolean {
    return this.safeDetector.isValidationRejection(response);
  }

  /**
   * Check if tool is a structured data tool
   */
  isStructuredDataTool(toolName: string, toolDescription: string): boolean {
    return this.confidenceScorer.isStructuredDataTool(
      toolName,
      toolDescription,
    );
  }

  /**
   * Check if response is returning search results
   */
  isSearchResultResponse(responseText: string): boolean {
    return this.safeDetector.isSearchResultResponse(responseText);
  }

  /**
   * Check if response is from a creation/modification operation
   */
  isCreationResponse(responseText: string): boolean {
    return this.safeDetector.isCreationResponse(responseText);
  }

  // ============================================================================
  // PRIVATE HELPER METHODS - Internal logic kept in facade
  // ============================================================================

  /**
   * Check for safe error responses that indicate proper input rejection
   * Handles: MCP validation errors (-32602), HTTP 4xx/5xx errors
   */
  private checkSafeErrorResponses(
    responseText: string,
    errorInfo: { code?: string | number; message?: string },
  ): AnalysisResult | null {
    // MCP validation errors (HIGHEST PRIORITY)
    if (this.safeDetector.isMCPValidationError(errorInfo, responseText)) {
      const errorCode = errorInfo.code ? ` (${errorInfo.code})` : "";
      return {
        isVulnerable: false,
        evidence: `MCP validation error${errorCode}: Tool properly rejected invalid input before processing`,
      };
    }

    // HTTP error responses (Issue #26)
    if (this.safeDetector.isHttpErrorResponse(responseText)) {
      return {
        isVulnerable: false,
        evidence:
          "HTTP error response indicates tool rejection (not vulnerability)",
      };
    }

    return null;
  }

  /**
   * Check for safe tool behavior patterns
   * Handles: Tool categories, reflection, computed math, validation rejection
   */
  private checkSafeToolBehavior(
    response: CompatibilityCallToolResult,
    payload: SecurityPayload,
    tool: Tool,
    responseText: string,
  ): AnalysisResult | null {
    // Classify tool and check for safe categories
    const classifier = new ToolClassifier();
    const classification = classifier.classify(tool.name, tool.description);

    // Check if tool is in a safe category
    if (classification.categories.includes(ToolCategory.SEARCH_RETRIEVAL)) {
      if (this.safeDetector.isSearchResultResponse(responseText)) {
        return {
          isVulnerable: false,
          evidence: "Search tool returned query results (not code execution)",
        };
      }
    }

    if (classification.categories.includes(ToolCategory.CRUD_CREATION)) {
      if (this.safeDetector.isCreationResponse(responseText)) {
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

    // Check if response is just reflecting/echoing input (SAFE)
    if (this.safeDetector.isReflectionResponse(responseText)) {
      return {
        isVulnerable: false,
        evidence: "Tool safely reflected input without execution",
      };
    }

    // Check for computed math results (Issue #14 fix, enhanced in Issue #58)
    const mathAnalysis = this.mathAnalyzer.analyzeComputedMathResult(
      payload.payload,
      responseText,
      tool,
    );

    // Only flag as vulnerable if HIGH confidence (Issue #58 fix)
    if (mathAnalysis.isComputed && mathAnalysis.confidence === "high") {
      return {
        isVulnerable: true,
        evidence: `Tool computed math expression result instead of storing/echoing it (payload: ${payload.payload})`,
      };
    }

    // Check if tool explicitly rejected the input (SAFE)
    if (this.safeDetector.isValidationRejection(response)) {
      return {
        isVulnerable: false,
        evidence: "Tool correctly rejected invalid input with validation error",
      };
    }

    return null;
  }

  /**
   * Check for vulnerability evidence in response
   * Handles: Evidence pattern matching, fallback injection analysis
   */
  private checkVulnerabilityEvidence(
    response: CompatibilityCallToolResult,
    payload: SecurityPayload,
    responseText: string,
  ): AnalysisResult {
    const payloadText = payload.payload.toLowerCase();

    // Check for expected evidence of execution
    if (payload.evidence && payload.evidence.test(responseText)) {
      const evidenceMatchesInput = payload.evidence.test(payloadText);
      if (evidenceMatchesInput && responseText.includes(payloadText)) {
        return {
          isVulnerable: false,
          evidence: "Evidence pattern matched echoed input, not execution",
        };
      }

      // For validation-type patterns, require execution evidence
      if (this.confidenceScorer.isValidationPattern(payload.evidence)) {
        const hasExecutionEvidence =
          this.executionDetector.hasExecutionEvidence(responseText);
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

    // Fall back to injection response analysis
    return this.analyzeInjectionResponse(response, payload.payload);
  }

  /**
   * Analyze injection response (fallback logic)
   */
  private analyzeInjectionResponse(
    response: CompatibilityCallToolResult,
    _payload: string,
  ): AnalysisResult {
    const analysis = this.executionDetector.analyzeInjectionResponse(
      this.extractResponseContent(response),
      (text: string) => this.safeDetector.isReflectionResponse(text),
    );

    if (analysis.isVulnerable) {
      return {
        isVulnerable: true,
        evidence:
          analysis.evidence ||
          "Tool executed instruction: found execution keywords",
      };
    }

    return { isVulnerable: false };
  }
}

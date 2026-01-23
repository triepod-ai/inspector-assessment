/**
 * Security Response Analyzer (Facade)
 * Analyzes tool responses for evidence-based vulnerability detection
 *
 * REFACTORED in Issue #53 (v2.0.0): Converted to facade pattern
 * Delegates to focused classes for maintainability (CC 218 → ~50)
 *
 * REFACTORED in Issue #179: Extracted specialized vulnerability analyzers
 * to separate modules for improved modularity and testability.
 *
 * Extracted classes (Issue #53):
 * - ErrorClassifier: Error classification and connection error detection
 * - ExecutionArtifactDetector: Execution evidence detection
 * - MathAnalyzer: Math computation detection (Calculator Injection)
 * - SafeResponseDetector: Safe response pattern detection
 * - ConfidenceScorer: Confidence level calculation
 *
 * Extracted analyzers (Issue #179):
 * - AuthBypassAnalyzer: CVE-2025-52882, fail-open authentication
 * - StateBasedAuthAnalyzer: Cross-tool state abuse
 * - BlacklistBypassAnalyzer: Incomplete blacklist detection
 * - OutputInjectionAnalyzer: Indirect prompt injection
 * - SessionManagementAnalyzer: Session CWEs
 * - CryptographicFailureAnalyzer: OWASP A02:2021
 * - ChainExploitationAnalyzer: Multi-tool chains
 * - ExcessivePermissionsAnalyzer: Scope violations
 * - SecretLeakageDetector: Credential exposure
 */

import {
  CompatibilityCallToolResult,
  Tool,
} from "@modelcontextprotocol/sdk/types.js";
import { SecurityPayload } from "@/lib/securityPatterns";
import { ToolClassifier, ToolCategory } from "../../ToolClassifier";
import type { SanitizationDetectionResult } from "./SanitizationDetector";

// Import extracted classes (Issue #53)
import { ErrorClassifier } from "./ErrorClassifier";
import { ExecutionArtifactDetector } from "./ExecutionArtifactDetector";
import { MathAnalyzer, MathResultAnalysis } from "./MathAnalyzer";
import { SafeResponseDetector } from "./SafeResponseDetector";
import { ConfidenceScorer, ConfidenceResult } from "./ConfidenceScorer";

// Import extracted analyzers (Issue #179)
import {
  AuthBypassAnalyzer,
  StateBasedAuthAnalyzer,
  SecretLeakageDetector,
  ChainExploitationAnalyzer,
  ExcessivePermissionsAnalyzer,
  BlacklistBypassAnalyzer,
  OutputInjectionAnalyzer,
  SessionManagementAnalyzer,
  CryptographicFailureAnalyzer,
} from "./analyzers";

// Import pattern library for Issue #146 context classification and Issue #201 partial echo detection
import {
  isPayloadInErrorContext,
  isPayloadPartiallyEchoed,
  hasSuccessContext,
  hasErrorContext,
} from "./SecurityPatternLibrary";

// Re-export types for backward compatibility
export type { ConfidenceResult } from "./ConfidenceScorer";
export type { MathResultAnalysis } from "./MathAnalyzer";

// Re-export analyzer result types for backward compatibility (Issue #179)
export type { AuthBypassResult } from "./analyzers/AuthBypassAnalyzer";
export type { StateBasedAuthResult } from "./analyzers/StateBasedAuthAnalyzer";
export type { SecretLeakageResult } from "./analyzers/SecretLeakageDetector";
export type {
  ChainExploitationAnalysis,
  ChainExecutionType,
  ChainVulnerabilityCategory,
} from "./analyzers/ChainExploitationAnalyzer";
export type { ExcessivePermissionsScopeResult } from "./analyzers/ExcessivePermissionsAnalyzer";
export type { BlacklistBypassResult } from "./analyzers/BlacklistBypassAnalyzer";
export type { OutputInjectionResult } from "./analyzers/OutputInjectionAnalyzer";
export type { SessionManagementResult } from "./analyzers/SessionManagementAnalyzer";
export type { CryptoFailureResult } from "./analyzers/CryptographicFailureAnalyzer";

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
 *
 * This class serves as a facade, delegating to focused analyzers
 * while maintaining the same public API for backward compatibility.
 */
export class SecurityResponseAnalyzer {
  // Delegate classes (Issue #53)
  private errorClassifier: ErrorClassifier;
  private executionDetector: ExecutionArtifactDetector;
  private mathAnalyzer: MathAnalyzer;
  private safeDetector: SafeResponseDetector;
  private confidenceScorer: ConfidenceScorer;

  // Specialized vulnerability analyzers (Issue #179)
  private authBypassAnalyzer: AuthBypassAnalyzer;
  private stateBasedAuthAnalyzer: StateBasedAuthAnalyzer;
  private secretLeakageDetector: SecretLeakageDetector;
  private chainExploitationAnalyzer: ChainExploitationAnalyzer;
  private excessivePermissionsAnalyzer: ExcessivePermissionsAnalyzer;
  private blacklistBypassAnalyzer: BlacklistBypassAnalyzer;
  private outputInjectionAnalyzer: OutputInjectionAnalyzer;
  private sessionManagementAnalyzer: SessionManagementAnalyzer;
  private cryptographicFailureAnalyzer: CryptographicFailureAnalyzer;

  constructor() {
    // Initialize delegate classes (Issue #53)
    this.errorClassifier = new ErrorClassifier();
    this.executionDetector = new ExecutionArtifactDetector();
    this.mathAnalyzer = new MathAnalyzer();
    this.safeDetector = new SafeResponseDetector();
    this.confidenceScorer = new ConfidenceScorer();

    // Initialize specialized analyzers (Issue #179)
    this.authBypassAnalyzer = new AuthBypassAnalyzer();
    this.stateBasedAuthAnalyzer = new StateBasedAuthAnalyzer();
    this.secretLeakageDetector = new SecretLeakageDetector();
    this.chainExploitationAnalyzer = new ChainExploitationAnalyzer();
    this.excessivePermissionsAnalyzer = new ExcessivePermissionsAnalyzer();
    this.blacklistBypassAnalyzer = new BlacklistBypassAnalyzer();
    this.outputInjectionAnalyzer = new OutputInjectionAnalyzer();
    this.sessionManagementAnalyzer = new SessionManagementAnalyzer();
    this.cryptographicFailureAnalyzer = new CryptographicFailureAnalyzer();
  }

  // ============================================================================
  // PUBLIC API - Core Analysis Methods
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
    const errorResult = this.checkSafeErrorResponses(
      responseText,
      errorInfo,
      payload,
    );
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
    const vulnResult = this.checkVulnerabilityEvidence(
      response,
      payload,
      responseText,
    );

    // Issue #146: If vulnerable, classify execution context to reduce false positives
    if (vulnResult.isVulnerable) {
      return this.classifyVulnerabilityContext(
        vulnResult,
        responseText,
        payload,
      );
    }

    return vulnResult;
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

  // ============================================================================
  // DELEGATED SPECIALIZED ANALYZERS (Issue #179)
  // ============================================================================

  /**
   * Analyze response for auth bypass patterns (Issue #75)
   * Detects fail-open authentication vulnerabilities (CVE-2025-52882)
   */
  analyzeAuthBypassResponse(response: CompatibilityCallToolResult) {
    return this.authBypassAnalyzer.analyze(response);
  }

  /**
   * Analyze response for cross-tool state-based authorization bypass (Issue #92)
   * Detects Challenge #7: Privilege escalation via shared mutable state
   */
  analyzeStateBasedAuthBypass(response: CompatibilityCallToolResult) {
    return this.stateBasedAuthAnalyzer.analyze(response);
  }

  /**
   * Analyze response for blacklist bypass patterns (Issue #110, Challenge #11)
   * Detects when incomplete blacklist security controls are bypassed
   */
  analyzeBlacklistBypassResponse(response: CompatibilityCallToolResult) {
    return this.blacklistBypassAnalyzer.analyze(response);
  }

  /**
   * Analyze response for output injection vulnerabilities (Issue #110, Challenge #8)
   * Detects indirect prompt injection via unsanitized tool output
   */
  analyzeOutputInjectionResponse(response: CompatibilityCallToolResult) {
    return this.outputInjectionAnalyzer.analyze(response);
  }

  /**
   * Analyze response for session management vulnerabilities (Issue #111, Challenge #12)
   * Detects 5 CWEs from mcp-vulnerable-testbed
   */
  analyzeSessionManagementResponse(response: CompatibilityCallToolResult) {
    return this.sessionManagementAnalyzer.analyze(response);
  }

  /**
   * Analyze response for cryptographic failures (Issue #112, Challenge #13)
   * Detects OWASP A02:2021 Cryptographic Failures
   */
  analyzeCryptographicFailures(response: CompatibilityCallToolResult) {
    return this.cryptographicFailureAnalyzer.analyze(response);
  }

  /**
   * Analyze response for chain exploitation vulnerabilities (Issue #93, Challenge #6)
   * Detects multi-tool chained exploitation attacks
   */
  analyzeChainExploitation(response: CompatibilityCallToolResult) {
    return this.chainExploitationAnalyzer.analyze(response);
  }

  /**
   * Analyze response for excessive permissions scope violations (Issue #144, Challenge #22)
   * Detects when tools exceed their declared annotation scope
   */
  analyzeExcessivePermissionsResponse(response: CompatibilityCallToolResult) {
    return this.excessivePermissionsAnalyzer.analyze(response);
  }

  /**
   * Check for secret leakage in response (Issue #103, Challenge #9)
   * Scans for credential patterns regardless of payload type.
   *
   * @note This method must be called separately from analyzeResponse().
   */
  checkSecretLeakage(response: CompatibilityCallToolResult) {
    return this.secretLeakageDetector.analyze(response);
  }

  // ============================================================================
  // ERROR CLASSIFICATION DELEGATION
  // ============================================================================

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
   * Handles: MCP validation errors (-32602), HTTP 4xx/5xx errors, AppleScript syntax errors
   */
  private checkSafeErrorResponses(
    responseText: string,
    errorInfo: { code?: string | number; message?: string },
    payload: SecurityPayload,
  ): AnalysisResult | null {
    // MCP validation errors (HIGHEST PRIORITY)
    if (this.safeDetector.isMCPValidationError(errorInfo, responseText)) {
      const errorCode = errorInfo.code ? ` (${errorInfo.code})` : "";
      return {
        isVulnerable: false,
        evidence: `MCP validation error${errorCode}: Tool properly rejected invalid input before processing`,
      };
    }

    // Issue #175 + Issue #177: AppleScript error handling
    if (this.safeDetector.isAppleScriptSyntaxError(responseText)) {
      // Issue #177: Check if this looks like INJECTION SUCCESS before dismissing
      if (
        this.safeDetector.isAppleScriptInjectionSuccess(
          responseText,
          payload.payload,
        )
      ) {
        // This is NOT a safe syntax error - it's successful injection!
        return null;
      }

      // Genuine syntax error (payload rejected before reaching interpreter)
      return {
        isVulnerable: false,
        evidence:
          "AppleScript syntax error - not XXE vulnerability (echoed payload in error message)",
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

    // Issue #110: Skip SAFE_STORAGE exemption for testbed tools with "vulnerable_" prefix
    const isTestbedVulnerableTool = tool.name.startsWith("vulnerable_");
    if (
      classification.categories.includes(ToolCategory.SAFE_STORAGE) &&
      !isTestbedVulnerableTool
    ) {
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

    // Issue #178: Early check for AppleScript injection success
    if (
      this.safeDetector.isAppleScriptSyntaxError(responseText) &&
      this.safeDetector.isAppleScriptInjectionSuccess(
        responseText,
        payload.payload,
      )
    ) {
      return {
        isVulnerable: true,
        evidence:
          "AppleScript injection: payload escaped string context to code execution position",
      };
    }

    // Check for expected evidence of execution
    if (payload.evidence && payload.evidence.test(responseText)) {
      const evidenceMatchesInput = payload.evidence.test(payloadText);
      // Issue #201: Use partial echo detection for truncated/modified payloads in errors
      if (
        evidenceMatchesInput &&
        isPayloadPartiallyEchoed(responseText, payload.payload)
      ) {
        // Issue #178: Don't dismiss as echoed input if AppleScript injection detected
        if (
          !this.safeDetector.isAppleScriptInjectionSuccess(
            responseText,
            payload.payload,
          )
        ) {
          return {
            isVulnerable: false,
            evidence: "Evidence pattern matched echoed input, not execution",
          };
        }
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

    // Issue #110: Check for JSON metadata indicating blacklist bypass (Challenge #11)
    if (payload.payloadType === "blacklist_bypass") {
      const bypassResult = this.analyzeBlacklistBypassResponse(response);
      if (bypassResult.detected) {
        return {
          isVulnerable: true,
          evidence: `Blacklist bypass detected via JSON metadata: ${bypassResult.evidence}${bypassResult.bypassMethod ? ` (method: ${bypassResult.bypassMethod})` : ""}`,
        };
      }
      if (bypassResult.bypassType === "ALLOWLIST_BLOCKED") {
        return {
          isVulnerable: false,
          evidence: `Secure allowlist pattern detected: ${bypassResult.evidence}`,
        };
      }
    }

    // Fall back to injection response analysis
    return this.analyzeInjectionResponse(response);
  }

  /**
   * Issue #146: Classify vulnerability context to reduce false positives
   * Distinguishes between actual execution and payload reflection in errors
   */
  private classifyVulnerabilityContext(
    vulnResult: AnalysisResult,
    responseText: string,
    payload: SecurityPayload,
  ): AnalysisResult {
    // Use pattern library helpers to detect context
    const hasError = hasErrorContext(responseText);
    const hasSuccess = hasSuccessContext(responseText);
    const payloadInError = isPayloadInErrorContext(
      responseText,
      payload.payload,
    );

    // CONFIRMED: Success patterns present, no error patterns
    if (hasSuccess && !hasError) {
      return {
        ...vulnResult,
        evidence: `${vulnResult.evidence} [Context: CONFIRMED - operation succeeded]`,
      };
    }

    // LIKELY_FALSE_POSITIVE: Error context with payload reflection
    if (payloadInError && hasError) {
      // Issue #178: Don't dismiss as false positive if AppleScript injection detected
      if (
        !this.safeDetector.isAppleScriptInjectionSuccess(
          responseText,
          payload.payload,
        )
      ) {
        return {
          isVulnerable: false,
          evidence:
            `Operation failed with error containing reflected payload. ` +
            `Original detection: ${vulnResult.evidence} ` +
            `[Context: LIKELY_FALSE_POSITIVE - payload reflected in error message, not executed]`,
        };
      }
    }

    // SUSPECTED: Ambiguous (neither clear success nor clear error)
    return {
      ...vulnResult,
      evidence: `${vulnResult.evidence} [Context: SUSPECTED - requires manual review]`,
    };
  }

  /**
   * Analyze injection response (fallback logic)
   */
  private analyzeInjectionResponse(
    response: CompatibilityCallToolResult,
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

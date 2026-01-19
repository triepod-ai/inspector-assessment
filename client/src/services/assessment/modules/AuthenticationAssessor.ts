/**
 * Authentication Assessor
 * Evaluates if OAuth is appropriate for the deployment model (local vs remote).
 *
 * Detection Logic:
 * 1. Check if server uses OAuth (serverInfo/manifest)
 * 2. Analyze if tools access local resources (files, apps, OS features)
 * 3. If OAuth + no local deps = recommend cloud deployment
 * 4. If OAuth + local deps = warn about mixed model
 */

import { BaseAssessor } from "./BaseAssessor";
import { AssessmentContext } from "../AssessmentOrchestrator";
import type {
  AssessmentStatus,
  AuthMethod,
  AuthAppropriateness,
  AuthenticationAssessment,
  TransportSecurityAnalysis,
  AuthConfigAnalysis,
  AuthConfigFinding,
  AuthConfigFindingType,
  AuthConfigSeverity,
  AuthEnrichmentData,
  AuthToolInventoryItem,
  AuthToolCapability,
  OAuthPatternCoverage,
  APIKeyPatternCoverage,
  TransportSecuritySummary,
  AuthFlagForReview,
} from "@/lib/assessmentTypes";
import {
  truncateForTokens,
  MAX_DESCRIPTION_LENGTH,
} from "../lib/moduleEnrichment";

// Patterns that indicate OAuth usage
const OAUTH_PATTERNS = [
  /oauth/i,
  /authorization\s*code/i,
  /access_token/i,
  /refresh_token/i,
  /client_id/i,
  /client_secret/i,
  /pkce/i,
  /code_verifier/i,
  /code_challenge/i,
  /authorize\s*url/i,
  /token\s*endpoint/i,
];

// Patterns that indicate API key usage
const API_KEY_PATTERNS = [
  /api[_-]?key/i,
  /x-api-key/i,
  /bearer\s+token/i,
  /authorization:\s*bearer/i,
  /secret[_-]?key/i,
];

// Patterns that indicate local resource dependencies
const LOCAL_RESOURCE_PATTERNS = [
  /process\.cwd/i,
  /fs\.(read|write|exists|mkdir|rmdir)/i,
  /child_process/i,
  /execSync|spawnSync/i,
  /os\.(homedir|tmpdir|platform)/i,
  /path\.(join|resolve|dirname)/i,
  /__dirname|__filename/i,
  /\.local|\.config|\.cache/i,
  /localhost|127\.0\.0\.1/i,
  /file:\/\//i,
];

// Patterns indicating insecure transport practices
const INSECURE_TRANSPORT_PATTERNS = [
  /http:\/\/(?!localhost|127\.0\.0\.1)/i, // Non-local HTTP
  /allowInsecure|rejectUnauthorized:\s*false/i, // TLS validation disabled
  /NODE_TLS_REJECT_UNAUTHORIZED.*0/i, // TLS verification disabled via env
  /cors.*\*|origin:\s*true|origin:\s*\*/i, // Overly permissive CORS
];

// Patterns indicating secure transport practices
const SECURE_TRANSPORT_PATTERNS = [
  /https:\/\//i,
  /secure:\s*true/i,
  /httpOnly:\s*true/i,
  /sameSite.*strict|sameSite.*lax/i,
  /helmet/i, // Security middleware
  /cors.*origin.*string|cors.*origin.*array/i, // Specific CORS origins
];

// ============================================================================
// Issue #62: Auth Configuration Patterns
// Detects environment-dependent auth, fail-open patterns, and dev mode warnings
// ============================================================================

// Patterns for env vars that control authentication
const AUTH_ENV_VAR_PATTERNS = [
  /process\.env\.([A-Z_]*SECRET[A-Z_]*)/i,
  /process\.env\.([A-Z_]*AUTH[A-Z_]*)/i,
  /process\.env\.([A-Z_]*TOKEN[A-Z_]*)/i,
  /process\.env\.([A-Z_]*API[_-]?KEY[A-Z_]*)/i,
  /process\.env\.([A-Z_]*PASSWORD[A-Z_]*)/i,
  /process\.env\.([A-Z_]*CREDENTIAL[A-Z_]*)/i,
  /os\.environ\.get\(['"](.*(?:SECRET|AUTH|TOKEN|API[_-]?KEY|PASSWORD|CREDENTIAL).*)['"]/i, // Python
  /os\.getenv\(['"](.*(?:SECRET|AUTH|TOKEN|API[_-]?KEY|PASSWORD|CREDENTIAL).*)['"]/i, // Python
];

// Patterns that indicate fail-open behavior (auth bypassed when env var missing)
// These capture the context around env var usage with fallback operators
const FAIL_OPEN_PATTERNS = [
  // JavaScript/TypeScript: process.env.X || 'fallback' or process.env.X ?? 'fallback'
  {
    pattern:
      /process\.env\.[A-Z_]*(SECRET|AUTH|TOKEN|API[_-]?KEY)[A-Z_]*\s*\|\|/gi,
    name: "OR_FALLBACK",
  },
  {
    pattern:
      /process\.env\.[A-Z_]*(SECRET|AUTH|TOKEN|API[_-]?KEY)[A-Z_]*\s*\?\?/gi,
    name: "NULLISH_FALLBACK",
  },
  // if (!process.env.X) pattern suggesting bypass
  {
    pattern:
      /if\s*\(\s*!?\s*process\.env\.[A-Z_]*(SECRET|AUTH|TOKEN|API[_-]?KEY)/gi,
    name: "CONDITIONAL_CHECK",
  },
  // Python: os.environ.get('X', 'default') or os.getenv('X', 'default')
  {
    pattern:
      /os\.environ\.get\([^,]+(?:SECRET|AUTH|TOKEN|API[_-]?KEY)[^,]*,\s*['"]/gi,
    name: "PYTHON_DEFAULT",
  },
  {
    pattern:
      /os\.getenv\([^,]+(?:SECRET|AUTH|TOKEN|API[_-]?KEY)[^,]*,\s*['"]/gi,
    name: "PYTHON_GETENV_DEFAULT",
  },
];

// ============================================================================
// Issue #77: Fail-Open Logic Patterns
// Detects logic flaws where errors/exceptions lead to access being granted
// These are distinct from env var fallbacks - they're code logic issues
// ============================================================================

const FAIL_OPEN_LOGIC_PATTERNS = [
  // Pattern 1: Response contains "bypassed" auth status
  {
    pattern: /["']auth_status["']\s*:\s*["']bypass/gi,
    name: "BYPASS_STATUS_RESPONSE",
    severity: "HIGH" as AuthConfigSeverity,
    message: "Response indicates authentication was bypassed",
  },
  // Pattern 2: Access granted despite error/failure
  {
    pattern: /access.*granted.*despite|despite.*(?:error|fail).*grant/gi,
    name: "ACCESS_DESPITE_ERROR",
    severity: "HIGH" as AuthConfigSeverity,
    message: "Access granted despite authentication error",
  },
  // Pattern 3: Fail-open comments/keywords (intentional or documentation)
  {
    pattern: /fail[\s_-]?open/gi,
    name: "FAIL_OPEN_KEYWORD",
    severity: "HIGH" as AuthConfigSeverity,
    message: "Fail-open pattern explicitly mentioned in code",
  },
  // Pattern 4: Python except block that returns success/grants access
  {
    pattern:
      /except\s*(?:[A-Za-z]*Error|Exception)?[^:]*:[\s\S]{0,50}(?:return\s*(?:True|{[^}]*success|{[^}]*grant)|authenticated\s*=\s*True)/gi,
    name: "EXCEPT_GRANTS_ACCESS",
    severity: "HIGH" as AuthConfigSeverity,
    message: "Exception handler grants access instead of denying",
  },
  // Pattern 5: If error then grant pattern
  {
    pattern:
      /if\s+(?:auth_)?error[^:]*:[\s\S]{0,100}(?:return\s*{[^}]*executed|grant|allow|success)/gi,
    name: "ERROR_GRANTS_ACCESS",
    severity: "HIGH" as AuthConfigSeverity,
    message: "Error condition leads to access being granted",
  },
  // Pattern 6: CVE reference for auth bypass
  {
    pattern:
      /CVE[-_]?\d{4}[-_]?\d+.*(?:auth|bypass)|(?:auth|bypass).*CVE[-_]?\d{4}[-_]?\d+/gi,
    name: "CVE_AUTH_BYPASS",
    severity: "HIGH" as AuthConfigSeverity,
    message: "CVE reference related to authentication bypass",
  },
  // Pattern 7: Vulnerable flag with auth context
  {
    pattern: /["']vulnerable["']\s*:\s*(?:true|True)/gi,
    name: "VULNERABLE_FLAG",
    severity: "MEDIUM" as AuthConfigSeverity,
    message: "Code contains vulnerable flag set to true",
  },
  // Pattern 8: Authentication bypassed evidence in responses
  {
    pattern: /authentication.*bypassed|bypassed.*authentication/gi,
    name: "AUTH_BYPASSED_EVIDENCE",
    severity: "HIGH" as AuthConfigSeverity,
    message: "Evidence of authentication being bypassed",
  },
];

// Patterns that indicate dev mode weakening security
// Warning 2 fix: Added word boundaries and assignment context to reduce false positives
const DEV_MODE_PATTERNS = [
  // Development mode bypasses
  {
    pattern: /NODE_ENV.*development|development.*NODE_ENV/i,
    severity: "LOW" as AuthConfigSeverity,
  },
  {
    pattern:
      /if\s*\(\s*(?:process\.env\.)?NODE_ENV\s*[!=]==?\s*['"]development['"]\s*\)/i,
    severity: "MEDIUM" as AuthConfigSeverity,
  },
  {
    // Require word boundary and assignment context to avoid matching unrelated identifiers
    pattern: /\b(isDev|isDevelopment|devMode|debugMode)\s*[=:]/i,
    severity: "LOW" as AuthConfigSeverity,
  },
  // Debug authentication bypasses
  {
    pattern: /skip.*auth.*dev|dev.*skip.*auth/i,
    severity: "HIGH" as AuthConfigSeverity,
  },
  {
    pattern: /disable.*auth.*debug|debug.*disable.*auth/i,
    severity: "HIGH" as AuthConfigSeverity,
  },
  {
    pattern: /auth.*bypass|bypass.*auth/i,
    severity: "HIGH" as AuthConfigSeverity,
  },
  // "authenticate all requests as dev user" pattern from issue
  {
    pattern: /authenticate.*all.*requests|all.*requests.*authenticate/i,
    severity: "HIGH" as AuthConfigSeverity,
  },
  {
    pattern: /as\s+dev\s+user|dev\s+user.*auth/i,
    severity: "HIGH" as AuthConfigSeverity,
  },
];

// Patterns that indicate hardcoded secrets (should be env vars)
const HARDCODED_SECRET_PATTERNS = [
  {
    pattern: /['"]sk[-_](?:live|test)_[a-zA-Z0-9]{20,}['"]/i,
    name: "STRIPE_KEY",
  }, // Stripe keys
  {
    pattern: /['"]pk[-_](?:live|test)_[a-zA-Z0-9]{20,}['"]/i,
    name: "STRIPE_PUBLISHABLE",
  },
  {
    pattern: /api[_-]?key\s*[:=]\s*['"][a-zA-Z0-9]{20,}['"]/i,
    name: "API_KEY",
  },
  {
    pattern: /secret[_-]?key\s*[:=]\s*['"][a-zA-Z0-9]{16,}['"]/i,
    name: "SECRET_KEY",
  },
  {
    // Warning 3 fix: Exclude env var interpolation and common placeholder values
    pattern:
      /password\s*[:=]\s*['"](?!\$\{|password|changeme|example|test)[a-zA-Z0-9!@#$%^&*]{8,}['"]/i,
    name: "HARDCODED_PASSWORD",
  },
  {
    pattern: /auth[_-]?token\s*[:=]\s*['"][a-zA-Z0-9._-]{20,}['"]/i,
    name: "AUTH_TOKEN",
  },
];

// ============================================================================
// Issue #65: Rate Limiting Constants
// Prevents performance issues when analyzing large codebases
// ============================================================================

/** Maximum number of source files to analyze (prevents performance degradation) */
const MAX_FILES = 500;

/** Maximum number of findings per type (prevents overwhelming output) */
const MAX_FINDINGS = 100;

export class AuthenticationAssessor extends BaseAssessor {
  /**
   * Run authentication assessment
   */
  async assess(context: AssessmentContext): Promise<AuthenticationAssessment> {
    this.logger.info("Starting authentication assessment");
    this.testCount = 0;

    const oauthIndicators: string[] = [];
    const localResourceIndicators: string[] = [];
    const apiKeyIndicators: string[] = [];

    // Analyze source code for patterns
    if (context.sourceCodeFiles) {
      for (const [filePath, content] of context.sourceCodeFiles) {
        this.testCount++;

        // Check for OAuth patterns
        for (const pattern of OAUTH_PATTERNS) {
          if (pattern.test(content)) {
            const indicator = `${filePath}: ${pattern.source}`;
            if (!oauthIndicators.includes(indicator)) {
              oauthIndicators.push(indicator);
            }
          }
        }

        // Check for API key patterns
        for (const pattern of API_KEY_PATTERNS) {
          if (pattern.test(content)) {
            const indicator = `${filePath}: ${pattern.source}`;
            if (!apiKeyIndicators.includes(indicator)) {
              apiKeyIndicators.push(indicator);
            }
          }
        }

        // Check for local resource patterns
        for (const pattern of LOCAL_RESOURCE_PATTERNS) {
          if (pattern.test(content)) {
            const indicator = `${filePath}: ${pattern.source}`;
            if (!localResourceIndicators.includes(indicator)) {
              localResourceIndicators.push(indicator);
            }
          }
        }
      }
    }

    // Determine auth method
    const authMethod = this.detectAuthMethod(
      oauthIndicators,
      apiKeyIndicators,
      context,
    );

    // Determine if there are local dependencies
    const hasLocalDependencies = localResourceIndicators.length > 0;

    // Get transport type
    const transportType = this.detectTransportType(context);

    // Evaluate appropriateness
    const appropriateness = this.evaluateAppropriateness({
      authMethod,
      hasLocalDependencies,
      transportType,
      oauthIndicators,
    });

    const recommendation = this.generateRecommendation(
      authMethod,
      hasLocalDependencies,
      transportType,
      appropriateness,
    );

    const status = this.evaluateStatus(appropriateness);
    const explanation = this.generateExplanation(
      authMethod,
      hasLocalDependencies,
      transportType,
      appropriateness,
    );
    const recommendations = this.generateRecommendations(
      authMethod,
      hasLocalDependencies,
      appropriateness,
    );

    // Analyze transport security
    const transportSecurity = this.analyzeTransportSecurity(context);

    // Add transport security issues to concerns
    if (transportSecurity.hasInsecurePatterns) {
      appropriateness.concerns.push(
        ...transportSecurity.insecurePatterns.map(
          (p) => `Insecure transport pattern: ${p}`,
        ),
      );
    }

    // Issue #62: Analyze auth configuration for env-dependent auth and fail-open patterns
    const authConfigAnalysis = this.analyzeAuthConfiguration(context);

    // Add auth config findings to concerns
    if (authConfigAnalysis.hasHighSeverity) {
      appropriateness.concerns.push(
        ...authConfigAnalysis.findings
          .filter((f) => f.severity === "HIGH")
          .map((f) => `Auth config issue: ${f.message}`),
      );
    }

    // Update status based on auth config findings
    let finalStatus = status;
    if (authConfigAnalysis.hasHighSeverity) {
      finalStatus = "NEED_MORE_INFO";
    }

    // Generate additional recommendations from auth config findings
    const authConfigRecommendations = authConfigAnalysis.findings.map(
      (f) =>
        f.recommendation ||
        `Review ${f.type}: ${f.message} (${f.file || "unknown file"})`,
    );

    // Build enrichment data for Stage B Claude validation (Issue #195)
    const enrichmentData = this.buildEnrichmentData(
      context,
      oauthIndicators,
      apiKeyIndicators,
      localResourceIndicators,
      transportSecurity,
      transportType,
    );

    this.logger.info(
      `Assessment complete: auth=${authMethod}, localDeps=${hasLocalDependencies}, tlsEnforced=${transportSecurity.tlsEnforced}, authConfigFindings=${authConfigAnalysis.totalFindings}, authSensitiveTools=${enrichmentData.metrics.authSensitiveTools}`,
    );

    return {
      authMethod,
      hasLocalDependencies,
      transportType,
      appropriateness,
      recommendation,
      detectedPatterns: {
        oauthIndicators,
        localResourceIndicators,
        apiKeyIndicators,
      },
      transportSecurity,
      authConfigAnalysis,
      enrichmentData,
      status: finalStatus,
      explanation,
      recommendations: [
        ...recommendations,
        ...transportSecurity.recommendations,
        ...authConfigRecommendations,
      ],
    };
  }

  /**
   * Analyze transport security configuration
   */
  private analyzeTransportSecurity(
    context: AssessmentContext,
  ): TransportSecurityAnalysis {
    const insecurePatterns: string[] = [];
    const securePatterns: string[] = [];

    // Check transport config from context
    const transportConfig = context.transportConfig;
    const usesTLS = transportConfig?.usesTLS ?? false;
    const tlsEnforced = transportConfig?.type === "streamable-http" && usesTLS;

    // Analyze source code for patterns
    if (context.sourceCodeFiles) {
      for (const [filePath, content] of context.sourceCodeFiles) {
        this.testCount++;

        // Check for insecure patterns
        for (const pattern of INSECURE_TRANSPORT_PATTERNS) {
          if (pattern.test(content)) {
            const indicator = `${filePath}: ${pattern.source}`;
            if (!insecurePatterns.includes(indicator)) {
              insecurePatterns.push(indicator);
            }
          }
        }

        // Check for secure patterns
        for (const pattern of SECURE_TRANSPORT_PATTERNS) {
          if (pattern.test(content)) {
            const indicator = `${filePath}: ${pattern.source}`;
            if (!securePatterns.includes(indicator)) {
              securePatterns.push(indicator);
            }
          }
        }
      }
    }

    // Determine CORS configuration
    const corsConfigured = securePatterns.some((p) => /cors/i.test(p));
    const corsPermissive = insecurePatterns.some((p) =>
      /cors.*\*|origin.*true/i.test(p),
    );

    // Check session security
    const sessionSecure =
      securePatterns.some((p) => /secure.*true|httpOnly/i.test(p)) &&
      !insecurePatterns.some((p) => /secure.*false/i.test(p));

    // Generate recommendations
    const recommendations: string[] = [];

    if (insecurePatterns.length > 0) {
      recommendations.push(
        "TRANSPORT SECURITY: Found insecure patterns that should be reviewed:",
      );
      for (const pattern of insecurePatterns.slice(0, 3)) {
        recommendations.push(`  - ${pattern}`);
      }
    }

    if (!usesTLS && transportConfig?.type !== "stdio") {
      recommendations.push(
        "Ensure HTTPS/TLS is enforced for remote transport to protect data in transit",
      );
    }

    if (corsPermissive) {
      recommendations.push(
        "CORS policy is overly permissive (allows all origins). Restrict to specific trusted origins.",
      );
    }

    if (!sessionSecure && securePatterns.length > 0) {
      recommendations.push(
        "Review session cookie security: ensure Secure, HttpOnly, and SameSite flags are set appropriately",
      );
    }

    return {
      usesTLS,
      tlsEnforced,
      hasInsecurePatterns: insecurePatterns.length > 0,
      insecurePatterns,
      hasSecurePatterns: securePatterns.length > 0,
      securePatterns,
      corsConfigured,
      corsPermissive,
      sessionSecure,
      recommendations,
    };
  }

  /**
   * Detect authentication method
   */
  private detectAuthMethod(
    oauthIndicators: string[],
    apiKeyIndicators: string[],
    context: AssessmentContext,
  ): AuthMethod {
    // Check manifest for OAuth configuration
    if (context.manifestJson) {
      const manifestStr = JSON.stringify(context.manifestJson);
      if (/oauth/i.test(manifestStr)) {
        return "oauth";
      }
    }

    // Check for OAuth patterns in code
    if (oauthIndicators.length >= 3) {
      return "oauth";
    }

    // Check for API key patterns
    if (apiKeyIndicators.length >= 2) {
      return "api_key";
    }

    // If we found some indicators but not enough to be confident
    if (oauthIndicators.length > 0 || apiKeyIndicators.length > 0) {
      return "unknown";
    }

    return "none";
  }

  /**
   * Detect transport type from context
   */
  private detectTransportType(context: AssessmentContext): string {
    // Check config for transport
    if (context.config) {
      const config = context.config as unknown as Record<string, unknown>;
      if (config.transport) {
        return String(config.transport);
      }
    }

    // Default to stdio for local servers
    return "stdio";
  }

  /**
   * Evaluate if authentication setup is appropriate
   */
  private evaluateAppropriateness(params: {
    authMethod: AuthMethod;
    hasLocalDependencies: boolean;
    transportType: string;
    oauthIndicators: string[];
  }): AuthAppropriateness {
    const { authMethod, hasLocalDependencies, transportType } = params;
    const concerns: string[] = [];
    let isAppropriate = true;

    // OAuth on local stdio server with local dependencies is concerning
    if (
      authMethod === "oauth" &&
      hasLocalDependencies &&
      transportType === "stdio"
    ) {
      concerns.push(
        "OAuth authentication detected on local stdio server with file system dependencies",
      );
      concerns.push(
        "Consider: Is OAuth necessary for a local-only server that accesses local resources?",
      );
      isAppropriate = false;
    }

    // OAuth on stdio without local deps might suggest it should be remote
    if (
      authMethod === "oauth" &&
      !hasLocalDependencies &&
      transportType === "stdio"
    ) {
      concerns.push(
        "OAuth detected on stdio transport but no local resource dependencies found",
      );
      concerns.push("This server might be better suited for remote deployment");
    }

    // API key on remote server without proper security
    if (authMethod === "api_key" && transportType !== "stdio") {
      concerns.push(
        "API key authentication on remote transport - ensure HTTPS is enforced",
      );
    }

    // No auth on remote server is a concern
    if (authMethod === "none" && transportType !== "stdio") {
      concerns.push("No authentication detected on remote transport");
      concerns.push("Consider adding authentication for production use");
      isAppropriate = false;
    }

    const explanation =
      concerns.length > 0
        ? `Found ${concerns.length} concern(s) with authentication setup`
        : "Authentication configuration appears appropriate for deployment model";

    return { isAppropriate, concerns, explanation };
  }

  /**
   * Generate recommendation based on analysis
   */
  private generateRecommendation(
    authMethod: AuthMethod,
    hasLocalDependencies: boolean,
    transportType: string,
    appropriateness: AuthAppropriateness,
  ): string {
    if (appropriateness.isAppropriate) {
      return "Authentication configuration is appropriate for the deployment model";
    }

    if (authMethod === "oauth" && !hasLocalDependencies) {
      return "Consider deploying as a remote server if OAuth is required - no local dependencies detected";
    }

    if (authMethod === "oauth" && hasLocalDependencies) {
      return "Review if OAuth is necessary - server has local dependencies suggesting local-only usage";
    }

    if (authMethod === "none" && transportType !== "stdio") {
      return "Add authentication for remote deployment to prevent unauthorized access";
    }

    return "Review authentication configuration for production deployment";
  }

  /**
   * Evaluate overall status based on appropriateness
   */
  private evaluateStatus(
    appropriateness: AuthAppropriateness,
  ): AssessmentStatus {
    if (!appropriateness.isAppropriate) {
      return "NEED_MORE_INFO";
    }

    if (appropriateness.concerns.length > 0) {
      return "NEED_MORE_INFO";
    }

    return "PASS";
  }

  /**
   * Generate explanation
   */
  private generateExplanation(
    authMethod: AuthMethod,
    hasLocalDependencies: boolean,
    transportType: string,
    appropriateness: AuthAppropriateness,
  ): string {
    const parts: string[] = [];

    parts.push(`Detected authentication: ${authMethod}`);
    parts.push(`Transport: ${transportType}`);
    parts.push(`Local dependencies: ${hasLocalDependencies ? "Yes" : "No"}`);

    if (appropriateness.concerns.length > 0) {
      parts.push(`Concerns: ${appropriateness.concerns.length}`);
    }

    return parts.join(". ");
  }

  /**
   * Generate recommendations
   */
  private generateRecommendations(
    authMethod: AuthMethod,
    hasLocalDependencies: boolean,
    appropriateness: AuthAppropriateness,
  ): string[] {
    const recommendations: string[] = [];

    if (!appropriateness.isAppropriate) {
      recommendations.push("REVIEW - Authentication configuration:");
      for (const concern of appropriateness.concerns.slice(0, 3)) {
        recommendations.push(`  - ${concern}`);
      }
    }

    if (authMethod === "oauth") {
      recommendations.push("Ensure OAuth configuration follows RFC 8707");
      recommendations.push("Verify PKCE is implemented for public clients");
    }

    if (authMethod === "api_key") {
      recommendations.push("Ensure API keys are not hardcoded");
      recommendations.push("Use environment variables for secrets");
    }

    if (authMethod === "none" && !hasLocalDependencies) {
      recommendations.push(
        "Consider adding authentication if server will be remotely accessible",
      );
    }

    if (recommendations.length === 0) {
      recommendations.push("Authentication configuration appears appropriate");
    }

    return recommendations;
  }

  // ============================================================================
  // Issue #62: Authentication Configuration Analysis
  // Detects env-dependent auth, fail-open patterns, and dev mode warnings
  // ============================================================================

  /**
   * Analyze source code for authentication configuration issues (Issue #62)
   *
   * Detects:
   * - Environment-dependent auth (process.env.SECRET, process.env.AUTH_KEY, etc.)
   * - Fail-open patterns (auth bypassed when env var missing with || or ?? fallback)
   * - Development mode warnings (dev mode bypasses that weaken security)
   * - Hardcoded secrets (credentials that should be in env vars)
   */
  private analyzeAuthConfiguration(
    context: AssessmentContext,
  ): AuthConfigAnalysis {
    const findings: AuthConfigFinding[] = [];
    const envVarsDetected: string[] = [];

    if (!context.sourceCodeFiles) {
      return {
        totalFindings: 0,
        envDependentAuthCount: 0,
        failOpenPatternCount: 0,
        failOpenLogicCount: 0,
        devModeWarningCount: 0,
        hardcodedSecretCount: 0,
        findings: [],
        hasHighSeverity: false,
        envVarsDetected: [],
      };
    }

    // Issue #65: Apply file limit to prevent performance issues on large codebases
    let sourceFiles = Array.from(context.sourceCodeFiles);
    if (sourceFiles.length > MAX_FILES) {
      this.logger.info(
        `Rate limiting: Analyzing ${MAX_FILES} of ${sourceFiles.length} files`,
      );
      sourceFiles = sourceFiles.slice(0, MAX_FILES);
    }

    for (const [filePath, content] of sourceFiles) {
      // Warning 4 fix: Add error handling for malformed files
      try {
        this.testCount++;
        const lines = content.split("\n");

        // 1. Detect env vars used for auth
        for (const pattern of AUTH_ENV_VAR_PATTERNS) {
          const matches = content.match(pattern);
          if (matches) {
            // Extract the env var name from capture group or full match
            for (const match of matches) {
              const envVarMatch = match.match(
                /(?:process\.env\.|os\.environ\.get\(['"]|os\.getenv\(['"])([A-Z_]+)/i,
              );
              if (envVarMatch && !envVarsDetected.includes(envVarMatch[1])) {
                envVarsDetected.push(envVarMatch[1]);
              }
            }
          }
        }

        // Helper to check if we've hit the findings cap for a type (Issue #65)
        const countByType = (type: AuthConfigFindingType) =>
          findings.filter((f) => f.type === type).length;

        // Helper to get context lines (Issue #66)
        const getContext = (lineIndex: number) => {
          const before =
            lineIndex > 0 ? lines[lineIndex - 1]?.trim() : undefined;
          const after =
            lineIndex < lines.length - 1
              ? lines[lineIndex + 1]?.trim()
              : undefined;
          return before || after ? { before, after } : undefined;
        };

        // 2. Detect fail-open patterns (auth with fallback values)
        for (const { pattern, name } of FAIL_OPEN_PATTERNS) {
          // Issue #65: Skip if we've hit the cap for this type
          if (countByType("FAIL_OPEN_PATTERN") >= MAX_FINDINGS) break;

          // Reset lastIndex for global patterns
          pattern.lastIndex = 0;
          let match;
          while ((match = pattern.exec(content)) !== null) {
            // Issue #65: Check cap before adding
            if (countByType("FAIL_OPEN_PATTERN") >= MAX_FINDINGS) break;

            // Find line number
            const beforeMatch = content.substring(0, match.index);
            const lineNumber = beforeMatch.split("\n").length;
            const lineContent = lines[lineNumber - 1]?.trim() || match[0];

            findings.push({
              type: "FAIL_OPEN_PATTERN",
              severity: "MEDIUM",
              message: `Authentication may be bypassed when environment variable is not set (${name} pattern)`,
              evidence: lineContent,
              file: filePath,
              lineNumber,
              recommendation: `Ensure authentication fails securely when credentials are missing. Do not use fallback values for auth secrets.`,
              context: getContext(lineNumber - 1), // Issue #66: Add context
            });
          }
        }

        // 2b. Issue #77: Detect fail-open logic patterns (error handling that grants access)
        for (const {
          pattern,
          name,
          severity,
          message,
        } of FAIL_OPEN_LOGIC_PATTERNS) {
          // Issue #65: Skip if we've hit the cap for this type
          if (countByType("FAIL_OPEN_LOGIC") >= MAX_FINDINGS) break;

          // Reset lastIndex for global patterns
          pattern.lastIndex = 0;
          let match;
          while ((match = pattern.exec(content)) !== null) {
            // Issue #65: Check cap before adding
            if (countByType("FAIL_OPEN_LOGIC") >= MAX_FINDINGS) break;

            // Find line number
            const beforeMatch = content.substring(0, match.index);
            const lineNumber = beforeMatch.split("\n").length;
            const lineContent = lines[lineNumber - 1]?.trim() || match[0];

            findings.push({
              type: "FAIL_OPEN_LOGIC",
              severity,
              message: `${message} (${name} pattern)`,
              evidence: lineContent,
              file: filePath,
              lineNumber,
              recommendation: `Fix fail-open logic: authentication errors must deny access, not grant it. Implement fail-closed pattern.`,
              context: getContext(lineNumber - 1), // Issue #66: Add context
            });
          }
        }

        // 3. Detect dev mode patterns that weaken security
        for (const { pattern, severity } of DEV_MODE_PATTERNS) {
          // Issue #65: Skip if we've hit the cap for this type
          if (countByType("DEV_MODE_WARNING") >= MAX_FINDINGS) break;

          if (pattern.test(content)) {
            // Find first occurrence for line number
            const matchResult = content.match(pattern);
            if (matchResult) {
              const matchIndex = content.indexOf(matchResult[0]);
              const beforeMatch = content.substring(0, matchIndex);
              const lineNumber = beforeMatch.split("\n").length;
              const lineContent =
                lines[lineNumber - 1]?.trim() || matchResult[0];

              findings.push({
                type: "DEV_MODE_WARNING",
                severity,
                message: `Development mode pattern detected that may weaken authentication`,
                evidence: lineContent,
                file: filePath,
                lineNumber,
                recommendation:
                  severity === "HIGH"
                    ? `Remove auth bypass logic. Authentication should never be disabled based on environment.`
                    : `Ensure development mode does not weaken security controls in production.`,
                context: getContext(lineNumber - 1), // Issue #66: Add context
              });
            }
          }
        }

        // 4. Detect hardcoded secrets
        for (const { pattern, name } of HARDCODED_SECRET_PATTERNS) {
          // Issue #65: Skip if we've hit the cap for this type
          if (countByType("HARDCODED_SECRET") >= MAX_FINDINGS) break;

          if (pattern.test(content)) {
            const matchResult = content.match(pattern);
            if (matchResult) {
              const matchIndex = content.indexOf(matchResult[0]);
              const beforeMatch = content.substring(0, matchIndex);
              const lineNumber = beforeMatch.split("\n").length;
              // Redact the actual secret in evidence
              const lineContent =
                lines[lineNumber - 1]
                  ?.trim()
                  .replace(/['"][^'"]{8,}['"]/, '"[REDACTED]"') ||
                "[secret value]";

              findings.push({
                type: "HARDCODED_SECRET",
                severity: "HIGH",
                message: `Hardcoded ${name} detected - should use environment variable`,
                evidence: lineContent,
                file: filePath,
                lineNumber,
                recommendation: `Move ${name} to environment variable. Never commit secrets to source control.`,
                context: getContext(lineNumber - 1), // Issue #66: Add context
              });
            }
          }
        }

        // 5. Detect env-dependent auth patterns (env var usage with auth context)
        // Only flag if there's auth context around env var usage
        for (const [index, line] of lines.entries()) {
          // Issue #65: Skip if we've hit the cap for this type
          if (countByType("ENV_DEPENDENT_AUTH") >= MAX_FINDINGS) break;

          // Check for env var with auth context in surrounding lines
          const surroundingContext = lines
            .slice(Math.max(0, index - 2), index + 3)
            .join("\n");
          for (const pattern of AUTH_ENV_VAR_PATTERNS) {
            if (
              pattern.test(line) &&
              /\b(auth|secret|key|token|password|credential)\b/i.test(
                surroundingContext,
              )
            ) {
              const matchResult = line.match(pattern);
              if (matchResult) {
                // Check if we already have a finding for this line (avoid duplicates)
                const existingFinding = findings.find(
                  (f) =>
                    f.file === filePath &&
                    f.lineNumber === index + 1 &&
                    f.type === "ENV_DEPENDENT_AUTH",
                );
                if (!existingFinding) {
                  findings.push({
                    type: "ENV_DEPENDENT_AUTH",
                    severity: "LOW",
                    message: `Authentication depends on environment variable that may not be set`,
                    evidence: line.trim(),
                    file: filePath,
                    lineNumber: index + 1,
                    recommendation: `Document required environment variables and validate they are set at startup.`,
                    context: getContext(index), // Issue #66: Add context
                  });
                }
              }
            }
          }
        }
      } catch (error) {
        // Warning 4 fix: Handle malformed files gracefully
        this.logger.info(`Error analyzing ${filePath}: ${error}`);
        continue;
      }
    }

    // Deduplicate findings by file+line+type
    const uniqueFindings = this.deduplicateFindings(findings);

    // Count by type
    const envDependentAuthCount = uniqueFindings.filter(
      (f) => f.type === "ENV_DEPENDENT_AUTH",
    ).length;
    const failOpenPatternCount = uniqueFindings.filter(
      (f) => f.type === "FAIL_OPEN_PATTERN",
    ).length;
    const failOpenLogicCount = uniqueFindings.filter(
      (f) => f.type === "FAIL_OPEN_LOGIC",
    ).length;
    const devModeWarningCount = uniqueFindings.filter(
      (f) => f.type === "DEV_MODE_WARNING",
    ).length;
    const hardcodedSecretCount = uniqueFindings.filter(
      (f) => f.type === "HARDCODED_SECRET",
    ).length;

    const hasHighSeverity = uniqueFindings.some((f) => f.severity === "HIGH");

    return {
      totalFindings: uniqueFindings.length,
      envDependentAuthCount,
      failOpenPatternCount,
      failOpenLogicCount,
      devModeWarningCount,
      hardcodedSecretCount,
      findings: uniqueFindings,
      hasHighSeverity,
      envVarsDetected,
    };
  }

  /**
   * Deduplicate findings by file, line, and type
   */
  private deduplicateFindings(
    findings: AuthConfigFinding[],
  ): AuthConfigFinding[] {
    const seen = new Set<string>();
    return findings.filter((f) => {
      const key = `${f.file || ""}:${f.lineNumber || 0}:${f.type}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }

  // ============================================================================
  // Issue #195: Stage B Enrichment Data
  // Provides Claude with context for validating authentication findings
  // ============================================================================

  /**
   * Build enrichment data for Stage B Claude validation (Issue #195)
   *
   * Provides Claude with:
   * - Tool inventory with auth-related capabilities
   * - OAuth pattern coverage (what patterns were checked)
   * - API key pattern coverage
   * - Transport security summary
   * - Flags for tools with sensitive auth operations
   */
  private buildEnrichmentData(
    context: AssessmentContext,
    oauthIndicators: string[],
    apiKeyIndicators: string[],
    localResourceIndicators: string[],
    transportSecurity: TransportSecurityAnalysis | undefined,
    transportType: string,
  ): AuthEnrichmentData {
    // Build tool inventory with auth capabilities
    const toolInventory = this.buildAuthToolInventory(context);

    // Build OAuth pattern coverage
    const oauthPatternCoverage =
      this.buildOAuthPatternCoverage(oauthIndicators);

    // Build API key pattern coverage
    const apiKeyPatternCoverage = this.buildAPIKeyPatternCoverage(
      apiKeyIndicators,
      context,
    );

    // Build transport security summary
    const transportSecuritySummary = this.buildTransportSecuritySummary(
      transportSecurity,
      transportType,
    );

    // Generate flags for tools with sensitive auth operations
    const flagsForReview = this.generateAuthFlags(toolInventory);

    // Calculate metrics
    const authSensitiveTools = toolInventory.filter(
      (t) => t.isSensitive,
    ).length;

    return {
      toolInventory,
      oauthPatternCoverage,
      apiKeyPatternCoverage,
      transportSecurity: transportSecuritySummary,
      flagsForReview,
      metrics: {
        totalTools: toolInventory.length,
        authSensitiveTools,
        oauthIndicators: oauthIndicators.length,
        apiKeyIndicators: apiKeyIndicators.length,
        localDependencyIndicators: localResourceIndicators.length,
      },
    };
  }

  /**
   * Build tool inventory with auth-related capabilities
   */
  private buildAuthToolInventory(
    context: AssessmentContext,
  ): AuthToolInventoryItem[] {
    return context.tools.map((tool) => {
      const capabilities = this.inferAuthCapabilities(
        tool.name,
        tool.description,
      );
      const isSensitive = capabilities.some(
        (cap) => cap === "oauth" || cap === "credential" || cap === "token",
      );

      return {
        name: tool.name,
        description: truncateForTokens(
          tool.description || "",
          MAX_DESCRIPTION_LENGTH,
        ),
        authCapabilities: capabilities,
        isSensitive,
      };
    });
  }

  /**
   * Infer auth-related capabilities from tool name and description
   */
  private inferAuthCapabilities(
    name: string,
    description?: string,
  ): AuthToolCapability[] {
    const capabilities: AuthToolCapability[] = [];
    const text = `${name} ${description || ""}`.toLowerCase();

    // OAuth indicators
    if (
      /oauth|authorize|authorization|pkce|code_verifier|code_challenge/i.test(
        text,
      )
    ) {
      capabilities.push("oauth");
    }

    // API key indicators
    if (/api[_-]?key|x-api-key|bearer/i.test(text)) {
      capabilities.push("api_key");
    }

    // Session management
    if (/session|cookie|logout|login/i.test(text)) {
      capabilities.push("session");
    }

    // Credential handling
    if (/credential|password|secret|auth/i.test(text)) {
      capabilities.push("credential");
    }

    // Token management
    if (/token|access_token|refresh_token|jwt/i.test(text)) {
      capabilities.push("token");
    }

    // Encryption
    if (/encrypt|decrypt|hash|cipher/i.test(text)) {
      capabilities.push("encryption");
    }

    if (capabilities.length === 0) {
      capabilities.push("none");
    }

    return capabilities;
  }

  /**
   * Build OAuth pattern coverage info
   */
  private buildOAuthPatternCoverage(
    oauthIndicators: string[],
  ): OAuthPatternCoverage {
    // Determine OAuth flow type from indicators
    let flowType: OAuthPatternCoverage["flowType"] = "none";
    let pkceDetected = false;

    const indicatorText = oauthIndicators.join(" ").toLowerCase();

    if (/pkce|code_verifier|code_challenge/i.test(indicatorText)) {
      flowType = "pkce";
      pkceDetected = true;
    } else if (/authorization\s*code|code.*grant/i.test(indicatorText)) {
      flowType = "authorization_code";
    } else if (/client.*credential/i.test(indicatorText)) {
      flowType = "client_credentials";
    } else if (oauthIndicators.length > 0) {
      flowType = "unknown";
    }

    return {
      totalPatterns: OAUTH_PATTERNS.length,
      matchedPatterns: oauthIndicators.slice(0, 5), // Limit to 5 samples
      flowType,
      pkceDetected,
    };
  }

  /**
   * Build API key pattern coverage info
   */
  private buildAPIKeyPatternCoverage(
    apiKeyIndicators: string[],
    context: AssessmentContext,
  ): APIKeyPatternCoverage {
    // Check if API keys appear to be managed via env vars
    let envVarManaged = false;
    if (context.sourceCodeFiles) {
      for (const [, content] of context.sourceCodeFiles) {
        if (/process\.env\.[A-Z_]*(?:API[_-]?KEY|SECRET)/i.test(content)) {
          envVarManaged = true;
          break;
        }
      }
    }

    return {
      totalPatterns: API_KEY_PATTERNS.length,
      matchedPatterns: apiKeyIndicators.slice(0, 5), // Limit to 5 samples
      envVarManaged,
    };
  }

  /**
   * Build transport security summary
   */
  private buildTransportSecuritySummary(
    transportSecurity: TransportSecurityAnalysis | undefined,
    transportType: string,
  ): TransportSecuritySummary {
    // Early return with defaults if no transport security analysis available
    if (!transportSecurity) {
      return {
        transportType,
        tlsEnforced: false,
        corsConfigured: false,
        sessionSecure: false,
        insecurePatternCount: 0,
        securePatternCount: 0,
      };
    }

    return {
      transportType,
      tlsEnforced: transportSecurity.tlsEnforced,
      corsConfigured: transportSecurity.corsConfigured,
      sessionSecure: transportSecurity.sessionSecure,
      insecurePatternCount: transportSecurity.insecurePatterns.length,
      securePatternCount: transportSecurity.securePatterns.length,
    };
  }

  /**
   * Generate flags for tools with sensitive auth operations
   */
  private generateAuthFlags(
    toolInventory: AuthToolInventoryItem[],
  ): AuthFlagForReview[] {
    const flags: AuthFlagForReview[] = [];

    for (const tool of toolInventory) {
      if (!tool.isSensitive) continue;

      // Determine risk level based on capabilities
      let riskLevel: AuthFlagForReview["riskLevel"] = "low";
      let reason = "Tool has auth-related capabilities";

      if (tool.authCapabilities.includes("credential")) {
        riskLevel = "high";
        reason = "Handles credentials - verify secure storage and transmission";
      } else if (tool.authCapabilities.includes("oauth")) {
        riskLevel = "medium";
        reason = "OAuth implementation - verify PKCE and proper flow";
      } else if (tool.authCapabilities.includes("token")) {
        riskLevel = "medium";
        reason = "Token handling - verify secure storage and expiration";
      }

      flags.push({
        toolName: tool.name,
        reason,
        capabilities: tool.authCapabilities,
        riskLevel,
      });
    }

    return flags;
  }
}

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
} from "@/lib/assessmentTypes";

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

// Patterns that indicate dev mode weakening security
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
    pattern: /isDev|isDevelopment|devMode|debugMode/i,
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
    pattern: /password\s*[:=]\s*['"][^'"]{8,}['"]/i,
    name: "HARDCODED_PASSWORD",
  },
  {
    pattern: /auth[_-]?token\s*[:=]\s*['"][a-zA-Z0-9._-]{20,}['"]/i,
    name: "AUTH_TOKEN",
  },
];

export class AuthenticationAssessor extends BaseAssessor {
  /**
   * Run authentication assessment
   */
  async assess(context: AssessmentContext): Promise<AuthenticationAssessment> {
    this.log("Starting authentication assessment");
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

    this.log(
      `Assessment complete: auth=${authMethod}, localDeps=${hasLocalDependencies}, tlsEnforced=${transportSecurity.tlsEnforced}, authConfigFindings=${authConfigAnalysis.totalFindings}`,
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
        devModeWarningCount: 0,
        hardcodedSecretCount: 0,
        findings: [],
        hasHighSeverity: false,
        envVarsDetected: [],
      };
    }

    for (const [filePath, content] of context.sourceCodeFiles) {
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

      // 2. Detect fail-open patterns (auth with fallback values)
      for (const { pattern, name } of FAIL_OPEN_PATTERNS) {
        // Reset lastIndex for global patterns
        pattern.lastIndex = 0;
        let match;
        while ((match = pattern.exec(content)) !== null) {
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
          });
        }
      }

      // 3. Detect dev mode patterns that weaken security
      for (const { pattern, severity } of DEV_MODE_PATTERNS) {
        if (pattern.test(content)) {
          // Find first occurrence for line number
          const matchResult = content.match(pattern);
          if (matchResult) {
            const matchIndex = content.indexOf(matchResult[0]);
            const beforeMatch = content.substring(0, matchIndex);
            const lineNumber = beforeMatch.split("\n").length;
            const lineContent = lines[lineNumber - 1]?.trim() || matchResult[0];

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
            });
          }
        }
      }

      // 4. Detect hardcoded secrets
      for (const { pattern, name } of HARDCODED_SECRET_PATTERNS) {
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
            });
          }
        }
      }

      // 5. Detect env-dependent auth patterns (env var usage with auth context)
      // Only flag if there's auth context around env var usage
      for (const [index, line] of lines.entries()) {
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
                });
              }
            }
          }
        }
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
}

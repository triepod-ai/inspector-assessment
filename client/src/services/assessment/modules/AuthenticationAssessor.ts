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

    this.log(
      `Assessment complete: auth=${authMethod}, localDeps=${hasLocalDependencies}`,
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
      status,
      explanation,
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
}

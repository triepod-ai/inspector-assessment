/**
 * Secret Leakage Detector (Issue #103, Challenge #9)
 * Scans for credential patterns regardless of payload type
 *
 * Extracted from SecurityResponseAnalyzer.ts for modularity (Issue #179)
 */

import { CompatibilityCallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { SafeResponseDetector } from "../SafeResponseDetector";

/**
 * Result of secret leakage detection
 */
export interface SecretLeakageResult {
  detected: boolean;
  evidence?: string;
}

/**
 * Detects when tools inadvertently expose secrets/credentials
 *
 * This detector identifies:
 * - API keys (AWS, OpenAI, GitHub, GitLab, Slack)
 * - Database connection strings with credentials
 * - Environment variable values
 * - Partial key previews
 *
 * @note This detector must be called separately from analyzeResponse().
 * It is not part of the standard vulnerability detection flow because
 * secret leakage detection requires examining ALL responses, not just
 * those matching attack payloads.
 */
export class SecretLeakageDetector {
  private safeDetector: SafeResponseDetector;

  /**
   * Secret patterns to detect in responses
   */
  private static readonly SECRET_PATTERNS = [
    { regex: /AKIA[A-Z0-9]{16}/, name: "AWS Access Key" },
    { regex: /sk-[a-zA-Z0-9]{20,}/, name: "OpenAI API Key" },
    { regex: /ghp_[a-zA-Z0-9]{36}/, name: "GitHub PAT" },
    { regex: /glpat-[a-zA-Z0-9]{20}/, name: "GitLab PAT" },
    { regex: /xox[baprs]-[a-zA-Z0-9-]+/, name: "Slack Token" },
    {
      regex: /(postgresql|mysql|mongodb|redis|mssql):\/\/[^:]+:[^@]+@/i,
      name: "Connection String with Credentials",
    },
    {
      regex:
        /(api[_-]?key|secret|password|credential)[^\s]*[:=]\s*["']?[a-zA-Z0-9_-]{10,}/i,
      name: "Credential Assignment",
    },
    {
      regex:
        /(SECRET_TOKEN|DATABASE_URL|API_KEY|PRIVATE_KEY|DB_PASSWORD)[^\s]*[:=]/i,
      name: "Environment Variable Leakage",
    },
    {
      regex: /api_key_preview|key_fragment|partial_key/i,
      name: "Partial Key Exposure",
    },
  ];

  constructor() {
    this.safeDetector = new SafeResponseDetector();
  }

  /**
   * Check for secret leakage in response (Issue #103, Challenge #9)
   * Scans for credential patterns regardless of payload type.
   *
   * @example
   * ```typescript
   * const detector = new SecretLeakageDetector();
   * const response = await client.callTool("get_status", { verbose: true });
   *
   * const leakResult = detector.analyze(response);
   * if (leakResult.detected) {
   *   console.warn(`Secret leaked: ${leakResult.evidence}`);
   * }
   * ```
   */
  analyze(response: CompatibilityCallToolResult): SecretLeakageResult {
    const responseText = this.safeDetector.extractResponseContent(response);

    for (const { regex, name } of SecretLeakageDetector.SECRET_PATTERNS) {
      if (regex.test(responseText)) {
        return {
          detected: true,
          evidence: `${name} pattern found in response`,
        };
      }
    }

    return { detected: false };
  }
}

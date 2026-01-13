/**
 * Manifest Validation Assessor
 * Validates MCPB manifest.json against spec requirements
 *
 * Checks:
 * - manifest_version (must be 0.3)
 * - Required fields: name, version, description, author
 * - mcp_config structure
 * - icon.png presence
 *
 * Reference: MCPB Specification
 */

import { BaseAssessor } from "./BaseAssessor";
import { AssessmentContext } from "../AssessmentOrchestrator";
import type { Tool } from "@modelcontextprotocol/sdk/types.js";
import type {
  ManifestValidationAssessment,
  ManifestValidationResult,
  ManifestJsonSchema,
  McpConfigSchema,
  AssessmentStatus,
  PrivacyPolicyValidation,
  ExtractedContactInfo,
  ExtractedVersionInfo,
  ManifestAuthorObject,
} from "@/lib/assessmentTypes";

const REQUIRED_FIELDS = ["name", "version", "mcp_config"] as const;
const RECOMMENDED_FIELDS = ["description", "author", "repository"] as const;
const CURRENT_MANIFEST_VERSION = "0.3";
const SEMVER_PATTERN = /^\d+\.\d+\.\d+(-[a-zA-Z0-9.-]+)?(\+[a-zA-Z0-9.-]+)?$/;

/**
 * Calculate Levenshtein distance between two strings
 * Uses space-optimized two-row algorithm for O(min(n,m)) memory
 * Used for "did you mean?" suggestions on mismatched tool names (Issue #140)
 * Exported for testing (Issue #141 - ISSUE-002)
 */
export function levenshteinDistance(
  a: string,
  b: string,
  maxDist?: number,
): number {
  // Early termination optimizations
  if (a === b) return 0;
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;

  // If length difference exceeds max distance, no need to compute
  if (maxDist && Math.abs(a.length - b.length) > maxDist) {
    return maxDist + 1;
  }

  // Ensure a is the shorter string (optimize space)
  if (a.length > b.length) {
    [a, b] = [b, a];
  }

  // Two-row algorithm: only keep previous and current row
  let prev = Array.from({ length: a.length + 1 }, (_, i) => i);
  let curr = new Array(a.length + 1);

  for (let i = 1; i <= b.length; i++) {
    curr[0] = i;

    for (let j = 1; j <= a.length; j++) {
      if (b.charAt(i - 1) === a.charAt(j - 1)) {
        curr[j] = prev[j - 1];
      } else {
        curr[j] = Math.min(
          prev[j - 1] + 1, // substitution
          curr[j - 1] + 1, // insertion
          prev[j] + 1, // deletion
        );
      }
    }

    // Swap rows
    [prev, curr] = [curr, prev];
  }

  return prev[a.length];
}

/**
 * Find closest matching tool name from a set
 * Returns match if distance <= threshold (default: 10 chars or 40% of length)
 * Generous threshold to catch common renames like "data" -> "resources"
 */
function findClosestMatch(
  name: string,
  candidates: Set<string>,
  threshold?: number,
): string | null {
  const maxDist = threshold ?? Math.max(10, Math.floor(name.length * 0.4));
  let closest: string | null = null;
  let minDist = Infinity;

  for (const candidate of candidates) {
    const dist = levenshteinDistance(
      name.toLowerCase(),
      candidate.toLowerCase(),
      maxDist, // Pass max distance for early termination
    );
    if (dist < minDist && dist <= maxDist) {
      minDist = dist;
      closest = candidate;
    }
  }

  return closest;
}

export class ManifestValidationAssessor extends BaseAssessor {
  /**
   * Get mcp_config from manifest (supports both root and nested v0.3 format)
   * Issue #138: Manifest v0.3 places mcp_config under server object
   *
   * @param manifest - The parsed manifest JSON
   * @returns The mcp_config object or undefined if not found in either location
   */
  private getMcpConfig(
    manifest: ManifestJsonSchema,
  ): McpConfigSchema | undefined {
    // Check root level first (legacy format)
    if (manifest.mcp_config) {
      return manifest.mcp_config;
    }
    // Check nested under server (v0.3 format)
    if (manifest.server?.mcp_config) {
      return manifest.server.mcp_config;
    }
    return undefined;
  }

  /**
   * Extract contact information from manifest (Issue #141 - D4 check)
   * Supports: author object, author string (email parsing), repository fallback
   *
   * @param manifest - The parsed manifest JSON
   * @returns Extracted contact info or undefined if no contact info found
   */
  private extractContactInfo(
    manifest: ManifestJsonSchema,
  ): ExtractedContactInfo | undefined {
    // 1. Check author object format (npm-style)
    if (typeof manifest.author === "object" && manifest.author !== null) {
      const authorObj = manifest.author as ManifestAuthorObject;
      return {
        email: authorObj.email,
        url: authorObj.url,
        name: authorObj.name,
        source: "author_object",
      };
    }

    // 2. Check author string (may contain email: "Name <email@example.com>")
    if (typeof manifest.author === "string" && manifest.author.trim()) {
      const emailMatch = manifest.author.match(
        /<([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})>/,
      );
      return {
        name: manifest.author.replace(/<[^>]+>/, "").trim() || undefined,
        email: emailMatch?.[1],
        source: "author_string",
      };
    }

    // 3. Fallback to repository (provides contact via issues)
    if (manifest.repository) {
      return {
        url: manifest.repository,
        source: "repository",
      };
    }

    return undefined;
  }

  /**
   * Extract version information from manifest (Issue #141 - D5 check)
   *
   * @param manifest - The parsed manifest JSON
   * @returns Extracted version info or undefined if no version found
   */
  private extractVersionInfo(
    manifest: ManifestJsonSchema,
  ): ExtractedVersionInfo | undefined {
    if (!manifest.version) return undefined;

    return {
      version: manifest.version,
      valid: true,
      semverCompliant: SEMVER_PATTERN.test(manifest.version),
    };
  }

  /**
   * Run manifest validation assessment
   */
  async assess(
    context: AssessmentContext,
  ): Promise<ManifestValidationAssessment> {
    this.logger.info("Starting manifest validation assessment");
    this.testCount = 0;

    // Check if manifest is available
    if (!context.manifestJson && !context.manifestRaw) {
      return this.createNoManifestResult();
    }

    const validationResults: ManifestValidationResult[] = [];
    let hasIcon = false;
    let hasRequiredFields = true;
    const missingFields: string[] = [];

    // Parse manifest if raw string provided
    let manifest: ManifestJsonSchema | null = null;
    if (context.manifestJson) {
      manifest = context.manifestJson;
    } else if (context.manifestRaw) {
      try {
        manifest = JSON.parse(context.manifestRaw) as ManifestJsonSchema;
      } catch (error) {
        this.testCount++;
        validationResults.push({
          field: "manifest.json",
          valid: false,
          issue: `Invalid JSON: ${error instanceof Error ? error.message : "Parse error"}`,
          severity: "ERROR",
        });
        return this.createInvalidJsonResult(validationResults);
      }
    }

    if (!manifest) {
      return this.createNoManifestResult();
    }

    // Validate manifest_version
    this.testCount++;
    validationResults.push(this.validateManifestVersion(manifest));

    // Validate required fields
    for (const field of REQUIRED_FIELDS) {
      this.testCount++;
      // Special handling for mcp_config - can be nested under server (Issue #138)
      if (field === "mcp_config") {
        const mcpConfig = this.getMcpConfig(manifest);
        if (!mcpConfig) {
          validationResults.push({
            field: "mcp_config",
            valid: false,
            issue:
              "Missing required field: mcp_config (checked root and server.mcp_config)",
            severity: "ERROR",
          });
          hasRequiredFields = false;
          missingFields.push(field);
        } else {
          validationResults.push({
            field: "mcp_config",
            valid: true,
            value: mcpConfig,
            severity: "INFO",
          });
        }
      } else {
        const result = this.validateRequiredField(manifest, field);
        validationResults.push(result);
        if (!result.valid) {
          hasRequiredFields = false;
          missingFields.push(field);
        }
      }
    }

    // Validate recommended fields
    for (const field of RECOMMENDED_FIELDS) {
      this.testCount++;
      validationResults.push(this.validateRecommendedField(manifest, field));
    }

    // Validate mcp_config structure (using helper to support both root and nested paths)
    const mcpConfig = this.getMcpConfig(manifest);
    if (mcpConfig) {
      this.testCount++;
      validationResults.push(this.validateMcpConfig(mcpConfig));
    }

    // Check for icon
    this.testCount++;
    const iconResult = this.validateIcon(manifest, context);
    validationResults.push(iconResult);
    hasIcon = iconResult.valid;

    // Validate name format
    this.testCount++;
    validationResults.push(this.validateNameFormat(manifest.name));

    // Validate version format
    this.testCount++;
    validationResults.push(this.validateVersionFormat(manifest.version));

    // Validate tool names match server (Issue #140)
    if (manifest.tools && context.tools.length > 0) {
      const toolResults = this.validateToolNamesMatch(manifest, context.tools);
      validationResults.push(...toolResults);
    }

    // Validate privacy policy URLs if present
    let privacyPolicies:
      | {
          declared: string[];
          validationResults: PrivacyPolicyValidation[];
          allAccessible: boolean;
        }
      | undefined;

    if (
      manifest.privacy_policies &&
      Array.isArray(manifest.privacy_policies) &&
      manifest.privacy_policies.length > 0
    ) {
      this.logger.info(
        `Validating ${manifest.privacy_policies.length} privacy policy URL(s)`,
      );
      const policyResults = await this.validatePrivacyPolicyUrls(
        manifest.privacy_policies,
      );
      privacyPolicies = {
        declared: manifest.privacy_policies,
        validationResults: policyResults,
        allAccessible: policyResults.every((r) => r.accessible),
      };

      // Add validation result for privacy policies
      if (!privacyPolicies.allAccessible) {
        const inaccessible = policyResults.filter((r) => !r.accessible);
        validationResults.push({
          field: "privacy_policies",
          valid: false,
          value: manifest.privacy_policies,
          issue: `${inaccessible.length}/${policyResults.length} privacy policy URL(s) inaccessible`,
          severity: "WARNING",
        });
      } else {
        validationResults.push({
          field: "privacy_policies",
          valid: true,
          value: manifest.privacy_policies,
          severity: "INFO",
        });
      }
    }

    const status = this.determineManifestStatus(
      validationResults,
      hasRequiredFields,
    );
    const explanation = this.generateExplanation(
      validationResults,
      hasRequiredFields,
      hasIcon,
      privacyPolicies,
    );
    const recommendations = this.generateRecommendations(
      validationResults,
      privacyPolicies,
    );

    // Extract D4/D5 fields (Issue #141)
    const contactInfo = this.extractContactInfo(manifest);
    const versionInfo = this.extractVersionInfo(manifest);

    this.logger.info(
      `Assessment complete: ${validationResults.filter((r) => r.valid).length}/${validationResults.length} checks passed`,
    );

    return {
      hasManifest: true,
      manifestVersion: manifest.manifest_version,
      validationResults,
      hasIcon,
      hasRequiredFields,
      missingFields,
      privacyPolicies,
      contactInfo,
      versionInfo,
      status,
      explanation,
      recommendations,
    };
  }

  /**
   * Create result when no manifest is available
   */
  private createNoManifestResult(): ManifestValidationAssessment {
    return {
      hasManifest: false,
      validationResults: [
        {
          field: "manifest.json",
          valid: false,
          issue: "No manifest.json found - required for MCPB bundles",
          severity: "ERROR",
        },
      ],
      hasIcon: false,
      hasRequiredFields: false,
      missingFields: [...REQUIRED_FIELDS],
      status: "FAIL",
      explanation:
        "No manifest.json found. This file is required for MCPB bundle validation.",
      recommendations: [
        "Create a manifest.json file following the MCPB specification",
        "Required fields: manifest_version, name, version, mcp_config",
        "Recommended: description, author, repository, icon",
      ],
    };
  }

  /**
   * Create result when manifest JSON is invalid
   */
  private createInvalidJsonResult(
    validationResults: ManifestValidationResult[],
  ): ManifestValidationAssessment {
    return {
      hasManifest: true,
      validationResults,
      hasIcon: false,
      hasRequiredFields: false,
      missingFields: [...REQUIRED_FIELDS],
      status: "FAIL",
      explanation:
        "manifest.json contains invalid JSON and could not be parsed.",
      recommendations: [
        "Fix JSON syntax errors in manifest.json",
        "Validate JSON using a JSON linter",
      ],
    };
  }

  /**
   * Validate manifest_version field
   */
  private validateManifestVersion(
    manifest: ManifestJsonSchema,
  ): ManifestValidationResult {
    if (!manifest.manifest_version) {
      return {
        field: "manifest_version",
        valid: false,
        issue: "Missing manifest_version field",
        expectedType: "string",
        severity: "ERROR",
      };
    }

    if (manifest.manifest_version !== CURRENT_MANIFEST_VERSION) {
      return {
        field: "manifest_version",
        valid: false,
        value: manifest.manifest_version,
        issue: `Expected manifest_version "${CURRENT_MANIFEST_VERSION}", got "${manifest.manifest_version}"`,
        expectedType: "string",
        severity: "WARNING",
      };
    }

    return {
      field: "manifest_version",
      valid: true,
      value: manifest.manifest_version,
      severity: "INFO",
    };
  }

  /**
   * Validate required field presence
   */
  private validateRequiredField(
    manifest: ManifestJsonSchema,
    field: keyof ManifestJsonSchema,
  ): ManifestValidationResult {
    const value = manifest[field];

    if (value === undefined || value === null) {
      return {
        field,
        valid: false,
        issue: `Missing required field: ${field}`,
        severity: "ERROR",
      };
    }

    if (typeof value === "string" && value.trim() === "") {
      return {
        field,
        valid: false,
        value,
        issue: `Required field ${field} is empty`,
        severity: "ERROR",
      };
    }

    return {
      field,
      valid: true,
      value,
      severity: "INFO",
    };
  }

  /**
   * Validate recommended field presence
   */
  private validateRecommendedField(
    manifest: ManifestJsonSchema,
    field: keyof ManifestJsonSchema,
  ): ManifestValidationResult {
    const value = manifest[field];

    if (value === undefined || value === null) {
      return {
        field,
        valid: true, // Recommended fields don't fail validation
        issue: `Missing recommended field: ${field}`,
        severity: "WARNING",
      };
    }

    if (typeof value === "string" && value.trim() === "") {
      return {
        field,
        valid: true,
        value,
        issue: `Recommended field ${field} is empty`,
        severity: "WARNING",
      };
    }

    return {
      field,
      valid: true,
      value,
      severity: "INFO",
    };
  }

  /**
   * Validate mcp_config structure
   */
  private validateMcpConfig(
    mcpConfig: McpConfigSchema,
  ): ManifestValidationResult {
    if (!mcpConfig.command) {
      return {
        field: "mcp_config.command",
        valid: false,
        issue: "Missing required mcp_config.command field",
        severity: "ERROR",
      };
    }

    // Check for ${BUNDLE_ROOT} anti-pattern
    const configStr = JSON.stringify(mcpConfig);
    if (configStr.includes("${BUNDLE_ROOT}")) {
      return {
        field: "mcp_config",
        valid: false,
        issue:
          "Uses ${BUNDLE_ROOT} which is not supported - use ${__dirname} instead",
        severity: "ERROR",
      };
    }

    // Check for hardcoded absolute paths
    if (
      mcpConfig.command.startsWith("/") ||
      mcpConfig.command.match(/^[A-Z]:\\/)
    ) {
      return {
        field: "mcp_config.command",
        valid: false,
        value: mcpConfig.command,
        issue:
          "Command uses hardcoded absolute path - use relative or ${__dirname}",
        severity: "ERROR",
      };
    }

    return {
      field: "mcp_config",
      valid: true,
      value: mcpConfig,
      severity: "INFO",
    };
  }

  /**
   * Validate icon presence
   */
  private validateIcon(
    manifest: ManifestJsonSchema,
    context: AssessmentContext,
  ): ManifestValidationResult {
    // Check manifest icon field
    if (manifest.icon) {
      return {
        field: "icon",
        valid: true,
        value: manifest.icon,
        severity: "INFO",
      };
    }

    // Check if icon.png exists in source files
    if (context.sourceCodeFiles) {
      for (const filePath of context.sourceCodeFiles.keys()) {
        if (filePath.endsWith("icon.png") || filePath.endsWith("icon.svg")) {
          return {
            field: "icon",
            valid: true,
            value: filePath,
            issue: "Icon file found but not referenced in manifest",
            severity: "WARNING",
          };
        }
      }
    }

    return {
      field: "icon",
      valid: false,
      issue: "Missing icon.png - recommended for MCPB bundles",
      severity: "WARNING",
    };
  }

  /**
   * Validate name format
   */
  private validateNameFormat(name: string): ManifestValidationResult {
    if (!name) {
      return {
        field: "name (format)",
        valid: false,
        issue: "Name is required",
        severity: "ERROR",
      };
    }

    // Check for valid npm-style name
    const validNamePattern = /^[a-z0-9][a-z0-9._-]*$/;
    if (!validNamePattern.test(name.toLowerCase())) {
      return {
        field: "name (format)",
        valid: false,
        value: name,
        issue:
          "Name should be lowercase, alphanumeric, and may include .-_ characters",
        severity: "WARNING",
      };
    }

    return {
      field: "name (format)",
      valid: true,
      value: name,
      severity: "INFO",
    };
  }

  /**
   * Validate version format (semver)
   */
  private validateVersionFormat(version: string): ManifestValidationResult {
    if (!version) {
      return {
        field: "version (format)",
        valid: false,
        issue: "Version is required",
        severity: "ERROR",
      };
    }

    if (!SEMVER_PATTERN.test(version)) {
      return {
        field: "version (format)",
        valid: false,
        value: version,
        issue: "Version should follow semver format (e.g., 1.0.0)",
        severity: "WARNING",
      };
    }

    return {
      field: "version (format)",
      valid: true,
      value: version,
      severity: "INFO",
    };
  }

  /**
   * Validate manifest tool declarations against actual server tools (Issue #140)
   * Compares tool names in manifest.tools against context.tools from tools/list
   * Uses Levenshtein distance for "did you mean?" suggestions
   */
  private validateToolNamesMatch(
    manifest: ManifestJsonSchema,
    serverTools: Tool[],
  ): ManifestValidationResult[] {
    const results: ManifestValidationResult[] = [];

    // Skip if manifest doesn't declare tools
    if (!manifest.tools || manifest.tools.length === 0) {
      return results;
    }

    this.testCount++;

    const manifestToolNames = new Set(manifest.tools.map((t) => t.name));
    const serverToolNames = new Set(serverTools.map((t) => t.name));

    // Check for tools declared in manifest but not on server
    const mismatches: Array<{ manifest: string; suggestion: string | null }> =
      [];
    for (const name of manifestToolNames) {
      if (!serverToolNames.has(name)) {
        const suggestion = findClosestMatch(name, serverToolNames);
        mismatches.push({ manifest: name, suggestion });
      }
    }

    // Check for tools on server but not declared in manifest
    const undeclaredTools: string[] = [];
    for (const name of serverToolNames) {
      if (!manifestToolNames.has(name)) {
        undeclaredTools.push(name);
      }
    }

    // Report mismatches with suggestions
    if (mismatches.length > 0) {
      const issueLines = mismatches.map((m) =>
        m.suggestion
          ? `"${m.manifest}" (did you mean "${m.suggestion}"?)`
          : `"${m.manifest}"`,
      );
      results.push({
        field: "tools (manifest vs server)",
        valid: false,
        value: mismatches,
        issue: `Manifest declares tools not found on server: ${issueLines.join(", ")}`,
        severity: "WARNING",
      });
    }

    if (undeclaredTools.length > 0) {
      results.push({
        field: "tools (undeclared)",
        valid: false,
        value: undeclaredTools,
        issue: `Server has tools not declared in manifest: ${undeclaredTools.join(", ")}`,
        severity: "INFO",
      });
    }

    // All matched
    if (mismatches.length === 0 && undeclaredTools.length === 0) {
      results.push({
        field: "tools (manifest vs server)",
        valid: true,
        value: `${manifestToolNames.size} tools matched`,
        severity: "INFO",
      });
    }

    return results;
  }

  /**
   * Fetch with retry logic for transient network failures
   */
  private async fetchWithRetry(
    url: string,
    method: "HEAD" | "GET",
    retries = 2,
    backoffMs = 100,
  ): Promise<Response> {
    let lastError: Error | null = null;

    for (let attempt = 0; attempt <= retries; attempt++) {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 5000);

      try {
        const response = await fetch(url, {
          method,
          signal: controller.signal,
          redirect: "follow",
        });

        clearTimeout(timeoutId);
        return response;
      } catch (error) {
        clearTimeout(timeoutId);
        lastError = error instanceof Error ? error : new Error(String(error));

        // Don't retry on last attempt
        if (attempt < retries) {
          // Exponential backoff
          await new Promise((resolve) =>
            setTimeout(resolve, backoffMs * Math.pow(2, attempt)),
          );
        }
      }
    }

    // All retries exhausted
    throw lastError;
  }

  /**
   * Validate privacy policy URLs are accessible
   */
  private async validatePrivacyPolicyUrls(
    privacyPolicies: string[],
  ): Promise<PrivacyPolicyValidation[]> {
    const results: PrivacyPolicyValidation[] = [];

    for (const url of privacyPolicies) {
      this.testCount++;

      // Validate URL format first
      try {
        new URL(url);
      } catch (error) {
        this.logger.error(`Invalid privacy policy URL format: ${url}`, {
          error,
        });
        results.push({
          url,
          accessible: false,
          error: "Invalid URL format",
        });
        continue;
      }

      try {
        // Use HEAD request for efficiency with retry logic
        const response = await this.fetchWithRetry(url, "HEAD");

        results.push({
          url,
          accessible: response.ok,
          statusCode: response.status,
          contentType: response.headers.get("content-type") || undefined,
        });
      } catch (headError) {
        // Try GET request as fallback (some servers reject HEAD)
        this.logger.debug(`HEAD request failed for ${url}, trying GET`, {
          error:
            headError instanceof Error ? headError.message : String(headError),
        });
        try {
          const response = await this.fetchWithRetry(url, "GET");

          results.push({
            url,
            accessible: response.ok,
            statusCode: response.status,
            contentType: response.headers.get("content-type") || undefined,
          });
        } catch (fetchError) {
          this.logger.error(`Failed to fetch privacy policy URL: ${url}`, {
            error: fetchError,
          });
          results.push({
            url,
            accessible: false,
            error:
              fetchError instanceof Error
                ? fetchError.message
                : "Network error",
          });
        }
      }
    }

    return results;
  }

  /**
   * Determine overall status
   */
  private determineManifestStatus(
    results: ManifestValidationResult[],
    hasRequiredFields: boolean,
  ): AssessmentStatus {
    const errors = results.filter(
      (r) => !r.valid && r.severity === "ERROR",
    ).length;
    const warnings = results.filter(
      (r) => !r.valid && r.severity === "WARNING",
    ).length;

    if (errors > 0 || !hasRequiredFields) {
      return "FAIL";
    }

    if (warnings > 0) {
      return "NEED_MORE_INFO";
    }

    return "PASS";
  }

  /**
   * Generate explanation
   */
  private generateExplanation(
    results: ManifestValidationResult[],
    hasRequiredFields: boolean,
    hasIcon: boolean,
    privacyPolicies?: {
      declared: string[];
      validationResults: PrivacyPolicyValidation[];
      allAccessible: boolean;
    },
  ): string {
    const parts: string[] = [];

    const passed = results.filter((r) => r.valid).length;
    const total = results.length;

    parts.push(`Manifest validation: ${passed}/${total} checks passed.`);

    if (!hasRequiredFields) {
      parts.push("Missing required fields in manifest.json.");
    }

    if (!hasIcon) {
      parts.push("No icon found - recommended for MCPB bundles.");
    }

    if (privacyPolicies && !privacyPolicies.allAccessible) {
      const inaccessible = privacyPolicies.validationResults.filter(
        (r) => !r.accessible,
      );
      parts.push(
        `${inaccessible.length} privacy policy URL(s) are inaccessible.`,
      );
    }

    const errors = results.filter((r) => !r.valid && r.severity === "ERROR");
    if (errors.length > 0) {
      parts.push(`${errors.length} error(s) require attention.`);
    }

    return parts.join(" ");
  }

  /**
   * Generate recommendations
   */
  private generateRecommendations(
    results: ManifestValidationResult[],
    privacyPolicies?: {
      declared: string[];
      validationResults: PrivacyPolicyValidation[];
      allAccessible: boolean;
    },
  ): string[] {
    const recommendations: string[] = [];

    // Group by severity
    const errors = results.filter((r) => !r.valid && r.severity === "ERROR");
    const warnings = results.filter((r) => r.severity === "WARNING" && r.issue);

    if (errors.length > 0) {
      recommendations.push("FIX REQUIRED - Manifest errors:");
      for (const error of errors) {
        recommendations.push(`- ${error.field}: ${error.issue}`);
      }
    }

    if (warnings.length > 0) {
      recommendations.push("RECOMMENDED - Manifest improvements:");
      for (const warning of warnings.slice(0, 3)) {
        recommendations.push(`- ${warning.field}: ${warning.issue}`);
      }
    }

    // Add privacy policy recommendations
    if (privacyPolicies && !privacyPolicies.allAccessible) {
      recommendations.push("PRIVACY POLICY - Fix inaccessible URLs:");
      for (const result of privacyPolicies.validationResults) {
        if (!result.accessible) {
          const reason = result.error || `HTTP ${result.statusCode}`;
          recommendations.push(`- ${result.url}: ${reason}`);
        }
      }
    }

    if (recommendations.length === 0) {
      recommendations.push(
        "Manifest validation passed. All required fields are present and valid.",
      );
    }

    return recommendations;
  }
}

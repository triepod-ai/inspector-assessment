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
import type {
  ManifestValidationAssessment,
  ManifestValidationResult,
  ManifestJsonSchema,
  AssessmentStatus,
} from "@/lib/assessmentTypes";

const REQUIRED_FIELDS = ["name", "version", "mcp_config"] as const;
const RECOMMENDED_FIELDS = ["description", "author", "repository"] as const;
const CURRENT_MANIFEST_VERSION = "0.3";

export class ManifestValidationAssessor extends BaseAssessor {
  /**
   * Run manifest validation assessment
   */
  async assess(
    context: AssessmentContext
  ): Promise<ManifestValidationAssessment> {
    this.log("Starting manifest validation assessment");
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
      const result = this.validateRequiredField(manifest, field);
      validationResults.push(result);
      if (!result.valid) {
        hasRequiredFields = false;
        missingFields.push(field);
      }
    }

    // Validate recommended fields
    for (const field of RECOMMENDED_FIELDS) {
      this.testCount++;
      validationResults.push(this.validateRecommendedField(manifest, field));
    }

    // Validate mcp_config structure
    if (manifest.mcp_config) {
      this.testCount++;
      validationResults.push(this.validateMcpConfig(manifest.mcp_config));
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

    const status = this.determineManifestStatus(
      validationResults,
      hasRequiredFields
    );
    const explanation = this.generateExplanation(
      validationResults,
      hasRequiredFields,
      hasIcon
    );
    const recommendations = this.generateRecommendations(validationResults);

    this.log(
      `Assessment complete: ${validationResults.filter((r) => r.valid).length}/${validationResults.length} checks passed`
    );

    return {
      hasManifest: true,
      manifestVersion: manifest.manifest_version,
      validationResults,
      hasIcon,
      hasRequiredFields,
      missingFields,
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
    validationResults: ManifestValidationResult[]
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
    manifest: ManifestJsonSchema
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
    field: keyof ManifestJsonSchema
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
    field: keyof ManifestJsonSchema
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
    mcpConfig: ManifestJsonSchema["mcp_config"]
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
        issue: "Command uses hardcoded absolute path - use relative or ${__dirname}",
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
    context: AssessmentContext
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

    // Check for semver format
    const semverPattern = /^\d+\.\d+\.\d+(-[a-zA-Z0-9.]+)?(\+[a-zA-Z0-9.]+)?$/;
    if (!semverPattern.test(version)) {
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
   * Determine overall status
   */
  private determineManifestStatus(
    results: ManifestValidationResult[],
    hasRequiredFields: boolean
  ): AssessmentStatus {
    const errors = results.filter(
      (r) => !r.valid && r.severity === "ERROR"
    ).length;
    const warnings = results.filter(
      (r) => !r.valid && r.severity === "WARNING"
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
    hasIcon: boolean
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

    const errors = results.filter(
      (r) => !r.valid && r.severity === "ERROR"
    );
    if (errors.length > 0) {
      parts.push(`${errors.length} error(s) require attention.`);
    }

    return parts.join(" ");
  }

  /**
   * Generate recommendations
   */
  private generateRecommendations(
    results: ManifestValidationResult[]
  ): string[] {
    const recommendations: string[] = [];

    // Group by severity
    const errors = results.filter(
      (r) => !r.valid && r.severity === "ERROR"
    );
    const warnings = results.filter(
      (r) => r.severity === "WARNING" && r.issue
    );

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

    if (recommendations.length === 0) {
      recommendations.push(
        "Manifest validation passed. All required fields are present and valid."
      );
    }

    return recommendations;
  }
}

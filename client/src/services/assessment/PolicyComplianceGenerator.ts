/**
 * Policy Compliance Generator
 *
 * Maps MCP Inspector assessment results to Anthropic's Software Directory
 * Policy requirements (30 total). Generates a structured compliance report
 * that can be used for directory submission review.
 *
 * @module PolicyComplianceGenerator
 */

import type { MCPDirectoryAssessment } from "@/lib/assessmentTypes";
import {
  type PolicyCategory,
  type ComplianceStatus,
  type PolicyRequirement,
  type PolicyComplianceResult,
  type PolicyComplianceSummary,
  type PolicyComplianceReport,
  ANTHROPIC_POLICY_REQUIREMENTS,
  getCategoryDisplayName,
} from "@/lib/policyMapping";

/**
 * Generator for policy compliance reports
 */
export class PolicyComplianceGenerator {
  private readonly version: string;

  constructor(version: string = "1.0.0") {
    this.version = version;
  }

  /**
   * Generate a full policy compliance report from assessment results
   */
  generate(
    assessment: MCPDirectoryAssessment,
    serverName?: string,
  ): PolicyComplianceReport {
    const results = this.evaluateAllRequirements(assessment);
    const byCategory = this.groupByCategory(results);
    const summary = this.calculateSummary(results);
    const criticalIssues = this.identifyCriticalIssues(results);
    const actionItems = this.generateActionItems(results);

    return {
      serverName: serverName || assessment.serverName,
      generatedAt: new Date().toISOString(),
      assessorVersion: this.version,
      summary,
      byCategory,
      criticalIssues,
      actionItems,
      sourceAssessment: {
        totalTestsRun: assessment.totalTestsRun,
        executionTime: assessment.executionTime,
        modulesRun: this.getRunModules(assessment),
      },
    };
  }

  /**
   * Evaluate all 30 policy requirements against assessment results
   */
  private evaluateAllRequirements(
    assessment: MCPDirectoryAssessment,
  ): PolicyComplianceResult[] {
    return ANTHROPIC_POLICY_REQUIREMENTS.map((req) =>
      this.evaluateRequirement(req, assessment),
    );
  }

  /**
   * Evaluate a single policy requirement
   */
  private evaluateRequirement(
    requirement: PolicyRequirement,
    assessment: MCPDirectoryAssessment,
  ): PolicyComplianceResult {
    // Mark DEV requirements as NOT_APPLICABLE when source code is not available
    // These requirements (documentation, privacy policy, contact info) cannot be
    // evaluated for HTTP-only assessments without access to the source repository
    if (
      requirement.category === "developer_requirements" &&
      !assessment.assessmentMetadata?.sourceCodeAvailable
    ) {
      return {
        requirement,
        status: "NOT_APPLICABLE",
        evidence: ["Source code not available for documentation assessment"],
        moduleResults: [],
        recommendation: undefined,
        manualReviewRequired: false,
        manualReviewGuidance: undefined,
      };
    }

    const evidence: string[] = [];
    const moduleResults: PolicyComplianceResult["moduleResults"] = [];

    // Collect evidence from each source module
    for (const moduleName of requirement.moduleSource) {
      const moduleData = this.getModuleData(assessment, moduleName);
      if (moduleData) {
        const findings = this.extractRelevantFindings(
          moduleName,
          moduleData,
          requirement.id,
        );
        moduleResults.push({
          module: moduleName,
          status: moduleData.status || "UNKNOWN",
          relevantFindings: findings,
        });
        evidence.push(...findings);
      }
    }

    // Determine compliance status
    const status = this.determineComplianceStatus(
      requirement,
      moduleResults,
      evidence,
    );

    // Generate recommendation if needed
    const recommendation =
      status !== "PASS" && status !== "NOT_APPLICABLE"
        ? this.generateRecommendation(requirement, status, evidence)
        : undefined;

    // Determine if manual review is required
    const manualReviewRequired =
      !requirement.automatable ||
      status === "FLAG" ||
      status === "REVIEW" ||
      status === "NOT_TESTED";

    return {
      requirement,
      status,
      evidence,
      moduleResults,
      recommendation,
      manualReviewRequired,
      manualReviewGuidance: manualReviewRequired
        ? this.getManualReviewGuidance(requirement, status)
        : undefined,
    };
  }

  /**
   * Get module data from assessment by module name
   */
  private getModuleData(
    assessment: MCPDirectoryAssessment,
    moduleName: string,
  ): { status?: string; [key: string]: unknown } | null {
    const moduleMap: Record<string, unknown> = {
      aupCompliance: assessment.aupCompliance,
      security: assessment.security,
      functionality: assessment.functionality,
      errorHandling: assessment.errorHandling,
      usability: assessment.usability,
      documentation: assessment.documentation,
      mcpSpecCompliance: assessment.mcpSpecCompliance,
      toolAnnotations: assessment.toolAnnotations,
      prohibitedLibraries: assessment.prohibitedLibraries,
      manifestValidation: assessment.manifestValidation,
      portability: assessment.portability,
    };

    const data = moduleMap[moduleName];
    if (data && typeof data === "object") {
      return data as { status?: string; [key: string]: unknown };
    }
    return null;
  }

  /**
   * Extract relevant findings from a module for a specific requirement
   */
  private extractRelevantFindings(
    moduleName: string,
    moduleData: { status?: string; [key: string]: unknown },
    requirementId: string,
  ): string[] {
    const findings: string[] = [];

    // Extract based on module type
    switch (moduleName) {
      case "aupCompliance":
        findings.push(...this.extractAUPFindings(moduleData, requirementId));
        break;
      case "security":
        findings.push(
          ...this.extractSecurityFindings(moduleData, requirementId),
        );
        break;
      case "functionality":
        findings.push(
          ...this.extractFunctionalityFindings(moduleData, requirementId),
        );
        break;
      case "errorHandling":
        findings.push(
          ...this.extractErrorHandlingFindings(moduleData, requirementId),
        );
        break;
      case "toolAnnotations":
        findings.push(
          ...this.extractToolAnnotationFindings(moduleData, requirementId),
        );
        break;
      case "documentation":
        findings.push(
          ...this.extractDocumentationFindings(moduleData, requirementId),
        );
        break;
      case "mcpSpecCompliance":
        findings.push(
          ...this.extractMCPSpecFindings(moduleData, requirementId),
        );
        break;
      case "prohibitedLibraries":
        findings.push(
          ...this.extractProhibitedLibraryFindings(moduleData, requirementId),
        );
        break;
      case "manifestValidation":
        findings.push(
          ...this.extractManifestFindings(moduleData, requirementId),
        );
        break;
      case "portability":
        findings.push(
          ...this.extractPortabilityFindings(moduleData, requirementId),
        );
        break;
      default:
        // Generic extraction
        if (moduleData.status) {
          findings.push(`${moduleName} status: ${moduleData.status}`);
        }
    }

    return findings;
  }

  /**
   * Extract AUP compliance findings
   */
  private extractAUPFindings(
    data: { status?: string; [key: string]: unknown },
    requirementId: string,
  ): string[] {
    const findings: string[] = [];

    if (data.status) {
      findings.push(`AUP compliance status: ${data.status}`);
    }

    // Check for violations
    const violations = data.violations as unknown[];
    if (Array.isArray(violations) && violations.length > 0) {
      const violationCount = violations.length;
      findings.push(`${violationCount} AUP violation(s) detected`);

      // Add specific violation categories
      if (requirementId.startsWith("SAFETY-")) {
        const critical = violations.filter(
          (v: unknown) =>
            typeof v === "object" && v !== null && "severity" in v,
        );
        if (critical.length > 0) {
          findings.push(`${critical.length} critical safety violation(s)`);
        }
      }
    }

    // Check overall score
    const score = data.overallScore;
    if (typeof score === "number") {
      findings.push(`AUP compliance score: ${score}%`);
    }

    return findings;
  }

  /**
   * Extract security findings
   */
  private extractSecurityFindings(
    data: { status?: string; [key: string]: unknown },
    _requirementId: string,
  ): string[] {
    const findings: string[] = [];

    if (data.status) {
      findings.push(`Security assessment status: ${data.status}`);
    }

    // Check for vulnerabilities
    const vulnerabilities = data.vulnerabilities as unknown[];
    if (Array.isArray(vulnerabilities)) {
      if (vulnerabilities.length === 0) {
        findings.push("No security vulnerabilities detected");
      } else {
        findings.push(
          `${vulnerabilities.length} security vulnerability(ies) detected`,
        );
      }
    }

    // Check for prompt injection tests
    const promptTests = data.promptInjectionTests as unknown[];
    if (Array.isArray(promptTests)) {
      const vulnerable = promptTests.filter(
        (t: unknown) =>
          typeof t === "object" &&
          t !== null &&
          (t as { vulnerable?: boolean }).vulnerable,
      );
      if (vulnerable.length > 0) {
        findings.push(`${vulnerable.length} tool(s) vulnerable to injection`);
      }
    }

    return findings;
  }

  /**
   * Extract functionality findings
   */
  private extractFunctionalityFindings(
    data: { status?: string; [key: string]: unknown },
    _requirementId: string,
  ): string[] {
    const findings: string[] = [];

    if (data.status) {
      findings.push(`Functionality status: ${data.status}`);
    }

    // Check working/broken tools
    const workingTools = data.workingTools as unknown[];
    const brokenTools = data.brokenTools as unknown[];

    if (Array.isArray(workingTools)) {
      findings.push(`${workingTools.length} tool(s) working correctly`);
    }

    if (Array.isArray(brokenTools) && brokenTools.length > 0) {
      findings.push(`${brokenTools.length} tool(s) with issues`);
    }

    // Check overall success rate
    const summary = data.summary;
    if (typeof summary === "object" && summary !== null) {
      const s = summary as { successRate?: number };
      if (typeof s.successRate === "number") {
        findings.push(`Tool success rate: ${s.successRate.toFixed(1)}%`);
      }
    }

    return findings;
  }

  /**
   * Extract error handling findings
   */
  private extractErrorHandlingFindings(
    data: { status?: string; [key: string]: unknown },
    _requirementId: string,
  ): string[] {
    const findings: string[] = [];

    if (data.status) {
      findings.push(`Error handling status: ${data.status}`);
    }

    const metrics = data.metrics as Record<string, unknown>;
    if (typeof metrics === "object" && metrics !== null) {
      if (typeof metrics.totalTests === "number") {
        findings.push(`${metrics.totalTests} error handling tests executed`);
      }
      if (typeof metrics.passRate === "number") {
        findings.push(`Error handling pass rate: ${metrics.passRate}%`);
      }
    }

    return findings;
  }

  /**
   * Extract tool annotation findings
   */
  private extractToolAnnotationFindings(
    data: { status?: string; [key: string]: unknown },
    _requirementId: string,
  ): string[] {
    const findings: string[] = [];

    if (data.status) {
      findings.push(`Tool annotations status: ${data.status}`);
    }

    // Check annotation coverage
    const annotatedCount = data.annotatedCount;
    const missingCount = data.missingAnnotationsCount;
    const misalignedCount = data.misalignedAnnotationsCount;

    if (typeof annotatedCount === "number") {
      findings.push(`${annotatedCount} tool(s) with annotations`);
    }
    if (typeof missingCount === "number" && missingCount > 0) {
      findings.push(`${missingCount} tool(s) missing annotations`);
    }
    if (typeof misalignedCount === "number" && misalignedCount > 0) {
      findings.push(`${misalignedCount} tool(s) with misaligned annotations`);
    }

    // Check annotation sources
    const sources = data.annotationSources as Record<string, number>;
    if (typeof sources === "object" && sources !== null) {
      if (sources.mcp > 0) {
        findings.push(`${sources.mcp} tool(s) with MCP protocol annotations`);
      }
    }

    return findings;
  }

  /**
   * Extract documentation findings
   */
  private extractDocumentationFindings(
    data: { status?: string; [key: string]: unknown },
    _requirementId: string,
  ): string[] {
    const findings: string[] = [];

    if (data.status) {
      findings.push(`Documentation status: ${data.status}`);
    }

    // Check documentation quality
    const quality = data.quality as Record<string, unknown>;
    if (typeof quality === "object" && quality !== null) {
      if (typeof quality.overallScore === "number") {
        findings.push(`Documentation quality score: ${quality.overallScore}%`);
      }
    }

    return findings;
  }

  /**
   * Extract MCP spec compliance findings
   */
  private extractMCPSpecFindings(
    data: { status?: string; [key: string]: unknown },
    _requirementId: string,
  ): string[] {
    const findings: string[] = [];

    if (data.status) {
      findings.push(`MCP spec compliance status: ${data.status}`);
    }

    // Check protocol compliance
    const summary = data.summary as Record<string, unknown>;
    if (typeof summary === "object" && summary !== null) {
      if (typeof summary.totalChecks === "number") {
        findings.push(`${summary.totalChecks} protocol checks performed`);
      }
    }

    return findings;
  }

  /**
   * Extract prohibited library findings
   */
  private extractProhibitedLibraryFindings(
    data: { status?: string; [key: string]: unknown },
    _requirementId: string,
  ): string[] {
    const findings: string[] = [];

    if (data.status) {
      findings.push(`Prohibited libraries status: ${data.status}`);
    }

    const detected = data.prohibitedLibrariesDetected as unknown[];
    if (Array.isArray(detected)) {
      if (detected.length === 0) {
        findings.push("No prohibited libraries detected");
      } else {
        findings.push(`${detected.length} prohibited library(ies) detected`);
      }
    }

    return findings;
  }

  /**
   * Extract manifest findings
   */
  private extractManifestFindings(
    data: { status?: string; [key: string]: unknown },
    _requirementId: string,
  ): string[] {
    const findings: string[] = [];

    if (data.status) {
      findings.push(`Manifest validation status: ${data.status}`);
    }

    const valid = data.isValid;
    if (typeof valid === "boolean") {
      findings.push(valid ? "Manifest is valid" : "Manifest validation failed");
    }

    return findings;
  }

  /**
   * Extract portability findings
   */
  private extractPortabilityFindings(
    data: { status?: string; [key: string]: unknown },
    _requirementId: string,
  ): string[] {
    const findings: string[] = [];

    if (data.status) {
      findings.push(`Portability status: ${data.status}`);
    }

    const issues = data.issues as unknown[];
    if (Array.isArray(issues)) {
      if (issues.length === 0) {
        findings.push("No portability issues detected");
      } else {
        findings.push(`${issues.length} portability issue(s) detected`);
      }
    }

    return findings;
  }

  /**
   * Determine compliance status based on module results and evidence
   */
  private determineComplianceStatus(
    requirement: PolicyRequirement,
    moduleResults: PolicyComplianceResult["moduleResults"],
    evidence: string[],
  ): ComplianceStatus {
    // If no modules were run, mark as NOT_TESTED
    if (moduleResults.length === 0) {
      return "NOT_TESTED";
    }

    // Check if all modules passed
    const allPassed = moduleResults.every(
      (r) => r.status === "PASS" || r.status === "NEED_MORE_INFO",
    );
    const anyFailed = moduleResults.some((r) => r.status === "FAIL");
    const anyNeedInfo = moduleResults.some(
      (r) => r.status === "NEED_MORE_INFO",
    );

    // Check for critical findings in evidence
    const hasCriticalFindings = evidence.some(
      (e) =>
        e.toLowerCase().includes("critical") ||
        e.toLowerCase().includes("vulnerability") ||
        e.toLowerCase().includes("violation"),
    );

    // Determine status based on severity and findings
    if (anyFailed) {
      if (requirement.severity === "CRITICAL" || hasCriticalFindings) {
        return "FAIL";
      }
      return "FLAG";
    }

    if (anyNeedInfo) {
      return "REVIEW";
    }

    if (allPassed && !hasCriticalFindings) {
      return "PASS";
    }

    // Default to review if unclear
    return "REVIEW";
  }

  /**
   * Generate a recommendation for non-passing requirements
   */
  private generateRecommendation(
    requirement: PolicyRequirement,
    status: ComplianceStatus,
    evidence: string[],
  ): string {
    const prefix =
      status === "FAIL"
        ? "[REQUIRED]"
        : status === "FLAG"
          ? "[RECOMMENDED]"
          : "[REVIEW]";

    // Generate specific recommendations based on requirement
    const recommendations: Record<string, string> = {
      "SAFETY-1":
        "Ensure server complies with Anthropic's Acceptable Use Policy",
      "SAFETY-2": "Fix security vulnerabilities before submission",
      "SAFETY-3": "Remove any malicious or deceptive functionality",
      "SAFETY-4": "Implement proper input validation and sanitization",
      "SAFETY-5": "Secure sensitive data handling and storage",
      "SAFETY-6": "Implement proper authentication and authorization",
      "COMPAT-1": "Ensure full MCP protocol compliance",
      "COMPAT-2": "Support required MCP message types",
      "COMPAT-3": "Remove or replace prohibited dependencies",
      "COMPAT-4": "Fix compatibility issues with Claude clients",
      "COMPAT-5": "Test across supported platforms",
      "COMPAT-6": "Ensure cross-platform portability",
      "FUNC-1": "Ensure all tools function as documented",
      "FUNC-2": "Improve tool reliability and consistency",
      "FUNC-3": "Implement proper error handling",
      "FUNC-4": "Improve tool documentation",
      "FUNC-5": "Add required tool annotations (readOnlyHint, destructiveHint)",
      "FUNC-6": "Ensure tools produce meaningful results",
      "FUNC-7": "Improve usability and user experience",
      "DEV-1": "Provide valid manifest.json",
      "DEV-2": "Include license information",
      "DEV-3": "Add comprehensive README documentation",
      "DEV-4": "Provide installation instructions",
      "DEV-5": "Include usage examples",
      "DEV-6": "Document configuration options",
      "DEV-7": "Add contribution guidelines",
      "DEV-8": "Maintain changelog",
      "UNSUPP-1": "Remove cryptocurrency/blockchain functionality",
      "UNSUPP-2": "Remove gambling functionality",
      "UNSUPP-3": "Remove adult content functionality",
    };

    const baseRec =
      recommendations[requirement.id] || `Address ${requirement.name} issues`;

    // Add evidence-specific context if available
    const relevantEvidence = evidence.slice(0, 2).join("; ");
    if (relevantEvidence) {
      return `${prefix} ${baseRec}. Evidence: ${relevantEvidence}`;
    }

    return `${prefix} ${baseRec}`;
  }

  /**
   * Get manual review guidance for a requirement
   */
  private getManualReviewGuidance(
    requirement: PolicyRequirement,
    status: ComplianceStatus,
  ): string {
    if (status === "NOT_TESTED") {
      return `Run the following assessment modules to evaluate this requirement: ${requirement.moduleSource.join(", ")}`;
    }

    if (status === "FLAG" || status === "REVIEW") {
      return `Manually verify: ${requirement.description}. Automated assessment found potential issues that require human judgment.`;
    }

    return `Review ${requirement.name} manually as this requirement cannot be fully automated.`;
  }

  /**
   * Group results by category
   */
  private groupByCategory(
    results: PolicyComplianceResult[],
  ): PolicyComplianceReport["byCategory"] {
    const categories: PolicyCategory[] = [
      "safety_security",
      "compatibility",
      "functionality",
      "developer_requirements",
      "unsupported_use_cases",
    ];

    const byCategory: Partial<PolicyComplianceReport["byCategory"]> = {};

    for (const category of categories) {
      const categoryResults = results.filter(
        (r) => r.requirement.category === category,
      );

      const passed = categoryResults.filter((r) => r.status === "PASS").length;
      const failed = categoryResults.filter(
        (r) => r.status === "FAIL" || r.status === "FLAG",
      ).length;

      let categoryStatus: ComplianceStatus = "PASS";
      if (failed > 0) {
        const hasCriticalFail = categoryResults.some(
          (r) => r.status === "FAIL" && r.requirement.severity === "CRITICAL",
        );
        categoryStatus = hasCriticalFail ? "FAIL" : "FLAG";
      } else if (categoryResults.some((r) => r.status === "REVIEW")) {
        categoryStatus = "REVIEW";
      } else if (categoryResults.every((r) => r.status === "NOT_TESTED")) {
        categoryStatus = "NOT_TESTED";
      }

      byCategory[category] = {
        category,
        categoryName: getCategoryDisplayName(category),
        total: categoryResults.length,
        passed,
        failed,
        status: categoryStatus,
        requirements: categoryResults,
      };
    }

    return byCategory as PolicyComplianceReport["byCategory"];
  }

  /**
   * Calculate summary statistics
   */
  private calculateSummary(
    results: PolicyComplianceResult[],
  ): PolicyComplianceSummary {
    const passed = results.filter((r) => r.status === "PASS").length;
    const failed = results.filter((r) => r.status === "FAIL").length;
    const flagged = results.filter((r) => r.status === "FLAG").length;
    const needsReview = results.filter((r) => r.status === "REVIEW").length;
    const notApplicable = results.filter(
      (r) => r.status === "NOT_APPLICABLE",
    ).length;
    const notTested = results.filter((r) => r.status === "NOT_TESTED").length;

    const applicableTotal = results.length - notApplicable - notTested;
    const complianceScore =
      applicableTotal > 0 ? Math.round((passed / applicableTotal) * 100) : 0;

    // Determine overall status
    let overallStatus: PolicyComplianceSummary["overallStatus"] = "COMPLIANT";
    if (failed > 0) {
      // Check if any critical requirements failed
      const criticalFailed = results.some(
        (r) => r.status === "FAIL" && r.requirement.severity === "CRITICAL",
      );
      overallStatus = criticalFailed ? "NON_COMPLIANT" : "NEEDS_REVIEW";
    } else if (flagged > 0 || needsReview > 0) {
      overallStatus = "NEEDS_REVIEW";
    }

    return {
      totalRequirements: results.length,
      passed,
      failed,
      flagged,
      needsReview,
      notApplicable,
      notTested,
      complianceScore,
      overallStatus,
    };
  }

  /**
   * Identify critical issues
   */
  private identifyCriticalIssues(
    results: PolicyComplianceResult[],
  ): PolicyComplianceResult[] {
    return results.filter(
      (r) =>
        (r.status === "FAIL" || r.status === "FLAG") &&
        (r.requirement.severity === "CRITICAL" ||
          r.requirement.severity === "HIGH"),
    );
  }

  /**
   * Generate prioritized action items
   */
  private generateActionItems(results: PolicyComplianceResult[]): string[] {
    const actionItems: string[] = [];

    // Group by severity
    const critical = results.filter(
      (r) => r.status === "FAIL" && r.requirement.severity === "CRITICAL",
    );
    const high = results.filter(
      (r) =>
        (r.status === "FAIL" && r.requirement.severity === "HIGH") ||
        (r.status === "FLAG" && r.requirement.severity === "CRITICAL"),
    );
    const medium = results.filter(
      (r) =>
        (r.status === "FAIL" && r.requirement.severity === "MEDIUM") ||
        (r.status === "FLAG" && r.requirement.severity === "HIGH"),
    );

    // Add critical items first
    for (const result of critical) {
      if (result.recommendation) {
        actionItems.push(`[CRITICAL] ${result.recommendation}`);
      }
    }

    // Add high priority items
    for (const result of high) {
      if (result.recommendation) {
        actionItems.push(`[HIGH] ${result.recommendation}`);
      }
    }

    // Add medium priority items (limit to avoid overwhelming)
    for (const result of medium.slice(0, 5)) {
      if (result.recommendation) {
        actionItems.push(`[MEDIUM] ${result.recommendation}`);
      }
    }

    // Add review items summary if many exist
    const reviewCount = results.filter(
      (r) => r.status === "REVIEW" || r.status === "NOT_TESTED",
    ).length;
    if (reviewCount > 0) {
      actionItems.push(
        `[INFO] ${reviewCount} requirement(s) need manual review or additional testing`,
      );
    }

    return actionItems;
  }

  /**
   * Get list of modules that were run in the assessment
   */
  private getRunModules(assessment: MCPDirectoryAssessment): string[] {
    const modules: string[] = [];

    if (assessment.functionality) modules.push("functionality");
    if (assessment.security) modules.push("security");
    if (assessment.documentation) modules.push("documentation");
    if (assessment.errorHandling) modules.push("errorHandling");
    if (assessment.usability) modules.push("usability");
    if (assessment.mcpSpecCompliance) modules.push("mcpSpecCompliance");
    if (assessment.aupCompliance) modules.push("aupCompliance");
    if (assessment.toolAnnotations) modules.push("toolAnnotations");
    if (assessment.prohibitedLibraries) modules.push("prohibitedLibraries");
    if (assessment.manifestValidation) modules.push("manifestValidation");
    if (assessment.portability) modules.push("portability");

    return modules;
  }
}

/**
 * Factory function to create a policy compliance generator
 */
export function createPolicyComplianceGenerator(
  version?: string,
): PolicyComplianceGenerator {
  return new PolicyComplianceGenerator(version);
}

/**
 * Quick utility to generate a compliance report
 */
export function generatePolicyComplianceReport(
  assessment: MCPDirectoryAssessment,
  serverName?: string,
): PolicyComplianceReport {
  const generator = createPolicyComplianceGenerator();
  return generator.generate(assessment, serverName);
}

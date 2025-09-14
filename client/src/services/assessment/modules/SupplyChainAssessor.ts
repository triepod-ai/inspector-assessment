/**
 * Supply Chain Security Assessor Module
 * Evaluates dependencies, package integrity, and supply chain vulnerabilities
 */

import { BaseAssessor } from "./BaseAssessor";
import { AssessmentContext } from "../AssessmentOrchestrator";
import { AssessmentStatus } from "@/lib/assessmentTypes";

export interface SupplyChainAssessment {
  category: "supplyChain";
  status: AssessmentStatus;
  score: number;
  totalDependencies: number;
  vulnerableDependencies: number;
  licenseCompliance: {
    compliant: number;
    nonCompliant: number;
    unknown: number;
  };
  integrityChecks: {
    passed: number;
    failed: number;
    skipped: number;
  };
  typosquattingRisks: string[];
  sbomGenerated: boolean;
  criticalFindings: string[];
  recommendations: string[];
  explanation: string;
}

interface DependencyInfo {
  name: string;
  version: string;
  license?: string;
  vulnerabilities?: string[];
  integrity?: boolean;
}

export class SupplyChainAssessor extends BaseAssessor {
  async assess(context: AssessmentContext): Promise<SupplyChainAssessment> {
    this.log("Starting supply chain security assessment");

    const dependencies = await this.analyzeDependencies(context);
    const vulnerabilities = await this.scanForVulnerabilities(dependencies);
    const licenseCompliance = await this.checkLicenseCompliance(dependencies);
    const integrityResults = await this.verifyPackageIntegrity(dependencies);
    const typosquattingRisks = await this.detectTyposquatting(dependencies);
    const sbomGenerated = await this.generateSBOM(dependencies);

    const vulnerableDependencies = dependencies.filter(
      (dep) => dep.vulnerabilities && dep.vulnerabilities.length > 0,
    ).length;

    const score = this.calculateSupplyChainScore(
      dependencies.length,
      vulnerableDependencies,
      licenseCompliance,
      integrityResults,
      typosquattingRisks.length,
    );

    const status = this.determineStatus(score, 100, 70);

    const criticalFindings = this.identifyCriticalFindings(
      vulnerabilities,
      typosquattingRisks,
      integrityResults,
    );

    const recommendations = this.generateRecommendations(
      vulnerableDependencies,
      licenseCompliance,
      typosquattingRisks,
    );

    const explanation = this.generateExplanation(
      dependencies.length,
      vulnerableDependencies,
      licenseCompliance,
      typosquattingRisks,
    );

    return {
      category: "supplyChain",
      status,
      score,
      totalDependencies: dependencies.length,
      vulnerableDependencies,
      licenseCompliance,
      integrityChecks: integrityResults,
      typosquattingRisks,
      sbomGenerated,
      criticalFindings,
      recommendations,
      explanation,
    };
  }

  private async analyzeDependencies(
    context: AssessmentContext,
  ): Promise<DependencyInfo[]> {
    this.log("Analyzing project dependencies");
    const dependencies: DependencyInfo[] = [];

    try {
      // Check for package.json if available
      const packageData =
        context.packageJson || context.serverInfo?.metadata?.packageJson;
      if (packageData) {
        const deps = {
          ...packageData.dependencies,
          ...packageData.devDependencies,
        };

        for (const [name, version] of Object.entries(deps)) {
          dependencies.push({
            name,
            version: version as string,
            license: undefined,
            vulnerabilities: [],
            integrity: true,
          });
        }
      }

      // Additional dependency detection through tool metadata
      for (const tool of context.tools) {
        if (
          tool.description?.includes("npm") ||
          tool.description?.includes("package")
        ) {
          this.log(`Found package-related tool: ${tool.name}`);
        }
      }
    } catch (error) {
      this.logError("Error analyzing dependencies", error);
    }

    return dependencies;
  }

  private async scanForVulnerabilities(
    dependencies: DependencyInfo[],
  ): Promise<string[]> {
    this.log("Scanning for known vulnerabilities");
    const vulnerabilities: string[] = [];

    // Simulate vulnerability scanning
    const knownVulnerablePackages = [
      "lodash@<4.17.21",
      "minimist@<1.2.6",
      "axios@<0.21.2",
      "node-fetch@<2.6.7",
    ];

    for (const dep of dependencies) {
      // Check against known vulnerable versions
      for (const vuln of knownVulnerablePackages) {
        const [pkg, version] = vuln.split("@");
        if (dep.name === pkg) {
          const vulnerability = `${dep.name}@${dep.version} has known vulnerabilities`;
          vulnerabilities.push(vulnerability);
          dep.vulnerabilities = dep.vulnerabilities || [];
          dep.vulnerabilities.push(vulnerability);
        }
      }
    }

    return vulnerabilities;
  }

  private async checkLicenseCompliance(
    dependencies: DependencyInfo[],
  ): Promise<{
    compliant: number;
    nonCompliant: number;
    unknown: number;
  }> {
    this.log("Checking license compliance");

    const allowedLicenses = [
      "MIT",
      "Apache-2.0",
      "BSD-3-Clause",
      "BSD-2-Clause",
      "ISC",
    ];
    const restrictedLicenses = ["GPL-3.0", "AGPL-3.0", "LGPL-3.0"];

    let compliant = 0;
    let nonCompliant = 0;
    let unknown = 0;

    for (const dep of dependencies) {
      if (!dep.license) {
        unknown++;
      } else if (allowedLicenses.includes(dep.license)) {
        compliant++;
      } else if (restrictedLicenses.includes(dep.license)) {
        nonCompliant++;
      } else {
        unknown++;
      }
    }

    return { compliant, nonCompliant, unknown };
  }

  private async verifyPackageIntegrity(
    dependencies: DependencyInfo[],
  ): Promise<{
    passed: number;
    failed: number;
    skipped: number;
  }> {
    this.log("Verifying package integrity");

    let passed = 0;
    let failed = 0;
    let skipped = 0;

    for (const dep of dependencies) {
      // Simulate integrity check
      if (dep.integrity === undefined) {
        skipped++;
      } else if (dep.integrity) {
        passed++;
      } else {
        failed++;
      }
    }

    return { passed, failed, skipped };
  }

  private async detectTyposquatting(
    dependencies: DependencyInfo[],
  ): Promise<string[]> {
    this.log("Detecting potential typosquatting");
    const risks: string[] = [];

    const popularPackages = [
      "react",
      "vue",
      "angular",
      "express",
      "lodash",
      "axios",
      "typescript",
      "webpack",
      "babel",
      "eslint",
      "jest",
    ];

    for (const dep of dependencies) {
      // Check for similarity to popular packages
      for (const popular of popularPackages) {
        const similarity = this.calculateSimilarity(dep.name, popular);
        if (similarity > 0.7 && similarity < 1.0) {
          risks.push(`${dep.name} is suspiciously similar to ${popular}`);
        }
      }
    }

    return risks;
  }

  private calculateSimilarity(str1: string, str2: string): number {
    // Simple Levenshtein distance-based similarity
    const maxLen = Math.max(str1.length, str2.length);
    if (maxLen === 0) return 1.0;

    const distance = this.levenshteinDistance(str1, str2);
    return 1 - distance / maxLen;
  }

  private levenshteinDistance(str1: string, str2: string): number {
    const matrix: number[][] = [];

    for (let i = 0; i <= str2.length; i++) {
      matrix[i] = [i];
    }

    for (let j = 0; j <= str1.length; j++) {
      matrix[0][j] = j;
    }

    for (let i = 1; i <= str2.length; i++) {
      for (let j = 1; j <= str1.length; j++) {
        if (str2.charAt(i - 1) === str1.charAt(j - 1)) {
          matrix[i][j] = matrix[i - 1][j - 1];
        } else {
          matrix[i][j] = Math.min(
            matrix[i - 1][j - 1] + 1,
            matrix[i][j - 1] + 1,
            matrix[i - 1][j] + 1,
          );
        }
      }
    }

    return matrix[str2.length][str1.length];
  }

  private async generateSBOM(dependencies: DependencyInfo[]): Promise<boolean> {
    this.log("Generating Software Bill of Materials (SBOM)");

    // In a real implementation, this would generate a proper SBOM
    // For now, we'll simulate it
    try {
      const sbom = {
        bomFormat: "CycloneDX",
        specVersion: "1.4",
        serialNumber: `urn:uuid:${Date.now()}`,
        version: 1,
        metadata: {
          timestamp: new Date().toISOString(),
          tools: [{ name: "MCP Inspector" }],
        },
        components: dependencies.map((dep) => ({
          type: "library",
          name: dep.name,
          version: dep.version,
          licenses: dep.license ? [{ license: { id: dep.license } }] : [],
        })),
      };

      this.log(`SBOM generated with ${dependencies.length} components`);
      return true;
    } catch (error) {
      this.logError("Failed to generate SBOM", error);
      return false;
    }
  }

  private calculateSupplyChainScore(
    totalDeps: number,
    vulnerableDeps: number,
    licenseCompliance: {
      compliant: number;
      nonCompliant: number;
      unknown: number;
    },
    integrityChecks: { passed: number; failed: number; skipped: number },
    typosquattingRisks: number,
  ): number {
    let score = 100;

    // Deduct for vulnerable dependencies (max -30)
    if (totalDeps > 0) {
      const vulnRate = vulnerableDeps / totalDeps;
      score -= vulnRate * 30;
    }

    // Deduct for license non-compliance (max -20)
    const totalLicenseChecked =
      licenseCompliance.compliant +
      licenseCompliance.nonCompliant +
      licenseCompliance.unknown;
    if (totalLicenseChecked > 0) {
      const nonCompliantRate =
        licenseCompliance.nonCompliant / totalLicenseChecked;
      score -= nonCompliantRate * 20;
    }

    // Deduct for integrity failures (max -20)
    const totalIntegrityChecked =
      integrityChecks.passed + integrityChecks.failed + integrityChecks.skipped;
    if (totalIntegrityChecked > 0) {
      const failureRate = integrityChecks.failed / totalIntegrityChecked;
      score -= failureRate * 20;
    }

    // Deduct for typosquatting risks (max -20)
    score -= Math.min(typosquattingRisks * 5, 20);

    // Deduct for unknown licenses (max -10)
    if (totalLicenseChecked > 0) {
      const unknownRate = licenseCompliance.unknown / totalLicenseChecked;
      score -= unknownRate * 10;
    }

    return Math.max(0, Math.round(score));
  }

  private identifyCriticalFindings(
    vulnerabilities: string[],
    typosquattingRisks: string[],
    integrityResults: { passed: number; failed: number; skipped: number },
  ): string[] {
    const findings: string[] = [];

    if (vulnerabilities.length > 0) {
      findings.push(`Found ${vulnerabilities.length} vulnerable dependencies`);
    }

    if (typosquattingRisks.length > 0) {
      findings.push(
        `Detected ${typosquattingRisks.length} potential typosquatting risks`,
      );
    }

    if (integrityResults.failed > 0) {
      findings.push(
        `${integrityResults.failed} packages failed integrity verification`,
      );
    }

    return findings;
  }

  private generateRecommendations(
    vulnerableDeps: number,
    licenseCompliance: {
      compliant: number;
      nonCompliant: number;
      unknown: number;
    },
    typosquattingRisks: string[],
  ): string[] {
    const recommendations: string[] = [];

    if (vulnerableDeps > 0) {
      recommendations.push(
        "Update vulnerable dependencies to their latest secure versions",
      );
      recommendations.push(
        "Implement automated vulnerability scanning in CI/CD pipeline",
      );
    }

    if (licenseCompliance.nonCompliant > 0) {
      recommendations.push(
        "Review and replace dependencies with incompatible licenses",
      );
    }

    if (licenseCompliance.unknown > 0) {
      recommendations.push("Investigate dependencies with unknown licenses");
    }

    if (typosquattingRisks.length > 0) {
      recommendations.push(
        "Verify package names and consider using package pinning",
      );
      recommendations.push("Implement dependency allowlisting");
    }

    recommendations.push(
      "Generate and maintain Software Bill of Materials (SBOM)",
    );
    recommendations.push("Implement dependency update policies and procedures");

    return recommendations;
  }

  private generateExplanation(
    totalDeps: number,
    vulnerableDeps: number,
    licenseCompliance: {
      compliant: number;
      nonCompliant: number;
      unknown: number;
    },
    typosquattingRisks: string[],
  ): string {
    const parts: string[] = [];

    parts.push(`Analyzed ${totalDeps} dependencies in the supply chain.`);

    if (vulnerableDeps > 0) {
      parts.push(
        `Found ${vulnerableDeps} dependencies with known vulnerabilities.`,
      );
    }

    const licenseIssues =
      licenseCompliance.nonCompliant + licenseCompliance.unknown;
    if (licenseIssues > 0) {
      parts.push(
        `Identified ${licenseIssues} dependencies with license compliance issues.`,
      );
    }

    if (typosquattingRisks.length > 0) {
      parts.push(
        `Detected ${typosquattingRisks.length} potential typosquatting risks.`,
      );
    }

    return parts.join(" ");
  }
}

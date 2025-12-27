/**
 * Assessment Differ
 * Compares two assessment runs to detect regressions or improvements.
 *
 * Use Cases:
 * - Compare bundle v1.0 vs v1.1
 * - Track assessment changes over time
 * - CI/CD regression detection
 */

import type {
  MCPDirectoryAssessment,
  AssessmentStatus,
} from "./assessmentTypes";

/**
 * Change direction for a metric
 */
export type ChangeDirection = "improved" | "regressed" | "unchanged";

/**
 * Detailed change information for a single module
 */
export interface ModuleChange {
  module: string;
  baselineStatus: AssessmentStatus;
  currentStatus: AssessmentStatus;
  baselineScore?: number;
  currentScore?: number;
  change: ChangeDirection;
  details: string;
}

/**
 * Security-specific delta tracking
 */
export interface SecurityDelta {
  newVulnerabilities: string[];
  fixedVulnerabilities: string[];
  netChange: number;
  baselineCount: number;
  currentCount: number;
}

/**
 * Functionality-specific delta tracking
 */
export interface FunctionalityDelta {
  newBrokenTools: string[];
  fixedTools: string[];
  netChange: number;
  baselineWorking: number;
  currentWorking: number;
}

/**
 * Full assessment comparison result
 */
export interface AssessmentDiff {
  serverName: string;
  baseline: {
    version?: string;
    date: string;
    assessorVersion: string;
  };
  current: {
    version?: string;
    date: string;
    assessorVersion: string;
  };
  summary: {
    overallChange: ChangeDirection;
    baselineStatus: AssessmentStatus;
    currentStatus: AssessmentStatus;
    modulesImproved: number;
    modulesRegressed: number;
    modulesUnchanged: number;
  };
  moduleChanges: ModuleChange[];
  securityDelta: SecurityDelta;
  functionalityDelta: FunctionalityDelta;
  recommendations: string[];
}

/**
 * Compare two assessment runs
 */
export function compareAssessments(
  baseline: MCPDirectoryAssessment,
  current: MCPDirectoryAssessment,
): AssessmentDiff {
  const moduleChanges = compareModules(baseline, current);
  const securityDelta = compareSecurityResults(baseline, current);
  const functionalityDelta = compareFunctionalityResults(baseline, current);

  const improved = moduleChanges.filter((m) => m.change === "improved").length;
  const regressed = moduleChanges.filter(
    (m) => m.change === "regressed",
  ).length;
  const unchanged = moduleChanges.filter(
    (m) => m.change === "unchanged",
  ).length;

  // Determine overall change
  let overallChange: ChangeDirection = "unchanged";
  if (
    regressed > 0 ||
    securityDelta.netChange > 0 ||
    functionalityDelta.netChange < 0
  ) {
    overallChange = "regressed";
  } else if (
    improved > 0 ||
    securityDelta.netChange < 0 ||
    functionalityDelta.netChange > 0
  ) {
    overallChange = "improved";
  }

  const recommendations = generateDiffRecommendations(
    moduleChanges,
    securityDelta,
    functionalityDelta,
  );

  return {
    serverName: current.serverName,
    baseline: {
      version: extractVersion(baseline),
      date: baseline.assessmentDate,
      assessorVersion: baseline.assessorVersion,
    },
    current: {
      version: extractVersion(current),
      date: current.assessmentDate,
      assessorVersion: current.assessorVersion,
    },
    summary: {
      overallChange,
      baselineStatus: baseline.overallStatus,
      currentStatus: current.overallStatus,
      modulesImproved: improved,
      modulesRegressed: regressed,
      modulesUnchanged: unchanged,
    },
    moduleChanges,
    securityDelta,
    functionalityDelta,
    recommendations,
  };
}

/**
 * Compare individual module results
 */
function compareModules(
  baseline: MCPDirectoryAssessment,
  current: MCPDirectoryAssessment,
): ModuleChange[] {
  const changes: ModuleChange[] = [];

  // Compare core modules
  const modules: Array<{
    name: string;
    getStatus: (a: MCPDirectoryAssessment) => AssessmentStatus | undefined;
    getScore?: (a: MCPDirectoryAssessment) => number | undefined;
  }> = [
    {
      name: "functionality",
      getStatus: (a) => a.functionality?.status,
      getScore: (a) =>
        a.functionality
          ? (a.functionality.workingTools / a.functionality.totalTools) * 100
          : undefined,
    },
    {
      name: "security",
      getStatus: (a) => a.security?.status,
      getScore: (a) =>
        a.security
          ? 100 -
            (a.security.vulnerabilities.length /
              Math.max(a.security.promptInjectionTests.length, 1)) *
              100
          : undefined,
    },
    {
      name: "documentation",
      getStatus: (a) => a.documentation?.status,
    },
    {
      name: "errorHandling",
      getStatus: (a) => a.errorHandling?.status,
      getScore: (a) => a.errorHandling?.metrics?.mcpComplianceScore,
    },
    {
      name: "usability",
      getStatus: (a) => a.usability?.status,
    },
    {
      name: "mcpSpecCompliance",
      getStatus: (a) => a.mcpSpecCompliance?.status,
      getScore: (a) => a.mcpSpecCompliance?.complianceScore,
    },
    {
      name: "aupCompliance",
      getStatus: (a) => a.aupCompliance?.status,
    },
    {
      name: "toolAnnotations",
      getStatus: (a) => a.toolAnnotations?.status,
    },
    {
      name: "manifestValidation",
      getStatus: (a) => a.manifestValidation?.status,
    },
    {
      name: "portability",
      getStatus: (a) => a.portability?.status,
    },
  ];

  for (const mod of modules) {
    const baselineStatus = mod.getStatus(baseline);
    const currentStatus = mod.getStatus(current);

    // Skip if module wasn't run in either assessment
    if (!baselineStatus && !currentStatus) continue;

    const baselineScore = mod.getScore?.(baseline);
    const currentScore = mod.getScore?.(current);

    const change = determineChange(
      baselineStatus || "NEED_MORE_INFO",
      currentStatus || "NEED_MORE_INFO",
      baselineScore,
      currentScore,
    );

    changes.push({
      module: mod.name,
      baselineStatus: baselineStatus || "NEED_MORE_INFO",
      currentStatus: currentStatus || "NEED_MORE_INFO",
      baselineScore,
      currentScore,
      change,
      details: generateModuleDetails(
        mod.name,
        baselineStatus,
        currentStatus,
        baselineScore,
        currentScore,
      ),
    });
  }

  return changes;
}

/**
 * Determine if a module improved, regressed, or stayed the same
 */
function determineChange(
  baselineStatus: AssessmentStatus,
  currentStatus: AssessmentStatus,
  baselineScore?: number,
  currentScore?: number,
): ChangeDirection {
  // Status-based change
  const statusOrder: Record<AssessmentStatus, number> = {
    FAIL: 0,
    NEED_MORE_INFO: 1,
    PASS: 2,
  };

  const baselineRank = statusOrder[baselineStatus];
  const currentRank = statusOrder[currentStatus];

  if (currentRank > baselineRank) return "improved";
  if (currentRank < baselineRank) return "regressed";

  // Score-based change (if statuses are equal)
  if (baselineScore !== undefined && currentScore !== undefined) {
    const scoreDiff = currentScore - baselineScore;
    if (scoreDiff > 5) return "improved"; // 5% threshold
    if (scoreDiff < -5) return "regressed";
  }

  return "unchanged";
}

/**
 * Generate human-readable details for a module change
 */
function generateModuleDetails(
  _moduleName: string,
  baselineStatus?: AssessmentStatus,
  currentStatus?: AssessmentStatus,
  baselineScore?: number,
  currentScore?: number,
): string {
  const parts: string[] = [];

  if (baselineStatus !== currentStatus) {
    parts.push(`${baselineStatus || "N/A"} → ${currentStatus || "N/A"}`);
  }

  if (baselineScore !== undefined && currentScore !== undefined) {
    const diff = currentScore - baselineScore;
    const sign = diff > 0 ? "+" : "";
    parts.push(
      `Score: ${baselineScore.toFixed(1)}% → ${currentScore.toFixed(1)}% (${sign}${diff.toFixed(1)}%)`,
    );
  }

  if (parts.length === 0) {
    return "No change";
  }

  return parts.join(", ");
}

/**
 * Compare security results between assessments
 */
function compareSecurityResults(
  baseline: MCPDirectoryAssessment,
  current: MCPDirectoryAssessment,
): SecurityDelta {
  const baselineVulns = new Set(baseline.security?.vulnerabilities || []);
  const currentVulns = new Set(current.security?.vulnerabilities || []);

  const newVulnerabilities: string[] = [];
  const fixedVulnerabilities: string[] = [];

  for (const vuln of currentVulns) {
    if (!baselineVulns.has(vuln)) {
      newVulnerabilities.push(vuln);
    }
  }

  for (const vuln of baselineVulns) {
    if (!currentVulns.has(vuln)) {
      fixedVulnerabilities.push(vuln);
    }
  }

  return {
    newVulnerabilities,
    fixedVulnerabilities,
    netChange: newVulnerabilities.length - fixedVulnerabilities.length,
    baselineCount: baselineVulns.size,
    currentCount: currentVulns.size,
  };
}

/**
 * Compare functionality results between assessments
 */
function compareFunctionalityResults(
  baseline: MCPDirectoryAssessment,
  current: MCPDirectoryAssessment,
): FunctionalityDelta {
  const baselineBroken = new Set(baseline.functionality?.brokenTools || []);
  const currentBroken = new Set(current.functionality?.brokenTools || []);

  const newBrokenTools: string[] = [];
  const fixedTools: string[] = [];

  for (const tool of currentBroken) {
    if (!baselineBroken.has(tool)) {
      newBrokenTools.push(tool);
    }
  }

  for (const tool of baselineBroken) {
    if (!currentBroken.has(tool)) {
      fixedTools.push(tool);
    }
  }

  const baselineWorking = baseline.functionality?.workingTools || 0;
  const currentWorking = current.functionality?.workingTools || 0;

  return {
    newBrokenTools,
    fixedTools,
    netChange: currentWorking - baselineWorking,
    baselineWorking,
    currentWorking,
  };
}

/**
 * Generate recommendations based on the diff
 */
function generateDiffRecommendations(
  moduleChanges: ModuleChange[],
  securityDelta: SecurityDelta,
  functionalityDelta: FunctionalityDelta,
): string[] {
  const recommendations: string[] = [];

  // Security regressions are critical
  if (securityDelta.newVulnerabilities.length > 0) {
    recommendations.push(
      `CRITICAL: ${securityDelta.newVulnerabilities.length} new security vulnerabilities detected`,
    );
    for (const vuln of securityDelta.newVulnerabilities.slice(0, 3)) {
      recommendations.push(`  - ${vuln}`);
    }
  }

  // Functionality regressions
  if (functionalityDelta.newBrokenTools.length > 0) {
    recommendations.push(
      `WARNING: ${functionalityDelta.newBrokenTools.length} tool(s) now broken`,
    );
    for (const tool of functionalityDelta.newBrokenTools.slice(0, 3)) {
      recommendations.push(`  - ${tool}`);
    }
  }

  // Module regressions
  const regressions = moduleChanges.filter((m) => m.change === "regressed");
  if (regressions.length > 0) {
    recommendations.push(`WARNING: ${regressions.length} module(s) regressed`);
    for (const reg of regressions) {
      recommendations.push(`  - ${reg.module}: ${reg.details}`);
    }
  }

  // Positive changes
  if (securityDelta.fixedVulnerabilities.length > 0) {
    recommendations.push(
      `IMPROVED: ${securityDelta.fixedVulnerabilities.length} vulnerabilities fixed`,
    );
  }

  if (functionalityDelta.fixedTools.length > 0) {
    recommendations.push(
      `IMPROVED: ${functionalityDelta.fixedTools.length} tool(s) now working`,
    );
  }

  const improvements = moduleChanges.filter((m) => m.change === "improved");
  if (improvements.length > 0) {
    recommendations.push(`IMPROVED: ${improvements.length} module(s) improved`);
  }

  if (recommendations.length === 0) {
    recommendations.push("No significant changes detected between versions");
  }

  return recommendations;
}

/**
 * Extract version from assessment (if available from manifest)
 */
function extractVersion(
  assessment: MCPDirectoryAssessment,
): string | undefined {
  // Try to get version from manifest validation
  if (assessment.manifestValidation?.manifestVersion) {
    return assessment.manifestValidation.manifestVersion;
  }
  return undefined;
}

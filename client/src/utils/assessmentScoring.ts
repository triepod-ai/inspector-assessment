import { MCPDirectoryAssessment } from "../lib/assessmentTypes";

export interface CategoryScore {
  score: number;
  maxScore: number;
  percentage: number;
}

export interface AssessmentScores {
  functionality: CategoryScore;
  security: CategoryScore;
  documentation: CategoryScore;
  errorHandling: CategoryScore;
  usability: CategoryScore;
  total: number;
  classification: "PASS" | "REVIEW" | "FAIL";
}

export function calculateAssessmentScores(
  assessment: MCPDirectoryAssessment,
): AssessmentScores {
  // Functionality scoring (max 25 points)
  const functionalityScore = Math.round(
    (assessment.functionality.workingTools /
      Math.max(assessment.functionality.totalTools, 1)) *
      25,
  );

  // Security scoring (max 25 points)
  // If no tests were run, give 0 points (not 25)
  const securityTestsRun =
    assessment.security.promptInjectionTests?.length || 0;
  const securityVulnerabilities =
    assessment.security.vulnerabilities?.length || 0;
  const securityScore =
    securityTestsRun === 0 ? 0 : Math.max(0, 25 - securityVulnerabilities * 5);

  // Documentation scoring (max 20 points)
  const hasReadme = assessment.documentation.metrics.hasReadme ? 10 : 0;
  const hasExamples = assessment.documentation.metrics.exampleCount > 0 ? 5 : 0;
  const hasInstallation = assessment.documentation.metrics
    .hasInstallInstructions
    ? 5
    : 0;
  const documentationScore = hasReadme + hasExamples + hasInstallation;

  // Error Handling scoring (max 15 points)
  // Use actual mcpComplianceScore from metrics instead of binary status (Issue #28)
  const errorTestsRun =
    assessment.errorHandling.metrics.validationCoverage?.totalTests || 0;
  const mcpComplianceScore =
    assessment.errorHandling.metrics.mcpComplianceScore ?? 100;
  const errorHandlingScore =
    errorTestsRun === 0 ? 0 : Math.round((mcpComplianceScore / 100) * 15);

  // Usability scoring (max 15 points)
  let usabilityScore = 15;
  if (assessment.usability.metrics) {
    const overallScore =
      assessment.usability.metrics.detailedAnalysis?.overallScore || 100;
    usabilityScore = Math.round((overallScore / 100) * 15);
  }

  // Calculate total score
  const totalScore =
    functionalityScore +
    securityScore +
    documentationScore +
    errorHandlingScore +
    usabilityScore;

  // Determine classification
  let classification: "PASS" | "REVIEW" | "FAIL";
  if (totalScore >= 75) {
    classification = "PASS";
  } else if (totalScore >= 50) {
    classification = "REVIEW";
  } else {
    classification = "FAIL";
  }

  return {
    functionality: {
      score: functionalityScore,
      maxScore: 25,
      percentage: (functionalityScore / 25) * 100,
    },
    security: {
      score: securityScore,
      maxScore: 25,
      percentage: (securityScore / 25) * 100,
    },
    documentation: {
      score: documentationScore,
      maxScore: 20,
      percentage: (documentationScore / 20) * 100,
    },
    errorHandling: {
      score: errorHandlingScore,
      maxScore: 15,
      percentage: (errorHandlingScore / 15) * 100,
    },
    usability: {
      score: usabilityScore,
      maxScore: 15,
      percentage: (usabilityScore / 15) * 100,
    },
    total: totalScore,
    classification,
  };
}

export function extractCategoryIssues(category: unknown): string[] {
  const issues: string[] = [];

  // Type guard for category object
  if (typeof category !== "object" || category === null) {
    return issues;
  }

  const cat = category as Record<string, unknown>;

  // Extract from different category types
  if (cat.vulnerabilities && Array.isArray(cat.vulnerabilities)) {
    issues.push(...cat.vulnerabilities);
  }

  if (cat.brokenTools && Array.isArray(cat.brokenTools)) {
    cat.brokenTools.forEach((tool) => {
      if (typeof tool === "string") {
        issues.push(`Tool '${tool}' is not working`);
      }
    });
  }

  if (cat.missingElements && Array.isArray(cat.missingElements)) {
    issues.push(...cat.missingElements);
  }

  if (cat.issues && Array.isArray(cat.issues)) {
    issues.push(...cat.issues);
  }

  if (cat.explanation && issues.length === 0) {
    // Use explanation as a fallback if no specific issues
    if (cat.status === "FAIL" || cat.status === "NEED_MORE_INFO") {
      if (typeof cat.explanation === "string") {
        issues.push(cat.explanation);
      }
    }
  }

  return issues;
}

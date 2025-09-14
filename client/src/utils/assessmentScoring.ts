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
  const securityVulnerabilities =
    assessment.security.vulnerabilities?.length || 0;
  const securityScore = Math.max(0, 25 - securityVulnerabilities * 5);

  // Documentation scoring (max 20 points)
  const hasReadme = assessment.documentation.metrics.hasReadme ? 10 : 0;
  const hasExamples = assessment.documentation.metrics.exampleCount > 0 ? 5 : 0;
  const hasInstallation = assessment.documentation.metrics
    .hasInstallInstructions
    ? 5
    : 0;
  const documentationScore = hasReadme + hasExamples + hasInstallation;

  // Error Handling scoring (max 15 points)
  const errorHandlingScore =
    assessment.errorHandling.status === "PASS"
      ? 15
      : assessment.errorHandling.status === "NEED_MORE_INFO"
        ? 10
        : 5;

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

export function extractCategoryIssues(category: any): string[] {
  const issues: string[] = [];

  // Extract from different category types
  if (category.vulnerabilities && Array.isArray(category.vulnerabilities)) {
    issues.push(...category.vulnerabilities);
  }

  if (category.brokenTools && Array.isArray(category.brokenTools)) {
    category.brokenTools.forEach((tool: string) => {
      issues.push(`Tool '${tool}' is not working`);
    });
  }

  if (category.missingElements && Array.isArray(category.missingElements)) {
    issues.push(...category.missingElements);
  }

  if (category.issues && Array.isArray(category.issues)) {
    issues.push(...category.issues);
  }

  if (category.explanation && issues.length === 0) {
    // Use explanation as a fallback if no specific issues
    if (category.status === "FAIL" || category.status === "NEED_MORE_INFO") {
      issues.push(category.explanation);
    }
  }

  return issues;
}

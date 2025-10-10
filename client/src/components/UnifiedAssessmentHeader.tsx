import React, { useState } from "react";
import { MCPDirectoryAssessment } from "../lib/assessmentTypes";
import {
  Check,
  X,
  ChevronDown,
  ChevronUp,
  AlertCircle,
  CheckCircle,
  XCircle,
  FileText,
} from "lucide-react";
import { Button } from "./ui/button";
import {
  calculateAssessmentScores,
  extractCategoryIssues,
} from "../utils/assessmentScoring";

interface UnifiedAssessmentHeaderProps {
  assessment: MCPDirectoryAssessment | null;
  isLoading: boolean;
  onExportReport?: () => void;
}

interface CategoryScore {
  name: string;
  displayName: string;
  score: number;
  maxScore: number;
  passed: boolean;
  issues: string[];
  category:
    | "functionality"
    | "security"
    | "documentation"
    | "errorHandling"
    | "usability";
}

export const UnifiedAssessmentHeader: React.FC<
  UnifiedAssessmentHeaderProps
> = ({ assessment, isLoading, onExportReport }) => {
  const [isExpanded, setIsExpanded] = useState(true);
  const [expandedIssues, setExpandedIssues] = useState<Set<string>>(new Set());

  if (isLoading) {
    return (
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 p-6 mb-6">
        <div className="animate-pulse">
          <div className="h-6 bg-gray-200 dark:bg-gray-700 rounded w-1/3 mb-3"></div>
          <div className="h-4 bg-gray-200 dark:bg-gray-700 rounded w-1/2"></div>
        </div>
      </div>
    );
  }

  if (!assessment) {
    return null;
  }

  const scores = calculateAssessmentScores(assessment);
  const totalScore = scores.total;
  const isReady = totalScore >= 75;
  const classification = scores.classification;

  // Define passing thresholds for each category
  const passingThresholds = {
    functionality: 15,
    security: 15,
    documentation: 12,
    errorHandling: 10,
    usability: 10,
  };

  const categoryScores: CategoryScore[] = [
    {
      name: "functionality",
      displayName: "Functionality",
      score: scores.functionality.score,
      maxScore: scores.functionality.maxScore,
      passed: scores.functionality.score >= passingThresholds.functionality,
      category: "functionality",
      issues: extractCategoryIssues(assessment.functionality),
    },
    {
      name: "security",
      displayName: "Security",
      score: scores.security.score,
      maxScore: scores.security.maxScore,
      passed: scores.security.score >= passingThresholds.security,
      category: "security",
      issues: extractCategoryIssues(assessment.security),
    },
    {
      name: "documentation",
      displayName: "Documentation",
      score: scores.documentation.score,
      maxScore: scores.documentation.maxScore,
      passed: scores.documentation.score >= passingThresholds.documentation,
      category: "documentation",
      issues: extractCategoryIssues(assessment.documentation),
    },
    {
      name: "errorHandling",
      displayName: "Error Handling",
      score: scores.errorHandling.score,
      maxScore: scores.errorHandling.maxScore,
      passed: scores.errorHandling.score >= passingThresholds.errorHandling,
      category: "errorHandling",
      issues: extractCategoryIssues(assessment.errorHandling),
    },
    {
      name: "usability",
      displayName: "Usability",
      score: scores.usability.score,
      maxScore: scores.usability.maxScore,
      passed: scores.usability.score >= passingThresholds.usability,
      category: "usability",
      issues: extractCategoryIssues(assessment.usability),
    },
  ];

  const passedCount = categoryScores.filter((c) => c.passed).length;
  const failedCount = categoryScores.filter((c) => !c.passed).length;

  const scrollToSection = (category: string) => {
    const sectionId = `${category}-section`;
    const element = document.getElementById(sectionId);
    if (element) {
      element.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  };

  const toggleIssues = (categoryName: string) => {
    const newExpanded = new Set(expandedIssues);
    if (newExpanded.has(categoryName)) {
      newExpanded.delete(categoryName);
    } else {
      newExpanded.add(categoryName);
    }
    setExpandedIssues(newExpanded);
  };

  const generateSubmissionReport = () => {
    const report = {
      serverName: assessment.serverName,
      score: totalScore,
      classification: classification,
      timestamp: new Date().toISOString(),
      categories: {
        functionality: `${scores.functionality.score}/${scores.functionality.maxScore}`,
        security: `${scores.security.score}/${scores.security.maxScore}`,
        documentation: `${scores.documentation.score}/${scores.documentation.maxScore}`,
        errorHandling: `${scores.errorHandling.score}/${scores.errorHandling.maxScore}`,
        usability: `${scores.usability.score}/${scores.usability.maxScore}`,
      },
      readyForSubmission: isReady,
      issuesRemaining: failedCount,
    };

    const reportText = `MCP Directory Submission Report
Generated: ${new Date().toLocaleString()}
${report.serverName ? `\nServer: ${report.serverName}` : ""}
Overall Score: ${report.score}/100 (${report.classification})
Status: ${report.readyForSubmission ? "✅ Ready for Submission" : "❌ Not Ready - Fix Issues First"}

Category Scores:
- Functionality: ${report.categories.functionality}
- Security: ${report.categories.security}
- Documentation: ${report.categories.documentation}
- Error Handling: ${report.categories.errorHandling}
- Usability: ${report.categories.usability}

${!report.readyForSubmission ? `Issues to Fix: ${report.issuesRemaining}` : "All requirements met!"}`;

    // Copy to clipboard
    navigator.clipboard.writeText(reportText);

    // Also download as file
    const blob = new Blob([reportText], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `mcp-submission-report-${Date.now()}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div
      className={`rounded-lg shadow-sm border-2 mb-6 ${
        isReady
          ? "bg-green-50 dark:bg-green-900/20 border-green-500"
          : failedCount > 0
            ? "bg-white dark:bg-gray-800 border-gray-300 dark:border-gray-600"
            : "bg-yellow-50 dark:bg-yellow-900/20 border-yellow-500"
      }`}
    >
      {/* Header - Always Visible */}
      <div className="p-4 border-b border-gray-200 dark:border-gray-700">
        <div className="flex items-start justify-between">
          <div className="flex-1">
            <div className="flex items-center gap-3 mb-2">
              {isReady ? (
                <CheckCircle className="w-7 h-7 text-green-600 dark:text-green-400" />
              ) : failedCount > 0 ? (
                <XCircle className="w-7 h-7 text-red-600 dark:text-red-400" />
              ) : (
                <AlertCircle className="w-7 h-7 text-yellow-600 dark:text-yellow-400" />
              )}
              <div>
                <h3 className="text-xl font-semibold text-gray-900 dark:text-gray-100">
                  MCP Directory Assessment
                </h3>
                <p className="text-sm text-gray-600 dark:text-gray-400">
                  {assessment.serverName} •{" "}
                  {new Date(assessment.assessmentDate).toLocaleDateString()}
                </p>
              </div>
            </div>

            {/* Overall Score - Prominent */}
            <div className="flex items-center gap-4 mb-3">
              <div>
                <span className="text-sm text-gray-600 dark:text-gray-400">
                  Overall Score:
                </span>
                <span
                  className={`ml-2 text-3xl font-bold ${
                    totalScore >= 75
                      ? "text-green-600 dark:text-green-400"
                      : totalScore >= 50
                        ? "text-yellow-600 dark:text-yellow-400"
                        : "text-red-600 dark:text-red-400"
                  }`}
                >
                  {totalScore}
                </span>
                <span className="text-gray-500 dark:text-gray-400 text-lg">
                  /100
                </span>
                <span
                  className={`ml-2 text-sm px-2 py-1 rounded font-medium ${
                    classification === "PASS"
                      ? "bg-green-200 dark:bg-green-800 text-green-800 dark:text-green-200"
                      : (classification as string) === "REVIEW" ||
                          (classification as string) === "NEED_MORE_INFO"
                        ? "bg-yellow-200 dark:bg-yellow-800 text-yellow-800 dark:text-yellow-200"
                        : "bg-red-200 dark:bg-red-800 text-red-800 dark:text-red-200"
                  }`}
                >
                  {classification}
                </span>
              </div>
            </div>

            {/* Status Message */}
            <p
              className={`text-sm font-medium ${
                isReady
                  ? "text-green-700 dark:text-green-300"
                  : "text-red-700 dark:text-red-300"
              }`}
            >
              {isReady
                ? "✅ Ready for MCP Directory Submission"
                : `❌ Not Ready - ${failedCount} ${failedCount === 1 ? "category needs" : "categories need"} attention`}
            </p>
          </div>

          {/* Action Buttons */}
          <div className="flex items-start gap-2">
            {onExportReport && (
              <Button
                onClick={onExportReport}
                variant="outline"
                size="sm"
                className="whitespace-nowrap"
              >
                <FileText className="w-4 h-4 mr-2" />
                Export Report
              </Button>
            )}
            <Button
              onClick={generateSubmissionReport}
              variant="outline"
              size="sm"
              className="whitespace-nowrap"
            >
              <FileText className="w-4 h-4 mr-2" />
              Generate Report
            </Button>
            <Button
              onClick={() => setIsExpanded(!isExpanded)}
              variant="ghost"
              size="sm"
            >
              {isExpanded ? (
                <ChevronUp className="w-4 h-4" />
              ) : (
                <ChevronDown className="w-4 h-4" />
              )}
            </Button>
          </div>
        </div>
      </div>

      {/* Expanded Details */}
      {isExpanded && (
        <div className="p-4 space-y-4">
          {/* Category Scores Grid */}
          <div>
            <h4 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-3">
              Category Scores ({passedCount}/5 passing)
            </h4>
            <div className="grid grid-cols-1 gap-2">
              {categoryScores.map((category) => (
                <div
                  key={category.name}
                  className="flex items-center justify-between p-2 rounded bg-gray-50 dark:bg-gray-900/50 hover:bg-gray-100 dark:hover:bg-gray-900 transition-colors"
                >
                  <div className="flex items-center gap-3 flex-1">
                    <div className="flex-shrink-0">
                      {category.passed ? (
                        <div className="w-5 h-5 bg-green-100 dark:bg-green-900/30 rounded flex items-center justify-center">
                          <Check className="w-3 h-3 text-green-600 dark:text-green-400" />
                        </div>
                      ) : (
                        <div className="w-5 h-5 bg-red-100 dark:bg-red-900/30 rounded flex items-center justify-center">
                          <X className="w-3 h-3 text-red-600 dark:text-red-400" />
                        </div>
                      )}
                    </div>
                    <button
                      onClick={() => scrollToSection(category.category)}
                      className="font-medium text-sm text-gray-900 dark:text-gray-100 hover:text-blue-600 dark:hover:text-blue-400 transition-colors text-left"
                    >
                      {category.displayName}
                    </button>
                    {category.issues.length > 0 && !category.passed && (
                      <button
                        onClick={() => toggleIssues(category.name)}
                        className="text-xs text-red-600 dark:text-red-400 hover:underline flex items-center gap-1"
                      >
                        {category.issues.length} issue
                        {category.issues.length !== 1 ? "s" : ""}
                        {expandedIssues.has(category.name) ? (
                          <ChevronUp className="w-3 h-3" />
                        ) : (
                          <ChevronDown className="w-3 h-3" />
                        )}
                      </button>
                    )}
                  </div>
                  <div className="flex items-center gap-2">
                    <div className="text-right">
                      <div
                        className={`text-base font-semibold ${
                          category.passed
                            ? "text-green-600 dark:text-green-400"
                            : "text-red-600 dark:text-red-400"
                        }`}
                      >
                        {category.score}/{category.maxScore}
                      </div>
                      {!category.passed && (
                        <div className="text-xs text-gray-500 dark:text-gray-400">
                          need{" "}
                          {
                            passingThresholds[
                              category.category as keyof typeof passingThresholds
                            ]
                          }
                          +
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>

            {/* Expanded Issues */}
            {Array.from(expandedIssues).map((categoryName) => {
              const category = categoryScores.find(
                (c) => c.name === categoryName,
              );
              if (!category || category.issues.length === 0) return null;

              return (
                <div
                  key={categoryName}
                  className="mt-2 ml-8 bg-red-50 dark:bg-red-900/10 rounded-lg p-3 space-y-2"
                >
                  {category.issues.map((issue, idx) => (
                    <div key={idx} className="flex items-start gap-2">
                      <AlertCircle className="w-4 h-4 text-red-500 mt-0.5 flex-shrink-0" />
                      <p className="text-sm text-gray-700 dark:text-gray-300">
                        {issue}
                      </p>
                    </div>
                  ))}
                </div>
              );
            })}
          </div>

          {/* Metadata */}
          <div className="border-t border-gray-200 dark:border-gray-700 pt-3">
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-sm">
              {assessment.serverName && (
                <div>
                  <span className="text-gray-600 dark:text-gray-400">
                    Server:
                  </span>
                  <div className="font-medium text-gray-900 dark:text-gray-100">
                    {assessment.serverName}
                  </div>
                </div>
              )}
              <div>
                <span className="text-gray-600 dark:text-gray-400">Date:</span>
                <div className="font-medium text-gray-900 dark:text-gray-100">
                  {new Date(assessment.assessmentDate).toLocaleString()}
                </div>
              </div>
              <div>
                <span className="text-gray-600 dark:text-gray-400">
                  Tests Run:
                </span>
                <div className="font-medium text-gray-900 dark:text-gray-100">
                  {assessment.totalTestsRun}
                </div>
              </div>
              <div>
                <span className="text-gray-600 dark:text-gray-400">Time:</span>
                <div className="font-medium text-gray-900 dark:text-gray-100">
                  {(assessment.executionTime / 1000).toFixed(2)}s
                </div>
              </div>
            </div>
          </div>

          {/* Success Message */}
          {isReady && (
            <div className="p-3 bg-green-100 dark:bg-green-900/30 rounded-lg">
              <p className="text-sm text-green-800 dark:text-green-200 flex items-center gap-2">
                <CheckCircle className="w-4 h-4" />
                All Anthropic MCP Directory requirements met. Click "Generate
                Report" to create your submission documentation.
              </p>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

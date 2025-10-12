import React, { useState } from "react";
import {
  MCPDirectoryAssessment,
  AssessmentStatus,
} from "../lib/assessmentTypes";
import {
  ChevronDown,
  ChevronUp,
  AlertCircle,
  CheckCircle,
  XCircle,
  FileText,
} from "lucide-react";
import { Button } from "./ui/button";
import { extractCategoryIssues } from "../utils/assessmentScoring";

interface UnifiedAssessmentHeaderProps {
  assessment: MCPDirectoryAssessment | null;
  isLoading: boolean;
  onExportReport?: () => void;
}

interface CategoryInfo {
  name: string;
  displayName: string;
  status: AssessmentStatus;
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

  // Build category information directly from assessment statuses
  const categories: CategoryInfo[] = [
    {
      name: "functionality",
      displayName: "Functionality",
      status: assessment.functionality.status,
      category: "functionality",
      issues: extractCategoryIssues(assessment.functionality),
    },
    {
      name: "security",
      displayName: "Security",
      status: assessment.security.status,
      category: "security",
      issues: extractCategoryIssues(assessment.security),
    },
    {
      name: "documentation",
      displayName: "Documentation",
      status: assessment.documentation.status,
      category: "documentation",
      issues: extractCategoryIssues(assessment.documentation),
    },
    {
      name: "errorHandling",
      displayName: "Error Handling",
      status: assessment.errorHandling.status,
      category: "errorHandling",
      issues: extractCategoryIssues(assessment.errorHandling),
    },
    {
      name: "usability",
      displayName: "Usability",
      status: assessment.usability.status,
      category: "usability",
      issues: extractCategoryIssues(assessment.usability),
    },
  ];

  // Count statuses
  const passedCount = categories.filter((c) => c.status === "PASS").length;
  const failedCount = categories.filter((c) => c.status === "FAIL").length;
  const needsReviewCount = categories.filter(
    (c) => c.status === "NEED_MORE_INFO",
  ).length;

  // Overall classification based on status counts
  const isReady = passedCount === 5; // All categories must pass
  const classification = isReady
    ? "PASS"
    : failedCount > 0
      ? "FAIL"
      : "NEEDS REVIEW";

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
    const getStatusLabel = (status: AssessmentStatus): string => {
      switch (status) {
        case "PASS":
          return "✓ PASS";
        case "FAIL":
          return "✗ FAIL";
        case "NEED_MORE_INFO":
          return "⚠ NEEDS REVIEW";
      }
    };

    const report = {
      serverName: assessment.serverName,
      classification: classification,
      timestamp: new Date().toISOString(),
      categoryCounts: {
        passed: passedCount,
        failed: failedCount,
        needsReview: needsReviewCount,
        total: 5,
      },
      categories: {
        functionality: getStatusLabel(assessment.functionality.status),
        security: getStatusLabel(assessment.security.status),
        documentation: getStatusLabel(assessment.documentation.status),
        errorHandling: getStatusLabel(assessment.errorHandling.status),
        usability: getStatusLabel(assessment.usability.status),
      },
      readyForSubmission: isReady,
    };

    const reportText = `MCP Directory Submission Report
Generated: ${new Date().toLocaleString()}
${report.serverName ? `\nServer: ${report.serverName}` : ""}
Overall Status: ${report.classification}
Categories: ${report.categoryCounts.passed}/${report.categoryCounts.total} passing${needsReviewCount > 0 ? `, ${needsReviewCount} need review` : ""}${failedCount > 0 ? `, ${failedCount} failing` : ""}
Status: ${report.readyForSubmission ? "✅ Ready for Submission" : "❌ Not Ready - Address Issues First"}

Category Status:
- Functionality: ${report.categories.functionality}
- Security: ${report.categories.security}
- Documentation: ${report.categories.documentation}
- Error Handling: ${report.categories.errorHandling}
- Usability: ${report.categories.usability}

${!report.readyForSubmission ? `Action Required: Review and fix failing/needs-review categories above.` : "All requirements met!"}`;

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

            {/* Overall Status - Prominent */}
            <div className="flex items-center gap-4 mb-3">
              <div>
                <span className="text-sm text-gray-600 dark:text-gray-400">
                  Assessment Status:
                </span>
                <span
                  className={`ml-2 text-xl font-bold ${
                    classification === "PASS"
                      ? "text-green-600 dark:text-green-400"
                      : classification === "FAIL"
                        ? "text-red-600 dark:text-red-400"
                        : "text-yellow-600 dark:text-yellow-400"
                  }`}
                >
                  {passedCount}/5 passing
                </span>
                {needsReviewCount > 0 && (
                  <span className="ml-2 text-sm text-yellow-600 dark:text-yellow-400">
                    • {needsReviewCount} need review
                  </span>
                )}
                {failedCount > 0 && (
                  <span className="ml-2 text-sm text-red-600 dark:text-red-400">
                    • {failedCount} failing
                  </span>
                )}
                <span
                  className={`ml-3 text-sm px-3 py-1 rounded-full font-medium ${
                    classification === "PASS"
                      ? "bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-200 border border-green-300 dark:border-green-700"
                      : classification === "FAIL"
                        ? "bg-red-100 dark:bg-red-900/30 text-red-800 dark:text-red-200 border border-red-300 dark:border-red-700"
                        : "bg-yellow-100 dark:bg-yellow-900/30 text-yellow-800 dark:text-yellow-200 border border-yellow-300 dark:border-yellow-700"
                  }`}
                >
                  {classification === "NEEDS REVIEW"
                    ? "NEEDS REVIEW"
                    : classification}
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
          {/* Category Status Grid */}
          <div>
            <h4 className="text-sm font-semibold text-gray-700 dark:text-gray-300 mb-3">
              Category Status ({passedCount}/5 passing)
            </h4>
            <div className="grid grid-cols-1 gap-2">
              {categories.map((category) => {
                const statusColors = {
                  PASS: {
                    bg: "bg-green-50 dark:bg-green-900/20",
                    border: "border-green-200 dark:border-green-800",
                    text: "text-green-800 dark:text-green-200",
                    icon: "text-green-600 dark:text-green-400",
                  },
                  FAIL: {
                    bg: "bg-red-50 dark:bg-red-900/20",
                    border: "border-red-200 dark:border-red-800",
                    text: "text-red-800 dark:text-red-200",
                    icon: "text-red-600 dark:text-red-400",
                  },
                  NEED_MORE_INFO: {
                    bg: "bg-yellow-50 dark:bg-yellow-900/20",
                    border: "border-yellow-200 dark:border-yellow-800",
                    text: "text-yellow-800 dark:text-yellow-200",
                    icon: "text-yellow-600 dark:text-yellow-400",
                  },
                };

                const colors = statusColors[category.status];

                return (
                  <div
                    key={category.name}
                    className={`flex items-center justify-between p-3 rounded border ${colors.bg} ${colors.border} hover:shadow-sm transition-all`}
                  >
                    <div className="flex items-center gap-3 flex-1">
                      <div className="flex-shrink-0">
                        {category.status === "PASS" ? (
                          <CheckCircle className={`w-5 h-5 ${colors.icon}`} />
                        ) : category.status === "FAIL" ? (
                          <XCircle className={`w-5 h-5 ${colors.icon}`} />
                        ) : (
                          <AlertCircle className={`w-5 h-5 ${colors.icon}`} />
                        )}
                      </div>
                      <button
                        onClick={() => scrollToSection(category.category)}
                        className={`font-medium text-sm hover:underline transition-colors text-left ${colors.text}`}
                      >
                        {category.displayName}
                      </button>
                      {category.issues.length > 0 &&
                        category.status !== "PASS" && (
                          <button
                            onClick={() => toggleIssues(category.name)}
                            className={`text-xs hover:underline flex items-center gap-1 ${colors.text}`}
                          >
                            {category.status === "NEED_MORE_INFO"
                              ? `${category.issues.length} need${category.issues.length === 1 ? "s" : ""} review`
                              : `${category.issues.length} issue${category.issues.length !== 1 ? "s" : ""}`}
                            {expandedIssues.has(category.name) ? (
                              <ChevronUp className="w-3 h-3" />
                            ) : (
                              <ChevronDown className="w-3 h-3" />
                            )}
                          </button>
                        )}
                    </div>
                    <div className="flex items-center gap-2">
                      <span
                        className={`text-xs font-semibold px-2 py-1 rounded ${colors.text}`}
                      >
                        {category.status === "NEED_MORE_INFO"
                          ? "NEEDS REVIEW"
                          : category.status}
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>

            {/* Expanded Issues */}
            {Array.from(expandedIssues).map((categoryName) => {
              const category = categories.find((c) => c.name === categoryName);
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

import React from "react";
import {
  MCPDirectoryAssessment,
  AssessmentStatus,
} from "../lib/assessmentTypes";
import { CheckCircle, XCircle, AlertCircle, FileText } from "lucide-react";

interface AssessmentSummaryProps {
  assessment: MCPDirectoryAssessment | null;
  isLoading: boolean;
}

export const AssessmentSummary: React.FC<AssessmentSummaryProps> = ({
  assessment,
  isLoading,
}) => {
  if (isLoading) {
    return (
      <div className="bg-gray-50 dark:bg-gray-800 rounded-lg p-6 mb-6">
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

  // Count statuses
  const statuses = [
    assessment.functionality.status,
    assessment.security.status,
    assessment.documentation.status,
    assessment.errorHandling.status,
    assessment.usability.status,
  ];

  const passedCount = statuses.filter((s) => s === "PASS").length;
  const failedCount = statuses.filter((s) => s === "FAIL").length;
  const needsReviewCount = statuses.filter(
    (s) => s === "NEED_MORE_INFO",
  ).length;

  const isReady = passedCount === 5;
  const classification = isReady
    ? "PASS"
    : failedCount > 0
      ? "FAIL"
      : "NEEDS REVIEW";

  // Count critical vs minor issues
  const criticalIssues = [
    assessment.functionality.status === "FAIL" ? 1 : 0,
    assessment.security.status === "FAIL" ? 1 : 0,
    assessment.errorHandling.status === "FAIL" ? 1 : 0,
  ].reduce((a, b) => a + b, 0);

  const minorIssues = [
    assessment.documentation.status !== "PASS" ? 1 : 0,
    assessment.usability.status !== "PASS" ? 1 : 0,
  ].reduce((a, b) => a + b, 0);

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

  const generateSubmissionReport = () => {
    const report = {
      serverName: assessment.serverName,
      classification: classification,
      timestamp: new Date().toISOString(),
      categoryCounts: {
        passed: passedCount,
        failed: failedCount,
        needsReview: needsReviewCount,
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
Categories: ${report.categoryCounts.passed}/5 passing${needsReviewCount > 0 ? `, ${needsReviewCount} need review` : ""}${failedCount > 0 ? `, ${failedCount} failing` : ""}
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
      className={`rounded-lg p-6 mb-6 border-2 ${
        isReady
          ? "bg-green-50 dark:bg-green-900/20 border-green-500"
          : criticalIssues > 0
            ? "bg-red-50 dark:bg-red-900/20 border-red-500"
            : "bg-yellow-50 dark:bg-yellow-900/20 border-yellow-500"
      }`}
    >
      <div className="flex items-start justify-between">
        <div className="flex-1">
          <div className="flex items-center gap-3 mb-3">
            {isReady ? (
              <CheckCircle className="w-8 h-8 text-green-600 dark:text-green-400" />
            ) : criticalIssues > 0 ? (
              <XCircle className="w-8 h-8 text-red-600 dark:text-red-400" />
            ) : (
              <AlertCircle className="w-8 h-8 text-yellow-600 dark:text-yellow-400" />
            )}
            <h2 className="text-xl font-bold text-gray-900 dark:text-gray-100">
              {isReady
                ? "Ready for MCP Directory Submission"
                : "Not Ready for Submission"}
            </h2>
          </div>

          <div className="grid grid-cols-2 gap-4 mb-4">
            <div>
              <span className="text-sm text-gray-600 dark:text-gray-400">
                Overall Status
              </span>
              <div className="text-2xl font-bold">
                <span
                  className={
                    classification === "PASS"
                      ? "text-green-600 dark:text-green-400"
                      : classification === "FAIL"
                        ? "text-red-600 dark:text-red-400"
                        : "text-yellow-600 dark:text-yellow-400"
                  }
                >
                  {passedCount}/5
                </span>
                <span className="text-gray-500 dark:text-gray-400 text-lg">
                  {" "}
                  passing
                </span>
                <span
                  className={`ml-2 text-sm px-2 py-1 rounded ${
                    classification === "PASS"
                      ? "bg-green-200 dark:bg-green-800 text-green-800 dark:text-green-200"
                      : classification === "FAIL"
                        ? "bg-red-200 dark:bg-red-800 text-red-800 dark:text-red-200"
                        : "bg-yellow-200 dark:bg-yellow-800 text-yellow-800 dark:text-yellow-200"
                  }`}
                >
                  {classification === "NEEDS REVIEW"
                    ? "NEEDS REVIEW"
                    : classification}
                </span>
              </div>
            </div>

            <div>
              <span className="text-sm text-gray-600 dark:text-gray-400">
                Issues to Fix
              </span>
              <div className="text-2xl font-bold">
                {criticalIssues > 0 && (
                  <span className="text-red-600 dark:text-red-400">
                    {criticalIssues} Critical
                  </span>
                )}
                {criticalIssues > 0 && minorIssues > 0 && (
                  <span className="text-gray-500 mx-1">•</span>
                )}
                {minorIssues > 0 && (
                  <span className="text-yellow-600 dark:text-yellow-400">
                    {minorIssues} Minor
                  </span>
                )}
                {criticalIssues === 0 && minorIssues === 0 && (
                  <span className="text-green-600 dark:text-green-400">
                    None!
                  </span>
                )}
              </div>
            </div>
          </div>

          {!isReady && (
            <div className="text-sm text-gray-700 dark:text-gray-300 mb-4">
              <p className="font-medium mb-1">To get approved:</p>
              <ul className="list-disc list-inside space-y-1">
                {assessment.functionality.status === "FAIL" && (
                  <li className="text-red-600 dark:text-red-400">
                    Fix functionality issues (currently FAIL)
                  </li>
                )}
                {assessment.functionality.status === "NEED_MORE_INFO" && (
                  <li className="text-yellow-600 dark:text-yellow-400">
                    Review functionality warnings
                  </li>
                )}
                {assessment.security.status === "FAIL" && (
                  <li className="text-red-600 dark:text-red-400">
                    Fix security vulnerabilities (currently FAIL)
                  </li>
                )}
                {assessment.security.status === "NEED_MORE_INFO" && (
                  <li className="text-yellow-600 dark:text-yellow-400">
                    Review security warnings
                  </li>
                )}
                {assessment.errorHandling.status === "FAIL" && (
                  <li className="text-red-600 dark:text-red-400">
                    Improve error handling (currently FAIL)
                  </li>
                )}
                {assessment.errorHandling.status === "NEED_MORE_INFO" && (
                  <li className="text-yellow-600 dark:text-yellow-400">
                    Review error handling warnings
                  </li>
                )}
                {assessment.documentation.status !== "PASS" && (
                  <li className="text-yellow-600 dark:text-yellow-400">
                    Improve documentation (currently{" "}
                    {assessment.documentation.status === "FAIL"
                      ? "FAIL"
                      : "NEEDS REVIEW"}
                    )
                  </li>
                )}
                {assessment.usability.status !== "PASS" && (
                  <li className="text-yellow-600 dark:text-yellow-400">
                    Improve usability (currently{" "}
                    {assessment.usability.status === "FAIL"
                      ? "FAIL"
                      : "NEEDS REVIEW"}
                    )
                  </li>
                )}
              </ul>
            </div>
          )}
        </div>

        <div className="ml-4">
          <button
            onClick={generateSubmissionReport}
            className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors"
            title="Generate and download submission report"
          >
            <FileText className="w-4 h-4" />
            <span className="text-sm font-medium">Generate Report</span>
          </button>
        </div>
      </div>

      {isReady && (
        <div className="mt-4 p-3 bg-green-100 dark:bg-green-900/30 rounded-lg">
          <p className="text-sm text-green-800 dark:text-green-200 flex items-center gap-2">
            <CheckCircle className="w-4 h-4" />
            All Anthropic MCP Directory requirements met. Click "Generate
            Report" to create your submission documentation.
          </p>
        </div>
      )}
    </div>
  );
};

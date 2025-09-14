import React from "react";
import { MCPDirectoryAssessment } from "../lib/assessmentTypes";
import { CheckCircle, XCircle, AlertCircle, FileText } from "lucide-react";
import { calculateAssessmentScores } from "../utils/assessmentScoring";

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

  const scores = calculateAssessmentScores(assessment);
  const totalScore = scores.total;
  const isReady = totalScore >= 75;
  const classification = scores.classification;

  // Count issues that need fixing
  const criticalIssues = [
    scores.functionality.score < 15 ? 1 : 0,
    scores.security.score < 15 ? 1 : 0,
    scores.errorHandling.score < 10 ? 1 : 0,
  ].reduce((a, b) => a + b, 0);

  const minorIssues = [
    scores.documentation.score < scores.documentation.maxScore ? 1 : 0,
    scores.usability.score < scores.usability.maxScore ? 1 : 0,
  ].reduce((a, b) => a + b, 0);

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
      issuesRemaining: criticalIssues + minorIssues,
    };

    const reportText = `MCP Directory Submission Report
Generated: ${new Date().toLocaleString()}

Server: ${report.serverName}
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
                Overall Score
              </span>
              <div className="text-2xl font-bold">
                <span
                  className={
                    totalScore >= 75
                      ? "text-green-600 dark:text-green-400"
                      : totalScore >= 50
                        ? "text-yellow-600 dark:text-yellow-400"
                        : "text-red-600 dark:text-red-400"
                  }
                >
                  {totalScore}
                </span>
                <span className="text-gray-500 dark:text-gray-400 text-lg">
                  /100
                </span>
                <span
                  className={`ml-2 text-sm px-2 py-1 rounded ${
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
                {scores.functionality.score < 15 && (
                  <li>
                    Fix functionality issues (need 15+ points, have{" "}
                    {scores.functionality.score})
                  </li>
                )}
                {scores.security.score < 15 && (
                  <li>
                    Fix security vulnerabilities (need 15+ points, have{" "}
                    {scores.security.score})
                  </li>
                )}
                {scores.errorHandling.score < 10 && (
                  <li>
                    Improve error handling (need 10+ points, have{" "}
                    {scores.errorHandling.score})
                  </li>
                )}
                {totalScore < 75 && criticalIssues === 0 && (
                  <li>Improve overall score to 75+ (currently {totalScore})</li>
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

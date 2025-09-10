/**
 * MCP Directory Assessment Tab
 * UI for running systematic MCP server assessments
 */

import React, { useState, useCallback, useMemo } from "react";
import { TabsContent } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Checkbox } from "@/components/ui/checkbox";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  Play,
  Download,
  FileText,
  Shield,
  CheckCircle,
  XCircle,
  AlertCircle,
  Loader2,
  Copy,
  RotateCcw,
  ChevronDown,
  ChevronUp,
  Code2,
} from "lucide-react";
import {
  MCPDirectoryAssessment,
  AssessmentStatus,
  AssessmentConfiguration,
  DEFAULT_ASSESSMENT_CONFIG,
  SecurityTestResult,
} from "@/lib/assessmentTypes";
import { MCPAssessmentService } from "@/services/assessmentService";
import {
  Tool,
  CompatibilityCallToolResult,
} from "@modelcontextprotocol/sdk/types.js";
import JsonView from "./JsonView";

interface AssessmentTabProps {
  tools: Tool[];
  callTool: (
    name: string,
    params: Record<string, unknown>,
  ) => Promise<CompatibilityCallToolResult>;
  serverName?: string;
}

const AssessmentTab: React.FC<AssessmentTabProps> = ({
  tools,
  callTool,
  serverName = "MCP Server",
}) => {
  const [assessment, setAssessment] = useState<MCPDirectoryAssessment | null>(
    null,
  );
  const [isRunning, setIsRunning] = useState(false);
  const [currentTest, setCurrentTest] = useState("");
  const [readmeContent, setReadmeContent] = useState("");
  const [config, setConfig] = useState<AssessmentConfiguration>(
    DEFAULT_ASSESSMENT_CONFIG,
  );
  const [error, setError] = useState<string | null>(null);
  const [showJson, setShowJson] = useState(false);

  const assessmentService = useMemo(
    () => new MCPAssessmentService(config),
    [config],
  );

  const runAssessment = useCallback(async () => {
    setIsRunning(true);
    setError(null);
    setCurrentTest("Starting assessment...");

    try {
      const result = await assessmentService.runFullAssessment(
        serverName,
        tools,
        async (name, params) => {
          setCurrentTest(`Testing tool: ${name}`);
          return await callTool(name, params);
        },
        readmeContent,
      );

      setAssessment(result);
      setCurrentTest("");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Assessment failed");
      setCurrentTest("");
    } finally {
      setIsRunning(false);
    }
  }, [assessmentService, serverName, tools, callTool, readmeContent]);

  const copyReport = useCallback(() => {
    if (!assessment) return;

    const report = generateTextReport(assessment);
    navigator.clipboard.writeText(report);
  }, [assessment]);

  const downloadReport = useCallback(() => {
    if (!assessment) return;

    const report = generateTextReport(assessment);
    const blob = new Blob([report], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `mcp-assessment-${serverName}-${new Date().toISOString()}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  }, [assessment, serverName]);

  const downloadJson = useCallback(() => {
    if (!assessment) return;

    const blob = new Blob([JSON.stringify(assessment, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `mcp-assessment-${serverName}-${new Date().toISOString()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }, [assessment, serverName]);

  const resetAssessment = useCallback(() => {
    setAssessment(null);
    setError(null);
    setCurrentTest("");
  }, []);

  return (
    <TabsContent value="assessment" className="h-full flex flex-col">
      <div className="flex-1 overflow-y-auto p-4">
        {/* Configuration Section */}
        <div className="mb-6 space-y-4">
          <h3 className="text-lg font-semibold">Assessment Configuration</h3>

          <div className="space-y-2">
            <Label htmlFor="readme">README Content (optional)</Label>
            <Textarea
              id="readme"
              value={readmeContent}
              onChange={(e) => setReadmeContent(e.target.value)}
              placeholder="Paste the README content here for documentation assessment..."
              className="h-32"
              disabled={isRunning}
            />
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div className="flex items-center space-x-2">
              <Checkbox
                id="autoTest"
                checked={config.autoTest}
                onCheckedChange={(checked) =>
                  setConfig({ ...config, autoTest: !!checked })
                }
                disabled={isRunning}
              />
              <Label htmlFor="autoTest">Auto-test all tools</Label>
            </div>

            <div className="flex items-center space-x-2">
              <Checkbox
                id="verboseLogging"
                checked={config.verboseLogging}
                onCheckedChange={(checked) =>
                  setConfig({ ...config, verboseLogging: !!checked })
                }
                disabled={isRunning}
              />
              <Label htmlFor="verboseLogging">Verbose logging</Label>
            </div>

            <div className="flex items-center space-x-2">
              <Checkbox
                id="generateReport"
                checked={config.generateReport}
                onCheckedChange={(checked) =>
                  setConfig({ ...config, generateReport: !!checked })
                }
                disabled={isRunning}
              />
              <Label htmlFor="generateReport">Generate report</Label>
            </div>

            <div className="flex items-center space-x-2">
              <Checkbox
                id="saveEvidence"
                checked={config.saveEvidence}
                onCheckedChange={(checked) =>
                  setConfig({ ...config, saveEvidence: !!checked })
                }
                disabled={isRunning}
              />
              <Label htmlFor="saveEvidence">Save evidence</Label>
            </div>
          </div>

          {/* Action Buttons */}
          <div className="flex gap-2">
            <Button
              onClick={runAssessment}
              disabled={isRunning || tools.length === 0}
              className="flex items-center gap-2"
            >
              {isRunning ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin" />
                  Running Assessment...
                </>
              ) : (
                <>
                  <Play className="h-4 w-4" />
                  Run Assessment
                </>
              )}
            </Button>

            {assessment && (
              <>
                <Button
                  onClick={resetAssessment}
                  variant="outline"
                  className="flex items-center gap-2"
                >
                  <RotateCcw className="h-4 w-4" />
                  Reset
                </Button>

                <Button
                  onClick={() => setShowJson(!showJson)}
                  variant="outline"
                  className="flex items-center gap-2"
                >
                  <FileText className="h-4 w-4" />
                  {showJson ? "Show Report" : "Show JSON"}
                </Button>

                <Button
                  onClick={copyReport}
                  variant="outline"
                  className="flex items-center gap-2"
                >
                  <Copy className="h-4 w-4" />
                  Copy Report
                </Button>

                <Button
                  onClick={downloadReport}
                  variant="outline"
                  className="flex items-center gap-2"
                >
                  <Download className="h-4 w-4" />
                  Download Report
                </Button>

                <Button
                  onClick={downloadJson}
                  variant="outline"
                  className="flex items-center gap-2"
                >
                  <Download className="h-4 w-4" />
                  Download JSON
                </Button>
              </>
            )}
          </div>
        </div>

        {/* Current Test Status */}
        {currentTest && (
          <Alert className="mb-4">
            <Loader2 className="h-4 w-4 animate-spin" />
            <AlertDescription>{currentTest}</AlertDescription>
          </Alert>
        )}

        {/* Error Display */}
        {error && (
          <Alert variant="destructive" className="mb-4">
            <AlertCircle className="h-4 w-4" />
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        {/* Assessment Results */}
        {assessment && !showJson && (
          <div className="space-y-6">
            <div className="bg-muted p-4 rounded-lg">
              <h3 className="text-lg font-semibold mb-2">
                Overall Assessment: {getStatusBadge(assessment.overallStatus)}
              </h3>
              <p className="text-sm text-muted-foreground mb-4">
                {assessment.summary}
              </p>
              <div className="grid grid-cols-2 gap-2 text-sm">
                <div>Server: {assessment.serverName}</div>
                <div>
                  Date: {new Date(assessment.assessmentDate).toLocaleString()}
                </div>
                <div>Tests Run: {assessment.totalTestsRun}</div>
                <div>Time: {(assessment.executionTime / 1000).toFixed(2)}s</div>
              </div>
            </div>

            {/* Assessment Categories */}
            <AssessmentCategory
              title="Functionality"
              status={assessment.functionality.status}
              icon={<CheckCircle className="h-5 w-5" />}
              jsonData={assessment.functionality}
            >
              <p className="text-sm mb-2">
                {assessment.functionality.explanation}
              </p>
              <div className="grid grid-cols-2 gap-2 text-sm">
                <div>Total Tools: {assessment.functionality.totalTools}</div>
                <div>Tested: {assessment.functionality.testedTools}</div>
                <div>Working: {assessment.functionality.workingTools}</div>
                <div>
                  Coverage:{" "}
                  {assessment.functionality.coveragePercentage.toFixed(1)}%
                </div>
              </div>
              {assessment.functionality.brokenTools.length > 0 && (
                <div className="mt-2">
                  <strong className="text-sm">Broken Tools:</strong>
                  <ul className="list-disc list-inside text-sm mt-1">
                    {assessment.functionality.brokenTools.map((tool) => (
                      <li key={tool}>{tool}</li>
                    ))}
                  </ul>
                </div>
              )}
            </AssessmentCategory>

            <AssessmentCategory
              title="Security"
              status={assessment.security.status}
              icon={<Shield className="h-5 w-5" />}
              jsonData={assessment.security}
            >
              <p className="text-sm mb-2">{assessment.security.explanation}</p>
              <div className="text-sm">
                <div>Risk Level: {assessment.security.overallRiskLevel}</div>
                <div>
                  Vulnerabilities Found:{" "}
                  {assessment.security.vulnerabilities.length}
                </div>
              </div>
              <div className="mt-2">
                <strong className="text-sm">Security Test Results:</strong>
                <div className="mt-2 space-y-1">
                  {/* Group test results by tool name using the toolName field from test results */}
                  {(() => {
                    // Group tests by tool name from the test results themselves
                    const toolGroups = new Map<
                      string,
                      typeof assessment.security.promptInjectionTests
                    >();

                    assessment.security.promptInjectionTests.forEach(
                      (testResult) => {
                        const toolName = testResult.toolName || "Unknown Tool";
                        if (!toolGroups.has(toolName)) {
                          toolGroups.set(toolName, []);
                        }
                        toolGroups.get(toolName)!.push(testResult);
                      },
                    );

                    return Array.from(toolGroups.entries()).map(
                      ([toolName, toolTests]) => (
                        <div
                          key={toolName}
                          className="border border-gray-200 rounded p-2 mb-2"
                        >
                          <div className="text-sm font-semibold text-gray-700 mb-2 bg-gray-50 px-2 py-1 rounded">
                            🔧 Tool: {toolName}
                          </div>
                          <div className="space-y-1 pl-2">
                            {toolTests.map((testResult, index) => (
                              <SecurityVulnerabilityItem
                                key={`${toolName}-${testResult.testName}-${index}`}
                                vulnerability={`${testResult.testName}: ${testResult.description}`}
                                testResult={testResult}
                                toolName={toolName}
                              />
                            ))}
                          </div>
                        </div>
                      ),
                    );
                  })()}
                </div>
                {assessment.security.vulnerabilities.length > 0 && (
                  <div className="mt-3 p-3 bg-red-50 border border-red-200 rounded">
                    <div className="text-sm font-medium text-red-800 mb-1">
                      ⚠️ Actual Vulnerabilities Found:{" "}
                      {assessment.security.vulnerabilities.length}
                    </div>
                    <div className="text-xs text-red-600">
                      The tools above failed security tests and may execute
                      malicious inputs.
                    </div>
                  </div>
                )}
              </div>
            </AssessmentCategory>

            <AssessmentCategory
              title="Documentation"
              status={assessment.documentation.status}
              icon={<FileText className="h-5 w-5" />}
              jsonData={assessment.documentation}
            >
              <p className="text-sm mb-2">
                {assessment.documentation.explanation}
              </p>
              <div className="grid grid-cols-2 gap-2 text-sm mb-3">
                <div>
                  Has README:{" "}
                  {assessment.documentation.metrics.hasReadme ? "Yes" : "No"}
                </div>
                <div>
                  Examples: {assessment.documentation.metrics.exampleCount}/
                  {assessment.documentation.metrics.requiredExamples}
                </div>
                <div>
                  Install Guide:{" "}
                  {assessment.documentation.metrics.hasInstallInstructions
                    ? "Yes"
                    : "No"}
                </div>
                <div>
                  Usage Guide:{" "}
                  {assessment.documentation.metrics.hasUsageGuide
                    ? "Yes"
                    : "No"}
                </div>
              </div>

              {/* Display extracted examples if available */}
              {assessment.documentation.metrics.extractedExamples &&
                assessment.documentation.metrics.extractedExamples.length >
                  0 && (
                  <div className="mt-3 border-t pt-3">
                    <h5 className="text-sm font-semibold mb-2">
                      Code Examples Found (
                      {
                        assessment.documentation.metrics.extractedExamples
                          .length
                      }
                      ):
                    </h5>
                    <div className="space-y-3">
                      {assessment.documentation.metrics.extractedExamples.map(
                        (example, idx) => (
                          <div key={idx} className="bg-muted/50 rounded-lg p-3">
                            <div className="flex items-start justify-between mb-2">
                              <span className="text-xs font-medium">
                                Example {idx + 1}
                              </span>
                              {example.language && (
                                <span className="text-xs px-2 py-0.5 bg-primary/10 text-primary rounded">
                                  {example.language}
                                </span>
                              )}
                            </div>
                            {example.description && (
                              <p className="text-xs text-muted-foreground mb-2">
                                {example.description}
                              </p>
                            )}
                            <pre className="text-xs bg-background rounded p-2 overflow-x-auto">
                              <code>
                                {example.code.length > 200
                                  ? example.code.substring(0, 200) + "..."
                                  : example.code}
                              </code>
                            </pre>
                          </div>
                        ),
                      )}
                    </div>
                  </div>
                )}

              {/* Display installation instructions if found */}
              {assessment.documentation.metrics.installInstructions && (
                <div className="mt-3 border-t pt-3">
                  <h5 className="text-sm font-semibold mb-2">
                    Installation Instructions:
                  </h5>
                  <div className="bg-muted/50 rounded-lg p-3">
                    <pre className="text-xs whitespace-pre-wrap break-words">
                      {assessment.documentation.metrics.installInstructions}
                    </pre>
                  </div>
                </div>
              )}

              {/* Display usage instructions if found */}
              {assessment.documentation.metrics.usageInstructions && (
                <div className="mt-3 border-t pt-3">
                  <h5 className="text-sm font-semibold mb-2">
                    Usage Instructions:
                  </h5>
                  <div className="bg-muted/50 rounded-lg p-3">
                    <pre className="text-xs whitespace-pre-wrap break-words">
                      {assessment.documentation.metrics.usageInstructions}
                    </pre>
                  </div>
                </div>
              )}

              {assessment.documentation.recommendations.length > 0 && (
                <div className="mt-2">
                  <strong className="text-sm">Recommendations:</strong>
                  <ul className="list-disc list-inside text-sm mt-1">
                    {assessment.documentation.recommendations.map((rec) => (
                      <li key={rec}>{rec}</li>
                    ))}
                  </ul>
                </div>
              )}
            </AssessmentCategory>

            <AssessmentCategory
              title="Error Handling"
              status={assessment.errorHandling.status}
              icon={<AlertCircle className="h-5 w-5" />}
              jsonData={assessment.errorHandling}
            >
              <p className="text-sm mb-2">
                {assessment.errorHandling.explanation}
              </p>
              <div className="grid grid-cols-2 gap-2 text-sm mb-3">
                <div>
                  Compliance:{" "}
                  {assessment.errorHandling.metrics.mcpComplianceScore.toFixed(
                    1,
                  )}
                  %
                </div>
                <div>
                  Quality:{" "}
                  {assessment.errorHandling.metrics.errorResponseQuality}
                </div>
                <div>
                  Error Codes:{" "}
                  {assessment.errorHandling.metrics.hasProperErrorCodes
                    ? "Yes"
                    : "No"}
                </div>
                <div>
                  Descriptive:{" "}
                  {assessment.errorHandling.metrics.hasDescriptiveMessages
                    ? "Yes"
                    : "No"}
                </div>
              </div>

              {/* Display detailed test results if available */}
              {assessment.errorHandling.metrics.testDetails &&
                assessment.errorHandling.metrics.testDetails.length > 0 && (
                  <div className="mt-3 border-t pt-3">
                    <h5 className="text-sm font-semibold mb-2">
                      Error Test Details:
                    </h5>
                    <div className="space-y-3">
                      {assessment.errorHandling.metrics.testDetails.map(
                        (test, idx) => (
                          <div
                            key={idx}
                            className="bg-muted/50 rounded-lg p-3 text-xs"
                          >
                            <div className="flex items-start justify-between mb-2">
                              <span className="font-medium">
                                {test.toolName}
                              </span>
                              <span
                                className={`px-2 py-0.5 rounded-full ${
                                  test.passed
                                    ? "bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-100"
                                    : "bg-red-100 dark:bg-red-900 text-red-800 dark:text-red-100"
                                }`}
                              >
                                {test.passed ? "PASS" : "FAIL"}
                              </span>
                            </div>

                            <div className="space-y-1">
                              <div>
                                <span className="text-muted-foreground">
                                  Test Type:
                                </span>{" "}
                                {test.testType}
                              </div>
                              <div>
                                <span className="text-muted-foreground">
                                  Input:
                                </span>
                                <pre className="mt-1 p-2 bg-background rounded text-xs overflow-x-auto">
                                  {JSON.stringify(test.testInput, null, 2)}
                                </pre>
                              </div>
                              {test.actualResponse.errorMessage && (
                                <div>
                                  <span className="text-muted-foreground">
                                    Error Response:
                                  </span>
                                  <div className="mt-1 p-2 bg-background rounded">
                                    {test.actualResponse.errorCode && (
                                      <div className="text-yellow-600 dark:text-yellow-400">
                                        Code: {test.actualResponse.errorCode}
                                      </div>
                                    )}
                                    <div className="break-words">
                                      {test.actualResponse.errorMessage}
                                    </div>
                                  </div>
                                </div>
                              )}
                              {test.reason && (
                                <div>
                                  <span className="text-muted-foreground">
                                    Result:
                                  </span>{" "}
                                  {test.reason}
                                </div>
                              )}
                            </div>
                          </div>
                        ),
                      )}
                    </div>
                  </div>
                )}
            </AssessmentCategory>

            <AssessmentCategory
              title="Usability"
              status={assessment.usability.status}
              icon={<CheckCircle className="h-5 w-5" />}
              jsonData={assessment.usability}
            >
              <p className="text-sm mb-2">{assessment.usability.explanation}</p>
              <div className="grid grid-cols-2 gap-2 text-sm">
                <div>
                  Naming: {assessment.usability.metrics.toolNamingConvention}
                </div>
                <div>
                  Clarity: {assessment.usability.metrics.parameterClarity}
                </div>
                <div>
                  Descriptions:{" "}
                  {assessment.usability.metrics.hasHelpfulDescriptions
                    ? "Yes"
                    : "No"}
                </div>
                <div>
                  Best Practices:{" "}
                  {assessment.usability.metrics.followsBestPractices
                    ? "Yes"
                    : "No"}
                </div>
              </div>
            </AssessmentCategory>

            {/* Overall Recommendations */}
            {assessment.recommendations.length > 0 && (
              <div className="bg-muted p-4 rounded-lg">
                <h4 className="font-semibold mb-2">Overall Recommendations</h4>
                <ul className="list-disc list-inside text-sm space-y-1">
                  {assessment.recommendations.map((rec, idx) => (
                    <li key={idx}>{rec}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        )}

        {/* JSON View */}
        {assessment && showJson && (
          <div className="bg-background border rounded-lg p-4">
            <JsonView data={assessment} />
          </div>
        )}
      </div>
    </TabsContent>
  );
};

// Helper component for individual security vulnerability with clickable details
const SecurityVulnerabilityItem: React.FC<{
  vulnerability: string;
  testResult?: SecurityTestResult;
  toolName: string;
}> = ({ vulnerability, testResult, toolName }) => {
  const [isExpanded, setIsExpanded] = useState(false);

  // Get specific security guidance for vulnerability types
  const getSecurityGuidance = (vulnerabilityType: string): string => {
    const guidelines: Record<string, string> = {
      "Direct Command Injection":
        "Validate and sanitize all string inputs. Never pass user input directly to system commands or eval().",
      "Role Override":
        "Implement strict role validation. Reject inputs that attempt to change system behavior or bypass restrictions.",
      "Data Exfiltration":
        "Add input validation to prevent information disclosure. Avoid reflecting user input in error messages.",
      "Context Escape":
        "Implement proper input boundaries. Reject attempts to break out of expected parameter formats.",
      "Instruction Confusion":
        "Add clear parameter validation. Reject ambiguous or conflicting instructions.",
      "Unicode Bypass":
        "Normalize and validate Unicode input. Use allowlist validation for special characters.",
      "Nested Injection":
        "Validate nested data structures. Implement depth limits and recursive validation.",
      "System Command":
        "Never execute system commands from user input. Use safe alternatives or sandboxed environments.",
    };

    return (
      guidelines[vulnerabilityType] ||
      "Review input validation and implement proper sanitization."
    );
  };

  // Determine styling based on vulnerability status and risk level
  const getTestResultStyle = (testResult?: SecurityTestResult) => {
    if (!testResult) {
      return "text-gray-600 bg-gray-50 border-gray-200";
    }

    // If test shows the tool is secure, use green styling regardless of risk level
    if (!testResult.vulnerable) {
      return "text-green-600 bg-green-50 border-green-200";
    }

    // If actually vulnerable, use risk-based styling
    switch (testResult.riskLevel) {
      case "HIGH":
        return "text-red-600 bg-red-50 border-red-200";
      case "MEDIUM":
        return "text-orange-600 bg-orange-50 border-orange-200";
      case "LOW":
        return "text-yellow-600 bg-yellow-50 border-yellow-200";
      default:
        return "text-gray-600 bg-gray-50 border-gray-200";
    }
  };

  return (
    <div className={`border rounded p-2 ${getTestResultStyle(testResult)}`}>
      <div
        className="cursor-pointer flex items-center justify-between"
        onClick={() => setIsExpanded(!isExpanded)}
      >
        <div className="flex-1">
          <div className="text-sm font-medium">
            {testResult?.testName || "Security Test"}
          </div>
          {testResult && (
            <div className="text-xs opacity-75 mt-1">
              {testResult.description}
            </div>
          )}
        </div>
        <div className="flex items-center space-x-2">
          {testResult && (
            <>
              <span
                className={`text-xs px-2 py-1 rounded ${getTestResultStyle(testResult)}`}
              >
                {testResult.vulnerable ? "🚨 VULNERABLE" : "✅ SECURE"}
              </span>
              <span className="text-xs text-muted-foreground">
                {testResult.riskLevel}
              </span>
            </>
          )}
          {isExpanded ? (
            <ChevronUp className="h-4 w-4" />
          ) : (
            <ChevronDown className="h-4 w-4" />
          )}
        </div>
      </div>

      {isExpanded && testResult && (
        <div className="mt-3 pt-3 border-t border-current space-y-3">
          <div>
            <div className="text-xs font-medium text-muted-foreground uppercase tracking-wide mb-1">
              Test Details
            </div>
            <div className="text-sm">
              <div>
                <strong>Tool:</strong> {toolName}
              </div>
              <div>
                <strong>Test:</strong> {testResult.testName}
              </div>
              <div>
                <strong>Risk Level:</strong> {testResult.riskLevel}
              </div>
              <div
                className={`${testResult.vulnerable ? "text-red-700" : "text-green-700"}`}
              >
                <strong>Result:</strong>{" "}
                {testResult.vulnerable
                  ? "🚨 VULNERABLE - Tool executed malicious input!"
                  : "✅ SECURE - Tool properly rejected malicious input"}
              </div>
            </div>
          </div>

          <div>
            <div className="text-xs font-medium text-muted-foreground uppercase tracking-wide mb-1">
              Test Payload
            </div>
            <div className="bg-black text-green-400 p-2 rounded text-xs font-mono whitespace-pre-wrap break-all">
              {testResult.payload}
            </div>
          </div>

          <div>
            <div className="text-xs font-medium text-muted-foreground uppercase tracking-wide mb-1">
              {testResult.vulnerable
                ? "Evidence of Vulnerability"
                : "Security Validation Result"}
            </div>
            <div
              className={`p-2 rounded text-xs break-words ${
                testResult.vulnerable
                  ? "bg-red-100 text-red-800"
                  : "bg-green-100 text-green-800"
              }`}
            >
              {testResult.evidence || "No evidence available"}
            </div>
            {testResult.response && (
              <details className="mt-2">
                <summary className="text-xs text-muted-foreground cursor-pointer hover:text-foreground">
                  View Raw Response
                </summary>
                <div className="mt-1 bg-black text-green-400 p-2 rounded text-xs font-mono whitespace-pre-wrap break-all max-h-40 overflow-y-auto">
                  {testResult.response}
                </div>
              </details>
            )}
          </div>

          <div>
            <div className="text-xs font-medium text-muted-foreground uppercase tracking-wide mb-1">
              {testResult.vulnerable
                ? "How to Fix This Vulnerability"
                : "Security Assessment Summary"}
            </div>
            <div className="text-xs text-muted-foreground">
              <p className="mb-2">{testResult.description}</p>
              {testResult.vulnerable ? (
                <div className="bg-red-50 text-red-800 p-2 rounded">
                  <strong>🚨 Action Required:</strong>{" "}
                  {getSecurityGuidance(testResult.testName)}
                </div>
              ) : (
                <div className="bg-green-50 text-green-800 p-2 rounded">
                  <strong>✅ Good Security:</strong> This tool properly
                  validated input and rejected the malicious payload. No action
                  needed for this test.
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

// Helper component for assessment categories with expandable JSON view
const AssessmentCategory: React.FC<{
  title: string;
  status: AssessmentStatus;
  icon: React.ReactNode;
  children: React.ReactNode;
  jsonData?: unknown;
}> = ({ title, status, icon, children, jsonData }) => {
  const [isExpanded, setIsExpanded] = useState(false);
  const [showJson, setShowJson] = useState(false);

  return (
    <div className="border rounded-lg overflow-hidden">
      <div
        className="p-4 cursor-pointer hover:bg-muted/50 transition-colors"
        onClick={() => setIsExpanded(!isExpanded)}
      >
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            {icon}
            <h4 className="font-semibold">{title}</h4>
            {getStatusBadge(status)}
          </div>
          <div className="flex items-center gap-2">
            {jsonData !== undefined && (
              <Button
                size="sm"
                variant="ghost"
                onClick={(e) => {
                  e.stopPropagation();
                  setShowJson(!showJson);
                  setIsExpanded(true);
                }}
                className="text-xs"
              >
                <Code2 className="h-3 w-3 mr-1" />
                {showJson ? "Hide" : "Show"} JSON
              </Button>
            )}
            {isExpanded ? (
              <ChevronUp className="h-4 w-4" />
            ) : (
              <ChevronDown className="h-4 w-4" />
            )}
          </div>
        </div>
      </div>

      {isExpanded && (
        <div className="border-t p-4 bg-muted/20">
          {showJson && jsonData ? (
            <div className="bg-background rounded-lg p-3 mb-3 max-h-96 overflow-y-auto">
              <JsonView data={jsonData} />
            </div>
          ) : null}
          <div className={showJson && jsonData ? "mt-3" : ""}>{children}</div>
        </div>
      )}
    </div>
  );
};

// Helper function to get status badge
const getStatusBadge = (status: AssessmentStatus) => {
  switch (status) {
    case "PASS":
      return (
        <span className="inline-flex items-center gap-1 px-2 py-1 bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-100 rounded-full text-xs font-medium">
          <CheckCircle className="h-3 w-3" />
          PASS
        </span>
      );
    case "FAIL":
      return (
        <span className="inline-flex items-center gap-1 px-2 py-1 bg-red-100 dark:bg-red-900 text-red-800 dark:text-red-100 rounded-full text-xs font-medium">
          <XCircle className="h-3 w-3" />
          FAIL
        </span>
      );
    case "NEED_MORE_INFO":
      return (
        <span className="inline-flex items-center gap-1 px-2 py-1 bg-yellow-100 dark:bg-yellow-900 text-yellow-800 dark:text-yellow-100 rounded-full text-xs font-medium">
          <AlertCircle className="h-3 w-3" />
          NEEDS INFO
        </span>
      );
  }
};

// Helper function to generate text report
const generateTextReport = (assessment: MCPDirectoryAssessment): string => {
  const lines = [
    "=".repeat(80),
    "MCP DIRECTORY ASSESSMENT REPORT",
    "=".repeat(80),
    "",
    `Server: ${assessment.serverName}`,
    `Date: ${new Date(assessment.assessmentDate).toLocaleString()}`,
    `Assessor Version: ${assessment.assessorVersion}`,
    `Overall Status: ${assessment.overallStatus}`,
    "",
    "SUMMARY",
    "-".repeat(40),
    assessment.summary,
    "",
    "FUNCTIONALITY",
    "-".repeat(40),
    `Status: ${assessment.functionality.status}`,
    assessment.functionality.explanation,
    `- Total Tools: ${assessment.functionality.totalTools}`,
    `- Tested: ${assessment.functionality.testedTools}`,
    `- Working: ${assessment.functionality.workingTools}`,
    `- Coverage: ${assessment.functionality.coveragePercentage.toFixed(1)}%`,
  ];

  if (assessment.functionality.brokenTools.length > 0) {
    lines.push(
      `- Broken Tools: ${assessment.functionality.brokenTools.join(", ")}`,
    );
  }

  lines.push(
    "",
    "SECURITY",
    "-".repeat(40),
    `Status: ${assessment.security.status}`,
    assessment.security.explanation,
    `- Risk Level: ${assessment.security.overallRiskLevel}`,
    `- Vulnerabilities: ${assessment.security.vulnerabilities.length}`,
  );

  if (assessment.security.vulnerabilities.length > 0) {
    lines.push("- Issues Found:");
    assessment.security.vulnerabilities.forEach((vuln) => {
      lines.push(`  • ${vuln}`);
    });
  }

  lines.push(
    "",
    "DOCUMENTATION",
    "-".repeat(40),
    `Status: ${assessment.documentation.status}`,
    assessment.documentation.explanation,
    `- Has README: ${assessment.documentation.metrics.hasReadme ? "Yes" : "No"}`,
    `- Examples: ${assessment.documentation.metrics.exampleCount}/${assessment.documentation.metrics.requiredExamples}`,
    `- Installation Guide: ${assessment.documentation.metrics.hasInstallInstructions ? "Yes" : "No"}`,
    `- Usage Guide: ${assessment.documentation.metrics.hasUsageGuide ? "Yes" : "No"}`,
  );

  lines.push(
    "",
    "ERROR HANDLING",
    "-".repeat(40),
    `Status: ${assessment.errorHandling.status}`,
    assessment.errorHandling.explanation,
    `- Compliance Score: ${assessment.errorHandling.metrics.mcpComplianceScore.toFixed(1)}%`,
    `- Response Quality: ${assessment.errorHandling.metrics.errorResponseQuality}`,
    `- Proper Error Codes: ${assessment.errorHandling.metrics.hasProperErrorCodes ? "Yes" : "No"}`,
    `- Descriptive Messages: ${assessment.errorHandling.metrics.hasDescriptiveMessages ? "Yes" : "No"}`,
  );

  lines.push(
    "",
    "USABILITY",
    "-".repeat(40),
    `Status: ${assessment.usability.status}`,
    assessment.usability.explanation,
    `- Naming Convention: ${assessment.usability.metrics.toolNamingConvention}`,
    `- Parameter Clarity: ${assessment.usability.metrics.parameterClarity}`,
    `- Helpful Descriptions: ${assessment.usability.metrics.hasHelpfulDescriptions ? "Yes" : "No"}`,
    `- Follows Best Practices: ${assessment.usability.metrics.followsBestPractices ? "Yes" : "No"}`,
  );

  if (assessment.recommendations.length > 0) {
    lines.push("", "RECOMMENDATIONS", "-".repeat(40));
    assessment.recommendations.forEach((rec) => {
      lines.push(`• ${rec}`);
    });
  }

  lines.push(
    "",
    "METADATA",
    "-".repeat(40),
    `Total Tests Run: ${assessment.totalTestsRun}`,
    `Execution Time: ${(assessment.executionTime / 1000).toFixed(2)} seconds`,
    "",
    "=".repeat(80),
  );

  return lines.join("\n");
};

export default AssessmentTab;

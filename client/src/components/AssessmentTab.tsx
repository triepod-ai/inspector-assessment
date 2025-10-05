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
import { Input } from "@/components/ui/input";
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
  ChevronRight,
  Code2,
  Check,
  X,
} from "lucide-react";
import {
  MCPDirectoryAssessment,
  AssessmentStatus,
  AssessmentConfiguration,
  DEFAULT_ASSESSMENT_CONFIG,
  SecurityTestResult,
  EnhancedToolTestResult,
  ToolTestResult,
  ErrorTestDetail,
} from "@/lib/assessmentTypes";
import { MCPAssessmentService } from "@/services/assessmentService";
import {
  Tool,
  CompatibilityCallToolResult,
} from "@modelcontextprotocol/sdk/types.js";
import JsonView from "./JsonView";
import { MCPSpecComplianceDisplay } from "./ExtendedAssessmentCategories";
import {
  AssessmentCategoryFilter,
  CategoryFilterState,
} from "./AssessmentCategoryFilter";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { AssessmentSummary } from "./AssessmentSummary";
import { AssessmentChecklist } from "./AssessmentChecklist";

interface AssessmentTabProps {
  tools: Tool[];
  isLoadingTools?: boolean;
  callTool: (
    name: string,
    params: Record<string, unknown>,
  ) => Promise<CompatibilityCallToolResult>;
  serverName?: string;
}

const AssessmentTab: React.FC<AssessmentTabProps> = ({
  tools,
  isLoadingTools = false,
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
  const [collapsedTools, setCollapsedTools] = useState<Set<string>>(new Set());
  const [allToolsCollapsed, setAllToolsCollapsed] = useState(false);
  const [expandedToolDescriptions, setExpandedToolDescriptions] = useState<
    Set<string>
  >(new Set());
  const [categoryFilter, setCategoryFilter] = useState<CategoryFilterState>({
    functionality: true,
    security: true,
    documentation: true,
    errorHandling: true,
    usability: true,
    mcpSpecCompliance: true,
    privacy: true,
    // Removed non-essential categories: supplyChain, dynamicSecurity, humanInLoop
  });
  const [selectedToolDetails, setSelectedToolDetails] = useState<
    ToolTestResult | EnhancedToolTestResult | null
  >(null);

  const assessmentService = useMemo(
    () => new MCPAssessmentService(config),
    [config],
  );

  /**
   * Calculate the overall status based on filtered categories
   */
  const calculateFilteredOverallStatus = useCallback(
    (assessment: MCPDirectoryAssessment): AssessmentStatus => {
      if (!assessment) return "PASS";

      const statuses: AssessmentStatus[] = [];

      // Only include statuses for enabled categories
      if (categoryFilter.functionality) {
        statuses.push(assessment.functionality.status);
      }
      if (categoryFilter.security) {
        statuses.push(assessment.security.status);
      }
      if (categoryFilter.documentation) {
        statuses.push(assessment.documentation.status);
      }
      if (categoryFilter.errorHandling) {
        statuses.push(assessment.errorHandling.status);
      }
      if (categoryFilter.usability) {
        statuses.push(assessment.usability.status);
      }

      // Include extended assessment categories if enabled
      if (config.enableExtendedAssessment) {
        if (categoryFilter.mcpSpecCompliance && assessment.mcpSpecCompliance) {
          statuses.push(assessment.mcpSpecCompliance.status);
        }
      }

      // If no categories are selected, return PASS
      if (statuses.length === 0) return "PASS";

      // Apply the same logic as the original determineOverallStatus
      if (statuses.includes("FAIL")) return "FAIL";
      if (statuses.filter((s) => s === "NEED_MORE_INFO").length >= 2)
        return "FAIL";
      if (statuses.includes("NEED_MORE_INFO")) return "NEED_MORE_INFO";
      return "PASS";
    },
    [categoryFilter, config.enableExtendedAssessment],
  );

  const toggleToolDescription = useCallback((toolName: string) => {
    setExpandedToolDescriptions((prev) => {
      const newSet = new Set(prev);
      if (newSet.has(toolName)) {
        newSet.delete(toolName);
      } else {
        newSet.add(toolName);
      }
      return newSet;
    });
  }, []);

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

    const filteredStatus = calculateFilteredOverallStatus(assessment);
    const report = generateTextReport(
      assessment,
      filteredStatus,
      categoryFilter,
    );
    navigator.clipboard.writeText(report);
  }, [assessment, calculateFilteredOverallStatus, categoryFilter]);

  const downloadReport = useCallback(() => {
    if (!assessment) return;

    const filteredStatus = calculateFilteredOverallStatus(assessment);
    const report = generateTextReport(
      assessment,
      filteredStatus,
      categoryFilter,
    );
    const blob = new Blob([report], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `mcp-assessment-${serverName}-${new Date().toISOString()}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  }, [assessment, serverName, calculateFilteredOverallStatus, categoryFilter]);

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
              <Label
                htmlFor="autoTest"
                title="Enables testing of all available tools during the assessment. When disabled, only basic validation is performed."
              >
                Enable tool testing
              </Label>
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

            {/* Parallel Testing - Hidden until properly implemented
            <div className="flex items-center space-x-2">
              <Checkbox
                id="parallelTesting"
                checked={config.parallelTesting || false}
                onCheckedChange={(checked) =>
                  setConfig({ ...config, parallelTesting: !!checked })
                }
                disabled={isRunning}
              />
              <Label htmlFor="parallelTesting">Enable Parallel Testing</Label>
            </div>
            */}

            <div className="flex items-center space-x-2">
              <Checkbox
                id="enhancedTesting"
                checked={config.enableEnhancedTesting || false}
                onCheckedChange={(checked) =>
                  setConfig({ ...config, enableEnhancedTesting: !!checked })
                }
                disabled={isRunning}
              />
              <Label
                htmlFor="enhancedTesting"
                title="Tests each tool multiple times with different scenarios: normal data, edge cases, boundary values, and error conditions. Provides more thorough validation but takes longer to complete."
              >
                Run comprehensive tests (slower but more thorough)
              </Label>
            </div>

            <div className="flex items-center space-x-2">
              <Label
                htmlFor="maxToolsToTest"
                title="Limits how many tools receive intensive error handling tests. This is a subset of tool testing. Use -1 to test all tools."
              >
                Error handling test limit:
              </Label>
              <Input
                id="maxToolsToTest"
                type="number"
                min="-1"
                value={config.maxToolsToTestForErrors ?? 3}
                onChange={(e) => {
                  const value = parseInt(e.target.value);
                  if (!isNaN(value)) {
                    setConfig({ ...config, maxToolsToTestForErrors: value });
                  }
                }}
                disabled={isRunning}
                className="w-20"
                title="Limits error handling tests only. Set to -1 for all tools, or a smaller number for faster testing"
              />
              <span className="text-sm text-muted-foreground">
                {isLoadingTools ? (
                  <span className="flex items-center gap-1">
                    <Loader2 className="w-3 h-3 animate-spin" />
                    Loading tools...
                  </span>
                ) : tools.length > 0 ? (
                  config.maxToolsToTestForErrors === -1 ? (
                    `all ${tools.length} tools`
                  ) : (
                    `${config.maxToolsToTestForErrors} of ${tools.length} tools`
                  )
                ) : (
                  "(tools not loaded)"
                )}
              </span>
            </div>
            {!isLoadingTools && tools.length === 0 && (
              <p className="text-xs text-muted-foreground ml-7 -mt-1">
                Load tools first to see available options
              </p>
            )}
            {!isLoadingTools && tools.length > 0 && (
              <p className="text-xs text-muted-foreground ml-7 -mt-1">
                Limits error handling tests only (the most intensive tests)
              </p>
            )}

            {/* Preset buttons for quick configuration */}
            {tools.length > 0 && (
              <div className="flex items-center gap-2 ml-7 mb-2">
                <span className="text-xs text-muted-foreground">
                  Quick presets:
                </span>
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() =>
                    setConfig({ ...config, maxToolsToTestForErrors: -1 })
                  }
                  disabled={isRunning}
                  className="h-6 px-2 text-xs"
                >
                  Test All
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() =>
                    setConfig({ ...config, maxToolsToTestForErrors: 3 })
                  }
                  disabled={isRunning}
                  className="h-6 px-2 text-xs"
                >
                  Quick (3)
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() =>
                    setConfig({
                      ...config,
                      maxToolsToTestForErrors: Math.ceil(tools.length / 2),
                    })
                  }
                  disabled={isRunning}
                  className="h-6 px-2 text-xs"
                >
                  Half ({Math.ceil(tools.length / 2)})
                </Button>
              </div>
            )}

            <div className="flex items-center space-x-2 opacity-50">
              <Checkbox
                id="extendedAssessment"
                checked={false}
                disabled={true}
                className="cursor-not-allowed"
              />
              <Label
                htmlFor="extendedAssessment"
                className="cursor-not-allowed text-muted-foreground"
                title="Work in progress - This feature will enable 3 additional essential assessment categories"
              >
                Enable Extended Assessment (3 essential categories)
              </Label>
            </div>
          </div>

          {/* Action Buttons */}
          <div className="flex gap-2">
            <Button
              onClick={runAssessment}
              disabled={isRunning || tools.length === 0 || isLoadingTools}
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
            {/* Summary Box - Ready for Submission Status */}
            <AssessmentSummary assessment={assessment} isLoading={isRunning} />

            {/* Simple Checklist View */}
            <AssessmentChecklist assessment={assessment} />

            {/* Category Filter */}
            <AssessmentCategoryFilter
              categories={categoryFilter}
              onCategoryChange={(category, enabled) =>
                setCategoryFilter({ ...categoryFilter, [category]: enabled })
              }
              onSelectAll={() =>
                setCategoryFilter({
                  functionality: true,
                  security: true,
                  documentation: true,
                  errorHandling: true,
                  usability: true,
                  mcpSpecCompliance: true,
                  privacy: true,
                })
              }
              onDeselectAll={() =>
                setCategoryFilter({
                  functionality: false,
                  security: false,
                  documentation: false,
                  errorHandling: false,
                  usability: false,
                  mcpSpecCompliance: false,
                  privacy: false,
                })
              }
              isExtendedEnabled={config.enableExtendedAssessment || false}
            />
            <div className="bg-muted p-4 rounded-lg">
              <h3 className="text-lg font-semibold mb-2">
                Overall Assessment:{" "}
                {getStatusBadge(calculateFilteredOverallStatus(assessment))}
              </h3>
              <p className="text-sm text-muted-foreground mb-2">
                {assessment.summary}
              </p>
              {calculateFilteredOverallStatus(assessment) !==
                assessment.overallStatus && (
                <p className="text-xs text-muted-foreground italic">
                  Note: Overall status recalculated based on selected categories
                  (Original: {assessment.overallStatus})
                </p>
              )}
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
            {categoryFilter.functionality && (
              <AssessmentCategory
                id="functionality-section"
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
                {assessment.functionality.toolResults &&
                  assessment.functionality.toolResults.length > 0 && (
                    <div className="mt-2">
                      <strong className="text-sm">Tested Tools:</strong>
                      <div className="text-sm mt-1 max-h-32 overflow-y-auto">
                        {assessment.functionality.toolResults
                          .filter((result) => result.tested)
                          .map((result, idx, filteredArray) => (
                            <span key={result.toolName}>
                              <button
                                className="text-blue-600 hover:text-blue-800 hover:underline focus:outline-none"
                                onClick={() => setSelectedToolDetails(result)}
                              >
                                {result.toolName}
                              </button>
                              {result.status === "working"
                                ? " ✓"
                                : result.status === "broken"
                                  ? " ✗"
                                  : ""}
                              {idx < filteredArray.length - 1 ? ", " : ""}
                            </span>
                          ))}
                      </div>
                    </div>
                  )}
              </AssessmentCategory>
            )}

            {categoryFilter.security && (
              <AssessmentCategory
                id="security-section"
                title="Security"
                status={assessment.security.status}
                icon={<Shield className="h-5 w-5" />}
                jsonData={assessment.security}
              >
                <p className="text-sm mb-2">
                  {assessment.security.explanation}
                </p>
                <div className="text-sm">
                  <div>Risk Level: {assessment.security.overallRiskLevel}</div>
                  <div>
                    Vulnerabilities Found:{" "}
                    {assessment.security.vulnerabilities.length}
                  </div>
                </div>
                <div className="mt-2">
                  <div className="flex items-center justify-between mb-2">
                    <strong className="text-sm">Security Test Results:</strong>
                    <Button
                      variant="outline"
                      size="sm"
                      className="text-xs h-6 px-2"
                      onClick={() => {
                        const toolGroups = new Map<
                          string,
                          typeof assessment.security.promptInjectionTests
                        >();
                        assessment.security.promptInjectionTests.forEach(
                          (testResult) => {
                            const toolName =
                              testResult.toolName || "Unknown Tool";
                            if (!toolGroups.has(toolName)) {
                              toolGroups.set(toolName, []);
                            }
                          },
                        );

                        if (allToolsCollapsed) {
                          // Expand all
                          setCollapsedTools(new Set());
                          setAllToolsCollapsed(false);
                        } else {
                          // Collapse all
                          const allToolNames = Array.from(toolGroups.keys());
                          setCollapsedTools(new Set(allToolNames));
                          setAllToolsCollapsed(true);
                        }
                      }}
                    >
                      {allToolsCollapsed ? (
                        <>
                          <ChevronRight className="h-3 w-3 mr-1" />
                          Expand All
                        </>
                      ) : (
                        <>
                          <ChevronDown className="h-3 w-3 mr-1" />
                          Collapse All
                        </>
                      )}
                    </Button>
                  </div>
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
                          const toolName =
                            testResult.toolName || "Unknown Tool";
                          if (!toolGroups.has(toolName)) {
                            toolGroups.set(toolName, []);
                          }
                          toolGroups.get(toolName)!.push(testResult);
                        },
                      );

                      const handleToggleTool = (toolName: string) => {
                        const newCollapsed = new Set(collapsedTools);
                        if (newCollapsed.has(toolName)) {
                          newCollapsed.delete(toolName);
                        } else {
                          newCollapsed.add(toolName);
                        }
                        setCollapsedTools(newCollapsed);
                        // Update allToolsCollapsed state
                        setAllToolsCollapsed(
                          newCollapsed.size === toolGroups.size,
                        );
                      };

                      return Array.from(toolGroups.entries()).map(
                        ([toolName, toolTests]) => (
                          <CollapsibleToolSection
                            key={toolName}
                            toolName={toolName}
                            toolTests={toolTests}
                            isCollapsed={collapsedTools.has(toolName)}
                            onToggle={handleToggleTool}
                          />
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
            )}

            {categoryFilter.documentation && (
              <AssessmentCategory
                id="documentation-section"
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
                            <div
                              key={idx}
                              className="bg-muted/50 rounded-lg p-3"
                            >
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
            )}

            {categoryFilter.errorHandling && (
              <AssessmentCategory
                id="errorHandling-section"
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

                {/* Validation Coverage Breakdown */}
                {assessment.errorHandling.metrics.validationCoverage && (
                  <div className="mt-3 border-t pt-3">
                    <h5 className="text-sm font-semibold mb-2">
                      Validation Coverage
                      {assessment.errorHandling.metrics.validationCoverage
                        .overallPassRate !== undefined && (
                        <span className="ml-2 text-muted-foreground font-normal">
                          (Overall:{" "}
                          {assessment.errorHandling.metrics.validationCoverage.overallPassRate.toFixed(
                            0,
                          )}
                          %)
                        </span>
                      )}
                    </h5>
                    <div className="grid grid-cols-2 gap-2 text-xs">
                      <div className="bg-muted p-2 rounded">
                        <div className="text-muted-foreground">
                          Wrong Type Validation
                        </div>
                        <div className="font-semibold">
                          {assessment.errorHandling.metrics.validationCoverage.wrongType.toFixed(
                            0,
                          )}
                          %
                          {assessment.errorHandling.metrics.validationCoverage
                            .wrongTypeCount && (
                            <span className="text-muted-foreground font-normal ml-1">
                              (
                              {
                                assessment.errorHandling.metrics
                                  .validationCoverage.wrongTypeCount.passed
                              }
                              /
                              {
                                assessment.errorHandling.metrics
                                  .validationCoverage.wrongTypeCount.total
                              }
                              )
                            </span>
                          )}
                        </div>
                      </div>
                      <div className="bg-muted p-2 rounded">
                        <div className="text-muted-foreground">
                          Extra Params Rejection
                        </div>
                        <div className="font-semibold">
                          {assessment.errorHandling.metrics.validationCoverage.extraParams.toFixed(
                            0,
                          )}
                          %
                          {assessment.errorHandling.metrics.validationCoverage
                            .extraParamsCount && (
                            <span className="text-muted-foreground font-normal ml-1">
                              (
                              {
                                assessment.errorHandling.metrics
                                  .validationCoverage.extraParamsCount.passed
                              }
                              /
                              {
                                assessment.errorHandling.metrics
                                  .validationCoverage.extraParamsCount.total
                              }
                              )
                            </span>
                          )}
                        </div>
                      </div>
                      <div className="bg-muted p-2 rounded">
                        <div className="text-muted-foreground">
                          Required Field Validation
                        </div>
                        <div className="font-semibold">
                          {assessment.errorHandling.metrics.validationCoverage.missingRequired.toFixed(
                            0,
                          )}
                          %
                          {assessment.errorHandling.metrics.validationCoverage
                            .missingRequiredCount && (
                            <span className="text-muted-foreground font-normal ml-1">
                              (
                              {
                                assessment.errorHandling.metrics
                                  .validationCoverage.missingRequiredCount
                                  .passed
                              }
                              /
                              {
                                assessment.errorHandling.metrics
                                  .validationCoverage.missingRequiredCount.total
                              }
                              )
                            </span>
                          )}
                        </div>
                      </div>
                      <div className="bg-muted p-2 rounded">
                        <div className="text-muted-foreground">
                          Null Value Handling
                        </div>
                        <div className="font-semibold">
                          {assessment.errorHandling.metrics.validationCoverage.nullValues.toFixed(
                            0,
                          )}
                          %
                          {assessment.errorHandling.metrics.validationCoverage
                            .nullValuesCount && (
                            <span className="text-muted-foreground font-normal ml-1">
                              (
                              {
                                assessment.errorHandling.metrics
                                  .validationCoverage.nullValuesCount.passed
                              }
                              /
                              {
                                assessment.errorHandling.metrics
                                  .validationCoverage.nullValuesCount.total
                              }
                              )
                            </span>
                          )}
                        </div>
                      </div>
                    </div>
                    <div className="text-xs text-muted-foreground mt-2">
                      Tested{" "}
                      {
                        assessment.errorHandling.metrics.validationCoverage
                          .totalTests
                      }{" "}
                      validation scenarios across tools
                      {assessment.errorHandling.metrics.validationCoverage
                        .overallPassRate !== undefined && (
                        <span>
                          {" - "}
                          {assessment.errorHandling.metrics.validationCoverage.overallPassRate.toFixed(
                            0,
                          )}
                          % pass rate
                        </span>
                      )}
                    </div>
                  </div>
                )}

                {/* Display test results grouped by tool if available */}
                {assessment.errorHandling.metrics.testDetails &&
                  assessment.errorHandling.metrics.testDetails.length > 0 && (
                    <div className="mt-3 border-t pt-3">
                      <div className="flex items-center justify-between mb-2">
                        <strong className="text-sm">
                          Error Handling Test Results:
                        </strong>
                        <Button
                          variant="outline"
                          size="sm"
                          className="text-xs h-6 px-2"
                          onClick={() => {
                            const toolGroups = new Map<
                              string,
                              typeof assessment.errorHandling.metrics.testDetails
                            >();
                            assessment.errorHandling.metrics.testDetails?.forEach(
                              (testResult) => {
                                const toolName =
                                  testResult.toolName || "Unknown Tool";
                                if (!toolGroups.has(toolName)) {
                                  toolGroups.set(toolName, []);
                                }
                              },
                            );

                            if (allToolsCollapsed) {
                              // Expand all
                              setCollapsedTools(new Set());
                              setAllToolsCollapsed(false);
                            } else {
                              // Collapse all
                              const allToolNames = Array.from(
                                toolGroups.keys(),
                              );
                              setCollapsedTools(new Set(allToolNames));
                              setAllToolsCollapsed(true);
                            }
                          }}
                        >
                          {allToolsCollapsed ? (
                            <>
                              <ChevronRight className="h-3 w-3 mr-1" />
                              Expand All
                            </>
                          ) : (
                            <>
                              <ChevronDown className="h-3 w-3 mr-1" />
                              Collapse All
                            </>
                          )}
                        </Button>
                      </div>
                      <div className="mt-2 space-y-1">
                        {/* Group test results by tool name */}
                        {(() => {
                          const toolGroups = new Map<
                            string,
                            typeof assessment.errorHandling.metrics.testDetails
                          >();

                          assessment.errorHandling.metrics.testDetails?.forEach(
                            (testResult) => {
                              const toolName =
                                testResult.toolName || "Unknown Tool";
                              if (!toolGroups.has(toolName)) {
                                toolGroups.set(toolName, []);
                              }
                              toolGroups.get(toolName)!.push(testResult);
                            },
                          );

                          const handleToggleTool = (toolName: string) => {
                            const newCollapsed = new Set(collapsedTools);
                            if (newCollapsed.has(toolName)) {
                              newCollapsed.delete(toolName);
                            } else {
                              newCollapsed.add(toolName);
                            }
                            setCollapsedTools(newCollapsed);
                            // Update allToolsCollapsed state
                            setAllToolsCollapsed(
                              newCollapsed.size === toolGroups.size,
                            );
                          };

                          return Array.from(toolGroups.entries()).map(
                            ([toolName, toolTests]) => {
                              const passedCount = toolTests.filter(
                                (t) => t.passed,
                              ).length;
                              const totalCount = toolTests.length;
                              const allPassed = passedCount === totalCount;

                              return (
                                <div
                                  key={toolName}
                                  className="border rounded p-2 hover:bg-muted/50 transition-colors"
                                >
                                  <div
                                    className="flex items-center justify-between cursor-pointer"
                                    onClick={() => handleToggleTool(toolName)}
                                  >
                                    <div className="flex items-center gap-2">
                                      {collapsedTools.has(toolName) ? (
                                        <ChevronRight className="h-4 w-4" />
                                      ) : (
                                        <ChevronDown className="h-4 w-4" />
                                      )}
                                      <span className="text-sm font-medium">
                                        {toolName}
                                      </span>
                                    </div>
                                    <div className="flex items-center gap-2">
                                      <span
                                        className={`text-xs ${
                                          allPassed
                                            ? "text-green-600 dark:text-green-400"
                                            : passedCount === 0
                                              ? "text-red-600 dark:text-red-400"
                                              : "text-yellow-600 dark:text-yellow-400"
                                        }`}
                                      >
                                        {passedCount === totalCount
                                          ? `All ${totalCount} tests passed`
                                          : `${passedCount}/${totalCount} tests passed`}
                                      </span>
                                    </div>
                                  </div>
                                  {!collapsedTools.has(toolName) && (
                                    <div className="mt-2 pl-6 space-y-2">
                                      {toolTests.map((test, idx) => (
                                        <ErrorTestItem key={idx} test={test} />
                                      ))}
                                    </div>
                                  )}
                                </div>
                              );
                            },
                          );
                        })()}
                      </div>
                    </div>
                  )}
              </AssessmentCategory>
            )}

            {categoryFilter.usability && (
              <AssessmentCategory
                id="usability-section"
                title="Usability"
                status={assessment.usability.status}
                icon={<CheckCircle className="h-5 w-5" />}
                jsonData={assessment.usability}
              >
                <p className="text-sm mb-2">
                  {assessment.usability.explanation}
                </p>
                <div className="grid grid-cols-2 gap-2 text-sm mb-3">
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

                {/* Show detailed analysis if available */}
                {assessment.usability.metrics.detailedAnalysis && (
                  <div className="mt-4 border-t pt-4">
                    <h4 className="font-semibold text-sm mb-2">
                      Detailed Scoring Breakdown
                    </h4>

                    {/* Overall Score */}
                    <div className="mb-3">
                      <div className="flex justify-between items-center mb-1">
                        <span className="text-sm font-medium">
                          Overall Usability Score
                        </span>
                        <span className="text-sm font-bold">
                          {
                            assessment.usability.metrics.detailedAnalysis
                              .overallScore
                          }
                          /100
                        </span>
                      </div>
                      <div className="w-full bg-gray-200 rounded-full h-2">
                        <div
                          className={`h-2 rounded-full ${
                            assessment.usability.metrics.detailedAnalysis
                              .overallScore >= 75
                              ? "bg-green-500"
                              : assessment.usability.metrics.detailedAnalysis
                                    .overallScore >= 50
                                ? "bg-yellow-500"
                                : "bg-red-500"
                          }`}
                          style={{
                            width: `${assessment.usability.metrics.detailedAnalysis.overallScore}%`,
                          }}
                        />
                      </div>
                      {/* Pass/Fail Criteria Explanation */}
                      <div className="mt-2 p-2 bg-muted rounded text-xs">
                        <div className="font-semibold mb-1">
                          Scoring Criteria:
                        </div>
                        <div
                          className={
                            assessment.usability.metrics.detailedAnalysis
                              .overallScore >= 75
                              ? "text-green-600 font-medium"
                              : "text-muted-foreground"
                          }
                        >
                          ✓ PASS (75-100): Tools follow best practices for
                          naming and documentation
                        </div>
                        <div
                          className={
                            assessment.usability.metrics.detailedAnalysis
                              .overallScore >= 50 &&
                            assessment.usability.metrics.detailedAnalysis
                              .overallScore < 75
                              ? "text-yellow-600 font-medium"
                              : "text-muted-foreground"
                          }
                        >
                          ⚠ REVIEW (50-74): Some improvements needed for
                          clarity
                        </div>
                        <div
                          className={
                            assessment.usability.metrics.detailedAnalysis
                              .overallScore < 50
                              ? "text-red-600 font-medium"
                              : "text-muted-foreground"
                          }
                        >
                          ✗ FAIL (0-49): Significant usability issues that
                          impact developer experience
                        </div>
                      </div>
                    </div>

                    {/* Scoring Components */}
                    <h5 className="text-sm font-semibold mb-2">
                      Scoring Components (25 points each)
                    </h5>
                    <div className="grid grid-cols-2 gap-3 mb-3">
                      <div className="bg-muted p-2 rounded">
                        <div className="text-xs text-muted-foreground">
                          Naming Consistency
                        </div>
                        <div className="font-semibold">
                          {
                            assessment.usability.metrics.detailedAnalysis
                              .bestPracticeScore.naming
                          }
                          /25
                        </div>
                        <div className="text-xs text-muted-foreground mt-1">
                          {assessment.usability.metrics.detailedAnalysis
                            .bestPracticeScore.naming === 25
                            ? "✓ All tools use same pattern"
                            : "✗ Mixed naming patterns"}
                        </div>
                      </div>
                      <div className="bg-muted p-2 rounded">
                        <div className="text-xs text-muted-foreground">
                          Description Quality
                        </div>
                        <div className="font-semibold">
                          {
                            assessment.usability.metrics.detailedAnalysis
                              .bestPracticeScore.descriptions
                          }
                          /25
                        </div>
                        <div className="text-xs text-muted-foreground mt-1">
                          {assessment.usability.metrics.detailedAnalysis
                            .bestPracticeScore.descriptions === 25
                            ? "✓ All tools well-described"
                            : assessment.usability.metrics.detailedAnalysis
                                  .bestPracticeScore.descriptions === 15
                              ? "⚠ Most tools described"
                              : "✗ Many missing descriptions"}
                        </div>
                      </div>
                      <div className="bg-muted p-2 rounded">
                        <div className="text-xs text-muted-foreground">
                          Schema Completeness
                        </div>
                        <div className="font-semibold">
                          {
                            assessment.usability.metrics.detailedAnalysis
                              .bestPracticeScore.schemas
                          }
                          /25
                        </div>
                        <div className="text-xs text-muted-foreground mt-1">
                          {assessment.usability.metrics.detailedAnalysis
                            .bestPracticeScore.schemas === 25
                            ? "✓ All tools have schemas"
                            : assessment.usability.metrics.detailedAnalysis
                                  .bestPracticeScore.schemas === 15
                              ? "⚠ Most have schemas"
                              : "✗ Many missing schemas"}
                        </div>
                      </div>
                      <div className="bg-muted p-2 rounded">
                        <div className="text-xs text-muted-foreground">
                          Parameter Clarity
                        </div>
                        <div className="font-semibold">
                          {
                            assessment.usability.metrics.detailedAnalysis
                              .bestPracticeScore.clarity
                          }
                          /25
                        </div>
                        <div className="text-xs text-muted-foreground mt-1">
                          {assessment.usability.metrics.detailedAnalysis
                            .bestPracticeScore.clarity === 25
                            ? "✓ All params documented"
                            : assessment.usability.metrics.detailedAnalysis
                                  .bestPracticeScore.clarity === 15
                              ? "⚠ Some params unclear"
                              : "✗ Many params undocumented"}
                        </div>
                      </div>
                    </div>

                    {/* Tool Analysis Details */}
                    <div className="text-sm space-y-1 mb-3">
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">
                          Dominant Naming Pattern:
                        </span>
                        <span className="font-medium">
                          {
                            assessment.usability.metrics.detailedAnalysis.naming
                              .dominant
                          }
                        </span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">
                          Tools with Descriptions:
                        </span>
                        <span className="font-medium">
                          {
                            assessment.usability.metrics.detailedAnalysis
                              .descriptions.withDescriptions
                          }
                          /
                          {
                            assessment.usability.metrics.detailedAnalysis.tools
                              .length
                          }
                        </span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">
                          Avg Description Length:
                        </span>
                        <span className="font-medium">
                          {
                            assessment.usability.metrics.detailedAnalysis
                              .descriptions.averageLength
                          }{" "}
                          chars
                        </span>
                      </div>
                    </div>

                    {/* Parameter Issues */}
                    {assessment.usability.metrics.detailedAnalysis
                      .parameterIssues.length > 0 && (
                      <div className="bg-yellow-50 dark:bg-yellow-900/20 p-3 rounded mb-3">
                        <h5 className="text-sm font-semibold mb-1">
                          Issues Found:
                        </h5>
                        <ul className="text-xs space-y-1">
                          {assessment.usability.metrics.detailedAnalysis.parameterIssues
                            .slice(0, 3)
                            .map((issue, idx) => (
                              <li key={idx} className="text-muted-foreground">
                                • {issue}
                              </li>
                            ))}
                        </ul>
                      </div>
                    )}

                    {/* Tool-by-Tool Analysis */}
                    <div className="mt-3">
                      <h5 className="text-sm font-semibold mb-2">
                        Tool-by-Tool Analysis
                      </h5>
                      <div className="text-xs text-muted-foreground mb-1">
                        Click on tool names to view their descriptions
                      </div>
                      <div className="text-xs space-y-1 max-h-64 overflow-y-auto">
                        <div className="grid grid-cols-6 gap-1 font-semibold border-b pb-1 mb-1">
                          <div className="col-span-2">Tool Name</div>
                          <div>Naming</div>
                          <div>Description</div>
                          <div>Schema</div>
                          <div>Clarity</div>
                        </div>
                        {assessment.usability.metrics.detailedAnalysis.tools.map(
                          (tool, idx) => (
                            <React.Fragment key={idx}>
                              <div className="grid grid-cols-6 gap-1 py-1 border-b border-gray-100">
                                <div
                                  className="col-span-2 font-medium truncate cursor-pointer hover:text-blue-600 flex items-center gap-1"
                                  onClick={() =>
                                    toggleToolDescription(tool.toolName)
                                  }
                                  title="Click to view description"
                                >
                                  <span className="text-gray-400">
                                    {expandedToolDescriptions.has(
                                      tool.toolName,
                                    ) ? (
                                      <ChevronDown className="w-3 h-3" />
                                    ) : (
                                      <ChevronRight className="w-3 h-3" />
                                    )}
                                  </span>
                                  {tool.toolName}
                                </div>
                                <div
                                  className={
                                    tool.namingPattern ===
                                    assessment.usability.metrics
                                      .detailedAnalysis?.naming.dominant
                                      ? "text-green-600"
                                      : "text-yellow-600"
                                  }
                                >
                                  {tool.namingPattern.replace("_", " ")}
                                </div>
                                <div
                                  className={
                                    tool.hasDescription
                                      ? "text-green-600"
                                      : "text-red-600"
                                  }
                                >
                                  {tool.hasDescription
                                    ? `${tool.descriptionLength} chars`
                                    : "Missing"}
                                </div>
                                <div
                                  className={
                                    tool.hasSchema
                                      ? "text-green-600"
                                      : "text-red-600"
                                  }
                                >
                                  {tool.hasSchema
                                    ? `${tool.parameterCount} params`
                                    : "No schema"}
                                </div>
                                <div
                                  className={
                                    tool.schemaQuality === "excellent"
                                      ? "text-green-600"
                                      : tool.schemaQuality === "good"
                                        ? "text-blue-600"
                                        : tool.schemaQuality === "fair"
                                          ? "text-yellow-600"
                                          : "text-red-600"
                                  }
                                >
                                  {tool.schemaQuality}
                                </div>
                              </div>
                              {expandedToolDescriptions.has(tool.toolName) && (
                                <div className="col-span-6 bg-gray-50 dark:bg-gray-800 p-2 border-b border-gray-100 text-xs">
                                  <div className="font-semibold text-muted-foreground mb-1">
                                    Description:
                                  </div>
                                  <div className="text-gray-700 dark:text-gray-300 mb-2">
                                    {tool.description ||
                                      "No description provided"}
                                  </div>

                                  {/* Parameters Section */}
                                  {tool.parameters &&
                                    tool.parameters.length > 0 && (
                                      <>
                                        <div className="font-semibold text-muted-foreground mb-1">
                                          Parameters ({tool.parameters.length}):
                                        </div>
                                        <div className="space-y-1">
                                          {tool.parameters.map(
                                            (param, paramIdx) => (
                                              <div
                                                key={paramIdx}
                                                className="pl-2 border-l-2 border-gray-300 dark:border-gray-600"
                                              >
                                                <div className="flex items-start gap-2">
                                                  <span className="font-medium text-gray-900 dark:text-gray-100">
                                                    {param.name}
                                                    {param.required && (
                                                      <span className="text-red-500 ml-1">
                                                        *
                                                      </span>
                                                    )}
                                                  </span>
                                                  <span className="text-gray-500">
                                                    ({param.type})
                                                  </span>
                                                  {!param.hasDescription && (
                                                    <span className="text-red-500 text-xs">
                                                      ⚠ No description
                                                    </span>
                                                  )}
                                                </div>
                                                {param.description && (
                                                  <div className="text-gray-600 dark:text-gray-400 mt-0.5">
                                                    {param.description}
                                                  </div>
                                                )}
                                              </div>
                                            ),
                                          )}
                                        </div>
                                        {tool.parameters.filter(
                                          (p) => p.required,
                                        ).length > 0 && (
                                          <div className="text-xs text-muted-foreground mt-1">
                                            <span className="text-red-500">
                                              *
                                            </span>{" "}
                                            Required parameter
                                          </div>
                                        )}
                                      </>
                                    )}

                                  {(!tool.parameters ||
                                    tool.parameters.length === 0) &&
                                    tool.hasSchema && (
                                      <div className="text-gray-500 italic">
                                        No parameters defined
                                      </div>
                                    )}

                                  {!tool.hasSchema && (
                                    <div className="text-red-500 italic">
                                      No schema available - parameters unknown
                                    </div>
                                  )}
                                </div>
                              )}
                            </React.Fragment>
                          ),
                        )}
                      </div>

                      {/* Legend */}
                      <div className="mt-2 p-2 bg-muted rounded text-xs">
                        <div className="font-semibold mb-1">
                          How Tool Names Are Evaluated:
                        </div>
                        <div className="grid grid-cols-2 gap-2 text-muted-foreground">
                          <div>
                            <span className="font-medium">Naming:</span>{" "}
                            Consistent patterns (snake_case, camelCase, etc.)
                          </div>
                          <div>
                            <span className="font-medium">Description:</span>{" "}
                            Min 20 chars for clarity
                          </div>
                          <div>
                            <span className="font-medium">Schema:</span>{" "}
                            Parameter definitions present
                          </div>
                          <div>
                            <span className="font-medium">Clarity:</span>{" "}
                            Parameter descriptions quality
                          </div>
                        </div>
                        <div className="mt-2">
                          <span className="font-medium">Clarity Ratings:</span>
                          <span className="text-green-600 ml-2">
                            Excellent (80%+ params documented)
                          </span>
                          <span className="text-blue-600 ml-2">
                            Good (80%+ have descriptions)
                          </span>
                          <span className="text-yellow-600 ml-2">
                            Fair (50%+ documented)
                          </span>
                          <span className="text-red-600 ml-2">
                            Poor (&lt;50% documented)
                          </span>
                        </div>
                      </div>
                    </div>
                  </div>
                )}
              </AssessmentCategory>
            )}

            {/* Extended Assessment Categories (if enabled) */}
            {config.enableExtendedAssessment &&
              assessment.mcpSpecCompliance &&
              categoryFilter.mcpSpecCompliance && (
                <MCPSpecComplianceDisplay
                  assessment={assessment.mcpSpecCompliance}
                />
              )}

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

        {/* Tool Details Modal */}
        <Dialog
          open={!!selectedToolDetails}
          onOpenChange={(open) => !open && setSelectedToolDetails(null)}
        >
          <DialogContent className="max-w-4xl max-h-[85vh] overflow-y-auto">
            <DialogHeader>
              <DialogTitle className="text-xl font-semibold">
                Tool Test Details: {selectedToolDetails?.toolName}
              </DialogTitle>
              <DialogDescription>
                Detailed test results and scenarios for{" "}
                {selectedToolDetails?.toolName}
              </DialogDescription>
            </DialogHeader>

            {selectedToolDetails && (
              <div className="space-y-4 mt-4 max-w-full overflow-hidden">
                {/* Basic Status */}
                <div className="bg-secondary/50 rounded-lg p-4">
                  <h3 className="font-semibold mb-2 flex items-center gap-2">
                    Status
                    {selectedToolDetails.status === "working" ||
                    selectedToolDetails.status === "fully_working" ? (
                      <CheckCircle className="h-4 w-4 text-green-600" />
                    ) : selectedToolDetails.status === "broken" ? (
                      <XCircle className="h-4 w-4 text-red-600" />
                    ) : (
                      <AlertCircle className="h-4 w-4 text-yellow-600" />
                    )}
                  </h3>
                  <div className="grid grid-cols-2 gap-2 text-sm">
                    <div>
                      <span className="font-medium">Status:</span>{" "}
                      {selectedToolDetails.status || "Unknown"}
                    </div>
                    <div>
                      <span className="font-medium">Tested:</span>{" "}
                      {selectedToolDetails.tested ? "Yes" : "No"}
                    </div>
                    {selectedToolDetails.executionTime && (
                      <div>
                        <span className="font-medium">Execution Time:</span>{" "}
                        {selectedToolDetails.executionTime}ms
                      </div>
                    )}
                  </div>
                </div>

                {/* Enhanced Test Results if available */}
                {"confidence" in selectedToolDetails && (
                  <>
                    {/* Overall Classification */}
                    <div className="bg-secondary/50 rounded-lg p-4">
                      <h3 className="font-semibold mb-2">
                        Enhanced Testing Results
                      </h3>
                      <div className="grid grid-cols-2 gap-2 text-sm">
                        <div>
                          <span className="font-medium">Classification:</span>{" "}
                          <span
                            className={`font-semibold ${
                              selectedToolDetails.status === "fully_working"
                                ? "text-green-600"
                                : selectedToolDetails.status ===
                                    "partially_working"
                                  ? "text-yellow-600"
                                  : selectedToolDetails.status ===
                                      "connectivity_only"
                                    ? "text-orange-600"
                                    : "text-red-600"
                            }`}
                          >
                            {selectedToolDetails.status
                              ?.replace("_", " ")
                              .toUpperCase()}
                          </span>
                        </div>
                        <div>
                          <span className="font-medium">Confidence:</span>{" "}
                          {(selectedToolDetails.confidence * 100).toFixed(1)}%
                        </div>
                        <div>
                          <span className="font-medium">Scenarios Tested:</span>{" "}
                          {selectedToolDetails.detailedResults?.length || 0}
                        </div>
                        <div>
                          <span className="font-medium">Success Rate:</span>{" "}
                          {selectedToolDetails.scenariosPassed &&
                          selectedToolDetails.scenariosExecuted
                            ? `${((selectedToolDetails.scenariosPassed / selectedToolDetails.scenariosExecuted) * 100).toFixed(1)}%`
                            : "N/A"}
                        </div>
                      </div>
                    </div>

                    {/* Detailed Test Scenarios with Full Data */}
                    {selectedToolDetails.detailedResults &&
                      selectedToolDetails.detailedResults.length > 0 && (
                        <div className="bg-secondary/50 rounded-lg p-4">
                          <h3 className="font-semibold mb-3">
                            Test Scenarios & Data
                          </h3>
                          <div className="space-y-4">
                            {selectedToolDetails.detailedResults.map(
                              (scenarioResult, index) => (
                                <div
                                  key={index}
                                  className="border rounded-lg p-3 bg-background max-w-full overflow-hidden"
                                >
                                  {/* Scenario Header */}
                                  <div className="flex justify-between items-start mb-3 pb-2 border-b">
                                    <div>
                                      <h4 className="font-medium text-sm">
                                        {scenarioResult.scenarioName ||
                                          `Scenario ${index + 1}`}
                                      </h4>
                                      <span className="text-xs px-2 py-1 bg-muted rounded mt-1 inline-block">
                                        {scenarioResult.category.replace(
                                          "_",
                                          " ",
                                        )}
                                      </span>
                                    </div>
                                    <div className="flex flex-col items-end gap-1">
                                      <span
                                        className={`text-xs px-2 py-1 rounded font-medium ${
                                          scenarioResult.passed
                                            ? "bg-green-100 text-green-800"
                                            : "bg-red-100 text-red-800"
                                        }`}
                                      >
                                        {scenarioResult.passed
                                          ? "PASSED"
                                          : "FAILED"}
                                      </span>
                                      <span className="text-xs text-muted-foreground">
                                        {(
                                          scenarioResult.confidence * 100
                                        ).toFixed(0)}
                                        % confidence
                                      </span>
                                    </div>
                                  </div>

                                  {/* Issues */}
                                  {scenarioResult.issues &&
                                    scenarioResult.issues.length > 0 && (
                                      <div className="mb-3">
                                        <h5 className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-2">
                                          Issues Found
                                        </h5>
                                        <ul className="list-disc list-inside text-xs space-y-0.5 bg-red-50 border border-red-200 rounded p-3">
                                          {scenarioResult.issues.map(
                                            (issue, i) => (
                                              <li
                                                key={i}
                                                className="text-red-700"
                                              >
                                                {issue}
                                              </li>
                                            ),
                                          )}
                                        </ul>
                                      </div>
                                    )}

                                  {/* Evidence */}
                                  {scenarioResult.evidence &&
                                    scenarioResult.evidence.length > 0 && (
                                      <div className="mb-3">
                                        <h5 className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-2">
                                          Evidence
                                        </h5>
                                        <ul className="list-disc list-inside text-xs space-y-0.5 bg-green-50 border border-green-200 rounded p-3">
                                          {scenarioResult.evidence.map(
                                            (evidence, i) => (
                                              <li
                                                key={i}
                                                className="text-green-700"
                                              >
                                                {evidence}
                                              </li>
                                            ),
                                          )}
                                        </ul>
                                      </div>
                                    )}
                                </div>
                              ),
                            )}
                          </div>
                        </div>
                      )}

                    {/* Recommendations */}
                    {selectedToolDetails.recommendations &&
                      selectedToolDetails.recommendations.length > 0 && (
                        <div className="bg-secondary/50 rounded-lg p-4">
                          <h3 className="font-semibold mb-2">
                            Recommendations
                          </h3>
                          <ul className="list-disc list-inside text-sm space-y-1">
                            {selectedToolDetails.recommendations.map(
                              (rec: string, index: number) => (
                                <li key={index}>{rec}</li>
                              ),
                            )}
                          </ul>
                        </div>
                      )}
                  </>
                )}

                {/* Basic test data if no enhanced results */}
                {!("confidence" in selectedToolDetails) && (
                  <>
                    {"testParameters" in selectedToolDetails &&
                      selectedToolDetails.testParameters && (
                        <div className="bg-secondary/50 rounded-lg p-4">
                          <h3 className="font-semibold mb-2">Test Input</h3>
                          <pre className="text-xs bg-background rounded p-2 overflow-x-auto">
                            {JSON.stringify(
                              selectedToolDetails.testParameters,
                              null,
                              2,
                            )}
                          </pre>
                        </div>
                      )}

                    {selectedToolDetails.response && (
                      <div className="bg-secondary/50 rounded-lg p-4">
                        <h3 className="font-semibold mb-2">Response</h3>
                        <pre className="text-xs bg-background rounded p-2 overflow-x-auto">
                          {typeof selectedToolDetails.response === "string"
                            ? selectedToolDetails.response
                            : JSON.stringify(
                                selectedToolDetails.response,
                                null,
                                2,
                              )}
                        </pre>
                      </div>
                    )}

                    {selectedToolDetails.error && (
                      <div className="bg-red-50 rounded-lg p-4">
                        <h3 className="font-semibold mb-2 text-red-800">
                          Error
                        </h3>
                        <pre className="text-xs text-red-700 bg-white rounded p-2 overflow-x-auto">
                          {typeof selectedToolDetails.error === "string"
                            ? selectedToolDetails.error
                            : JSON.stringify(
                                selectedToolDetails.error,
                                null,
                                2,
                              )}
                        </pre>
                      </div>
                    )}
                  </>
                )}
              </div>
            )}
          </DialogContent>
        </Dialog>
      </div>
    </TabsContent>
  );
};

// Helper component for expandable error test details
const ErrorTestItem: React.FC<{
  test: ErrorTestDetail;
}> = ({ test }) => {
  const [expanded, setExpanded] = useState(false);

  return (
    <div
      className="text-xs border-l-2 pl-3 py-1"
      style={{
        borderColor: test.passed ? "rgb(34 197 94)" : "rgb(239 68 68)",
      }}
    >
      <div
        className="flex items-center justify-between cursor-pointer hover:bg-muted/30 rounded px-1"
        onClick={() => setExpanded(!expanded)}
      >
        <div className="flex items-center gap-2">
          {expanded ? (
            <ChevronDown className="h-3 w-3 text-muted-foreground" />
          ) : (
            <ChevronRight className="h-3 w-3 text-muted-foreground" />
          )}
          {test.passed ? (
            <Check className="h-3 w-3 text-green-600 dark:text-green-400" />
          ) : (
            <X className="h-3 w-3 text-red-600 dark:text-red-400" />
          )}
          <span className="font-medium">
            {test.testType
              .replace(/_/g, " ")
              .replace(/\b\w/g, (l: string) => l.toUpperCase())}
          </span>
        </div>
        <span
          className={`px-2 py-0.5 rounded text-xs ${
            test.passed
              ? "bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-100"
              : "bg-red-100 dark:bg-red-900 text-red-800 dark:text-red-100"
          }`}
        >
          {test.passed ? "PASS" : "FAIL"}
        </span>
      </div>

      {expanded && (
        <div className="mt-2 ml-6 space-y-2 bg-muted/20 rounded p-2">
          {/* Test Description */}
          {test.testDescription && (
            <div>
              <span className="text-muted-foreground font-medium">
                Description:
              </span>
              <div className="ml-2 mt-1">{test.testDescription}</div>
            </div>
          )}

          {/* Expected Behavior */}
          <div>
            <span className="text-muted-foreground font-medium">Expected:</span>
            <div className="ml-2 mt-1 text-yellow-600 dark:text-yellow-400">
              {test.expectedError}
            </div>
          </div>

          {/* Test Input */}
          <div>
            <span className="text-muted-foreground font-medium">
              Test Input:
            </span>
            <pre className="ml-2 mt-1 p-2 bg-background rounded text-xs overflow-x-auto">
              {JSON.stringify(test.testInput, null, 2)}
            </pre>
          </div>

          {/* Actual Response */}
          <div>
            <span className="text-muted-foreground font-medium">
              Actual Response:
            </span>
            <div className="ml-2 mt-1">
              {test.actualResponse.isError ? (
                <div className="space-y-1">
                  {test.actualResponse.errorCode && (
                    <div>
                      <span className="text-muted-foreground">Error Code:</span>{" "}
                      <span className="text-yellow-600 dark:text-yellow-400">
                        {test.actualResponse.errorCode}
                      </span>
                    </div>
                  )}
                  {test.actualResponse.errorMessage && (
                    <div>
                      <span className="text-muted-foreground">
                        Error Message:
                      </span>{" "}
                      <span className="break-words">
                        {test.actualResponse.errorMessage}
                      </span>
                    </div>
                  )}
                </div>
              ) : (
                <div className="text-orange-600 dark:text-orange-400">
                  No error returned (tool accepted invalid input)
                </div>
              )}

              {/* Show raw response if available and not too large */}
              {Boolean(test.actualResponse.rawResponse) &&
                String(test.actualResponse.rawResponse) !==
                  "[response omitted]" &&
                String(test.actualResponse.rawResponse) !==
                  "[error details omitted]" && (
                  <details className="mt-2">
                    <summary className="cursor-pointer text-muted-foreground hover:text-foreground">
                      View Raw Response
                    </summary>
                    <pre className="mt-1 p-2 bg-background rounded text-xs overflow-x-auto max-h-32">
                      {((): string => {
                        const raw = test.actualResponse.rawResponse;
                        return typeof raw === "string"
                          ? raw
                          : JSON.stringify(raw, null, 2);
                      })()}
                    </pre>
                  </details>
                )}
            </div>
          </div>

          {/* Test Result/Reason */}
          {test.reason && (
            <div>
              <span className="text-muted-foreground font-medium">Result:</span>
              <div
                className={`ml-2 mt-1 ${test.passed ? "text-green-600 dark:text-green-400" : "text-red-600 dark:text-red-400"}`}
              >
                {test.reason}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

// Helper component for collapsible tool section
const CollapsibleToolSection: React.FC<{
  toolName: string;
  toolTests: SecurityTestResult[];
  isCollapsed: boolean;
  onToggle: (toolName: string) => void;
}> = ({ toolName, toolTests, isCollapsed, onToggle }) => {
  // Calculate summary stats for the tool
  const totalTests = toolTests.length;
  const passedTests = toolTests.filter((t) => !t.vulnerable).length;
  const failedTests = totalTests - passedTests;
  const allPassed = failedTests === 0;

  return (
    <div className="border border-gray-200 rounded p-2 mb-2">
      <div
        className="text-sm font-semibold text-gray-700 bg-gray-50 px-2 py-1 rounded cursor-pointer hover:bg-gray-100 transition-colors flex items-center justify-between"
        onClick={() => onToggle(toolName)}
      >
        <div className="flex items-center gap-2">
          {isCollapsed ? (
            <ChevronRight className="h-4 w-4" />
          ) : (
            <ChevronDown className="h-4 w-4" />
          )}
          <span>🔧 Tool: {toolName}</span>
        </div>
        <div className="flex items-center gap-3 text-xs">
          {allPassed ? (
            <span className="text-green-600 flex items-center gap-1">
              <CheckCircle className="h-3 w-3" />
              All {totalTests} tests passed
            </span>
          ) : (
            <>
              <span className="text-green-600">{passedTests} passed</span>
              <span className="text-red-600">{failedTests} failed</span>
            </>
          )}
        </div>
      </div>

      {!isCollapsed && (
        <div className="space-y-1 pl-2 mt-2">
          {toolTests.map((testResult, idx) => (
            <SecurityVulnerabilityItem
              key={`${toolName}-${testResult.testName}-${idx}`}
              vulnerability={`${testResult.testName}: ${testResult.description}`}
              testResult={testResult}
              toolName={toolName}
            />
          ))}
        </div>
      )}
    </div>
  );
};

// Helper component for individual security vulnerability with clickable details
const SecurityVulnerabilityItem: React.FC<{
  vulnerability: string;
  testResult?: SecurityTestResult;
  toolName: string;
}> = ({ testResult, toolName }) => {
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
  id?: string;
}> = ({ title, status, icon, children, jsonData, id }) => {
  const [isExpanded, setIsExpanded] = useState(false);
  const [showJson, setShowJson] = useState(false);

  return (
    <div id={id} className="border rounded-lg overflow-hidden">
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
const generateTextReport = (
  assessment: MCPDirectoryAssessment,
  filteredStatus?: AssessmentStatus,
  categoryFilter?: CategoryFilterState,
): string => {
  const effectiveStatus = filteredStatus || assessment.overallStatus;
  const isFiltered =
    filteredStatus && filteredStatus !== assessment.overallStatus;

  const lines = [
    "=".repeat(80),
    "MCP DIRECTORY ASSESSMENT REPORT",
    "=".repeat(80),
    "",
    `Server: ${assessment.serverName}`,
    `Date: ${new Date(assessment.assessmentDate).toLocaleString()}`,
    `Assessor Version: ${assessment.assessorVersion}`,
    `Overall Status: ${effectiveStatus}${isFiltered ? ` (Filtered - Original: ${assessment.overallStatus})` : ""}`,
    "",
  ];

  // Add category filter information if provided
  if (categoryFilter) {
    const activeCategories = Object.entries(categoryFilter)
      .filter(([_, enabled]) => enabled)
      .map(([category]) => category);
    if (activeCategories.length < Object.keys(categoryFilter).length) {
      lines.push("ACTIVE CATEGORIES:", activeCategories.join(", "), "");
    }
  }

  lines.push(
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
  );

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

  // Add detailed usability analysis if available
  if (assessment.usability.metrics.detailedAnalysis) {
    const details = assessment.usability.metrics.detailedAnalysis;
    lines.push(
      "",
      "DETAILED USABILITY BREAKDOWN:",
      `- Best Practice Score: ${details.overallScore}/100`,
      "",
      "Scoring Components:",
      `  • Naming Consistency: ${details.bestPracticeScore.naming}/25`,
      `  • Description Quality: ${details.bestPracticeScore.descriptions}/25`,
      `  • Schema Completeness: ${details.bestPracticeScore.schemas}/25`,
      `  • Parameter Clarity: ${details.bestPracticeScore.clarity}/25`,
      "",
      "Tool Analysis:",
      `  • Total Tools Analyzed: ${details.tools.length}`,
      `  • Naming Patterns Found: ${details.naming.patterns.join(", ")}`,
      `  • Dominant Pattern: ${details.naming.dominant}`,
      `  • Tools with Descriptions: ${details.descriptions.withDescriptions}/${details.tools.length}`,
      `  • Average Description Length: ${details.descriptions.averageLength} chars`,
    );

    if (details.parameterIssues.length > 0) {
      lines.push("", "Parameter Issues Found:");
      details.parameterIssues.forEach((issue) => {
        lines.push(`  • ${issue}`);
      });
    }
  }

  // Extended Assessment Categories (if available)
  if (assessment.mcpSpecCompliance) {
    lines.push(
      "",
      "MCP SPEC COMPLIANCE",
      "-".repeat(40),
      `Status: ${assessment.mcpSpecCompliance.status}`,
      assessment.mcpSpecCompliance.explanation,
      `- Protocol Version: ${assessment.mcpSpecCompliance.protocolVersion}`,
      `- Compliance Score: ${assessment.mcpSpecCompliance.complianceScore.toFixed(1)}%`,
    );
  }

  // Privacy and HumanInLoop sections removed - outside Anthropic's 5 core criteria

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

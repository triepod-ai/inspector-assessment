/**
 * Essential Extended Assessment Categories Component
 * Displays the 3 critical assessment categories for MCP Directory approval:
 * 1. Supply Chain Security - Critical for Anthropic reputation and user trust
 * 2. MCP Spec Compliance - Essential for consistent Claude integration
 * 3. Privacy Compliance - Required for legal and ethical standards
 */

import React, { useState } from "react";
import {
  Shield,
  ChevronDown,
  ChevronUp,
  AlertCircle,
  CheckCircle,
  XCircle,
  Code2,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  MCPSpecComplianceAssessment,
  AssessmentStatus,
} from "@/lib/assessmentTypes";
import JsonView from "./JsonView";

interface ExtendedCategoryProps {
  title: string;
  icon: React.ReactNode;
  status: AssessmentStatus;
  children: React.ReactNode;
  jsonData?: Record<string, unknown>;
  defaultExpanded?: boolean;
}

const ExtendedAssessmentCategory: React.FC<ExtendedCategoryProps> = ({
  title,
  icon,
  status,
  children,
  jsonData,
  defaultExpanded = false,
}) => {
  const [isExpanded, setIsExpanded] = useState(defaultExpanded);
  const [showJson, setShowJson] = useState(false);

  const getStatusBadge = () => {
    switch (status) {
      case "PASS":
        return (
          <Badge className="bg-green-100 text-green-800">
            <CheckCircle className="h-3 w-3 mr-1" />
            PASS
          </Badge>
        );
      case "FAIL":
        return (
          <Badge className="bg-red-100 text-red-800">
            <XCircle className="h-3 w-3 mr-1" />
            FAIL
          </Badge>
        );
      case "NEED_MORE_INFO":
        return (
          <Badge className="bg-yellow-100 text-yellow-800">
            <AlertCircle className="h-3 w-3 mr-1" />
            NEEDS INFO
          </Badge>
        );
    }
  };

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
            {getStatusBadge()}
          </div>
          <div className="flex items-center gap-2">
            {jsonData && (
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
          {showJson && jsonData && (
            <div className="bg-background rounded-lg p-3 mb-3 max-h-96 overflow-y-auto">
              <JsonView data={jsonData} />
            </div>
          )}
          <div className={showJson && jsonData ? "mt-3" : ""}>{children}</div>
        </div>
      )}
    </div>
  );
};

interface MCPSpecComplianceProps {
  assessment: MCPSpecComplianceAssessment;
}

export const MCPSpecComplianceDisplay: React.FC<MCPSpecComplianceProps> = ({
  assessment,
}) => {
  const [expandedCheck, setExpandedCheck] = useState<string | null>(null);

  // Helper function to provide detailed test methodology
  const getTestMethod = (checkName: string): string => {
    switch (checkName) {
      case "jsonRpcCompliance":
        return "Made a test tool call and verified structured JSON-RPC 2.0 response format";
      case "serverInfoValidity":
        return "Validated serverInfo object structure and field types";
      case "schemaCompliance":
        return "Ran Ajv JSON Schema validator against all tool schemas";
      case "errorResponseCompliance":
        return "Sent invalid parameters and verified error response format";
      case "structuredOutputSupport":
        return "Checked if tools define outputSchema property (optional MCP 2025-06-18 feature)";
      default:
        return "Protocol validation test";
    }
  };

  return (
    <ExtendedAssessmentCategory
      title="MCP Spec Compliance"
      icon={<Shield className="h-5 w-5 text-blue-600" />}
      status={assessment.status}
      jsonData={assessment as unknown as Record<string, unknown>}
    >
      <div className="space-y-6">
        {/* Header Info */}
        <div className="bg-gray-50 border border-gray-200 rounded-lg p-3">
          <p className="text-sm text-gray-800 font-medium mb-1">
            ℹ️ Informational Assessment (Not Required for Directory Approval)
          </p>
          <p className="text-xs text-gray-600">
            Protocol validation provides additional insights into MCP
            specification compliance. The 5 core categories above are the
            required assessments.
          </p>
        </div>

        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="text-xs text-muted-foreground">
              Protocol Version
            </label>
            <p className="text-sm font-medium">{assessment.protocolVersion}</p>
          </div>
          <div>
            <label className="text-xs text-muted-foreground">
              Compliance Score (Protocol Checks Only)
            </label>
            <p className="text-sm font-medium">
              {assessment.complianceScore.toFixed(1)}%
            </p>
          </div>
        </div>

        <p className="text-sm">{assessment.explanation}</p>

        {/* SECTION 1: Protocol Checks (HIGH CONFIDENCE) */}
        <div className="bg-green-50 border-l-4 border-green-500 rounded p-4">
          <div className="flex items-center gap-2 mb-3">
            <CheckCircle className="w-5 h-5 text-green-600" />
            <h5 className="text-sm font-semibold text-green-900">
              Protocol Checks (Verified via Testing)
            </h5>
            <Badge className="bg-green-600 text-white text-xs">
              HIGH CONFIDENCE
            </Badge>
          </div>

          <div className="space-y-2">
            {assessment.protocolChecks &&
              Object.entries(assessment.protocolChecks).map(([key, check]) => (
                <div key={key} className="bg-white rounded">
                  {/* Clickable header */}
                  <div
                    className="flex items-start justify-between p-2 cursor-pointer hover:bg-green-100 transition-colors rounded"
                    onClick={() =>
                      setExpandedCheck(expandedCheck === key ? null : key)
                    }
                  >
                    <div className="flex items-center gap-2 flex-1">
                      {check.passed ? (
                        <CheckCircle className="w-4 h-4 text-green-600 flex-shrink-0" />
                      ) : (
                        <XCircle className="w-4 h-4 text-red-600 flex-shrink-0" />
                      )}
                      <div className="flex-1">
                        <span
                          className={`text-sm font-medium ${check.passed ? "text-green-700" : "text-red-700"}`}
                        >
                          {key
                            .replace(/([A-Z])/g, " $1")
                            .replace(/^./, (str) => str.toUpperCase())}
                        </span>
                        {check.evidence && (
                          <p className="text-xs text-gray-600 mt-0.5">
                            {check.evidence}
                          </p>
                        )}
                        {check.warnings && check.warnings.length > 0 && (
                          <div className="mt-1">
                            {check.warnings.map(
                              (warning: string, idx: number) => (
                                <p
                                  key={idx}
                                  className="text-xs text-yellow-700 flex items-start gap-1"
                                >
                                  <AlertCircle className="w-3 h-3 mt-0.5 flex-shrink-0" />
                                  {warning}
                                </p>
                              ),
                            )}
                          </div>
                        )}
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <Badge
                        variant={
                          check.confidence === "high"
                            ? "default"
                            : check.confidence === "medium"
                              ? "secondary"
                              : "outline"
                        }
                        className="text-xs"
                      >
                        {check.confidence.toUpperCase()}
                      </Badge>
                      {expandedCheck === key ? (
                        <ChevronUp className="w-4 h-4 text-gray-400 flex-shrink-0" />
                      ) : (
                        <ChevronDown className="w-4 h-4 text-gray-400 flex-shrink-0" />
                      )}
                    </div>
                  </div>

                  {/* Expandable details */}
                  {expandedCheck === key && (
                    <div className="px-2 pb-2 pt-1">
                      <div className="p-3 bg-gray-50 border-l-2 border-green-400 rounded text-xs space-y-3">
                        <div>
                          <span className="font-semibold text-gray-700">
                            Test Method:
                          </span>
                          <p className="text-gray-600 mt-1">
                            {getTestMethod(key)}
                          </p>
                        </div>

                        <div>
                          <span className="font-semibold text-gray-700">
                            Evidence:
                          </span>
                          <p className="text-gray-600 mt-1">
                            {check.evidence || "No specific evidence recorded"}
                          </p>
                        </div>

                        <div>
                          <span className="font-semibold text-gray-700">
                            Confidence Level:
                          </span>
                          <div className="mt-1">
                            <Badge
                              variant={
                                check.confidence === "high"
                                  ? "default"
                                  : check.confidence === "medium"
                                    ? "secondary"
                                    : "outline"
                              }
                            >
                              {check.confidence.toUpperCase()}
                            </Badge>
                            {check.confidence === "low" && (
                              <p className="text-yellow-700 mt-1 flex items-start gap-1">
                                <AlertCircle className="w-3 h-3 mt-0.5 flex-shrink-0" />
                                May have false positives (e.g., Zod/TypeBox
                                schema conversion issues)
                              </p>
                            )}
                          </div>
                        </div>

                        {check.warnings && check.warnings.length > 0 && (
                          <div>
                            <span className="font-semibold text-gray-700">
                              Warnings:
                            </span>
                            <ul className="list-disc ml-4 mt-1 space-y-1">
                              {check.warnings.map(
                                (warning: string, idx: number) => (
                                  <li key={idx} className="text-yellow-700">
                                    {warning}
                                  </li>
                                ),
                              )}
                            </ul>
                          </div>
                        )}

                        {/* Raw Response Section */}
                        {check.rawResponse && (
                          <div>
                            <span className="font-semibold text-gray-700">
                              Raw Test Output:
                            </span>
                            <details className="mt-1">
                              <summary className="cursor-pointer text-gray-600 hover:text-gray-900 transition-colors text-xs">
                                View Raw Response
                              </summary>
                              <pre className="mt-2 p-2 bg-white border border-gray-200 rounded text-xs overflow-x-auto max-h-64 text-gray-900">
                                {typeof check.rawResponse === "string"
                                  ? check.rawResponse
                                  : JSON.stringify(check.rawResponse, null, 2)}
                              </pre>
                            </details>
                          </div>
                        )}
                      </div>
                    </div>
                  )}
                </div>
              ))}
          </div>
        </div>

        {/* SECTION 2: Metadata Hints (LOW CONFIDENCE) */}
        {assessment.metadataHints && (
          <div className="bg-blue-50 border-l-4 border-blue-300 rounded p-4">
            <div className="flex items-center gap-2 mb-3">
              <AlertCircle className="w-5 h-5 text-blue-600" />
              <h5 className="text-sm font-semibold text-blue-900">
                Server Metadata (Informational Only)
              </h5>
              <Badge className="bg-yellow-500 text-white text-xs">
                LOW CONFIDENCE - Manual Verification Required
              </Badge>
            </div>

            <p className="text-xs text-blue-800 mb-3 italic">
              ⚠️ These are hints from server metadata and have NOT been tested.
              Framework servers may not expose this information even when
              features work.
            </p>

            <div className="space-y-3">
              {/* Transport Hints */}
              {assessment.metadataHints.transportHints && (
                <div className="bg-white rounded p-3">
                  <h6 className="font-medium text-sm text-blue-900 mb-2">
                    Transport Hints
                  </h6>
                  <div className="grid grid-cols-2 gap-2 text-sm text-blue-800">
                    <div>
                      STDIO:{" "}
                      {assessment.metadataHints.transportHints.supportsStdio
                        ? "Indicated"
                        : "Not indicated"}
                    </div>
                    <div>
                      HTTP:{" "}
                      {assessment.metadataHints.transportHints.supportsHTTP
                        ? "Indicated"
                        : "Not indicated"}
                    </div>
                    <div>
                      SSE:{" "}
                      {assessment.metadataHints.transportHints.supportsSSE
                        ? "Indicated"
                        : "Not indicated"}
                    </div>
                    <div className="text-xs text-gray-600">
                      Detection:{" "}
                      {assessment.metadataHints.transportHints.detectionMethod}
                    </div>
                  </div>
                </div>
              )}

              {/* OAuth Hints */}
              {assessment.metadataHints.oauthHints && (
                <div className="bg-white rounded p-3">
                  <h6 className="font-medium text-sm text-blue-900 mb-2">
                    OAuth Hints
                  </h6>
                  <div className="grid grid-cols-2 gap-2 text-sm text-blue-800">
                    <div>
                      OAuth:{" "}
                      {assessment.metadataHints.oauthHints.supportsOAuth
                        ? "Indicated"
                        : "Not indicated"}
                    </div>
                    <div>
                      PKCE:{" "}
                      {assessment.metadataHints.oauthHints.supportsPKCE
                        ? "Indicated"
                        : "Not indicated"}
                    </div>
                  </div>
                </div>
              )}

              {/* Manual Verification Steps */}
              <details className="bg-white rounded p-3">
                <summary className="cursor-pointer text-sm font-semibold text-blue-700 hover:text-blue-900">
                  📋 Manual Verification Steps
                </summary>
                <ul className="list-disc list-inside text-sm mt-2 ml-4 text-blue-800 space-y-1">
                  {assessment.metadataHints.manualVerificationSteps.map(
                    (step, i) => (
                      <li key={i}>{step}</li>
                    ),
                  )}
                </ul>
              </details>
            </div>
          </div>
        )}

        {/* Recommendations */}
        {assessment.recommendations &&
          assessment.recommendations.length > 0 && (
            <div className="bg-gray-50 border border-gray-200 rounded-lg p-4">
              <h5 className="text-sm font-semibold mb-3 text-gray-900">
                Recommendations
              </h5>
              <div className="space-y-2">
                {assessment.recommendations.map((rec, idx) => (
                  <div
                    key={idx}
                    className="text-sm text-gray-700 flex items-start gap-2"
                  >
                    <span className="text-gray-400 mt-0.5">•</span>
                    <span>{rec}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
      </div>
    </ExtendedAssessmentCategory>
  );
};

// Supply Chain Display removed - not essential for MCP Directory approval
// This category provided supplemental dependency checking but was determined
// to be out of scope for MCP interface assessment

/* interface SupplyChainProps {
  assessment: SupplyChainAssessment;
}

export const SupplyChainDisplay: React.FC<SupplyChainProps> = ({
  assessment,
}) => {
  const getVulnerabilitySeverityColor = (severity: string) => {
    switch (severity.toUpperCase()) {
      case "CRITICAL":
        return "text-red-600 bg-red-50";
      case "HIGH":
        return "text-orange-600 bg-orange-50";
      case "MEDIUM":
        return "text-yellow-600 bg-yellow-50";
      case "LOW":
        return "text-green-600 bg-green-50";
      default:
        return "text-gray-600 bg-gray-50";
    }
  };

  return (
    <ExtendedAssessmentCategory
      title="Supply Chain Security"
      icon={<Package className="h-5 w-5 text-purple-600" />}
      status={assessment.status}
      jsonData={assessment}
    >
      <div className="space-y-4">
        <div className="bg-purple-50 border border-purple-200 rounded-lg p-3 mb-4">
          <p className="text-sm text-purple-800 font-medium mb-1">
            🛡️ Highest Priority for Trust
          </p>
          <p className="text-xs text-purple-700">
            Validates the security and integrity of all dependencies, build
            processes, and supply chain components. Ensures no compromised
            libraries or build artifacts that could affect thousands of Claude
            users. Critical for Anthropic's reputation.
          </p>
        </div>
        <p className="text-sm">{assessment.explanation}</p>

        <div className="grid grid-cols-3 gap-4">
          <div>
            <label className="text-xs text-muted-foreground">
              Total Dependencies
            </label>
            <p className="text-sm font-medium">
              {assessment.dependencies.totalDependencies}
            </p>
          </div>
          <div>
            <label className="text-xs text-muted-foreground">Direct</label>
            <p className="text-sm font-medium">
              {assessment.dependencies.directDependencies}
            </p>
          </div>
          <div>
            <label className="text-xs text-muted-foreground">Transitive</label>
            <p className="text-sm font-medium">
              {assessment.dependencies.transitiveDependencies}
            </p>
          </div>
        </div>

        {assessment.vulnerabilities.length > 0 && (
          <div>
            <h5 className="text-sm font-semibold mb-2">
              Vulnerabilities Found
            </h5>
            <div className="space-y-2">
              {assessment.vulnerabilities.slice(0, 5).map((vuln, idx) => (
                <div
                  key={idx}
                  className={`p-2 rounded text-xs ${getVulnerabilitySeverityColor(vuln.severity)}`}
                >
                  <div className="font-medium">
                    {vuln.package || vuln.packageName}: {vuln.vulnerability}
                  </div>
                  <div className="opacity-75">Severity: {vuln.severity}</div>
                </div>
              ))}
              {assessment.vulnerabilities.length > 5 && (
                <p className="text-xs text-muted-foreground">
                  ... and {assessment.vulnerabilities.length - 5} more
                </p>
              )}
            </div>
          </div>
        )}

        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="text-xs text-muted-foreground">
              Package Integrity
            </label>
            <Progress
              value={assessment.packageIntegrity.integrityScore}
              className="h-2 mt-1"
            />
            <p className="text-xs mt-1">
              {assessment.packageIntegrity.integrityScore.toFixed(1)}%
            </p>
          </div>
          <div>
            <label className="text-xs text-muted-foreground">
              License Compliance
            </label>
            <p className="text-sm font-medium">
              {assessment.dependencies.licenseCompliance
                ? "Compliant"
                : "Issues Found"}
            </p>
          </div>
        </div>

        {assessment.recommendations &&
          assessment.recommendations.length > 0 && (
            <div>
              <h5 className="text-sm font-semibold">Recommendations</h5>
              <ul className="list-disc list-inside text-sm mt-1 space-y-1">
                {assessment.recommendations.map((rec, idx) => (
                  <li key={idx}>{rec}</li>
                ))}
              </ul>
            </div>
          )}
      </div>
    </ExtendedAssessmentCategory>
  );
}; */

// Dynamic Security Display removed - not essential for MCP Directory approval
// This category provided supplemental security testing but was determined
// to be less critical than core requirements

// Privacy Compliance Display removed - not essential for MCP Directory approval
// This category was removed along with PrivacyComplianceAssessor module

// Human-in-the-Loop Display removed - not essential for MCP Directory approval
// This category provided workflow enhancement features but was determined
// to be less critical than core requirements

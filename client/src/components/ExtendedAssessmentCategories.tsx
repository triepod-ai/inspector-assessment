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
  Package,
  Lock,
  ChevronDown,
  ChevronUp,
  AlertCircle,
  CheckCircle,
  XCircle,
  Code2,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { Badge } from "@/components/ui/badge";
import {
  MCPSpecComplianceAssessment,
  SupplyChainAssessment,
  PrivacyComplianceAssessment,
  AssessmentStatus,
} from "@/lib/assessmentTypes";
import JsonView from "./JsonView";

interface ExtendedCategoryProps {
  title: string;
  icon: React.ReactNode;
  status: AssessmentStatus;
  children: React.ReactNode;
  jsonData?: Record<string, any>; // Changed from unknown to more specific type
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
  return (
    <ExtendedAssessmentCategory
      title="MCP Spec Compliance"
      icon={<Shield className="h-5 w-5 text-blue-600" />}
      status={assessment.status}
      jsonData={assessment}
    >
      <div className="space-y-4">
        <div className="bg-blue-50 border border-blue-200 rounded-lg p-3 mb-4">
          <p className="text-sm text-blue-800 font-medium mb-1">
            🎯 Critical for Directory Approval
          </p>
          <p className="text-xs text-blue-700">
            Comprehensive validation against MCP protocol specification ensuring
            seamless Claude integration. Prevents workflow breaks, user
            confusion, and reduces support burden for Anthropic.
          </p>
        </div>
        <p className="text-sm">{assessment.explanation}</p>

        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="text-xs text-muted-foreground">
              Protocol Version
            </label>
            <p className="text-sm font-medium">{assessment.protocolVersion}</p>
          </div>
          <div>
            <label className="text-xs text-muted-foreground">
              Compliance Score
            </label>
            <p className="text-sm font-medium">
              {assessment.complianceScore.toFixed(1)}%
            </p>
          </div>
        </div>

        <div className="space-y-2">
          <h5 className="text-sm font-semibold">Transport Compliance</h5>
          <div className="grid grid-cols-2 gap-2 text-sm">
            <div>
              HTTP Support:{" "}
              {assessment.transportCompliance.supportsStdio ? "✓" : "✗"}
            </div>
            <div>
              SSE Support:{" "}
              {assessment.transportCompliance.supportsSSE ? "✓" : "✗"}
            </div>
          </div>
        </div>

        {assessment.oauthImplementation && (
          <div className="space-y-2">
            <h5 className="text-sm font-semibold">OAuth Implementation</h5>
            <div className="grid grid-cols-2 gap-2 text-sm">
              <div>
                OAuth Support:{" "}
                {assessment.oauthImplementation.supportsOAuth ? "✓" : "✗"}
              </div>
              <div>
                PKCE: {assessment.oauthImplementation.supportsPKCE ? "✓" : "✗"}
              </div>
            </div>
          </div>
        )}

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
};

interface SupplyChainProps {
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
};

// Dynamic Security Display removed - not essential for MCP Directory approval
// This category provided supplemental security testing but was determined
// to be less critical than Supply Chain Security, MCP Spec Compliance, and Privacy Compliance

interface PrivacyComplianceProps {
  assessment: PrivacyComplianceAssessment;
}

export const PrivacyComplianceDisplay: React.FC<PrivacyComplianceProps> = ({
  assessment,
}) => {
  return (
    <ExtendedAssessmentCategory
      title="Privacy Compliance"
      icon={<Lock className="h-5 w-5 text-indigo-600" />}
      status={assessment.status}
      jsonData={assessment}
    >
      <div className="space-y-4">
        <div className="bg-indigo-50 border border-indigo-200 rounded-lg p-3 mb-4">
          <p className="text-sm text-indigo-800 font-medium mb-1">
            ⚖️ Legal & Ethical Requirement
          </p>
          <p className="text-xs text-indigo-700">
            Ensures compliance with privacy regulations (GDPR, CCPA) and
            Anthropic's data handling standards. Validates user consent
            mechanisms, data retention policies, and PII protection to prevent
            regulatory risk.
          </p>
        </div>
        <p className="text-sm">{assessment.explanation}</p>

        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="text-xs text-muted-foreground">
              Data Encryption
            </label>
            <div className="flex gap-2 mt-1">
              <Badge
                variant={
                  assessment.dataHandling.encryptionAtRest
                    ? "default"
                    : "secondary"
                }
              >
                At Rest
              </Badge>
              <Badge
                variant={
                  assessment.dataHandling.encryptionInTransit
                    ? "default"
                    : "secondary"
                }
              >
                In Transit
              </Badge>
            </div>
          </div>
          <div>
            <label className="text-xs text-muted-foreground">
              Data Retention
            </label>
            <p className="text-sm font-medium">
              {assessment.dataHandling.retentionPolicy || "Not specified"}
            </p>
          </div>
        </div>

        <div>
          <h5 className="text-sm font-semibold mb-2">Regulatory Compliance</h5>
          <div className="grid grid-cols-2 gap-2">
            <div className="flex items-center justify-between p-2 bg-muted rounded">
              <span className="text-sm">GDPR</span>
              <Badge
                variant={
                  assessment.regulatoryCompliance.gdprCompliant
                    ? "default"
                    : "secondary"
                }
              >
                {assessment.regulatoryCompliance.gdprCompliant
                  ? "Compliant"
                  : "Non-compliant"}
              </Badge>
            </div>
            <div className="flex items-center justify-between p-2 bg-muted rounded">
              <span className="text-sm">CCPA</span>
              <Badge
                variant={
                  assessment.regulatoryCompliance.ccpaCompliant
                    ? "default"
                    : "secondary"
                }
              >
                {assessment.regulatoryCompliance.ccpaCompliant
                  ? "Compliant"
                  : "Non-compliant"}
              </Badge>
            </div>
          </div>
        </div>

        {assessment.piiDetection.detectedTypes &&
          assessment.piiDetection.detectedTypes.length > 0 && (
            <div>
              <h5 className="text-sm font-semibold mb-2">PII Detection</h5>
              <div className="flex flex-wrap gap-2">
                {assessment.piiDetection.detectedTypes.map((type, idx) => (
                  <Badge key={idx} variant="outline">
                    {type}
                  </Badge>
                ))}
              </div>
              <p className="text-xs text-muted-foreground mt-2">
                Found {assessment.piiDetection.totalFindings || 0} instances
                across {assessment.piiDetection.affectedTools?.length || 0}{" "}
                tools
              </p>
            </div>
          )}

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
};

// Human-in-the-Loop Display removed - not essential for MCP Directory approval
// This category provided workflow enhancement features but was determined
// to be less critical than Supply Chain Security, MCP Spec Compliance, and Privacy Compliance

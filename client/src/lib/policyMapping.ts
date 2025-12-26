/**
 * Policy Compliance Mapping Types
 *
 * Maps MCP Inspector assessment results to Anthropic's official Software Directory Policy
 * requirements (30 total). Based on:
 * - https://support.anthropic.com/en/articles/11697096-anthropic-mcp-directory-policy
 * - https://support.claude.com/en/articles/12922490-remote-mcp-server-submission-guide
 *
 * @module policyMapping
 */

import { AssessmentStatus } from "./assessmentTypes";

// ============================================================================
// Policy Category Types
// ============================================================================

/**
 * Categories from Anthropic's Software Directory Policy
 */
export type PolicyCategory =
  | "safety_security"
  | "compatibility"
  | "functionality"
  | "developer_requirements"
  | "unsupported_use_cases";

/**
 * Compliance status for each requirement
 */
export type ComplianceStatus =
  | "PASS" // Requirement fully met
  | "FAIL" // Requirement not met (blocking)
  | "FLAG" // Potential issue, needs human review
  | "REVIEW" // Insufficient data to determine
  | "NOT_APPLICABLE" // Requirement doesn't apply (e.g., OAuth for local server)
  | "NOT_TESTED"; // Module not run or data unavailable

/**
 * Severity levels for policy requirements
 */
export type PolicySeverity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";

// ============================================================================
// Policy Requirement Interfaces
// ============================================================================

/**
 * Definition of a single policy requirement
 */
export interface PolicyRequirement {
  /** Unique identifier (e.g., "SAFETY-1", "FUNC-17") */
  id: string;
  /** Short name for display */
  name: string;
  /** Full policy text/description */
  description: string;
  /** Policy category */
  category: PolicyCategory;
  /** Impact severity if not met */
  severity: PolicySeverity;
  /** Which assessment modules provide evidence for this requirement */
  moduleSource: string[];
  /** Whether this can be fully automated or needs human review */
  automatable: boolean;
  /** Reference to official policy section (if applicable) */
  policyReference?: string;
}

/**
 * Result of evaluating a single policy requirement
 */
export interface PolicyComplianceResult {
  /** The requirement being evaluated */
  requirement: PolicyRequirement;
  /** Compliance status */
  status: ComplianceStatus;
  /** Evidence supporting the status */
  evidence: string[];
  /** Module results that contributed to this evaluation */
  moduleResults: {
    module: string;
    status: string;
    relevantFindings: string[];
  }[];
  /** Recommended action if not passing */
  recommendation?: string;
  /** Whether manual review is required */
  manualReviewRequired: boolean;
  /** Guidance for manual review */
  manualReviewGuidance?: string;
}

/**
 * Summary statistics for policy compliance
 */
export interface PolicyComplianceSummary {
  totalRequirements: number;
  passed: number;
  failed: number;
  flagged: number;
  needsReview: number;
  notApplicable: number;
  notTested: number;
  /** Compliance score as percentage (0-100) */
  complianceScore: number;
  /** Overall status based on critical requirements */
  overallStatus: "COMPLIANT" | "NON_COMPLIANT" | "NEEDS_REVIEW";
}

/**
 * Category-level compliance summary
 */
export interface CategoryCompliance {
  category: PolicyCategory;
  categoryName: string;
  total: number;
  passed: number;
  failed: number;
  status: ComplianceStatus;
  requirements: PolicyComplianceResult[];
}

/**
 * Complete policy compliance report
 */
export interface PolicyComplianceReport {
  /** Server name from assessment */
  serverName: string;
  /** Generation timestamp */
  generatedAt: string;
  /** Inspector version */
  assessorVersion: string;

  /** Summary statistics */
  summary: PolicyComplianceSummary;

  /** Results grouped by category */
  byCategory: {
    safety_security: CategoryCompliance;
    compatibility: CategoryCompliance;
    functionality: CategoryCompliance;
    developer_requirements: CategoryCompliance;
    unsupported_use_cases: CategoryCompliance;
  };

  /** Critical issues that must be fixed */
  criticalIssues: PolicyComplianceResult[];

  /** Prioritized action items */
  actionItems: string[];

  /** Reference to source assessment */
  sourceAssessment: {
    totalTestsRun: number;
    executionTime: number;
    modulesRun: string[];
  };
}

// ============================================================================
// Anthropic Policy Requirements (30 Total)
// ============================================================================

/**
 * Complete list of Anthropic's Software Directory Policy requirements.
 *
 * Organized by category:
 * - Safety & Security: 6 requirements (SAFETY-1 to SAFETY-6)
 * - Compatibility: 6 requirements (COMPAT-1 to COMPAT-6)
 * - Functionality: 7 requirements (FUNC-1 to FUNC-7)
 * - Developer Requirements: 8 requirements (DEV-1 to DEV-8)
 * - Unsupported Use Cases: 3 requirements (UNSUPP-1 to UNSUPP-3)
 */
export const ANTHROPIC_POLICY_REQUIREMENTS: PolicyRequirement[] = [
  // ============================================================================
  // SAFETY & SECURITY (6 requirements)
  // ============================================================================
  {
    id: "SAFETY-1",
    name: "AUP Compliance",
    description:
      "MCP servers must not facilitate violation of Anthropic's Acceptable Use Policy (AUP). This includes all 14 prohibited categories (A-N).",
    category: "safety_security",
    severity: "CRITICAL",
    moduleSource: ["aupCompliance"],
    automatable: true,
    policyReference: "Safety & Security Requirements",
  },
  {
    id: "SAFETY-2",
    name: "Universal Usage Standards",
    description:
      "Servers must meet core safety requirements and universal usage standards as defined by Anthropic.",
    category: "safety_security",
    severity: "CRITICAL",
    moduleSource: ["aupCompliance", "security"],
    automatable: true,
  },
  {
    id: "SAFETY-3",
    name: "High-Risk Domain Compliance",
    description:
      "Servers operating in high-risk domains (medical, legal, financial) must implement appropriate safeguards and disclaimers.",
    category: "safety_security",
    severity: "HIGH",
    moduleSource: ["aupCompliance"],
    automatable: false,
  },
  {
    id: "SAFETY-4",
    name: "OAuth 2.0 Security",
    description:
      "Remote servers using authentication must implement OAuth 2.0 with PKCE and RFC 8707 resource indicators.",
    category: "safety_security",
    severity: "HIGH",
    moduleSource: ["mcpSpecCompliance"],
    automatable: false,
  },
  {
    id: "SAFETY-5",
    name: "No External Behavior Injection",
    description:
      "Servers must not dynamically pull instructions from external sources that could modify Claude's behavior.",
    category: "safety_security",
    severity: "CRITICAL",
    moduleSource: ["security"],
    automatable: true,
  },
  {
    id: "SAFETY-6",
    name: "No Server Interference",
    description:
      "Servers must not interfere with other MCP servers or the host system.",
    category: "safety_security",
    severity: "HIGH",
    moduleSource: ["security"],
    automatable: true,
  },

  // ============================================================================
  // COMPATIBILITY (6 requirements)
  // ============================================================================
  {
    id: "COMPAT-1",
    name: "Streamable HTTP Transport",
    description:
      "Remote servers must support Streamable HTTP transport for Claude web and mobile clients.",
    category: "compatibility",
    severity: "HIGH",
    moduleSource: ["mcpSpecCompliance"],
    automatable: false,
  },
  {
    id: "COMPAT-2",
    name: "SSE Deprecation Warning",
    description:
      "Server-Sent Events (SSE) transport is deprecated. Servers should migrate to Streamable HTTP.",
    category: "compatibility",
    severity: "MEDIUM",
    moduleSource: ["mcpSpecCompliance"],
    automatable: true,
  },
  {
    id: "COMPAT-3",
    name: "Current Dependencies",
    description:
      "Servers must use reasonably current package versions without known critical vulnerabilities.",
    category: "compatibility",
    severity: "MEDIUM",
    moduleSource: ["prohibitedLibraries"],
    automatable: true,
  },
  {
    id: "COMPAT-4",
    name: "Token Efficiency",
    description:
      "Servers should use tokens frugally, with usage commensurate with the task complexity.",
    category: "compatibility",
    severity: "MEDIUM",
    moduleSource: ["functionality"],
    automatable: false,
  },
  {
    id: "COMPAT-5",
    name: "Response Size Limit",
    description: "Tool responses should not exceed 25,000 tokens per response.",
    category: "compatibility",
    severity: "MEDIUM",
    moduleSource: ["functionality"],
    automatable: true,
  },
  {
    id: "COMPAT-6",
    name: "Cross-Platform Portability",
    description:
      "Local servers must work across platforms without hardcoded paths or platform-specific assumptions.",
    category: "compatibility",
    severity: "MEDIUM",
    moduleSource: ["portability"],
    automatable: true,
  },

  // ============================================================================
  // FUNCTIONALITY (7 requirements)
  // ============================================================================
  {
    id: "FUNC-1",
    name: "Reliable Performance",
    description:
      "Servers must provide fast, reliable response times appropriate for the operation.",
    category: "functionality",
    severity: "HIGH",
    moduleSource: ["functionality"],
    automatable: true,
  },
  {
    id: "FUNC-2",
    name: "High Availability",
    description:
      "Remote servers must maintain consistent uptime and availability.",
    category: "functionality",
    severity: "HIGH",
    moduleSource: ["functionality"],
    automatable: false,
  },
  {
    id: "FUNC-3",
    name: "Graceful Error Handling",
    description:
      "Servers must provide helpful error feedback following MCP protocol. No generic 'unknown error' messages.",
    category: "functionality",
    severity: "HIGH",
    moduleSource: ["errorHandling"],
    automatable: true,
  },
  {
    id: "FUNC-4",
    name: "Tool Description Accuracy",
    description:
      "Tool descriptions must accurately reflect actual functionality. No misleading or exaggerated claims.",
    category: "functionality",
    severity: "HIGH",
    moduleSource: ["functionality", "documentation"],
    automatable: false,
  },
  {
    id: "FUNC-5",
    name: "Tool Annotations Required",
    description:
      "All tools must include readOnlyHint and destructiveHint annotations per MCP specification.",
    category: "functionality",
    severity: "HIGH",
    moduleSource: ["toolAnnotations"],
    automatable: true,
    policyReference: "Policy #17",
  },
  {
    id: "FUNC-6",
    name: "No Unexpected Functionality",
    description:
      "Servers must not include hidden functionality or fail to deliver promised features.",
    category: "functionality",
    severity: "HIGH",
    moduleSource: ["functionality", "security"],
    automatable: false,
  },
  {
    id: "FUNC-7",
    name: "Clear Tool Identity",
    description:
      "Tools must have clear, non-conflicting descriptions that don't confuse with other servers.",
    category: "functionality",
    severity: "MEDIUM",
    moduleSource: ["usability"],
    automatable: true,
  },

  // ============================================================================
  // DEVELOPER REQUIREMENTS (8 requirements)
  // ============================================================================
  {
    id: "DEV-1",
    name: "Privacy Policy",
    description:
      "Developers must provide clear data handling documentation and privacy policy URLs.",
    category: "developer_requirements",
    severity: "HIGH",
    moduleSource: ["manifestValidation", "documentation"],
    automatable: true,
  },
  {
    id: "DEV-2",
    name: "Contact Information",
    description:
      "Developers must provide verified support channels and contact information.",
    category: "developer_requirements",
    severity: "MEDIUM",
    moduleSource: ["documentation"],
    automatable: false,
  },
  {
    id: "DEV-3",
    name: "Documentation",
    description:
      "Servers must include documentation explaining how the server works and troubleshooting guidance.",
    category: "developer_requirements",
    severity: "HIGH",
    moduleSource: ["documentation"],
    automatable: true,
  },
  {
    id: "DEV-4",
    name: "Testing Account",
    description:
      "Developers must provide sample data or testing accounts for verification.",
    category: "developer_requirements",
    severity: "MEDIUM",
    moduleSource: [],
    automatable: false,
  },
  {
    id: "DEV-5",
    name: "Example Prompts",
    description:
      "Servers must include at least 3 example prompts demonstrating core functionality.",
    category: "developer_requirements",
    severity: "HIGH",
    moduleSource: ["documentation"],
    automatable: true,
    policyReference: "Policy #24",
  },
  {
    id: "DEV-6",
    name: "API Ownership",
    description:
      "Developers must have control of or affiliation with connected API endpoints.",
    category: "developer_requirements",
    severity: "HIGH",
    moduleSource: [],
    automatable: false,
  },
  {
    id: "DEV-7",
    name: "Maintenance Commitment",
    description:
      "Developers must commit to addressing issues in reasonable timeframes.",
    category: "developer_requirements",
    severity: "MEDIUM",
    moduleSource: [],
    automatable: false,
  },
  {
    id: "DEV-8",
    name: "Terms Agreement",
    description: "Developers must accept MCP Directory Terms and Conditions.",
    category: "developer_requirements",
    severity: "CRITICAL",
    moduleSource: [],
    automatable: false,
  },

  // ============================================================================
  // UNSUPPORTED USE CASES (3 requirements)
  // ============================================================================
  {
    id: "UNSUPP-1",
    name: "No Financial Transactions",
    description:
      "Servers must not facilitate financial transactions, cryptocurrency, or money transfers.",
    category: "unsupported_use_cases",
    severity: "CRITICAL",
    moduleSource: ["prohibitedLibraries", "aupCompliance"],
    automatable: true,
    policyReference: "Policy #28",
  },
  {
    id: "UNSUPP-2",
    name: "No Media Generation",
    description: "Servers must not generate images, videos, or audio content.",
    category: "unsupported_use_cases",
    severity: "CRITICAL",
    moduleSource: ["prohibitedLibraries", "aupCompliance"],
    automatable: true,
    policyReference: "Policy #29",
  },
  {
    id: "UNSUPP-3",
    name: "No Cross-Service Orchestration",
    description:
      "Servers must not orchestrate actions across unrelated third-party services.",
    category: "unsupported_use_cases",
    severity: "HIGH",
    moduleSource: ["aupCompliance"],
    automatable: false,
    policyReference: "Policy #30",
  },
];

// ============================================================================
// Helper Functions
// ============================================================================

/**
 * Get all requirements for a specific category
 */
export function getRequirementsByCategory(
  category: PolicyCategory,
): PolicyRequirement[] {
  return ANTHROPIC_POLICY_REQUIREMENTS.filter((r) => r.category === category);
}

/**
 * Get a specific requirement by ID
 */
export function getRequirementById(id: string): PolicyRequirement | undefined {
  return ANTHROPIC_POLICY_REQUIREMENTS.find((r) => r.id === id);
}

/**
 * Get all requirements that a specific module provides evidence for
 */
export function getRequirementsForModule(
  moduleName: string,
): PolicyRequirement[] {
  return ANTHROPIC_POLICY_REQUIREMENTS.filter((r) =>
    r.moduleSource.includes(moduleName),
  );
}

/**
 * Get all critical requirements
 */
export function getCriticalRequirements(): PolicyRequirement[] {
  return ANTHROPIC_POLICY_REQUIREMENTS.filter((r) => r.severity === "CRITICAL");
}

/**
 * Get all automatable requirements
 */
export function getAutomatableRequirements(): PolicyRequirement[] {
  return ANTHROPIC_POLICY_REQUIREMENTS.filter((r) => r.automatable);
}

/**
 * Get human-readable category name
 */
export function getCategoryDisplayName(category: PolicyCategory): string {
  const names: Record<PolicyCategory, string> = {
    safety_security: "Safety & Security",
    compatibility: "Compatibility",
    functionality: "Functionality",
    developer_requirements: "Developer Requirements",
    unsupported_use_cases: "Unsupported Use Cases",
  };
  return names[category];
}

/**
 * Convert ComplianceStatus to AssessmentStatus
 */
export function complianceToAssessmentStatus(
  status: ComplianceStatus,
): AssessmentStatus {
  switch (status) {
    case "PASS":
      return "PASS";
    case "FAIL":
    case "FLAG":
      return "FAIL";
    case "REVIEW":
    case "NOT_TESTED":
    case "NOT_APPLICABLE":
      return "NEED_MORE_INFO";
  }
}

/**
 * Calculate compliance score from results
 */
export function calculateComplianceScore(
  results: PolicyComplianceResult[],
): number {
  const applicableResults = results.filter(
    (r) => r.status !== "NOT_APPLICABLE" && r.status !== "NOT_TESTED",
  );

  if (applicableResults.length === 0) return 0;

  const passed = applicableResults.filter((r) => r.status === "PASS").length;
  return Math.round((passed / applicableResults.length) * 100);
}

/**
 * Determine overall compliance status
 */
export function determineOverallStatus(
  results: PolicyComplianceResult[],
): "COMPLIANT" | "NON_COMPLIANT" | "NEEDS_REVIEW" {
  // Check for any critical failures
  const criticalFailures = results.filter(
    (r) => r.requirement.severity === "CRITICAL" && r.status === "FAIL",
  );

  if (criticalFailures.length > 0) {
    return "NON_COMPLIANT";
  }

  // Check for any failures
  const failures = results.filter((r) => r.status === "FAIL");
  if (failures.length > 0) {
    return "NON_COMPLIANT";
  }

  // Check if any need review
  const needsReview = results.filter(
    (r) => r.status === "REVIEW" || r.status === "FLAG",
  );
  if (needsReview.length > 0) {
    return "NEEDS_REVIEW";
  }

  return "COMPLIANT";
}

// ============================================================================
// Module-to-Policy Mapping
// ============================================================================

/**
 * Mapping of assessment modules to the policy requirements they satisfy.
 * Used by PolicyComplianceGenerator to map results.
 */
export const MODULE_TO_POLICY_MAP: Record<string, string[]> = {
  aupCompliance: [
    "SAFETY-1",
    "SAFETY-2",
    "SAFETY-3",
    "UNSUPP-1",
    "UNSUPP-2",
    "UNSUPP-3",
  ],
  security: ["SAFETY-2", "SAFETY-5", "SAFETY-6", "FUNC-6"],
  functionality: ["COMPAT-4", "COMPAT-5", "FUNC-1", "FUNC-4", "FUNC-6"],
  errorHandling: ["FUNC-3"],
  usability: ["FUNC-7"],
  documentation: ["DEV-1", "DEV-3", "DEV-5", "FUNC-4"],
  mcpSpecCompliance: ["SAFETY-4", "COMPAT-1", "COMPAT-2"],
  toolAnnotations: ["FUNC-5"],
  prohibitedLibraries: ["COMPAT-3", "UNSUPP-1", "UNSUPP-2"],
  manifestValidation: ["DEV-1"],
  portability: ["COMPAT-6"],
};

/**
 * Get which policy requirements are evaluated by a given module
 */
export function getPolicyRequirementsForModule(moduleName: string): string[] {
  return MODULE_TO_POLICY_MAP[moduleName] || [];
}

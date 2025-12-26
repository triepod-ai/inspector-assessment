/**
 * MCP Vulnerable Testbed Configuration
 *
 * This configuration file defines expected outcomes for validating the
 * SecurityAssessor against the MCP Vulnerable Testbed reference implementation.
 *
 * The testbed provides:
 * - 10 REAL, EXPLOITABLE vulnerabilities in the vulnerable server
 * - 0 vulnerabilities in the hardened server (all fixed)
 * - 6 safe control tools that should NOT be flagged (false positive checks)
 *
 * Target Metrics:
 * - 100% Recall: All 10 vulnerabilities detected in vulnerable server
 * - 100% Precision: 0 false positives (safe tools not flagged)
 * - 0 false positives on hardened server
 */

export interface TestbedServerConfig {
  name: string;
  transport: "http" | "stdio";
  url: string;
  expectedVulnerabilities: number;
  expectedTools: number;
  expectedAnnotationCoverage?: number;
  toolCategories?: {
    high_risk: number;
    medium_risk: number;
    safe_control: number;
    metadata: number;
  };
}

export interface ExpectedVulnerability {
  tool: string;
  type: string;
  evidence: string;
  riskLevel: "HIGH" | "MEDIUM" | "LOW";
}

/**
 * Testbed Server Configurations
 */
export const TESTBED_CONFIG = {
  vulnerable: {
    name: "vulnerable-testbed",
    transport: "http" as const,
    url: "http://localhost:10900/mcp",
    expectedVulnerabilities: 10,
    expectedTools: 17,
    toolCategories: {
      high_risk: 6,
      medium_risk: 4,
      safe_control: 6,
      metadata: 1,
    },
  },
  hardened: {
    name: "hardened-testbed",
    transport: "http" as const,
    url: "http://localhost:10901/mcp",
    expectedVulnerabilities: 0,
    expectedTools: 17,
    expectedAnnotationCoverage: 100,
  },
};

/**
 * Expected Vulnerabilities in Vulnerable Server
 *
 * These are the 10 REAL, EXPLOITABLE vulnerabilities that security assessment
 * tools should detect. Each vulnerability has been validated to actually work
 * (see docs/VULNERABILITY-VALIDATION-RESULTS.md in the testbed repo).
 */
export const EXPECTED_VULNERABILITIES: ExpectedVulnerability[] = [
  // HIGH RISK (6)
  {
    tool: "vulnerable_calculator_tool",
    type: "command_injection",
    evidence: "eval(query) - actually executes Python expressions",
    riskLevel: "HIGH",
  },
  {
    tool: "vulnerable_system_exec_tool",
    type: "command_injection",
    evidence: "subprocess.run(command, shell=True) - executes shell commands",
    riskLevel: "HIGH",
  },
  {
    tool: "vulnerable_data_leak_tool",
    type: "data_exfiltration",
    evidence: "Returns FAKE_ENV containing API keys and DB credentials",
    riskLevel: "HIGH",
  },
  {
    tool: "vulnerable_config_modifier_tool",
    type: "config_drift",
    evidence: "exec() modifies config_state including admin_mode",
    riskLevel: "HIGH",
  },
  {
    tool: "vulnerable_tool_override_tool",
    type: "tool_shadowing",
    evidence: "Accepts tool registry modifications",
    riskLevel: "HIGH",
  },
  {
    tool: "vulnerable_fetcher_tool",
    type: "prompt_injection",
    evidence: "requests.get(url) fetches external content",
    riskLevel: "HIGH",
  },
  // MEDIUM RISK (4)
  {
    tool: "vulnerable_unicode_processor_tool",
    type: "unicode_bypass",
    evidence: "Decodes unicode then eval() - bypasses input filters",
    riskLevel: "MEDIUM",
  },
  {
    tool: "vulnerable_nested_parser_tool",
    type: "nested_injection",
    evidence: "Executes fields from nested JSON via eval()",
    riskLevel: "MEDIUM",
  },
  {
    tool: "vulnerable_package_installer_tool",
    type: "package_squatting",
    evidence: "subprocess.run(['pip', 'install', package]) - any package",
    riskLevel: "MEDIUM",
  },
  {
    tool: "vulnerable_rug_pull_tool",
    type: "rug_pull",
    evidence: "After 10 invocations, executes system commands",
    riskLevel: "MEDIUM",
  },
];

/**
 * Safe Control Tools
 *
 * These tools should NEVER be flagged as vulnerable.
 * They use the REFLECTION pattern: input is stored/echoed as data, not executed.
 *
 * Key pattern:
 * VULNERABLE: eval(input) -> executes code
 * SAFE: return f"Stored: {input}" -> reflects data
 */
export const EXPECTED_SAFE_TOOLS = [
  "safe_storage_tool_mcp",
  "safe_search_tool_mcp",
  "safe_list_tool_mcp",
  "safe_info_tool_mcp",
  "safe_echo_tool_mcp",
  "safe_validate_tool_mcp",
];

/**
 * Metadata tools (not security-tested)
 */
export const METADATA_TOOLS = ["get_testbed_info"];

/**
 * All vulnerable tool names for quick lookup
 */
export const VULNERABLE_TOOL_NAMES = EXPECTED_VULNERABILITIES.map(
  (v) => v.tool,
);

/**
 * Validation Metrics Types
 */
export interface ValidationMetrics {
  recall: number; // TP / (TP + FN) - % of vulnerabilities detected
  precision: number; // TP / (TP + FP) - % of flagged items that are actually vulnerable
  falsePositiveRate: number; // FP / (FP + TN) - % of safe tools incorrectly flagged
  falseNegativeRate: number; // FN / (FN + TP) - % of vulnerabilities missed
  detected: string[];
  missed: string[];
  falsePositives: string[];
}

/**
 * Calculate validation metrics from assessment results
 */
export function calculateMetrics(
  detectedVulnerabilities: string[],
  flaggedTools: string[],
): ValidationMetrics {
  // True Positives: Vulnerable tools that were correctly flagged
  const truePositives = detectedVulnerabilities.filter((v) =>
    VULNERABLE_TOOL_NAMES.includes(v),
  );

  // False Negatives: Vulnerable tools that were NOT flagged
  const falseNegatives = VULNERABLE_TOOL_NAMES.filter(
    (v) => !detectedVulnerabilities.includes(v),
  );

  // False Positives: Safe tools that were incorrectly flagged
  const falsePositives = flaggedTools.filter((t) =>
    EXPECTED_SAFE_TOOLS.includes(t),
  );

  // True Negatives: Safe tools that were correctly NOT flagged
  const trueNegatives = EXPECTED_SAFE_TOOLS.filter(
    (t) => !flaggedTools.includes(t),
  );

  const tp = truePositives.length;
  const fn = falseNegatives.length;
  const fp = falsePositives.length;
  const tn = trueNegatives.length;

  return {
    recall: tp / (tp + fn) || 0,
    precision: tp / (tp + fp) || 0,
    falsePositiveRate: fp / (fp + tn) || 0,
    falseNegativeRate: fn / (fn + tp) || 0,
    detected: truePositives,
    missed: falseNegatives,
    falsePositives,
  };
}

/**
 * Check if testbed servers are running
 */
export async function checkTestbedHealth(): Promise<{
  vulnerable: boolean;
  hardened: boolean;
}> {
  const checkServer = async (url: string): Promise<boolean> => {
    try {
      const response = await fetch(url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json, text/event-stream",
        },
        body: JSON.stringify({
          jsonrpc: "2.0",
          method: "initialize",
          params: {
            protocolVersion: "2024-11-05",
            capabilities: {},
            clientInfo: { name: "test", version: "1.0" },
          },
          id: 1,
        }),
      });
      return response.ok;
    } catch {
      return false;
    }
  };

  const [vulnerable, hardened] = await Promise.all([
    checkServer(TESTBED_CONFIG.vulnerable.url),
    checkServer(TESTBED_CONFIG.hardened.url),
  ]);

  return { vulnerable, hardened };
}

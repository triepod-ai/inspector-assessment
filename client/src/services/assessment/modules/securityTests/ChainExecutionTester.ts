/**
 * Chain Execution Tester
 * Dynamic testing for multi-tool chain exploitation vulnerabilities
 *
 * Issue #93, Challenge #6: Multi-tool chained exploitation attacks
 * Tests for:
 * 1. Arbitrary tool invocation without allowlist
 * 2. Output injection via {{output}} template substitution
 * 3. Recursive chain execution (DoS potential)
 * 4. State poisoning between chain steps
 * 5. Missing depth/size limits
 *
 * A/B Validation:
 * - vulnerable-mcp (10900): Should detect all vulnerability categories
 * - hardened-mcp (10901): 0 false positives (validation-only behavior)
 */

import {
  CompatibilityCallToolResult,
  Tool,
} from "@modelcontextprotocol/sdk/types.js";
import {
  SecurityResponseAnalyzer,
  ChainExploitationAnalysis,
  ChainVulnerabilityCategory,
} from "./SecurityResponseAnalyzer";

// Import shared CallToolFunction type from CrossToolStateTester (single source of truth)
import { CallToolFunction } from "./CrossToolStateTester";

// Re-export for consumers who import from this module
export type { CallToolFunction } from "./CrossToolStateTester";

/**
 * Reason for chain exploitation test result
 */
export type ChainTestReason =
  | "chain_execution_confirmed" // Tool executed chain with vulnerabilities
  | "output_injection_detected" // {{output}} substitution occurred
  | "recursive_execution_detected" // Self-referential chain worked
  | "arbitrary_tool_accepted" // Non-allowlisted tool accepted
  | "state_poisoning_detected" // Chain steps modified shared state
  | "validation_only" // Safe - only validated, didn't execute
  | "chain_rejected" // Safe - chain rejected entirely
  | "tool_not_chain_executor" // Tool doesn't accept chain input
  | "test_error"; // Error during testing

/**
 * Result of a single chain exploitation test
 */
export interface ChainExecutionTestResult {
  vulnerable: boolean;
  reason: ChainTestReason;
  vulnerabilityCategories?: ChainVulnerabilityCategory[];
  evidence?: {
    chainPayload: string;
    response: string;
    analysisResult: ChainExploitationAnalysis;
  };
  error?: string;
}

/**
 * Summary of chain exploitation tests for a tool
 */
export interface ChainExploitationSummary {
  total: number;
  vulnerable: number;
  safe: number;
  errors: number;
  vulnerableTests: string[];
  vulnerabilityCategories: ChainVulnerabilityCategory[];
}

/**
 * Configuration for chain execution testing
 */
export interface ChainExecutionTesterConfig {
  /** Enable verbose logging */
  verbose?: boolean;
  /** Maximum chain depth to test (default: 10) */
  maxChainDepth?: number;
}

/**
 * Test payload definition for chain exploitation
 */
interface ChainTestPayload {
  name: string;
  payload: string;
  description: string;
}

/**
 * Tests for multi-tool chain exploitation vulnerabilities
 */
export class ChainExecutionTester {
  private readonly verbose: boolean;
  private analyzer: SecurityResponseAnalyzer;

  constructor(config: ChainExecutionTesterConfig = {}) {
    this.verbose = config.verbose ?? false;
    this.analyzer = new SecurityResponseAnalyzer();
  }

  /**
   * Log message if verbose logging is enabled
   */
  private log(message: string): void {
    if (this.verbose) {
      console.log(`[ChainExecutionTester] ${message}`);
    }
  }

  /**
   * Identify tools that might be chain executors
   * Looks for tools with names/descriptions/parameters suggesting chain execution
   */
  identifyChainExecutorTools(tools: Tool[]): Tool[] {
    const chainNamePatterns = [
      /chain/i,
      /executor/i,
      /pipeline/i,
      /sequence/i,
      /workflow/i,
      /orchestrat/i,
      /multi.*tool/i,
      /batch/i,
    ];

    const chainParamPatterns = [
      /chain/i,
      /steps/i,
      /sequence/i,
      /pipeline/i,
      /tools/i,
      /commands/i,
    ];

    return tools.filter((tool) => {
      // Check tool name
      const nameMatches = chainNamePatterns.some((p) => p.test(tool.name));

      // Check description
      const descMatches =
        tool.description &&
        chainNamePatterns.some((p) => p.test(tool.description || ""));

      // Check parameter names
      const schema = tool.inputSchema as {
        properties?: Record<string, unknown>;
      };
      const paramNames = Object.keys(schema?.properties || {});
      const paramMatches = paramNames.some((param) =>
        chainParamPatterns.some((p) => p.test(param)),
      );

      return nameMatches || descMatches || paramMatches;
    });
  }

  /**
   * Get the parameter name for chain input from tool schema
   */
  private getChainParamName(tool: Tool): string {
    const schema = tool.inputSchema as { properties?: Record<string, unknown> };
    const paramNames = Object.keys(schema?.properties || {});

    // Look for chain-like parameter names
    const chainParam = paramNames.find((p) =>
      /chain|steps|sequence|pipeline/i.test(p),
    );

    return chainParam || "chain";
  }

  /**
   * Extract text content from tool response
   */
  private extractResponseText(response: CompatibilityCallToolResult): string {
    if (!response) return "";

    // Handle content array format
    if (response.content && Array.isArray(response.content)) {
      return response.content
        .map((item) => {
          if (typeof item === "string") return item;
          if (item && typeof item === "object" && "text" in item)
            return String(item.text);
          return JSON.stringify(item);
        })
        .join("\n");
    }

    return "";
  }

  /**
   * Determine the vulnerability reason from analysis result
   */
  private determineVulnerabilityReason(
    analysis: ChainExploitationAnalysis,
  ): ChainTestReason {
    if (analysis.vulnerabilityCategories.includes("OUTPUT_INJECTION")) {
      return "output_injection_detected";
    }
    if (analysis.vulnerabilityCategories.includes("RECURSIVE_CHAIN")) {
      return "recursive_execution_detected";
    }
    if (
      analysis.vulnerabilityCategories.includes("ARBITRARY_TOOL_INVOCATION")
    ) {
      return "arbitrary_tool_accepted";
    }
    if (analysis.vulnerabilityCategories.includes("STATE_POISONING")) {
      return "state_poisoning_detected";
    }
    return "chain_execution_confirmed";
  }

  /**
   * Test single chain payload against a tool
   */
  async testChainPayload(
    callTool: CallToolFunction,
    tool: Tool,
    chainPayload: string,
    paramName?: string,
  ): Promise<ChainExecutionTestResult> {
    const actualParamName = paramName || this.getChainParamName(tool);

    try {
      this.log(`Testing payload on ${tool.name} with param ${actualParamName}`);

      const response = await callTool(tool.name, {
        [actualParamName]: chainPayload,
      });
      const responseText = this.extractResponseText(response);

      // Analyze response for chain exploitation
      const analysis = this.analyzer.analyzeChainExploitation(response);

      if (analysis.vulnerable) {
        return {
          vulnerable: true,
          reason: this.determineVulnerabilityReason(analysis),
          vulnerabilityCategories: analysis.vulnerabilityCategories,
          evidence: {
            chainPayload,
            response: responseText.substring(0, 500),
            analysisResult: analysis,
          },
        };
      }

      if (analysis.safe) {
        return {
          vulnerable: false,
          reason:
            analysis.chainType === "SAFE_VALIDATION"
              ? "validation_only"
              : "chain_rejected",
        };
      }

      return {
        vulnerable: false,
        reason: "tool_not_chain_executor",
      };
    } catch (error) {
      return {
        vulnerable: false,
        reason: "test_error",
        error: error instanceof Error ? error.message : String(error),
      };
    }
  }

  /**
   * Get test payloads for chain exploitation testing
   */
  private getTestPayloads(): ChainTestPayload[] {
    return [
      {
        name: "single_step_execution",
        payload:
          '[{"tool": "vulnerable_calculator", "args": {"query": "2+2"}}]',
        description: "Test basic chain execution without allowlist",
      },
      {
        name: "output_injection",
        payload:
          '[{"tool": "calc", "args": {"q": "test"}}, {"tool": "exec", "args": {"cmd": "{{output}}"}}]',
        description: "Test output injection via {{output}} template",
      },
      {
        name: "recursive_chain",
        payload:
          '[{"tool": "vulnerable_chain_executor", "args": {"chain": "[]"}}]',
        description: "Test recursive/circular chain execution",
      },
      {
        name: "arbitrary_tool",
        payload: '[{"tool": "UNKNOWN_MALICIOUS_TOOL_XYZ", "args": {}}]',
        description: "Test acceptance of arbitrary tool names",
      },
      {
        name: "state_poisoning",
        payload:
          '[{"tool": "vulnerable_config_modifier", "args": {"setting": "admin_mode=true"}}, {"tool": "vulnerable_admin_action", "args": {"action": "read secrets"}}]',
        description: "Test state poisoning between chain steps",
      },
      {
        name: "depth_bypass",
        payload: JSON.stringify(
          Array(15)
            .fill(null)
            .map(() => ({ tool: "test", args: {} })),
        ),
        description: "Test depth limit bypass with 15 steps",
      },
    ];
  }

  /**
   * Run comprehensive chain exploitation tests on a tool
   */
  async runChainExploitationTests(
    callTool: CallToolFunction,
    tool: Tool,
  ): Promise<Map<string, ChainExecutionTestResult>> {
    const results = new Map<string, ChainExecutionTestResult>();
    const testPayloads = this.getTestPayloads();
    const chainParam = this.getChainParamName(tool);

    this.log(`Running chain exploitation tests on ${tool.name}`);
    this.log(`Using parameter: ${chainParam}`);

    for (const test of testPayloads) {
      this.log(`  Test: ${test.name} - ${test.description}`);

      const result = await this.testChainPayload(
        callTool,
        tool,
        test.payload,
        chainParam,
      );

      results.set(test.name, result);

      if (this.verbose) {
        console.log(
          `    Result: ${result.vulnerable ? "VULNERABLE" : "SAFE"} (${result.reason})`,
        );
      }
    }

    return results;
  }

  /**
   * Summarize chain exploitation test results
   */
  summarizeResults(
    results: Map<string, ChainExecutionTestResult>,
  ): ChainExploitationSummary {
    let vulnerable = 0;
    let safe = 0;
    let errors = 0;
    const vulnerableTests: string[] = [];
    const categories = new Set<ChainVulnerabilityCategory>();

    for (const [testName, result] of results) {
      if (result.reason === "test_error") {
        errors++;
      } else if (result.vulnerable) {
        vulnerable++;
        vulnerableTests.push(testName);
        result.vulnerabilityCategories?.forEach((c) => categories.add(c));
      } else {
        safe++;
      }
    }

    return {
      total: results.size,
      vulnerable,
      safe,
      errors,
      vulnerableTests,
      vulnerabilityCategories: Array.from(categories),
    };
  }
}

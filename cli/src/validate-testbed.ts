#!/usr/bin/env node

/**
 * Testbed Validation CLI
 *
 * Validates the MCP Inspector SecurityAssessor against the reference
 * Vulnerable Testbed implementation to ensure detection accuracy.
 *
 * Runs assessments against both vulnerable and hardened servers,
 * then calculates recall, precision, and false positive rates.
 *
 * Prerequisites:
 *   cd /home/bryan/mcp-servers/mcp-vulnerable-testbed && docker-compose up -d
 *
 * Usage:
 *   npm run validate:testbed
 *   mcp-validate-testbed
 *   mcp-validate-testbed --verbose
 */

import * as fs from "fs";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import {
  Tool,
  CompatibilityCallToolResult,
} from "@modelcontextprotocol/sdk/types.js";

// Import from local client lib
import { SecurityAssessor } from "../../client/lib/services/assessment/modules/SecurityAssessor.js";
import {
  AssessmentConfiguration,
  DEFAULT_ASSESSMENT_CONFIG,
  SecurityAssessment,
} from "../../client/lib/lib/assessmentTypes.js";
import { AssessmentContext } from "../../client/lib/services/assessment/AssessmentOrchestrator.js";

/**
 * Testbed Configuration
 */
const TESTBED_CONFIG = {
  vulnerable: {
    name: "vulnerable-testbed",
    url: "http://localhost:10900/mcp",
    expectedVulnerabilities: 10,
  },
  hardened: {
    name: "hardened-testbed",
    url: "http://localhost:10901/mcp",
    expectedVulnerabilities: 0,
  },
};

/**
 * Expected vulnerable tools (10 total)
 */
const VULNERABLE_TOOLS = [
  "vulnerable_calculator_tool",
  "vulnerable_system_exec_tool",
  "vulnerable_data_leak_tool",
  "vulnerable_config_modifier_tool",
  "vulnerable_tool_override_tool",
  "vulnerable_fetcher_tool",
  "vulnerable_unicode_processor_tool",
  "vulnerable_nested_parser_tool",
  "vulnerable_package_installer_tool",
  "vulnerable_rug_pull_tool",
];

/**
 * Expected safe tools (should NOT be flagged)
 */
const SAFE_TOOLS = [
  "safe_storage_tool_mcp",
  "safe_search_tool_mcp",
  "safe_list_tool_mcp",
  "safe_info_tool_mcp",
  "safe_echo_tool_mcp",
  "safe_validate_tool_mcp",
];

interface ValidationOptions {
  verbose: boolean;
  outputPath?: string;
}

interface ValidationMetrics {
  recall: number;
  precision: number;
  falsePositiveRate: number;
  falseNegativeRate: number;
  detected: string[];
  missed: string[];
  falsePositives: string[];
}

interface ValidationResult {
  serverName: string;
  totalTools: number;
  testsRun: number;
  vulnerabilitiesFound: number;
  metrics?: ValidationMetrics;
  assessment: SecurityAssessment;
}

/**
 * Check if a server is available
 */
async function checkServerHealth(url: string): Promise<boolean> {
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
          clientInfo: { name: "testbed-validator", version: "1.0" },
        },
        id: 1,
      }),
    });
    return response.ok;
  } catch {
    return false;
  }
}

/**
 * Connect to MCP server
 */
async function connectToServer(url: string): Promise<Client> {
  const transport = new StreamableHTTPClientTransport(new URL(url));

  const client = new Client(
    {
      name: "mcp-validate-testbed",
      version: "1.0.0",
    },
    {
      capabilities: {},
    },
  );

  await client.connect(transport);
  return client;
}

/**
 * Get tools from server
 */
async function getTools(client: Client): Promise<Tool[]> {
  const response = await client.listTools();
  return response.tools || [];
}

/**
 * Create callTool wrapper
 */
function createCallToolWrapper(client: Client) {
  return async (
    name: string,
    params: Record<string, unknown>,
  ): Promise<CompatibilityCallToolResult> => {
    try {
      const response = await client.callTool({
        name,
        arguments: params,
      });

      return {
        content: response.content,
        isError: response.isError || false,
        structuredContent: (response as Record<string, unknown>)
          .structuredContent,
      } as CompatibilityCallToolResult;
    } catch (error) {
      return {
        content: [
          {
            type: "text",
            text: `Error: ${error instanceof Error ? error.message : String(error)}`,
          },
        ],
        isError: true,
      } as CompatibilityCallToolResult;
    }
  };
}

/**
 * Run assessment on a server
 */
async function assessServer(
  serverName: string,
  url: string,
  verbose: boolean,
): Promise<ValidationResult> {
  if (verbose) {
    console.log(`\n  Connecting to ${url}...`);
  }

  const client = await connectToServer(url);
  const tools = await getTools(client);

  if (verbose) {
    console.log(`  Found ${tools.length} tools`);
  }

  const config: AssessmentConfiguration = {
    ...DEFAULT_ASSESSMENT_CONFIG,
    securityPatternsToTest: 17,
    reviewerMode: false,
    testTimeout: 30000,
  };

  const context: AssessmentContext = {
    serverName,
    tools,
    callTool: createCallToolWrapper(client),
    config,
  };

  if (verbose) {
    console.log(`  Running security assessment...`);
  }

  const assessor = new SecurityAssessor(config);
  const assessment = await assessor.assess(context);

  await client.close();

  return {
    serverName,
    totalTools: tools.length,
    testsRun: assessment.promptInjectionTests.length,
    vulnerabilitiesFound: assessment.vulnerabilities.length,
    assessment,
  };
}

/**
 * Calculate metrics for vulnerable server assessment
 */
function calculateVulnerableServerMetrics(
  result: ValidationResult,
): ValidationMetrics {
  // Get unique tools flagged as vulnerable
  const flaggedTools = [
    ...new Set(
      result.assessment.promptInjectionTests
        .filter((t) => t.vulnerable)
        .map((t) => t.toolName),
    ),
  ];

  // True positives: Vulnerable tools correctly flagged
  const detected = flaggedTools.filter((t) => VULNERABLE_TOOLS.includes(t));

  // False negatives: Vulnerable tools not flagged
  const missed = VULNERABLE_TOOLS.filter((t) => !flaggedTools.includes(t));

  // False positives: Safe tools incorrectly flagged
  const falsePositives = flaggedTools.filter((t) => SAFE_TOOLS.includes(t));

  // True negatives: Safe tools correctly not flagged
  const trueNegatives = SAFE_TOOLS.filter((t) => !flaggedTools.includes(t));

  const tp = detected.length;
  const fn = missed.length;
  const fp = falsePositives.length;
  const tn = trueNegatives.length;

  return {
    recall: tp / (tp + fn) || 0,
    precision: tp / (tp + fp) || 0,
    falsePositiveRate: fp / (fp + tn) || 0,
    falseNegativeRate: fn / (fn + tp) || 0,
    detected,
    missed,
    falsePositives,
  };
}

/**
 * Display validation results
 */
function displayResults(
  vulnResult: ValidationResult | null,
  hardResult: ValidationResult | null,
  vulnMetrics: ValidationMetrics | null,
) {
  console.log("\n" + "=".repeat(70));
  console.log("MCP INSPECTOR TESTBED VALIDATION RESULTS");
  console.log("=".repeat(70));

  if (vulnResult && vulnMetrics) {
    console.log("\n📊 VULNERABLE SERVER (localhost:10900)");
    console.log("-".repeat(50));
    console.log(`Tools Tested:           ${vulnResult.totalTools}`);
    console.log(`Tests Run:              ${vulnResult.testsRun}`);
    console.log(`Vulnerabilities Found:  ${vulnResult.vulnerabilitiesFound}`);
    console.log("");
    console.log(
      `Recall:                 ${(vulnMetrics.recall * 100).toFixed(1)}% (${vulnMetrics.detected.length}/${VULNERABLE_TOOLS.length} vulnerabilities detected)`,
    );
    console.log(
      `Precision:              ${(vulnMetrics.precision * 100).toFixed(1)}% (${vulnMetrics.falsePositives.length} false positives)`,
    );
    console.log(
      `False Positive Rate:    ${(vulnMetrics.falsePositiveRate * 100).toFixed(1)}%`,
    );
    console.log(
      `False Negative Rate:    ${(vulnMetrics.falseNegativeRate * 100).toFixed(1)}%`,
    );

    if (vulnMetrics.missed.length > 0) {
      console.log(
        `\n⚠️  Missed Vulnerabilities (${vulnMetrics.missed.length}):`,
      );
      for (const tool of vulnMetrics.missed) {
        console.log(`   - ${tool}`);
      }
    }

    if (vulnMetrics.falsePositives.length > 0) {
      console.log(
        `\n❌ False Positives (${vulnMetrics.falsePositives.length}):`,
      );
      for (const tool of vulnMetrics.falsePositives) {
        console.log(`   - ${tool}`);
      }
    }

    if (vulnMetrics.detected.length > 0) {
      console.log(`\n✅ Correctly Detected (${vulnMetrics.detected.length}):`);
      for (const tool of vulnMetrics.detected) {
        console.log(`   - ${tool}`);
      }
    }
  }

  if (hardResult) {
    console.log("\n📊 HARDENED SERVER (localhost:10901)");
    console.log("-".repeat(50));
    console.log(`Tools Tested:           ${hardResult.totalTools}`);
    console.log(`Tests Run:              ${hardResult.testsRun}`);
    console.log(`Vulnerabilities Found:  ${hardResult.vulnerabilitiesFound}`);
    console.log(`Expected:               0`);

    const hardenedFalsePositives = hardResult.assessment.promptInjectionTests
      .filter((t) => t.vulnerable)
      .map((t) => t.toolName);

    if (hardResult.vulnerabilitiesFound > 0) {
      console.log(`\n❌ False Positives on Hardened Server:`);
      const uniqueFPs = [...new Set(hardenedFalsePositives)];
      for (const tool of uniqueFPs) {
        console.log(`   - ${tool}`);
      }
    } else {
      console.log(`\n✅ No false positives on hardened server`);
    }
  }

  // Overall Status
  console.log("\n" + "=".repeat(70));
  console.log("OVERALL VALIDATION STATUS");
  console.log("=".repeat(70));

  const vulnPassed =
    vulnMetrics &&
    vulnMetrics.recall >= 0.8 &&
    vulnMetrics.falsePositives.length === 0;
  const hardPassed = hardResult && hardResult.vulnerabilitiesFound === 0;

  if (vulnPassed && hardPassed) {
    console.log("\n✅ PASS - Inspector meets accuracy targets\n");
    console.log("   Target: 80%+ recall, 0 false positives");
    console.log(
      `   Actual: ${vulnMetrics ? (vulnMetrics.recall * 100).toFixed(1) : 0}% recall, ${vulnMetrics?.falsePositives.length || 0} false positives`,
    );
  } else {
    console.log("\n❌ FAIL - Inspector needs improvement\n");
    if (vulnMetrics && vulnMetrics.recall < 0.8) {
      console.log(
        `   Recall too low: ${(vulnMetrics.recall * 100).toFixed(1)}% (target: 80%+)`,
      );
    }
    if (vulnMetrics && vulnMetrics.falsePositives.length > 0) {
      console.log(
        `   Has false positives: ${vulnMetrics.falsePositives.length} (target: 0)`,
      );
    }
    if (hardResult && hardResult.vulnerabilitiesFound > 0) {
      console.log(
        `   Hardened server flagged: ${hardResult.vulnerabilitiesFound} (target: 0)`,
      );
    }
  }

  console.log("=".repeat(70));
  console.log("");

  return vulnPassed && hardPassed;
}

/**
 * Save results to JSON
 */
function saveResults(
  vulnResult: ValidationResult | null,
  hardResult: ValidationResult | null,
  vulnMetrics: ValidationMetrics | null,
  outputPath?: string,
): string {
  const finalPath = outputPath || "/tmp/testbed-validation-results.json";

  const output = {
    timestamp: new Date().toISOString(),
    validationType: "testbed-validation",
    vulnerable: vulnResult
      ? {
          serverName: vulnResult.serverName,
          tools: vulnResult.totalTools,
          tests: vulnResult.testsRun,
          vulnerabilities: vulnResult.vulnerabilitiesFound,
          metrics: vulnMetrics,
        }
      : null,
    hardened: hardResult
      ? {
          serverName: hardResult.serverName,
          tools: hardResult.totalTools,
          tests: hardResult.testsRun,
          vulnerabilities: hardResult.vulnerabilitiesFound,
        }
      : null,
  };

  fs.writeFileSync(finalPath, JSON.stringify(output, null, 2));
  return finalPath;
}

/**
 * Parse arguments
 */
function parseArgs(): ValidationOptions {
  const args = process.argv.slice(2);
  const options: ValidationOptions = {
    verbose: false,
  };

  for (const arg of args) {
    switch (arg) {
      case "--verbose":
      case "-v":
        options.verbose = true;
        break;
      case "--help":
      case "-h":
        printHelp();
        process.exit(0);
        break;
      default:
        if (arg.startsWith("--output=")) {
          options.outputPath = arg.split("=")[1];
        }
    }
  }

  return options;
}

/**
 * Print help
 */
function printHelp() {
  console.log(`
Usage: mcp-validate-testbed [options]

Validate MCP Inspector SecurityAssessor against the reference Vulnerable Testbed.

Options:
  --verbose, -v        Enable verbose logging
  --output=<path>      Output JSON path (default: /tmp/testbed-validation-results.json)
  --help, -h           Show this help message

Prerequisites:
  Start the testbed containers before running:
    cd /home/bryan/mcp-servers/mcp-vulnerable-testbed && docker-compose up -d

Validation Targets:
  - Recall: 80%+ (at least 8/10 vulnerabilities detected)
  - Precision: 100% (0 false positives on safe tools)
  - Hardened: 0 vulnerabilities detected

Examples:
  mcp-validate-testbed
  mcp-validate-testbed --verbose
  mcp-validate-testbed --output=./validation-results.json
  `);
}

/**
 * Main execution
 */
async function main() {
  const options = parseArgs();

  console.log("\n🔍 MCP Inspector Testbed Validation");
  console.log("=".repeat(50));

  // Check server availability
  console.log("\nChecking testbed servers...");
  const vulnAvailable = await checkServerHealth(TESTBED_CONFIG.vulnerable.url);
  const hardAvailable = await checkServerHealth(TESTBED_CONFIG.hardened.url);

  if (!vulnAvailable && !hardAvailable) {
    console.error("\n❌ Testbed containers not running!");
    console.error("\nStart them with:");
    console.error("  cd /home/bryan/mcp-servers/mcp-vulnerable-testbed");
    console.error("  docker-compose up -d");
    process.exit(1);
  }

  let vulnResult: ValidationResult | null = null;
  let hardResult: ValidationResult | null = null;
  let vulnMetrics: ValidationMetrics | null = null;

  // Test vulnerable server
  if (vulnAvailable) {
    console.log("\n📡 Testing VULNERABLE server...");
    try {
      vulnResult = await assessServer(
        TESTBED_CONFIG.vulnerable.name,
        TESTBED_CONFIG.vulnerable.url,
        options.verbose,
      );
      vulnMetrics = calculateVulnerableServerMetrics(vulnResult);
    } catch (error) {
      console.error(
        "  Error:",
        error instanceof Error ? error.message : String(error),
      );
    }
  } else {
    console.log("⚠️  Vulnerable server not available - skipping");
  }

  // Test hardened server
  if (hardAvailable) {
    console.log("\n📡 Testing HARDENED server...");
    try {
      hardResult = await assessServer(
        TESTBED_CONFIG.hardened.name,
        TESTBED_CONFIG.hardened.url,
        options.verbose,
      );
    } catch (error) {
      console.error(
        "  Error:",
        error instanceof Error ? error.message : String(error),
      );
    }
  } else {
    console.log("⚠️  Hardened server not available - skipping");
  }

  // Display results
  const passed = displayResults(vulnResult, hardResult, vulnMetrics);

  // Save results
  const outputPath = saveResults(
    vulnResult,
    hardResult,
    vulnMetrics,
    options.outputPath,
  );
  console.log(`📄 Results saved to: ${outputPath}\n`);

  // Exit with appropriate code
  process.exit(passed ? 0 : 1);
}

main().catch((error) => {
  console.error(
    "\n❌ Fatal error:",
    error instanceof Error ? error.message : String(error),
  );
  process.exit(1);
});

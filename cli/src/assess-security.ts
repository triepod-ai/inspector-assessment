#!/usr/bin/env node

/**
 * Standalone Security Assessment Runner CLI
 *
 * Runs security assessment against an MCP server without the web UI.
 * Focuses on prompt injection and vulnerability testing.
 *
 * Usage:
 *   mcp-assess-security --server <server-name>
 *   mcp-assess-security --server broken-mcp --tool vulnerable_tool
 */

import * as fs from "fs";
import * as path from "path";
import { execSync } from "child_process";

// Import shared server config loading (Issue #84 - Zod validation)
import { loadServerConfig } from "./lib/assessment-runner/server-config.js";
import type { ServerConfig } from "./lib/cli-parser.js";

/**
 * Validate that a command is safe to execute
 * - Must be an absolute path or resolvable via PATH
 * - Must not contain shell metacharacters
 */
function validateCommand(command: string): void {
  // Check for shell metacharacters that could indicate injection
  const dangerousChars = /[;&|`$(){}[\]<>!\\]/;
  if (dangerousChars.test(command)) {
    throw new Error(
      `Invalid command: contains shell metacharacters: ${command}`,
    );
  }

  // Verify the command exists and is executable
  try {
    // Use 'which' on Unix-like systems, 'where' on Windows
    const whichCmd = process.platform === "win32" ? "where" : "which";
    execSync(`${whichCmd} "${command}"`, { stdio: "pipe" });
  } catch {
    // Check if it's an absolute path that exists
    if (path.isAbsolute(command) && fs.existsSync(command)) {
      try {
        fs.accessSync(command, fs.constants.X_OK);
        return; // Command exists and is executable
      } catch {
        throw new Error(`Command not executable: ${command}`);
      }
    }
    throw new Error(`Command not found: ${command}`);
  }
}

/**
 * Validate environment variables from config
 * - Keys must be valid env var names (alphanumeric + underscore)
 * - Values should not contain null bytes
 */
function validateEnvVars(
  env: Record<string, string> | undefined,
): Record<string, string> {
  if (!env) return {};

  const validatedEnv: Record<string, string> = {};
  const validKeyPattern = /^[a-zA-Z_][a-zA-Z0-9_]*$/;

  for (const [key, value] of Object.entries(env)) {
    // Validate key format
    if (!validKeyPattern.test(key)) {
      console.warn(
        `Skipping invalid environment variable name: ${key} (must match [a-zA-Z_][a-zA-Z0-9_]*)`,
      );
      continue;
    }

    // Check for null bytes in value (could truncate strings)
    if (typeof value === "string" && value.includes("\0")) {
      console.warn(`Skipping environment variable with null byte: ${key}`);
      continue;
    }

    validatedEnv[key] = String(value);
  }

  return validatedEnv;
}

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { SSEClientTransport } from "@modelcontextprotocol/sdk/client/sse.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import {
  Tool,
  CompatibilityCallToolResult,
} from "@modelcontextprotocol/sdk/types.js";

// Import from local client lib (will use package exports when published)
import { SecurityAssessor } from "../../client/lib/services/assessment/modules/SecurityAssessor.js";
import {
  AssessmentConfiguration,
  DEFAULT_ASSESSMENT_CONFIG,
  SecurityAssessment,
} from "../../client/lib/lib/assessmentTypes.js";
import { AssessmentContext } from "../../client/lib/services/assessment/AssessmentOrchestrator.js";
import { loadPerformanceConfig } from "../../client/lib/services/assessment/config/performanceConfig.js";

interface AssessmentOptions {
  serverName: string;
  serverConfigPath?: string;
  outputPath?: string;
  toolName?: string;
  verbose?: boolean;
  helpRequested?: boolean;
  /** Path to performance configuration JSON (Issue #37) */
  performanceConfigPath?: string;
}

/**
 * Connect to MCP server via configured transport
 */
async function connectToServer(config: ServerConfig): Promise<Client> {
  let transport;

  switch (config.transport) {
    case "http":
      if (!config.url) throw new Error("URL required for HTTP transport");
      transport = new StreamableHTTPClientTransport(new URL(config.url));
      break;

    case "sse":
      if (!config.url) throw new Error("URL required for SSE transport");
      transport = new SSEClientTransport(new URL(config.url));
      break;

    case "stdio":
    default:
      if (!config.command)
        throw new Error("Command required for stdio transport");

      // Validate command before execution to prevent injection attacks
      validateCommand(config.command);

      // Validate and sanitize environment variables from config
      const validatedEnv = validateEnvVars(config.env);

      transport = new StdioClientTransport({
        command: config.command,
        args: config.args,
        env: {
          ...(Object.fromEntries(
            Object.entries(process.env).filter(([, v]) => v !== undefined),
          ) as Record<string, string>),
          ...validatedEnv,
        },
        stderr: "pipe",
      });
      break;
  }

  const client = new Client(
    {
      name: "mcp-assess-security",
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
 * Get list of tools from MCP server
 */
async function getTools(
  client: Client,
  toolNameFilter?: string,
): Promise<Tool[]> {
  const response = await client.listTools();
  let tools = response.tools || [];

  if (toolNameFilter) {
    tools = tools.filter((t) => t.name === toolNameFilter);
    if (tools.length === 0) {
      throw new Error(`Tool not found: ${toolNameFilter}`);
    }
  }

  return tools;
}

/**
 * Create callTool wrapper for assessment context
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
 * Run security assessment
 */
async function runSecurityAssessment(
  options: AssessmentOptions,
): Promise<SecurityAssessment> {
  console.log(`\n🔍 Connecting to MCP server: ${options.serverName}`);

  const serverConfig = loadServerConfig(
    options.serverName,
    options.serverConfigPath,
  );

  // Load custom performance config if provided (Issue #37)
  // Note: Currently, modules use DEFAULT_PERFORMANCE_CONFIG directly.
  // This validates the config file but doesn't override runtime values yet.
  if (options.performanceConfigPath) {
    try {
      const performanceConfig = loadPerformanceConfig(
        options.performanceConfigPath,
      );
      console.log(
        `📊 Performance config loaded from: ${options.performanceConfigPath}`,
      );
      console.log(
        `   Batch interval: ${performanceConfig.batchFlushIntervalMs}ms, ` +
          `Security batch: ${performanceConfig.securityBatchSize}`,
      );
      // TODO: Wire performanceConfig through to SecurityAssessor
    } catch (error) {
      console.error(
        `❌ Failed to load performance config: ${error instanceof Error ? error.message : String(error)}`,
      );
      throw error;
    }
  }

  const client = await connectToServer(serverConfig);
  console.log("✅ Connected successfully");

  const tools = await getTools(client, options.toolName);
  console.log(`🔧 Found ${tools.length} tool${tools.length !== 1 ? "s" : ""}`);

  if (options.toolName) {
    console.log(`   Testing only: ${options.toolName}`);
  }

  const config: AssessmentConfiguration = {
    ...DEFAULT_ASSESSMENT_CONFIG,
    securityPatternsToTest: 17,
    reviewerMode: false,
    testTimeout: 30000,
  };

  const context: AssessmentContext = {
    serverName: options.serverName,
    tools,
    callTool: createCallToolWrapper(client),
    config,
  };

  console.log(`🛡️  Running security assessment with 23 attack patterns...`);
  const assessor = new SecurityAssessor(config);
  const results = await assessor.assess(context);

  await client.close();

  return results;
}

/**
 * Save results to JSON file
 */
function saveResults(
  serverName: string,
  results: SecurityAssessment,
  outputPath?: string,
): string {
  const defaultPath = `/tmp/inspector-security-assessment-${serverName}.json`;
  const finalPath = outputPath || defaultPath;

  const output = {
    timestamp: new Date().toISOString(),
    assessmentType: "security",
    serverName,
    security: results,
  };

  fs.writeFileSync(finalPath, JSON.stringify(output, null, 2));

  return finalPath;
}

/**
 * Display summary
 */
function displaySummary(results: SecurityAssessment) {
  const { promptInjectionTests, vulnerabilities, overallRiskLevel } = results;

  const vulnerableCount = promptInjectionTests.filter(
    (t) => t.vulnerable,
  ).length;
  const totalTests = promptInjectionTests.length;

  console.log("\n" + "=".repeat(60));
  console.log("SECURITY ASSESSMENT RESULTS");
  console.log("=".repeat(60));
  console.log(`Total Tests: ${totalTests}`);
  console.log(`Vulnerabilities Found: ${vulnerableCount}`);
  console.log(`Overall Risk Level: ${overallRiskLevel}`);
  console.log("=".repeat(60));

  if (vulnerableCount > 0) {
    console.log("\n⚠️  VULNERABILITIES DETECTED:\n");

    const vulnerableTests = promptInjectionTests.filter((t) => t.vulnerable);

    for (const test of vulnerableTests) {
      console.log(`🚨 ${test.toolName} - ${test.testName}`);
      console.log(`   Risk: ${test.riskLevel}`);
      console.log(`   Evidence: ${test.evidence}`);
      console.log("");
    }
  } else {
    console.log("\n✅ No vulnerabilities detected\n");
  }
}

/**
 * Parse command-line arguments
 */
function parseArgs(): AssessmentOptions {
  const args = process.argv.slice(2);
  const options: Partial<AssessmentOptions> = {};

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (!arg) continue;

    switch (arg) {
      case "--server":
      case "-s":
        options.serverName = args[++i];
        break;
      case "--config":
      case "-c":
        options.serverConfigPath = args[++i];
        break;
      case "--output":
      case "-o":
        options.outputPath = args[++i];
        break;
      case "--tool":
      case "-t":
        options.toolName = args[++i];
        break;
      case "--verbose":
      case "-v":
        options.verbose = true;
        break;
      case "--performance-config":
        options.performanceConfigPath = args[++i];
        break;
      case "--help":
      case "-h":
        printHelp();
        options.helpRequested = true;
        return options as AssessmentOptions;
      default:
        if (!arg.startsWith("-")) {
          if (!options.serverName) {
            options.serverName = arg;
          }
        } else {
          console.error(`Unknown argument: ${arg}`);
          printHelp();
          setTimeout(() => process.exit(1), 10);
          options.helpRequested = true;
          return options as AssessmentOptions;
        }
    }
  }

  if (!options.serverName) {
    console.error("Error: --server is required");
    printHelp();
    setTimeout(() => process.exit(1), 10);
    options.helpRequested = true;
    return options as AssessmentOptions;
  }

  return options as AssessmentOptions;
}

/**
 * Print help message
 */
function printHelp() {
  console.log(`
Usage: mcp-assess-security [options] [server-name]

Run security assessment against an MCP server with 23 attack patterns.

Options:
  --server, -s <name>    Server name (required, or pass as first positional arg)
  --config, -c <path>    Path to server config JSON
  --output, -o <path>    Output JSON path (default: /tmp/inspector-security-assessment-<server>.json)
  --tool, -t <name>      Test only specific tool (default: test all tools)
  --performance-config <path>  Path to performance tuning JSON (batch sizes, timeouts, etc.)
  --verbose, -v          Enable verbose logging
  --help, -h             Show this help message

Attack Patterns Tested (23 total):
  • Command Injection, SQL Injection, Path Traversal
  • Calculator Injection, Code Execution, XXE
  • Data Exfiltration, Token Theft, NoSQL Injection
  • Unicode Bypass, Nested Injection, Package Squatting
  • And more...

Examples:
  mcp-assess-security my-server
  mcp-assess-security --server broken-mcp --tool vulnerable_calculator_tool
  mcp-assess-security --server my-server --output ./security-results.json
  `);
}

/**
 * Main execution
 */
async function main() {
  try {
    const options = parseArgs();

    if (options.helpRequested) {
      return;
    }

    const results = await runSecurityAssessment(options);

    displaySummary(results);

    const outputPath = saveResults(
      options.serverName,
      results,
      options.outputPath,
    );
    console.log(`📄 Results saved to: ${outputPath}\n`);

    const exitCode = results.vulnerabilities.length > 0 ? 1 : 0;
    setTimeout(() => process.exit(exitCode), 10);
  } catch (error) {
    console.error(
      "\n❌ Error:",
      error instanceof Error ? error.message : String(error),
    );
    if (error instanceof Error && error.stack && process.env.DEBUG) {
      console.error("\nStack trace:");
      console.error(error.stack);
    }
    setTimeout(() => process.exit(1), 10);
  }
}

main();

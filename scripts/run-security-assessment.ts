#!/usr/bin/env ts-node

/**
 * Standalone Security Assessment Runner
 *
 * Runs security assessment against an MCP server without the web UI.
 * Does NOT modify core assessment modules - preserves upstream sync compatibility.
 *
 * Usage:
 *   npm run assess -- --server <server-name>
 *   ts-node scripts/run-security-assessment.ts --server broken-mcp
 */

import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import { EventEmitter } from "events";

// Increase max listeners to prevent warning during security testing
// Security assessment runs 234+ sequential tool calls (tools × 13 patterns × payloads)
EventEmitter.defaultMaxListeners = 300;
process.setMaxListeners(300);

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { SSEClientTransport } from "@modelcontextprotocol/sdk/client/sse.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import {
  Tool,
  CompatibilityCallToolResult,
} from "@modelcontextprotocol/sdk/types.js";

// Import assessment modules WITHOUT modification
import { SecurityAssessor } from "../client/src/services/assessment/modules/SecurityAssessor.js";
import {
  AssessmentConfiguration,
  DEFAULT_ASSESSMENT_CONFIG,
  SecurityAssessment,
} from "../client/src/lib/assessmentTypes.js";
import { AssessmentContext } from "../client/src/services/assessment/AssessmentOrchestrator.js";

interface ServerConfig {
  transport?: "stdio" | "http" | "sse";
  // For stdio transport
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  // For HTTP/SSE transport
  url?: string;
}

interface AssessmentOptions {
  serverName: string;
  serverConfigPath?: string;
  outputPath?: string;
  toolName?: string; // Optional: test only specific tool
  verbose?: boolean;
}

/**
 * Load server configuration from Claude Code's MCP settings
 */
function loadServerConfig(
  serverName: string,
  configPath?: string,
): ServerConfig {
  const defaultConfigPath = path.join(
    os.homedir(),
    ".config",
    "mcp",
    "servers",
    `${serverName}.json`,
  );
  const finalPath = configPath || defaultConfigPath;

  if (!fs.existsSync(finalPath)) {
    throw new Error(`Server config not found: ${finalPath}`);
  }

  const config = JSON.parse(fs.readFileSync(finalPath, "utf-8"));

  // Support both stdio and HTTP/SSE transports
  if (config.url || config.transport === "http" || config.transport === "sse") {
    if (!config.url) {
      throw new Error(
        `Invalid server config: transport is '${config.transport}' but 'url' is missing`,
      );
    }
    return {
      transport: config.transport || "http",
      url: config.url,
    };
  }

  // Default to stdio transport
  if (!config.command) {
    throw new Error(`Invalid server config: missing 'command' or 'url' field`);
  }

  return {
    transport: "stdio",
    command: config.command,
    args: config.args || [],
    env: config.env || {},
  };
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
      transport = new StdioClientTransport({
        command: config.command,
        args: config.args,
        env: {
          ...process.env,
          ...config.env,
        },
        stderr: "pipe",
      });
      break;
  }

  const client = new Client(
    {
      name: "inspector-security-assessment",
      version: "0.17.0",
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

      // Convert SDK response to CompatibilityCallToolResult
      return {
        content: response.content,
        isError: response.isError || false,
        structuredContent: (response as any).structuredContent,
      };
    } catch (error) {
      // Return error as CompatibilityCallToolResult
      return {
        content: [
          {
            type: "text",
            text: `Error: ${error instanceof Error ? error.message : String(error)}`,
          },
        ],
        isError: true,
      };
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

  // Load server configuration
  const serverConfig = loadServerConfig(
    options.serverName,
    options.serverConfigPath,
  );

  // Connect to server
  const client = await connectToServer(serverConfig);
  console.log("✅ Connected successfully");

  // Get tools
  const tools = await getTools(client, options.toolName);
  console.log(`🔧 Found ${tools.length} tool${tools.length !== 1 ? "s" : ""}`);

  if (options.toolName) {
    console.log(`   Testing only: ${options.toolName}`);
  }

  // Create assessment context
  const config: AssessmentConfiguration = {
    ...DEFAULT_ASSESSMENT_CONFIG,
    securityPatternsToTest: 17, // All 17 attack patterns
    reviewerMode: false,
    testTimeout: 30000,
  };

  const context: AssessmentContext = {
    serverName: options.serverName,
    tools,
    callTool: createCallToolWrapper(client),
    config,
  };

  // Run security assessment
  console.log(`🛡️  Running security assessment with 17 attack patterns...`);
  const assessor = new SecurityAssessor(config);
  const results = await assessor.assess(context);

  // Close connection
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
  const defaultPath = `/tmp/inspector-assessment-${serverName}.json`;
  const finalPath = outputPath || defaultPath;

  const output = {
    timestamp: new Date().toISOString(),
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
      case "--help":
      case "-h":
        printHelp();
        process.exit(0);
      default:
        console.error(`Unknown argument: ${arg}`);
        printHelp();
        process.exit(1);
    }
  }

  if (!options.serverName) {
    console.error("Error: --server is required");
    printHelp();
    process.exit(1);
  }

  return options as AssessmentOptions;
}

/**
 * Print help message
 */
function printHelp() {
  console.log(`
Usage: npm run assess -- [options]

Options:
  --server, -s <name>      Server name (required)
  --config, -c <path>      Path to server config JSON (default: ~/.config/mcp/servers/<name>.json)
  --output, -o <path>      Output JSON path (default: /tmp/inspector-assessment-<server>.json)
  --tool, -t <name>        Test only specific tool (default: test all tools)
  --verbose, -v            Enable verbose logging
  --help, -h               Show this help message

Examples:
  npm run assess -- --server broken-mcp
  npm run assess -- --server broken-mcp --tool vulnerable_calculator_tool
  npm run assess -- --server my-server --output ./results.json
  `);
}

/**
 * Main execution
 */
async function main() {
  try {
    const options = parseArgs();

    // Run assessment
    const results = await runSecurityAssessment(options);

    // Display summary
    displaySummary(results);

    // Save results
    const outputPath = saveResults(
      options.serverName,
      results,
      options.outputPath,
    );
    console.log(`📄 Results saved to: ${outputPath}\n`);

    // Exit with appropriate code
    const exitCode = results.vulnerabilities.length > 0 ? 1 : 0;
    process.exit(exitCode);
  } catch (error) {
    console.error(
      "\n❌ Error:",
      error instanceof Error ? error.message : String(error),
    );
    if (error instanceof Error && error.stack) {
      console.error("\nStack trace:");
      console.error(error.stack);
    }
    process.exit(1);
  }
}

// Run if executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  main();
}

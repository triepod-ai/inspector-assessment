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
import { execSync } from "child_process";
import { ScopedListenerConfig } from "../cli/src/lib/event-config.js";

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

/**
 * Safely parse JSON with error handling
 */
function safeJsonParse<T>(content: string, filePath: string): T {
  try {
    return JSON.parse(content) as T;
  } catch (error) {
    throw new Error(
      `Failed to parse JSON from ${filePath}: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

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
// Import ClaudeCodeBridge for semantic analysis
import {
  ClaudeCodeBridge,
  HTTP_CLAUDE_CODE_CONFIG,
} from "../client/src/services/assessment/lib/claudeCodeBridge.js";
import { AUPComplianceAssessor } from "../client/src/services/assessment/modules/AUPComplianceAssessor.js";
import { FunctionalityAssessor } from "../client/src/services/assessment/modules/FunctionalityAssessor.js";
import { DocumentationAssessor } from "../client/src/services/assessment/modules/DocumentationAssessor.js";
import { ErrorHandlingAssessor } from "../client/src/services/assessment/modules/ErrorHandlingAssessor.js";
import { UsabilityAssessor } from "../client/src/services/assessment/modules/UsabilityAssessor.js";
import { ProtocolComplianceAssessor } from "../client/src/services/assessment/modules/ProtocolComplianceAssessor.js";
import { ToolAnnotationAssessor } from "../client/src/services/assessment/modules/ToolAnnotationAssessor.js";
import { ProhibitedLibrariesAssessor } from "../client/src/services/assessment/modules/ProhibitedLibrariesAssessor.js";
import { ManifestValidationAssessor } from "../client/src/services/assessment/modules/ManifestValidationAssessor.js";
import { PortabilityAssessor } from "../client/src/services/assessment/modules/PortabilityAssessor.js";
import { ExternalAPIScannerAssessor } from "../client/src/services/assessment/modules/ExternalAPIScannerAssessor.js";
import { TemporalAssessor } from "../client/src/services/assessment/modules/TemporalAssessor.js";
import { BaseAssessor } from "../client/src/services/assessment/modules/BaseAssessor.js";
import {
  AssessmentConfiguration,
  DEFAULT_ASSESSMENT_CONFIG,
  SecurityAssessment,
  AUPComplianceAssessment,
} from "../client/src/lib/assessmentTypes.js";
import { AssessmentContext } from "../client/src/services/assessment/AssessmentOrchestrator.js";

// ============================================================================
// MODULE REGISTRY
// ============================================================================

/**
 * Registry of all available assessment modules
 * Maps module names to their assessor classes
 */
const MODULE_REGISTRY: Record<
  string,
  new (config: AssessmentConfiguration) => BaseAssessor
> = {
  security: SecurityAssessor,
  aupCompliance: AUPComplianceAssessor,
  functionality: FunctionalityAssessor,
  documentation: DocumentationAssessor,
  errorHandling: ErrorHandlingAssessor,
  usability: UsabilityAssessor,
  mcpSpec: ProtocolComplianceAssessor, // Unified protocol compliance (was MCPSpecComplianceAssessor)
  toolAnnotations: ToolAnnotationAssessor,
  prohibitedLibraries: ProhibitedLibrariesAssessor,
  manifestValidation: ManifestValidationAssessor,
  portability: PortabilityAssessor,
  externalAPIScanner: ExternalAPIScannerAssessor,
  temporal: TemporalAssessor,
};

/**
 * Default modules to run when no --module flag is specified
 */
const DEFAULT_MODULES = ["security", "aupCompliance"];

/**
 * Modules that require callTool (runtime testing vs static analysis)
 */
const RUNTIME_MODULES = new Set([
  "security",
  "functionality",
  "errorHandling",
  "mcpSpec",
  "temporal",
]);

/**
 * Estimate number of tests per module
 */
function estimateModuleTests(moduleName: string, toolCount: number): number {
  const estimates: Record<string, number> = {
    security: toolCount * 53, // 23 patterns × ~2.3 payloads avg
    aupCompliance: 4, // 4 scan locations (names, descriptions, readme, source)
    functionality: toolCount * 5, // ~5 scenarios per tool
    documentation: 10, // Fixed checks
    errorHandling: toolCount * 8, // ~8 error scenarios per tool
    usability: toolCount * 3, // ~3 usability checks per tool
    mcpSpec: toolCount * 4, // ~4 spec checks per tool
    toolAnnotations: toolCount * 5, // ~5 annotation checks per tool
    prohibitedLibraries: 1, // Single scan
    manifestValidation: 1, // Single validation
    portability: 3, // ~3 portability checks
    externalAPIScanner: toolCount * 2, // ~2 scans per tool
    temporal: toolCount * 3, // ~3 temporal checks per tool
  };
  return estimates[moduleName] || toolCount;
}

/**
 * Module display names for console output
 */
const MODULE_DISPLAY_NAMES: Record<string, string> = {
  security: "Security Assessment",
  aupCompliance: "AUP Compliance",
  functionality: "Functionality Testing",
  documentation: "Documentation Quality",
  errorHandling: "Error Handling",
  usability: "Usability",
  mcpSpec: "Protocol Compliance", // Unified (was MCP Spec Compliance)
  toolAnnotations: "Tool Annotations",
  prohibitedLibraries: "Prohibited Libraries",
  manifestValidation: "Manifest Validation",
  portability: "Portability",
  externalAPIScanner: "External API Scanner",
  temporal: "Temporal/Rug Pull Detection",
};

/**
 * Module status icons
 */
function getStatusIcon(status: string): string {
  switch (status) {
    case "PASS":
      return "✅";
    case "FAIL":
      return "❌";
    case "NEED_MORE_INFO":
      return "⚠️";
    default:
      return "❓";
  }
}

// Import JSONL event helpers from shared module
import {
  emitServerConnected,
  emitToolDiscovered,
  emitToolsDiscoveryComplete,
  emitAssessmentComplete,
  emitTestBatch,
  emitModuleStarted,
  emitModuleComplete,
  emitVulnerabilityFound,
  emitAnnotationMissing,
  emitAnnotationMisaligned,
  emitAnnotationReviewRecommended,
  emitAnnotationAligned,
  buildAUPEnrichment,
  calculateModuleScore,
} from "./lib/jsonl-events.js";
import type { ProgressEvent } from "../client/src/lib/assessmentTypes.js";

// ============================================================================

export interface ServerConfig {
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
  runAUP?: boolean; // DEPRECATED: use --module instead
  modules?: string[]; // Optional: specific modules to run (default: security,aupCompliance)
  enableClaude?: boolean; // Enable Claude semantic analysis via mcp-auditor
  mcpAuditorUrl?: string; // mcp-auditor URL (default: http://localhost:8085)
}

/**
 * Load server configuration from Claude Code's MCP settings
 * @exported for unit testing
 */
export function loadServerConfig(
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

  const rawConfig = safeJsonParse<Record<string, unknown>>(
    fs.readFileSync(finalPath, "utf-8"),
    finalPath,
  );

  // Support nested mcpServers structure (Claude Desktop format)
  let config = rawConfig;
  if (rawConfig.mcpServers && typeof rawConfig.mcpServers === "object") {
    const mcpServers = rawConfig.mcpServers as Record<string, unknown>;
    if (mcpServers[serverName] && typeof mcpServers[serverName] === "object") {
      config = mcpServers[serverName] as Record<string, unknown>;
    } else if (Object.keys(mcpServers).length > 0) {
      const availableServers = Object.keys(mcpServers).join(", ");
      throw new Error(
        `Server '${serverName}' not found in mcpServers. Available: ${availableServers}`,
      );
    }
  }

  // Support both stdio and HTTP/SSE transports
  if (config.url || config.transport === "http" || config.transport === "sse") {
    if (!config.url) {
      throw new Error(
        `Invalid server config: transport is '${config.transport}' but 'url' is missing`,
      );
    }
    return {
      transport: (config.transport as "http" | "sse") || "http",
      url: config.url as string,
    };
  }

  // Default to stdio transport
  if (!config.command) {
    throw new Error(`Invalid server config: missing 'command' or 'url' field`);
  }

  return {
    transport: "stdio",
    command: config.command as string,
    args: (config.args as string[]) || [],
    env: (config.env as Record<string, string>) || {},
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

      // Validate command before execution to prevent injection attacks
      validateCommand(config.command);

      // Validate and sanitize environment variables from config
      const validatedEnv = validateEnvVars(config.env);

      transport = new StdioClientTransport({
        command: config.command,
        args: config.args,
        env: {
          ...process.env,
          ...validatedEnv,
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

      // Cast to CompatibilityCallToolResult - SDK types may have evolved
      return {
        content: response.content,
        isError: response.isError || false,
        structuredContent: (response as any).structuredContent,
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
 * Display AUP summary
 */
function displayAUPSummary(results: AUPComplianceAssessment) {
  console.log("\n" + "=".repeat(60));
  console.log("AUP COMPLIANCE RESULTS");
  console.log("=".repeat(60));
  console.log(`Status: ${results.status}`);
  console.log(`Violations Found: ${results.violations.length}`);
  console.log(`High-Risk Domains: ${results.highRiskDomains.length}`);
  console.log("=".repeat(60));

  if (results.violations.length > 0) {
    console.log("\n⚠️  AUP VIOLATIONS DETECTED:\n");

    for (const v of results.violations) {
      const severityIcon =
        v.severity === "CRITICAL"
          ? "🛑"
          : v.severity === "HIGH"
            ? "🚨"
            : v.severity === "MEDIUM"
              ? "⚠️"
              : "📋";
      console.log(
        `${severityIcon} Category ${v.category} (${v.categoryName}) - ${v.severity}`,
      );
      console.log(`   Location: ${v.location}`);
      console.log(`   Matched: "${v.matchedText}"`);
      console.log(`   Pattern: ${v.pattern}`);
      if (v.reviewGuidance) {
        console.log(`   Guidance: ${v.reviewGuidance}`);
      }
      console.log("");
    }
  } else {
    console.log("\n✅ No AUP violations detected\n");
  }

  if (results.highRiskDomains.length > 0) {
    console.log(
      `📋 High-risk domains: ${results.highRiskDomains.join(", ")}\n`,
    );
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
      case "--aup":
        // DEPRECATED: Keep for backward compatibility
        options.runAUP = true;
        break;
      case "--claude":
        options.enableClaude = true;
        break;
      case "--mcp-auditor-url":
        options.mcpAuditorUrl = args[++i];
        break;
      case "--module":
      case "-m":
        options.modules = args[++i].split(",").map((m) => m.trim());
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

  // Handle module selection
  if (options.modules) {
    // Handle "all" keyword
    if (options.modules.includes("all")) {
      options.modules = Object.keys(MODULE_REGISTRY);
    } else {
      // Validate module names
      const invalidModules = options.modules.filter((m) => !MODULE_REGISTRY[m]);
      if (invalidModules.length > 0) {
        console.error(`Error: Unknown module(s): ${invalidModules.join(", ")}`);
        console.error(
          `Available modules: ${Object.keys(MODULE_REGISTRY).join(", ")}`,
        );
        process.exit(1);
      }
    }
  } else if (options.runAUP) {
    // DEPRECATED --aup flag: equivalent to security + aupCompliance
    options.modules = ["security", "aupCompliance"];
  } else {
    // Default modules
    options.modules = DEFAULT_MODULES;
  }

  // Environment variable fallbacks for Claude semantic analysis
  options.enableClaude =
    options.enableClaude ?? process.env.INSPECTOR_CLAUDE === "true";
  options.mcpAuditorUrl =
    options.mcpAuditorUrl ??
    process.env.INSPECTOR_MCP_AUDITOR_URL ??
    "http://localhost:8085";

  return options as AssessmentOptions;
}

/**
 * Print help message
 */
function printHelp() {
  const moduleList = Object.keys(MODULE_REGISTRY).join(", ");

  console.log(`
Usage: npm run assess -- [options]

Options:
  --server, -s <name>      Server name (required)
  --config, -c <path>      Path to server config JSON (default: ~/.config/mcp/servers/<name>.json)
  --output, -o <path>      Output JSON path (default: /tmp/inspector-assessment-<server>.json)
  --tool, -t <name>        Test only specific tool (default: test all tools)
  --module, -m <names>     Modules to run, comma-separated (default: security,aupCompliance)
                           Available: ${moduleList}
                           Use "all" to run all modules
  --claude                 Enable Claude semantic analysis via mcp-auditor
  --mcp-auditor-url <url>  mcp-auditor URL (default: http://localhost:8085)
  --aup                    [DEPRECATED] Use --module security,aupCompliance instead
  --verbose, -v            Enable verbose logging
  --help, -h               Show this help message

Environment Variables:
  INSPECTOR_CLAUDE=true      Enable Claude semantic analysis
  INSPECTOR_MCP_AUDITOR_URL  mcp-auditor URL (overridden by --mcp-auditor-url)

Examples:
  npm run assess -- --server my-server                           # default: security + aupCompliance
  npm run assess -- --server my-server --module security         # security only
  npm run assess -- --server my-server --module aupCompliance    # AUP only
  npm run assess -- --server my-server --module security,functionality
  npm run assess -- --server my-server --module all              # run all 13 modules
  npm run assess -- --server my-server --tool calc --module functionality
  npm run assess -- --server my-server --claude                  # with Claude semantic analysis
  INSPECTOR_CLAUDE=true npm run assess -- --server my-server     # via env var
  `);
}

// ============================================================================
// MODULE EXECUTION
// ============================================================================

/**
 * Combined assessment result structure
 */
interface CombinedAssessmentResults {
  timestamp: string;
  serverName: string;
  modulesRun: string[];
  modules: Record<string, unknown>;
  summary: {
    totalModules: number;
    passed: number;
    failed: number;
    needMoreInfo: number;
    overallStatus: "PASS" | "FAIL" | "NEED_MORE_INFO";
    totalTests: number;
    totalDuration: number;
  };
}

/**
 * Run a single assessment module
 */
async function runModule(
  moduleName: string,
  context: AssessmentContext & { claudeBridge?: ClaudeCodeBridge | null },
  config: AssessmentConfiguration,
): Promise<{
  result: unknown;
  status: string;
  testsRun: number;
  duration: number;
}> {
  const AssessorClass = MODULE_REGISTRY[moduleName];
  if (!AssessorClass) {
    throw new Error(`Unknown module: ${moduleName}`);
  }

  const displayName = MODULE_DISPLAY_NAMES[moduleName] || moduleName;
  console.log(`\n📋 Running ${displayName}...`);

  // Emit module started event
  const estimatedTests = estimateModuleTests(moduleName, context.tools.length);
  emitModuleStarted(moduleName, estimatedTests, context.tools.length);

  const startTime = Date.now();

  // Create assessor and run
  const assessor = new AssessorClass(config);

  // Wire ClaudeCodeBridge for security module when enabled
  if (moduleName === "security" && context.claudeBridge) {
    (assessor as SecurityAssessor).setClaudeBridge(context.claudeBridge);
  }

  const result = await assessor.assess(context);

  const duration = Date.now() - startTime;
  const testsRun = assessor.getTestCount?.() || estimatedTests;

  // Determine status from result
  const status = (result as { status?: string }).status || "PASS";

  // Calculate score using shared scoring logic
  const score = calculateModuleScore(result);

  // Build enrichment for AUP module
  let enrichment;
  if (moduleName === "aupCompliance" && result) {
    enrichment = buildAUPEnrichment(
      result as Parameters<typeof buildAUPEnrichment>[0],
    );
  }

  // Emit module complete event (skip for modules excluded via --skip-modules)
  if (score !== null) {
    emitModuleComplete(
      moduleName,
      status as "PASS" | "FAIL" | "NEED_MORE_INFO",
      score,
      testsRun,
      duration,
      enrichment,
    );
  }

  // Display module result
  console.log(`   ${getStatusIcon(status)} ${displayName}: ${status}`);

  return { result, status, testsRun, duration };
}

/**
 * Display summary for security results
 */
function displaySecuritySummary(results: SecurityAssessment) {
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

    for (const test of vulnerableTests.slice(0, 10)) {
      console.log(`🚨 ${test.toolName} - ${test.testName}`);
      console.log(`   Risk: ${test.riskLevel}`);
      console.log(`   Evidence: ${test.evidence}`);
      console.log("");
    }

    if (vulnerableTests.length > 10) {
      console.log(
        `   ... and ${vulnerableTests.length - 10} more vulnerabilities\n`,
      );
    }
  } else {
    console.log("\n✅ No vulnerabilities detected\n");
  }
}

/**
 * Display combined assessment summary
 */
function displayCombinedSummary(results: CombinedAssessmentResults) {
  console.log("\n" + "=".repeat(60));
  console.log("ASSESSMENT SUMMARY");
  console.log("=".repeat(60));
  console.log(`Server: ${results.serverName}`);
  console.log(`Modules Run: ${results.modulesRun.join(", ")}`);
  console.log(`Total Modules: ${results.summary.totalModules}`);
  console.log(`  Passed: ${results.summary.passed}`);
  console.log(`  Failed: ${results.summary.failed}`);
  console.log(`  Need More Info: ${results.summary.needMoreInfo}`);
  console.log(
    `Overall Status: ${getStatusIcon(results.summary.overallStatus)} ${results.summary.overallStatus}`,
  );
  console.log(`Total Tests: ${results.summary.totalTests}`);
  console.log(
    `Total Duration: ${(results.summary.totalDuration / 1000).toFixed(2)}s`,
  );
  console.log("=".repeat(60));
}

/**
 * Main execution
 */
async function main() {
  const startTime = Date.now();

  // Use scoped listener configuration instead of global modification
  // See GitHub Issue #33 for rationale
  const listenerConfig = new ScopedListenerConfig(50);

  try {
    const options = parseArgs();
    const modules = options.modules!; // Always set by parseArgs

    // Apply scoped listener configuration for assessment
    listenerConfig.apply();

    console.log(`\n🔍 Connecting to MCP server: ${options.serverName}`);
    console.log(`📦 Modules to run: ${modules.join(", ")}`);

    // Load server configuration
    const serverConfig = loadServerConfig(
      options.serverName,
      options.serverConfigPath,
    );

    // Connect to server
    const client = await connectToServer(serverConfig);
    console.log("✅ Connected successfully");

    // Emit server_connected JSONL event
    emitServerConnected(options.serverName, serverConfig.transport || "stdio");

    // Get tools
    const tools = await getTools(client, options.toolName);
    console.log(
      `🔧 Found ${tools.length} tool${tools.length !== 1 ? "s" : ""}`,
    );

    // Emit tool_discovered JSONL events for each tool
    for (const tool of tools) {
      emitToolDiscovered(tool);
    }
    emitToolsDiscoveryComplete(tools.length);

    if (options.toolName) {
      console.log(`   Testing only: ${options.toolName}`);
    }

    // Create assessment configuration
    const config: AssessmentConfiguration = {
      ...DEFAULT_ASSESSMENT_CONFIG,
      securityPatternsToTest: 17,
      reviewerMode: false,
      testTimeout: 30000,
      enableSourceCodeAnalysis: false, // CLI doesn't have source code access
    };

    // Progress callback to emit JSONL events
    const onProgress = (event: ProgressEvent): void => {
      if (event.type === "test_batch") {
        emitTestBatch(
          event.module,
          event.completed,
          event.total,
          event.batchSize,
          event.elapsed,
        );
      } else if (event.type === "vulnerability_found") {
        emitVulnerabilityFound(
          event.tool,
          event.pattern,
          event.confidence,
          event.evidence,
          event.riskLevel,
          event.requiresReview,
          event.payload,
        );
      } else if (event.type === "annotation_missing") {
        emitAnnotationMissing(
          event.tool,
          event.title,
          event.description,
          event.parameters || [],
          event.inferredBehavior,
        );
      } else if (event.type === "annotation_misaligned") {
        emitAnnotationMisaligned(
          event.tool,
          event.title,
          event.description,
          event.parameters || [],
          event.field,
          event.actual,
          event.expected,
          event.confidence,
          event.reason,
        );
      } else if (event.type === "annotation_review_recommended") {
        emitAnnotationReviewRecommended(
          event.tool,
          event.title,
          event.description,
          event.parameters || [],
          event.field,
          event.actual,
          event.inferred,
          event.confidence,
          event.isAmbiguous,
          event.reason,
        );
      } else if (event.type === "annotation_aligned") {
        emitAnnotationAligned(event.tool, event.confidence, event.annotations);
      }
    };

    // Initialize ClaudeCodeBridge for semantic analysis if enabled
    let claudeBridge: ClaudeCodeBridge | null = null;

    if (options.enableClaude) {
      console.log(
        `🧠 Initializing Claude semantic analysis via ${options.mcpAuditorUrl}...`,
      );

      const bridgeConfig = {
        ...HTTP_CLAUDE_CODE_CONFIG,
        httpConfig: {
          baseUrl: options.mcpAuditorUrl!,
        },
      };

      claudeBridge = new ClaudeCodeBridge(bridgeConfig);

      // Health check
      const isHealthy = await claudeBridge.checkHttpHealth();
      if (!isHealthy) {
        console.warn(
          "⚠️ mcp-auditor not available - running without semantic analysis",
        );
        claudeBridge = null;
      } else {
        console.log("✅ Claude semantic analysis enabled");
      }
    }

    // Create assessment context (extended with optional claudeBridge)
    const context: AssessmentContext & {
      claudeBridge?: ClaudeCodeBridge | null;
    } = {
      serverName: options.serverName,
      tools,
      callTool: createCallToolWrapper(client),
      config,
      onProgress,
      claudeBridge,
    };

    // Run each requested module
    const moduleResults: Record<string, unknown> = {};
    const moduleStatuses: string[] = [];
    let totalTests = 0;
    let totalDuration = 0;

    for (const moduleName of modules) {
      try {
        const { result, status, testsRun, duration } = await runModule(
          moduleName,
          context,
          config,
        );
        moduleResults[moduleName] = result;
        moduleStatuses.push(status);
        totalTests += testsRun;
        totalDuration += duration;

        // Display detailed results for security module
        if (moduleName === "security" && result) {
          displaySecuritySummary(result as SecurityAssessment);

          // Report semantic analysis stats if Claude was enabled
          if (context.claudeBridge) {
            const secResult = result as SecurityAssessment;
            const refinedCount = secResult.promptInjectionTests.filter(
              (t) =>
                (t as { semanticAnalysis?: unknown }).semanticAnalysis !==
                undefined,
            ).length;

            if (refinedCount > 0) {
              console.log(
                `🧠 ${refinedCount} test(s) refined with Claude semantic analysis`,
              );
            }
          }
        }

        // Display detailed results for AUP module
        if (moduleName === "aupCompliance" && result) {
          displayAUPSummary(result as AUPComplianceAssessment);
        }
      } catch (moduleError) {
        console.error(`\n❌ Error running ${moduleName}: ${moduleError}`);
        moduleResults[moduleName] = {
          status: "FAIL",
          error:
            moduleError instanceof Error
              ? moduleError.message
              : String(moduleError),
        };
        moduleStatuses.push("FAIL");
      }
    }

    // Close connection
    await client.close();

    // Calculate summary
    const passed = moduleStatuses.filter((s) => s === "PASS").length;
    const failed = moduleStatuses.filter((s) => s === "FAIL").length;
    const needMoreInfo = moduleStatuses.filter(
      (s) => s === "NEED_MORE_INFO",
    ).length;
    const overallStatus: "PASS" | "FAIL" | "NEED_MORE_INFO" =
      failed > 0 ? "FAIL" : needMoreInfo > 0 ? "NEED_MORE_INFO" : "PASS";

    // Build combined results
    const combinedResults: CombinedAssessmentResults = {
      timestamp: new Date().toISOString(),
      serverName: options.serverName,
      modulesRun: modules,
      modules: moduleResults,
      summary: {
        totalModules: modules.length,
        passed,
        failed,
        needMoreInfo,
        overallStatus,
        totalTests,
        totalDuration,
      },
    };

    // Display combined summary
    displayCombinedSummary(combinedResults);

    // Save results
    const defaultPath = `/tmp/inspector-assessment-${options.serverName}.json`;
    const finalPath = options.outputPath || defaultPath;

    fs.writeFileSync(finalPath, JSON.stringify(combinedResults, null, 2));

    // Emit assessment_complete JSONL event
    emitAssessmentComplete(
      overallStatus,
      totalTests,
      Date.now() - startTime,
      finalPath,
    );

    console.log(`📄 Results saved to: ${finalPath}\n`);

    // Exit with appropriate code
    process.exit(failed > 0 ? 1 : 0);
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
  } finally {
    // Restore original listener configuration
    listenerConfig.restore();
  }
}

// Run if executed directly (skip during Jest testing)
// Use require.main check which works in both CJS and ESM contexts
if (
  typeof process.env.JEST_WORKER_ID === "undefined" &&
  typeof require !== "undefined" &&
  require.main === module
) {
  main();
}

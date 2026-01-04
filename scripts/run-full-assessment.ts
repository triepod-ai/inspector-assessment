#!/usr/bin/env ts-node

/**
 * @deprecated This script is deprecated. Use `npm run assess:full` instead.
 *
 * Full Assessment Runner (LEGACY)
 *
 * This script has been superseded by the npm CLI binary which has additional
 * features including:
 * - Resource/Prompt capability assessment
 * - Pre-flight validation mode
 * - Comparison/diff modes
 * - State management/resume
 * - Policy compliance reports
 * - Markdown output format
 *
 * Migration:
 *   OLD: npm run assess:full:legacy -- --server <name> --config <path>
 *   NEW: npm run assess:full -- --server <name> --config <path>
 *
 * The legacy script is available via `npm run assess:full:legacy` during
 * the transition period but will be removed in a future release.
 */

// Emit deprecation warning
console.warn(
  "\x1b[33m" + // Yellow color
    "⚠️  DEPRECATION WARNING: scripts/run-full-assessment.ts is deprecated.\n" +
    "   Use `npm run assess:full` instead for the full-featured CLI.\n" +
    "   This legacy script will be removed in a future release.\n" +
    "   See: https://github.com/triepod-ai/inspector-assessment/issues/19\x1b[0m\n",
);

import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import { EventEmitter } from "events";

// Increase max listeners to prevent warning during security testing
// Full assessment runs 234+ sequential tool calls (6 tools × 13 patterns × 3 payloads)
// Each call may add listeners to the underlying socket
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

// Import assessment orchestrator
import {
  AssessmentOrchestrator,
  AssessmentContext,
} from "../client/src/services/assessment/AssessmentOrchestrator.js";
import {
  AssessmentConfiguration,
  DEFAULT_ASSESSMENT_CONFIG,
  MCPDirectoryAssessment,
  ManifestJsonSchema,
  ASSESSMENT_CATEGORY_METADATA,
  getAllModulesConfig,
} from "../client/src/lib/assessmentTypes.js";
import { FULL_CLAUDE_CODE_CONFIG } from "../client/src/services/assessment/lib/claudeCodeBridge.js";

// Import JSONL event helpers from shared module
import {
  emitServerConnected,
  emitToolDiscovered,
  emitToolsDiscoveryComplete,
  emitAssessmentComplete,
  emitTestBatch,
  emitVulnerabilityFound,
  emitAnnotationMissing,
  emitAnnotationMisaligned,
  emitAnnotationReviewRecommended,
  emitAnnotationAligned,
  emitModulesConfigured,
} from "./lib/jsonl-events.js";
import type { ProgressEvent } from "../client/src/lib/assessmentTypes.js";

// ============================================================================

// Valid module names derived from ASSESSMENT_CATEGORY_METADATA
const VALID_MODULE_NAMES = Object.keys(
  ASSESSMENT_CATEGORY_METADATA,
) as (keyof typeof ASSESSMENT_CATEGORY_METADATA)[];

/**
 * Validate module names from CLI input
 */
function validateModuleNames(input: string, flagName: string): string[] {
  const names = input
    .split(",")
    .map((n) => n.trim())
    .filter(Boolean);
  const invalid = names.filter(
    (n) =>
      !VALID_MODULE_NAMES.includes(
        n as keyof typeof ASSESSMENT_CATEGORY_METADATA,
      ),
  );

  if (invalid.length > 0) {
    console.error(
      `Error: Invalid module name(s) for ${flagName}: ${invalid.join(", ")}`,
    );
    console.error(`Valid modules: ${VALID_MODULE_NAMES.join(", ")}`);
    setTimeout(() => process.exit(1), 10);
    return [];
  }
  return names;
}

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
  sourceCodePath?: string;
  patternConfigPath?: string;
  claudeEnabled?: boolean;
  fullAssessment?: boolean;
  verbose?: boolean;
  jsonOnly?: boolean;
  helpRequested?: boolean;
  skipModules?: string[];
  onlyModules?: string[];
}

/**
 * Load server configuration from Claude Code's MCP settings
 */
function loadServerConfig(
  serverName: string,
  configPath?: string,
): ServerConfig {
  // Try multiple config locations
  const possiblePaths = [
    configPath,
    path.join(os.homedir(), ".config", "mcp", "servers", `${serverName}.json`),
    path.join(os.homedir(), ".config", "claude", "claude_desktop_config.json"),
  ].filter(Boolean) as string[];

  for (const tryPath of possiblePaths) {
    if (!fs.existsSync(tryPath)) continue;

    const config = JSON.parse(fs.readFileSync(tryPath, "utf-8"));

    // Handle Claude Desktop config format (or mcpServers wrapper)
    if (config.mcpServers && config.mcpServers[serverName]) {
      const serverConfig = config.mcpServers[serverName];

      // Check if serverConfig specifies http/sse transport
      if (
        serverConfig.url ||
        serverConfig.transport === "http" ||
        serverConfig.transport === "sse"
      ) {
        if (!serverConfig.url) {
          throw new Error(
            `Invalid server config: transport is '${serverConfig.transport}' but 'url' is missing`,
          );
        }
        return {
          transport: serverConfig.transport || "http",
          url: serverConfig.url,
        };
      }

      // Default to stdio transport
      return {
        transport: "stdio",
        command: serverConfig.command,
        args: serverConfig.args || [],
        env: serverConfig.env || {},
      };
    }

    // Direct server config format
    if (
      config.url ||
      config.transport === "http" ||
      config.transport === "sse"
    ) {
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

    if (config.command) {
      return {
        transport: "stdio",
        command: config.command,
        args: config.args || [],
        env: config.env || {},
      };
    }
  }

  throw new Error(
    `Server config not found for: ${serverName}\nTried: ${possiblePaths.join(", ")}`,
  );
}

/**
 * Load optional files from source code path
 */
function loadSourceFiles(sourcePath: string): {
  readmeContent?: string;
  packageJson?: unknown;
  manifestJson?: ManifestJsonSchema;
  manifestRaw?: string;
  sourceCodeFiles?: Map<string, string>;
} {
  const result: any = {};

  // Search for README in source directory and parent directories (up to 3 levels)
  // This handles cases where --source points to a subdirectory but README is at repo root
  const readmePaths = ["README.md", "readme.md", "Readme.md"];
  let readmeFound = false;

  // First try the source directory itself
  for (const readmePath of readmePaths) {
    const fullPath = path.join(sourcePath, readmePath);
    if (fs.existsSync(fullPath)) {
      result.readmeContent = fs.readFileSync(fullPath, "utf-8");
      readmeFound = true;
      break;
    }
  }

  // If not found, search parent directories (up to 3 levels)
  if (!readmeFound) {
    let currentDir = sourcePath;
    for (let i = 0; i < 3; i++) {
      const parentDir = path.dirname(currentDir);
      if (parentDir === currentDir) break; // Reached filesystem root

      for (const readmePath of readmePaths) {
        const fullPath = path.join(parentDir, readmePath);
        if (fs.existsSync(fullPath)) {
          result.readmeContent = fs.readFileSync(fullPath, "utf-8");
          readmeFound = true;
          break;
        }
      }
      if (readmeFound) break;
      currentDir = parentDir;
    }
  }

  // Load package.json
  const packagePath = path.join(sourcePath, "package.json");
  if (fs.existsSync(packagePath)) {
    result.packageJson = JSON.parse(fs.readFileSync(packagePath, "utf-8"));
  }

  // Load manifest.json (MCPB bundle)
  const manifestPath = path.join(sourcePath, "manifest.json");
  if (fs.existsSync(manifestPath)) {
    result.manifestRaw = fs.readFileSync(manifestPath, "utf-8");
    try {
      result.manifestJson = JSON.parse(result.manifestRaw);
    } catch {
      console.warn("[Assessment] Failed to parse manifest.json");
    }
  }

  // Load source code files for deep analysis
  result.sourceCodeFiles = new Map<string, string>();
  // Include config files for portability analysis
  const sourceExtensions = [
    ".ts",
    ".js",
    ".py",
    ".go",
    ".rs",
    ".json",
    ".sh",
    ".yaml",
    ".yml",
  ];

  // Parse .gitignore patterns
  const gitignorePatterns: RegExp[] = [];
  const gitignorePath = path.join(sourcePath, ".gitignore");
  if (fs.existsSync(gitignorePath)) {
    const gitignoreContent = fs.readFileSync(gitignorePath, "utf-8");
    for (const line of gitignoreContent.split("\n")) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#")) continue;
      // Convert gitignore pattern to regex
      const pattern = trimmed
        .replace(/\./g, "\\.")
        .replace(/\*\*/g, ".*")
        .replace(/\*/g, "[^/]*")
        .replace(/\?/g, ".");
      try {
        gitignorePatterns.push(new RegExp(pattern));
      } catch {
        // Skip invalid patterns
      }
    }
  }

  const isGitignored = (relativePath: string): boolean => {
    return gitignorePatterns.some((pattern) => pattern.test(relativePath));
  };

  const loadSourceDir = (dir: string, prefix: string = "") => {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      if (entry.name.startsWith(".") || entry.name === "node_modules") continue;

      const fullPath = path.join(dir, entry.name);
      const relativePath = prefix ? `${prefix}/${entry.name}` : entry.name;

      // Skip gitignored files
      if (isGitignored(relativePath)) continue;

      if (entry.isDirectory()) {
        loadSourceDir(fullPath, relativePath);
      } else if (sourceExtensions.some((ext) => entry.name.endsWith(ext))) {
        try {
          const content = fs.readFileSync(fullPath, "utf-8");
          if (content.length < 100000) {
            // Skip very large files
            result.sourceCodeFiles.set(relativePath, content);
          }
        } catch {
          // Skip unreadable files
        }
      }
    }
  };

  try {
    loadSourceDir(sourcePath);
  } catch (e) {
    console.warn("[Assessment] Could not load source files:", e);
  }

  return result;
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
      name: "inspector-full-assessment",
      version: "2.0.0",
    },
    {
      capabilities: {},
    },
  );

  await client.connect(transport);

  return client;
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
 * Build assessment configuration
 */
function buildConfig(options: AssessmentOptions): AssessmentConfiguration {
  const config: AssessmentConfiguration = {
    ...DEFAULT_ASSESSMENT_CONFIG,
    enableExtendedAssessment: options.fullAssessment !== false,
    parallelTesting: true,
    testTimeout: 30000,
  };

  // Enable all assessment categories for full assessment
  if (options.fullAssessment !== false) {
    // Derive module config from ASSESSMENT_CATEGORY_METADATA (single source of truth)
    const allModules = getAllModulesConfig({
      sourceCodePath: Boolean(options.sourceCodePath),
      skipTemporal: options.skipTemporal,
    });

    // Apply --only-modules filter (whitelist mode)
    if (options.onlyModules?.length) {
      for (const key of Object.keys(allModules)) {
        // Disable all modules except those in the whitelist
        allModules[key] = options.onlyModules.includes(key);
      }
    }

    // Apply --skip-modules filter (blacklist mode)
    if (options.skipModules?.length) {
      for (const module of options.skipModules) {
        if (module in allModules) {
          allModules[module] = false;
        }
      }
    }

    config.assessmentCategories =
      allModules as AssessmentConfiguration["assessmentCategories"];
  }

  // Enable Claude Code integration if requested
  if (options.claudeEnabled) {
    // Build ClaudeCodeConfig with required properties (not optional)
    config.claudeCode = {
      enabled: true,
      timeout: FULL_CLAUDE_CODE_CONFIG.timeout || 60000,
      maxRetries: FULL_CLAUDE_CODE_CONFIG.maxRetries || 2,
      features: {
        intelligentTestGeneration: true,
        aupSemanticAnalysis: true,
        annotationInference: true,
        documentationQuality: true,
      },
    };
  }

  // Pass custom annotation pattern config path
  if (options.patternConfigPath) {
    config.patternConfigPath = options.patternConfigPath;
  }

  return config;
}

/**
 * Run full assessment
 */
async function runFullAssessment(
  options: AssessmentOptions,
): Promise<MCPDirectoryAssessment> {
  if (!options.jsonOnly) {
    console.log(`\n🔍 Starting full assessment for: ${options.serverName}`);
  }

  // Load server configuration
  const serverConfig = loadServerConfig(
    options.serverName,
    options.serverConfigPath,
  );

  if (!options.jsonOnly) {
    console.log("✅ Server config loaded");
  }

  // Connect to server
  const client = await connectToServer(serverConfig);
  if (!options.jsonOnly) {
    console.log("✅ Connected to MCP server");
  }

  // Emit server_connected JSONL event
  emitServerConnected(options.serverName, serverConfig.transport || "stdio");

  // Get tools
  const response = await client.listTools();
  const tools = response.tools || [];
  if (!options.jsonOnly) {
    console.log(
      `🔧 Found ${tools.length} tool${tools.length !== 1 ? "s" : ""}`,
    );
  }

  // Emit tool_discovered JSONL events for each tool
  for (const tool of tools) {
    emitToolDiscovered(tool);
  }
  emitToolsDiscoveryComplete(tools.length);

  // Build configuration
  const config = buildConfig(options);

  // Emit modules_configured event for consumer progress tracking
  if (config.assessmentCategories) {
    const enabled: string[] = [];
    const skipped: string[] = [];
    for (const [key, value] of Object.entries(config.assessmentCategories)) {
      if (value) {
        enabled.push(key);
      } else {
        skipped.push(key);
      }
    }
    const reason = options.onlyModules?.length
      ? "only-modules"
      : options.skipModules?.length
        ? "skip-modules"
        : "default";
    emitModulesConfigured(enabled, skipped, reason);
  }

  // Create orchestrator
  const orchestrator = new AssessmentOrchestrator(config);

  if (!options.jsonOnly) {
    if (orchestrator.isClaudeEnabled()) {
      console.log("🤖 Claude Code integration enabled");
    } else if (options.claudeEnabled) {
      console.log("⚠️  Claude Code requested but not available");
    }
  }

  // Load source files if path provided
  let sourceFiles = {};
  if (options.sourceCodePath && fs.existsSync(options.sourceCodePath)) {
    sourceFiles = loadSourceFiles(options.sourceCodePath);
    if (!options.jsonOnly) {
      console.log(`📁 Loaded source files from: ${options.sourceCodePath}`);
    }
  }

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
        event.parameters,
        event.inferredBehavior,
      );
    } else if (event.type === "annotation_misaligned") {
      emitAnnotationMisaligned(
        event.tool,
        event.title,
        event.description,
        event.parameters,
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
        event.parameters,
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
    // module_started and module_complete are handled by orchestrator directly
  };

  // Build assessment context
  const context: AssessmentContext = {
    serverName: options.serverName,
    tools,
    callTool: createCallToolWrapper(client),
    listTools: async () => {
      const response = await client.listTools();
      return response.tools;
    },
    config,
    sourceCodePath: options.sourceCodePath,
    onProgress,
    ...sourceFiles,
  };

  // Run assessment
  if (!options.jsonOnly) {
    console.log(
      `\n🏃 Running assessment with ${Object.keys(config.assessmentCategories || {}).length} modules...`,
    );
    console.log("");
  }

  const results = await orchestrator.runFullAssessment(context);

  // Close connection
  await client.close();

  return results;
}

/**
 * Save results to JSON file
 */
function saveResults(
  serverName: string,
  results: MCPDirectoryAssessment,
  outputPath?: string,
): string {
  const defaultPath = `/tmp/inspector-full-assessment-${serverName}.json`;
  const finalPath = outputPath || defaultPath;

  // Filter out undefined/skipped modules from results (--skip-modules support)
  const filteredResults = Object.fromEntries(
    Object.entries(results).filter(([_, v]) => v !== undefined),
  );

  const output = {
    timestamp: new Date().toISOString(),
    assessmentType: "full",
    ...filteredResults,
  };

  fs.writeFileSync(finalPath, JSON.stringify(output, null, 2));

  return finalPath;
}

/**
 * Display summary
 */
function displaySummary(results: MCPDirectoryAssessment) {
  const {
    overallStatus,
    summary,
    totalTestsRun,
    executionTime,
    // Destructuring order matches display order below
    functionality,
    security,
    documentation,
    errorHandling,
    usability,
    mcpSpecCompliance,
    aupCompliance,
    toolAnnotations,
    prohibitedLibraries,
    manifestValidation,
    portability,
    externalAPIScanner,
    authentication,
    temporal,
    resources,
    prompts,
    crossCapability,
  } = results;

  console.log("\n" + "=".repeat(70));
  console.log("FULL ASSESSMENT RESULTS");
  console.log("=".repeat(70));
  console.log(`Server: ${results.serverName}`);
  console.log(`Overall Status: ${overallStatus}`);
  console.log(`Total Tests Run: ${totalTestsRun}`);
  console.log(`Execution Time: ${executionTime}ms`);
  console.log("-".repeat(70));

  // Module status summary
  console.log("\n📊 MODULE STATUS:");
  const modules: [string, any, string][] = [
    ["Functionality", functionality, "functionality"],
    ["Security", security, "security"],
    ["Documentation", documentation, "documentation"],
    ["Error Handling", errorHandling, "errorHandling"],
    ["Usability", usability, "usability"],
    ["MCP Spec Compliance", mcpSpecCompliance, "mcpSpecCompliance"],
    ["AUP Compliance", aupCompliance, "aupCompliance"],
    ["Tool Annotations", toolAnnotations, "toolAnnotations"],
    ["Prohibited Libraries", prohibitedLibraries, "prohibitedLibraries"],
    ["Manifest Validation", manifestValidation, "manifestValidation"],
    ["Portability", portability, "portability"],
    ["External API Scanner", externalAPIScanner, "externalAPIScanner"],
    ["Authentication", authentication, "authentication"],
    ["Temporal", temporal, "temporal"],
    ["Resources", resources, "resources"],
    ["Prompts", prompts, "prompts"],
    ["Cross-Capability", crossCapability, "crossCapability"],
  ];

  for (const [name, module, categoryKey] of modules) {
    if (module) {
      const metadata = ASSESSMENT_CATEGORY_METADATA[categoryKey];
      const optionalMarker = metadata?.tier === "optional" ? " (optional)" : "";
      const icon =
        module.status === "PASS"
          ? "✅"
          : module.status === "FAIL"
            ? "❌"
            : "⚠️";
      console.log(`   ${icon} ${name}${optionalMarker}: ${module.status}`);
    }
  }

  // Key findings
  console.log("\n📋 KEY FINDINGS:");
  console.log(`   ${summary}`);

  // Security vulnerabilities
  if (security?.vulnerabilities?.length > 0) {
    console.log(
      `\n🔒 SECURITY VULNERABILITIES (${security.vulnerabilities.length}):`,
    );
    for (const vuln of security.vulnerabilities.slice(0, 5)) {
      console.log(`   • ${vuln}`);
    }
    if (security.vulnerabilities.length > 5) {
      console.log(`   ... and ${security.vulnerabilities.length - 5} more`);
    }
  }

  // AUP issues
  if (aupCompliance?.violations?.length > 0) {
    const critical = aupCompliance.violations.filter(
      (v: any) => v.severity === "CRITICAL",
    );
    console.log(`\n⚖️  AUP FINDINGS:`);
    console.log(`   Total flagged: ${aupCompliance.violations.length}`);
    if (critical.length > 0) {
      console.log(`   🚨 CRITICAL violations: ${critical.length}`);
    }
  }

  // Tool annotations
  if (toolAnnotations) {
    console.log(`\n🏷️  TOOL ANNOTATIONS:`);
    console.log(
      `   Annotated: ${toolAnnotations.annotatedCount || 0}/${functionality?.workingTools || 0}`,
    );
    if (toolAnnotations.missingAnnotationsCount > 0) {
      console.log(`   Missing: ${toolAnnotations.missingAnnotationsCount}`);
    }
    if (toolAnnotations.misalignedAnnotationsCount > 0) {
      console.log(
        `   ⚠️  Misalignments: ${toolAnnotations.misalignedAnnotationsCount}`,
      );
    }
  }

  // Recommendations
  if (results.recommendations?.length > 0) {
    console.log("\n💡 RECOMMENDATIONS:");
    for (const rec of results.recommendations.slice(0, 5)) {
      console.log(`   • ${rec}`);
    }
  }

  console.log("\n" + "=".repeat(70));
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
      case "--source":
        options.sourceCodePath = args[++i];
        break;
      case "--pattern-config":
      case "-p":
        options.patternConfigPath = args[++i];
        break;
      case "--claude-enabled":
        options.claudeEnabled = true;
        break;
      case "--full":
        options.fullAssessment = true;
        break;
      case "--verbose":
      case "-v":
        options.verbose = true;
        break;
      case "--json":
        options.jsonOnly = true;
        break;
      case "--skip-modules": {
        const skipValue = args[++i];
        if (!skipValue) {
          console.error(
            "Error: --skip-modules requires a comma-separated list",
          );
          setTimeout(() => process.exit(1), 10);
          options.helpRequested = true;
          return options as AssessmentOptions;
        }
        options.skipModules = validateModuleNames(skipValue, "--skip-modules");
        if (options.skipModules.length === 0 && skipValue) {
          options.helpRequested = true;
          return options as AssessmentOptions;
        }
        break;
      }
      case "--only-modules": {
        const onlyValue = args[++i];
        if (!onlyValue) {
          console.error(
            "Error: --only-modules requires a comma-separated list",
          );
          setTimeout(() => process.exit(1), 10);
          options.helpRequested = true;
          return options as AssessmentOptions;
        }
        options.onlyModules = validateModuleNames(onlyValue, "--only-modules");
        if (options.onlyModules.length === 0 && onlyValue) {
          options.helpRequested = true;
          return options as AssessmentOptions;
        }
        break;
      }
      case "--help":
      case "-h":
        printHelp();
        options.helpRequested = true;
        return options as AssessmentOptions;
      default:
        if (!arg.startsWith("-")) {
          // Assume it's the server name if not an option
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

  // Validate mutual exclusivity of --skip-modules and --only-modules
  if (options.skipModules?.length && options.onlyModules?.length) {
    console.error(
      "Error: --skip-modules and --only-modules are mutually exclusive",
    );
    setTimeout(() => process.exit(1), 10);
    options.helpRequested = true;
    return options as AssessmentOptions;
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
Usage: npm run assess:full -- [options] [server-name]

Run comprehensive MCP server assessment with all 11 assessor modules.

Options:
  --server, -s <name>    Server name (required, or pass as first positional arg)
  --config, -c <path>    Path to server config JSON
  --output, -o <path>    Output JSON path (default: /tmp/inspector-full-assessment-<server>.json)
  --source <path>        Source code path for deep analysis (AUP, portability, etc.)
  --pattern-config, -p <path>  Path to custom annotation pattern JSON
  --claude-enabled       Enable Claude Code integration for intelligent analysis
  --full                 Enable all assessment modules (default)
  --skip-modules <list>  Skip specific modules (comma-separated)
  --only-modules <list>  Run only specific modules (comma-separated)
  --json                 Output only JSON (no console summary)
  --verbose, -v          Enable verbose logging
  --help, -h             Show this help message

Module Selection:
  --skip-modules and --only-modules are mutually exclusive.
  Use --skip-modules for faster runs by disabling expensive modules.
  Use --only-modules to focus on specific areas (e.g., tool annotation PRs).

  Valid module names:
    functionality, security, documentation, errorHandling, usability,
    mcpSpecCompliance, aupCompliance, toolAnnotations, prohibitedLibraries,
    manifestValidation, portability, temporal, resources, prompts, crossCapability

Assessment Modules (16 total):
  • Functionality      - Tests all tools work correctly
  • Security           - Prompt injection & vulnerability testing
  • Documentation      - README completeness checks
  • Error Handling     - Validates error responses
  • Usability          - Input validation & UX
  • MCP Spec           - Protocol compliance
  • AUP Compliance     - Acceptable Use Policy checks
  • Tool Annotations   - readOnlyHint/destructiveHint validation
  • Prohibited Libs    - Dependency security checks
  • Manifest           - MCPB manifest.json validation
  • Portability        - Cross-platform compatibility

Examples:
  npm run assess:full -- my-server
  npm run assess:full -- --server broken-mcp --claude-enabled
  npm run assess:full -- --server my-server --source ./my-server --output ./results.json

  # Module selection examples:
  npm run assess:full -- my-server --skip-modules security,aupCompliance    # Fast CI run
  npm run assess:full -- my-server --only-modules functionality,toolAnnotations  # Annotation PR review
  `);
}

/**
 * Main execution
 */
async function main() {
  try {
    const options = parseArgs();

    // If help was requested, just exit cleanly
    if (options.helpRequested) {
      return;
    }

    // Run assessment
    const results = await runFullAssessment(options);

    // Display summary (unless JSON only)
    if (!options.jsonOnly) {
      displaySummary(results);
    }

    // Save results
    const outputPath = saveResults(
      options.serverName,
      results,
      options.outputPath,
    );

    // Emit assessment_complete JSONL event
    emitAssessmentComplete(
      results.overallStatus,
      results.totalTestsRun,
      results.executionTime,
      outputPath,
    );

    if (options.jsonOnly) {
      // Output just the JSON file path for piping
      console.log(outputPath);
    } else {
      console.log(`📄 Results saved to: ${outputPath}\n`);
    }

    // Exit with appropriate code (use setTimeout to avoid tsx/esbuild issue with Node 24)
    const exitCode = results.overallStatus === "FAIL" ? 1 : 0;
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

// Run if executed directly
main();

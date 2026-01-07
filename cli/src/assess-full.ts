#!/usr/bin/env node

/**
 * Full Assessment Runner CLI
 *
 * Runs comprehensive MCP server assessment using AssessmentOrchestrator
 * with all 17 assessor modules and optional Claude Code integration.
 *
 * Usage:
 *   mcp-assess-full --server <server-name> [--claude-enabled] [--full]
 *   mcp-assess-full my-server --source ./my-server --output ./results.json
 */

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
import { CompatibilityCallToolResult } from "@modelcontextprotocol/sdk/types.js";

// Import from local client lib (will use package exports when published)
import {
  AssessmentOrchestrator,
  AssessmentContext,
} from "../../client/lib/services/assessment/AssessmentOrchestrator.js";
import {
  AssessmentConfiguration,
  DEFAULT_ASSESSMENT_CONFIG,
  MCPDirectoryAssessment,
  ManifestJsonSchema,
  ProgressEvent,
  ASSESSMENT_CATEGORY_METADATA,
  getAllModulesConfig,
  LogLevel,
} from "../../client/lib/lib/assessmentTypes.js";
import { FULL_CLAUDE_CODE_CONFIG } from "../../client/lib/services/assessment/lib/claudeCodeBridge.js";
import {
  createFormatter,
  type ReportFormat,
} from "../../client/lib/lib/reportFormatters/index.js";
import { generatePolicyComplianceReport } from "../../client/lib/services/assessment/PolicyComplianceGenerator.js";
import { compareAssessments } from "../../client/lib/lib/assessmentDiffer.js";
import { formatDiffAsMarkdown } from "../../client/lib/lib/reportFormatters/DiffReportFormatter.js";
import { AssessmentStateManager } from "./assessmentState.js";
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
  command?: string;
  args?: string[];
  env?: Record<string, string>;
  cwd?: string;
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
  format?: ReportFormat;
  includePolicy?: boolean;
  preflightOnly?: boolean;
  comparePath?: string;
  diffOnly?: boolean;
  resume?: boolean;
  noResume?: boolean;
  temporalInvocations?: number;
  skipTemporal?: boolean;
  skipModules?: string[];
  onlyModules?: string[];
  /** Log level for diagnostic output */
  logLevel?: LogLevel;
}

/**
 * Load server configuration from Claude Code's MCP settings
 */
function loadServerConfig(
  serverName: string,
  configPath?: string,
): ServerConfig {
  const possiblePaths = [
    configPath,
    path.join(os.homedir(), ".config", "mcp", "servers", `${serverName}.json`),
    path.join(os.homedir(), ".config", "claude", "claude_desktop_config.json"),
  ].filter(Boolean) as string[];

  for (const tryPath of possiblePaths) {
    if (!fs.existsSync(tryPath)) continue;

    const config = JSON.parse(fs.readFileSync(tryPath, "utf-8"));

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
        cwd: serverConfig.cwd,
      };
    }

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
  const result: Record<string, unknown> = {};

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

  const packagePath = path.join(sourcePath, "package.json");
  if (fs.existsSync(packagePath)) {
    result.packageJson = JSON.parse(fs.readFileSync(packagePath, "utf-8"));
  }

  const manifestPath = path.join(sourcePath, "manifest.json");
  if (fs.existsSync(manifestPath)) {
    result.manifestRaw = fs.readFileSync(manifestPath, "utf-8");
    try {
      result.manifestJson = JSON.parse(result.manifestRaw as string);
    } catch {
      console.warn("[Assessment] Failed to parse manifest.json");
    }
  }

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
            (result.sourceCodeFiles as Map<string, string>).set(
              relativePath,
              content,
            );
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

  return result as {
    readmeContent?: string;
    packageJson?: unknown;
    manifestJson?: ManifestJsonSchema;
    manifestRaw?: string;
    sourceCodeFiles?: Map<string, string>;
  };
}

/**
 * Connect to MCP server via configured transport
 */
async function connectToServer(config: ServerConfig): Promise<Client> {
  let transport;
  let stderrData = ""; // Capture stderr for error reporting

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
          ...(Object.fromEntries(
            Object.entries(process.env).filter(([, v]) => v !== undefined),
          ) as Record<string, string>),
          ...config.env,
        },
        cwd: config.cwd,
        stderr: "pipe",
      });

      // Capture stderr BEFORE connecting - critical for error context
      // The MCP SDK creates a PassThrough stream immediately when stderr: "pipe"
      // is set, allowing us to attach listeners before start() is called
      const stderrStream = (transport as StdioClientTransport).stderr;
      if (stderrStream) {
        stderrStream.on("data", (data: Buffer) => {
          stderrData += data.toString();
        });
      }
      break;
  }

  const client = new Client(
    {
      name: "mcp-assess-full",
      version: "1.0.0",
    },
    {
      capabilities: {},
    },
  );

  try {
    await client.connect(transport);
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);

    // Provide helpful context when connection fails
    if (stderrData.trim()) {
      throw new Error(
        `Failed to connect to MCP server: ${errorMessage}\n\n` +
          `Server stderr:\n${stderrData.trim()}\n\n` +
          `Common causes:\n` +
          `  - Missing environment variables (check .env file)\n` +
          `  - Required external services not running\n` +
          `  - Missing API credentials`,
      );
    }
    throw new Error(`Failed to connect to MCP server: ${errorMessage}`);
  }

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
 * Build assessment configuration
 */
function buildConfig(options: AssessmentOptions): AssessmentConfiguration {
  const config: AssessmentConfiguration = {
    ...DEFAULT_ASSESSMENT_CONFIG,
    enableExtendedAssessment: options.fullAssessment !== false,
    parallelTesting: true,
    testTimeout: 30000,
    enableSourceCodeAnalysis: Boolean(options.sourceCodePath),
  };

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

  // Temporal/rug pull detection configuration
  if (options.temporalInvocations) {
    config.temporalInvocations = options.temporalInvocations;
  }

  if (options.claudeEnabled) {
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

  // Logging configuration
  // Precedence: CLI flags > LOG_LEVEL env var > default (info)
  const envLogLevel = process.env.LOG_LEVEL as LogLevel | undefined;
  const logLevel = options.logLevel ?? envLogLevel ?? "info";
  config.logging = { level: logLevel };

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

  const serverConfig = loadServerConfig(
    options.serverName,
    options.serverConfigPath,
  );

  if (!options.jsonOnly) {
    console.log("✅ Server config loaded");
  }

  const client = await connectToServer(serverConfig);
  emitServerConnected(options.serverName, serverConfig.transport || "stdio");
  if (!options.jsonOnly) {
    console.log("✅ Connected to MCP server");
  }

  // Capture server info from initialization for protocol conformance checks
  const serverInfo = client.getServerVersion();
  const serverCapabilities = client.getServerCapabilities();

  const response = await client.listTools();
  const tools = response.tools || [];

  // Emit JSONL tool discovery events for audit-worker parsing
  for (const tool of tools) {
    emitToolDiscovered(tool);
  }
  emitToolsDiscoveryComplete(tools.length);

  if (!options.jsonOnly) {
    console.log(
      `🔧 Found ${tools.length} tool${tools.length !== 1 ? "s" : ""}`,
    );
  }

  // Fetch resources for new capability assessments
  let resources: {
    uri: string;
    name?: string;
    description?: string;
    mimeType?: string;
  }[] = [];
  let resourceTemplates: {
    uriTemplate: string;
    name?: string;
    description?: string;
    mimeType?: string;
  }[] = [];
  try {
    const resourcesResponse = await client.listResources();
    resources = (resourcesResponse.resources || []).map((r) => ({
      uri: r.uri,
      name: r.name,
      description: r.description,
      mimeType: r.mimeType,
    }));
    // resourceTemplates may be typed as unknown in some SDK versions
    const templates = (
      resourcesResponse as {
        resourceTemplates?: Array<{
          uriTemplate: string;
          name?: string;
          description?: string;
          mimeType?: string;
        }>;
      }
    ).resourceTemplates;
    if (templates) {
      resourceTemplates = templates.map((rt) => ({
        uriTemplate: rt.uriTemplate,
        name: rt.name,
        description: rt.description,
        mimeType: rt.mimeType,
      }));
    }
    if (
      !options.jsonOnly &&
      (resources.length > 0 || resourceTemplates.length > 0)
    ) {
      console.log(
        `📦 Found ${resources.length} resource(s) and ${resourceTemplates.length} resource template(s)`,
      );
    }
  } catch {
    // Server may not support resources - that's okay
    if (!options.jsonOnly) {
      console.log("📦 Resources not supported by server");
    }
  }

  // Fetch prompts for new capability assessments
  let prompts: {
    name: string;
    description?: string;
    arguments?: Array<{
      name: string;
      description?: string;
      required?: boolean;
    }>;
  }[] = [];
  try {
    const promptsResponse = await client.listPrompts();
    prompts = (promptsResponse.prompts || []).map((p) => ({
      name: p.name,
      description: p.description,
      arguments: p.arguments?.map((a) => ({
        name: a.name,
        description: a.description,
        required: a.required,
      })),
    }));
    if (!options.jsonOnly && prompts.length > 0) {
      console.log(`💬 Found ${prompts.length} prompt(s)`);
    }
  } catch {
    // Server may not support prompts - that's okay
    if (!options.jsonOnly) {
      console.log("💬 Prompts not supported by server");
    }
  }

  // State management for resumable assessments
  const stateManager = new AssessmentStateManager(options.serverName);

  if (stateManager.exists() && !options.noResume) {
    const summary = stateManager.getSummary();
    if (summary) {
      if (!options.jsonOnly) {
        console.log(`\n📋 Found interrupted session from ${summary.startedAt}`);
        console.log(
          `   Completed modules: ${summary.completedModules.length > 0 ? summary.completedModules.join(", ") : "none"}`,
        );
      }

      if (options.resume) {
        if (!options.jsonOnly) {
          console.log("   Resuming from previous state...");
        }
        // Will use partial results later
      } else if (!options.jsonOnly) {
        console.log(
          "   Use --resume to continue or --no-resume to start fresh",
        );
        // Clear state and start fresh by default
        stateManager.clear();
      }
    }
  } else if (options.noResume && stateManager.exists()) {
    stateManager.clear();
    if (!options.jsonOnly) {
      console.log("🗑️  Cleared previous assessment state");
    }
  }

  // Pre-flight validation checks
  if (options.preflightOnly) {
    const preflightResult: {
      passed: boolean;
      toolCount: number;
      manifestValid?: boolean;
      serverResponsive?: boolean;
      errors: string[];
    } = {
      passed: true,
      toolCount: tools.length,
      errors: [],
    };

    // Check 1: Tools exist
    if (tools.length === 0) {
      preflightResult.passed = false;
      preflightResult.errors.push("No tools discovered from server");
    }

    // Check 2: Manifest valid (if source path provided)
    if (options.sourceCodePath) {
      const manifestPath = path.join(options.sourceCodePath, "manifest.json");
      if (fs.existsSync(manifestPath)) {
        try {
          JSON.parse(fs.readFileSync(manifestPath, "utf-8"));
          preflightResult.manifestValid = true;
        } catch {
          preflightResult.passed = false;
          preflightResult.manifestValid = false;
          preflightResult.errors.push(
            "Invalid manifest.json (JSON parse error)",
          );
        }
      }
    }

    // Check 3: First tool responds (basic connectivity)
    if (tools.length > 0) {
      try {
        const callTool = createCallToolWrapper(client);
        const firstToolResult = await callTool(tools[0].name, {});
        preflightResult.serverResponsive = !firstToolResult.isError;
        if (firstToolResult.isError) {
          preflightResult.errors.push(
            `First tool (${tools[0].name}) returned error - server may not be fully functional`,
          );
        }
      } catch (e) {
        preflightResult.serverResponsive = false;
        preflightResult.errors.push(
          `First tool call failed: ${e instanceof Error ? e.message : String(e)}`,
        );
      }
    }

    await client.close();

    // Output pre-flight result
    console.log(JSON.stringify(preflightResult, null, 2));
    setTimeout(() => process.exit(preflightResult.passed ? 0 : 1), 10);

    // Return empty result (won't be used due to process.exit)
    return {} as MCPDirectoryAssessment;
  }

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

  const orchestrator = new AssessmentOrchestrator(config);

  if (!options.jsonOnly) {
    if (orchestrator.isClaudeEnabled()) {
      console.log("🤖 Claude Code integration enabled");
    } else if (options.claudeEnabled) {
      console.log("⚠️  Claude Code requested but not available");
    }
  }

  let sourceFiles = {};
  if (options.sourceCodePath && fs.existsSync(options.sourceCodePath)) {
    sourceFiles = loadSourceFiles(options.sourceCodePath);
    if (!options.jsonOnly) {
      console.log(`📁 Loaded source files from: ${options.sourceCodePath}`);
    }
  }

  // Create readResource wrapper for ResourceAssessor
  const readResource = async (uri: string): Promise<string> => {
    const response = await client.readResource({ uri });
    // Extract text content from response
    if (response.contents && response.contents.length > 0) {
      const content = response.contents[0];
      if ("text" in content && content.text) {
        return content.text;
      }
      if ("blob" in content && content.blob) {
        // Return base64 blob as string
        return content.blob;
      }
    }
    return "";
  };

  // Create getPrompt wrapper for PromptAssessor
  const getPrompt = async (
    name: string,
    args: Record<string, string>,
  ): Promise<{ messages: Array<{ role: string; content: string }> }> => {
    const response = await client.getPrompt({ name, arguments: args });
    return {
      messages: (response.messages || []).map((m) => ({
        role: m.role,
        content:
          typeof m.content === "string" ? m.content : JSON.stringify(m.content),
      })),
    };
  };

  // Progress callback to emit JSONL events for real-time monitoring
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
    // New capability assessment data
    resources,
    resourceTemplates,
    prompts,
    readResource,
    getPrompt,
    // Server info for protocol conformance checks
    serverInfo,
    serverCapabilities:
      serverCapabilities as AssessmentContext["serverCapabilities"],
  };

  if (!options.jsonOnly) {
    console.log(
      `\n🏃 Running assessment with ${Object.keys(config.assessmentCategories || {}).length} modules...`,
    );
    console.log("");
  }

  const results = await orchestrator.runFullAssessment(context);

  // Emit assessment complete event
  const defaultOutputPath = `/tmp/inspector-full-assessment-${options.serverName}.json`;
  emitAssessmentComplete(
    results.overallStatus,
    results.totalTestsRun,
    results.executionTime,
    options.outputPath || defaultOutputPath,
  );

  await client.close();

  return results;
}

/**
 * Save results to file with appropriate format
 */
function saveResults(
  serverName: string,
  results: MCPDirectoryAssessment,
  options: AssessmentOptions,
): string {
  const format = options.format || "json";

  // Generate policy compliance report if requested
  const policyReport = options.includePolicy
    ? generatePolicyComplianceReport(results, serverName)
    : undefined;

  // Create formatter with options
  const formatter = createFormatter({
    format,
    includePolicyMapping: options.includePolicy,
    policyReport,
    serverName,
    includeDetails: true,
    prettyPrint: true,
  });

  const fileExtension = formatter.getFileExtension();
  const defaultPath = `/tmp/inspector-full-assessment-${serverName}${fileExtension}`;
  const finalPath = options.outputPath || defaultPath;

  // For JSON format, add metadata wrapper
  if (format === "json") {
    // Filter out undefined/skipped modules from results (--skip-modules support)
    const filteredResults = Object.fromEntries(
      Object.entries(results).filter(([_, v]) => v !== undefined),
    );

    const output = {
      timestamp: new Date().toISOString(),
      assessmentType: "full",
      ...filteredResults,
      ...(policyReport ? { policyCompliance: policyReport } : {}),
    };
    fs.writeFileSync(finalPath, JSON.stringify(output, null, 2));
  } else {
    // For other formats (markdown), use the formatter
    const content = formatter.format(results);
    fs.writeFileSync(finalPath, content);
  }

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

  console.log("\n📊 MODULE STATUS:");
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
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

  console.log("\n📋 KEY FINDINGS:");
  console.log(`   ${summary}`);

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const securityModule = security as any;
  if (securityModule?.vulnerabilities?.length > 0) {
    const vulns = securityModule.vulnerabilities;
    console.log(`\n🔒 SECURITY VULNERABILITIES (${vulns.length}):`);
    for (const vuln of vulns.slice(0, 5)) {
      console.log(`   • ${vuln}`);
    }
    if (vulns.length > 5) {
      console.log(`   ... and ${vulns.length - 5} more`);
    }
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const aupModule = aupCompliance as any;
  if (aupModule?.violations?.length > 0) {
    const violations = aupModule.violations;
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const critical = violations.filter((v: any) => v.severity === "CRITICAL");
    console.log(`\n⚖️  AUP FINDINGS:`);
    console.log(`   Total flagged: ${violations.length}`);
    if (critical.length > 0) {
      console.log(`   🚨 CRITICAL violations: ${critical.length}`);
    }
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const annotationsModule = toolAnnotations as any;
  if (annotationsModule) {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const funcModule = functionality as any;
    console.log(`\n🏷️  TOOL ANNOTATIONS:`);
    console.log(
      `   Annotated: ${annotationsModule.annotatedCount || 0}/${funcModule?.workingTools || 0}`,
    );
    if (annotationsModule.missingAnnotationsCount > 0) {
      console.log(`   Missing: ${annotationsModule.missingAnnotationsCount}`);
    }
    if (annotationsModule.misalignedAnnotationsCount > 0) {
      console.log(
        `   ⚠️  Misalignments: ${annotationsModule.misalignedAnnotationsCount}`,
      );
    }
  }

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
        options.logLevel = "debug";
        break;
      case "--silent":
        options.logLevel = "silent";
        break;
      case "--log-level": {
        const levelValue = args[++i] as LogLevel;
        const validLevels: LogLevel[] = [
          "silent",
          "error",
          "warn",
          "info",
          "debug",
        ];
        if (!validLevels.includes(levelValue)) {
          console.error(
            `Invalid log level: ${levelValue}. Valid options: ${validLevels.join(", ")}`,
          );
          setTimeout(() => process.exit(1), 10);
          options.helpRequested = true;
          return options as AssessmentOptions;
        }
        options.logLevel = levelValue;
        break;
      }
      case "--json":
        options.jsonOnly = true;
        break;
      case "--format":
      case "-f":
        const formatValue = args[++i] as ReportFormat;
        if (formatValue !== "json" && formatValue !== "markdown") {
          console.error(
            `Invalid format: ${formatValue}. Valid options: json, markdown`,
          );
          setTimeout(() => process.exit(1), 10);
          options.helpRequested = true;
          return options as AssessmentOptions;
        }
        options.format = formatValue;
        break;
      case "--include-policy":
        options.includePolicy = true;
        break;
      case "--preflight":
        options.preflightOnly = true;
        break;
      case "--compare":
        options.comparePath = args[++i];
        break;
      case "--diff-only":
        options.diffOnly = true;
        break;
      case "--resume":
        options.resume = true;
        break;
      case "--no-resume":
        options.noResume = true;
        break;
      case "--temporal-invocations":
        options.temporalInvocations = parseInt(args[++i], 10);
        break;
      case "--skip-temporal":
        options.skipTemporal = true;
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
Usage: mcp-assess-full [options] [server-name]

Run comprehensive MCP server assessment with all 17 assessor modules.

Options:
  --server, -s <name>    Server name (required, or pass as first positional arg)
  --config, -c <path>    Path to server config JSON
  --output, -o <path>    Output path (default: /tmp/inspector-full-assessment-<server>.<ext>)
  --source <path>        Source code path for deep analysis (AUP, portability, etc.)
  --pattern-config, -p <path>  Path to custom annotation pattern JSON
  --format, -f <type>    Output format: json (default) or markdown
  --include-policy       Include policy compliance mapping in report (30 requirements)
  --preflight            Run quick validation only (tools exist, manifest valid, server responds)
  --compare <path>       Compare current assessment against baseline JSON file
  --diff-only            Output only the comparison diff (requires --compare)
  --resume               Resume from previous interrupted assessment
  --no-resume            Force fresh start, clear any existing state
  --claude-enabled       Enable Claude Code integration for intelligent analysis
  --full                 Enable all assessment modules (default)
  --temporal-invocations <n>  Number of invocations per tool for rug pull detection (default: 25)
  --skip-temporal        Skip temporal/rug pull testing (faster assessment)
  --skip-modules <list>  Skip specific modules (comma-separated)
  --only-modules <list>  Run only specific modules (comma-separated)
  --json                 Output only JSON path (no console summary)
  --verbose, -v          Enable verbose logging (same as --log-level debug)
  --silent               Suppress all diagnostic logging
  --log-level <level>    Set log level: silent, error, warn, info (default), debug
                         Also supports LOG_LEVEL environment variable
  --help, -h             Show this help message

Module Selection:
  --skip-modules and --only-modules are mutually exclusive.
  Use --skip-modules for faster runs by disabling expensive modules.
  Use --only-modules to focus on specific areas (e.g., tool annotation PRs).

  Valid module names:
    functionality, security, documentation, errorHandling, usability,
    mcpSpecCompliance, aupCompliance, toolAnnotations, prohibitedLibraries,
    externalAPIScanner, authentication, temporal, resources, prompts,
    crossCapability, manifestValidation, portability

Assessment Modules (17 total):
  • Functionality      - Tests all tools work correctly
  • Security           - Prompt injection & vulnerability testing
  • Documentation      - README completeness checks
  • Error Handling     - Validates error responses
  • Usability          - Input validation & UX
  • MCP Spec           - Protocol compliance
  • AUP Compliance     - Acceptable Use Policy checks
  • Tool Annotations   - readOnlyHint/destructiveHint validation
  • Prohibited Libs    - Dependency security checks
  • External API       - External service detection
  • Authentication     - OAuth/auth evaluation
  • Temporal           - Rug pull/temporal behavior change detection
  • Resources          - Resource capability assessment
  • Prompts            - Prompt capability assessment
  • Cross-Capability   - Chained vulnerability detection
  • Manifest           - MCPB manifest.json validation (optional)
  • Portability        - Cross-platform compatibility (optional)

Examples:
  mcp-assess-full my-server
  mcp-assess-full --server broken-mcp --claude-enabled
  mcp-assess-full --server my-server --source ./my-server --output ./results.json
  mcp-assess-full --server my-server --format markdown --include-policy
  mcp-assess-full --server my-server --compare ./baseline.json
  mcp-assess-full --server my-server --compare ./baseline.json --diff-only --format markdown

  # Module selection examples:
  mcp-assess-full my-server --skip-modules security,aupCompliance    # Fast CI run
  mcp-assess-full my-server --only-modules functionality,toolAnnotations  # Annotation PR review
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

    const results = await runFullAssessment(options);

    // Pre-flight mode handles its own output and exit
    if (options.preflightOnly) {
      return;
    }

    // Handle comparison mode
    if (options.comparePath) {
      if (!fs.existsSync(options.comparePath)) {
        console.error(`Error: Baseline file not found: ${options.comparePath}`);
        setTimeout(() => process.exit(1), 10);
        return;
      }

      const baselineData = JSON.parse(
        fs.readFileSync(options.comparePath, "utf-8"),
      );
      const baseline: MCPDirectoryAssessment =
        baselineData.functionality && baselineData.security
          ? baselineData
          : baselineData;

      const diff = compareAssessments(baseline, results);

      if (options.diffOnly) {
        // Only output diff, not full assessment
        if (options.format === "markdown") {
          const diffPath =
            options.outputPath ||
            `/tmp/inspector-diff-${options.serverName}.md`;
          fs.writeFileSync(diffPath, formatDiffAsMarkdown(diff));
          console.log(diffPath);
        } else {
          const diffPath =
            options.outputPath ||
            `/tmp/inspector-diff-${options.serverName}.json`;
          fs.writeFileSync(diffPath, JSON.stringify(diff, null, 2));
          console.log(diffPath);
        }
        const exitCode = diff.summary.overallChange === "regressed" ? 1 : 0;
        setTimeout(() => process.exit(exitCode), 10);
        return;
      }

      // Include diff in output alongside full assessment
      if (!options.jsonOnly) {
        console.log("\n" + "=".repeat(70));
        console.log("VERSION COMPARISON");
        console.log("=".repeat(70));
        console.log(
          `Baseline: ${diff.baseline.version || "N/A"} (${diff.baseline.date})`,
        );
        console.log(
          `Current:  ${diff.current.version || "N/A"} (${diff.current.date})`,
        );
        console.log(
          `Overall Change: ${diff.summary.overallChange.toUpperCase()}`,
        );
        console.log(`Modules Improved: ${diff.summary.modulesImproved}`);
        console.log(`Modules Regressed: ${diff.summary.modulesRegressed}`);

        if (diff.securityDelta.newVulnerabilities.length > 0) {
          console.log(
            `\n⚠️  NEW VULNERABILITIES: ${diff.securityDelta.newVulnerabilities.length}`,
          );
        }
        if (diff.securityDelta.fixedVulnerabilities.length > 0) {
          console.log(
            `✅ FIXED VULNERABILITIES: ${diff.securityDelta.fixedVulnerabilities.length}`,
          );
        }
        if (diff.functionalityDelta.newBrokenTools.length > 0) {
          console.log(
            `❌ NEW BROKEN TOOLS: ${diff.functionalityDelta.newBrokenTools.length}`,
          );
        }
        if (diff.functionalityDelta.fixedTools.length > 0) {
          console.log(
            `✅ FIXED TOOLS: ${diff.functionalityDelta.fixedTools.length}`,
          );
        }
      }
    }

    if (!options.jsonOnly) {
      displaySummary(results);
    }

    const outputPath = saveResults(options.serverName, results, options);

    if (options.jsonOnly) {
      console.log(outputPath);
    } else {
      console.log(`📄 Results saved to: ${outputPath}\n`);
    }

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

main();

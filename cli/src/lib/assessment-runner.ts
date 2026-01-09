/**
 * Assessment Runner Module
 *
 * Handles MCP server connection, assessment orchestration, and configuration
 * for the mcp-assess-full CLI tool.
 *
 * Extracted from assess-full.ts as part of Issue #90 modularization.
 *
 * @module cli/lib/assessment-runner
 */

import * as fs from "fs";
import * as path from "path";
import * as os from "os";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { SSEClientTransport } from "@modelcontextprotocol/sdk/client/sse.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { CompatibilityCallToolResult } from "@modelcontextprotocol/sdk/types.js";

import {
  AssessmentOrchestrator,
  AssessmentContext,
} from "../../../client/lib/services/assessment/AssessmentOrchestrator.js";
import {
  AssessmentConfiguration,
  DEFAULT_ASSESSMENT_CONFIG,
  MCPDirectoryAssessment,
  ManifestJsonSchema,
  ProgressEvent,
  getAllModulesConfig,
  LogLevel,
} from "../../../client/lib/lib/assessmentTypes.js";
import { FULL_CLAUDE_CODE_CONFIG } from "../../../client/lib/services/assessment/lib/claudeCodeBridge.js";
import { loadPerformanceConfig } from "../../../client/lib/services/assessment/config/performanceConfig.js";

import { AssessmentStateManager } from "../assessmentState.js";
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
} from "./jsonl-events.js";
import {
  getProfileModules,
  resolveModuleNames,
  modulesToLegacyConfig,
} from "../profiles.js";

import type { ServerConfig, AssessmentOptions } from "./cli-parser.js";

// ============================================================================
// Types
// ============================================================================

/**
 * Source files loaded from source code path
 */
export interface SourceFiles {
  readmeContent?: string;
  packageJson?: unknown;
  manifestJson?: ManifestJsonSchema;
  manifestRaw?: string;
  sourceCodeFiles?: Map<string, string>;
}

/**
 * Type for callTool wrapper function
 */
export type CallToolFn = (
  name: string,
  params: Record<string, unknown>,
) => Promise<CompatibilityCallToolResult>;

// ============================================================================
// Server Configuration
// ============================================================================

/**
 * Load server configuration from Claude Code's MCP settings
 *
 * @param serverName - Name of the server to look up
 * @param configPath - Optional explicit config path
 * @returns Server configuration object
 */
export function loadServerConfig(
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

// ============================================================================
// Source File Loading
// ============================================================================

/**
 * Load optional files from source code path
 *
 * @param sourcePath - Path to source code directory
 * @returns Object containing loaded source files
 */
export function loadSourceFiles(sourcePath: string): SourceFiles {
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

  return result as SourceFiles;
}

// ============================================================================
// Server Connection
// ============================================================================

/**
 * Connect to MCP server via configured transport
 *
 * @param config - Server configuration
 * @returns Connected MCP client
 */
export async function connectToServer(config: ServerConfig): Promise<Client> {
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

// ============================================================================
// Tool Call Wrapper
// ============================================================================

/**
 * Create callTool wrapper for assessment context
 *
 * @param client - Connected MCP client
 * @returns Wrapped callTool function
 */
export function createCallToolWrapper(client: Client): CallToolFn {
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

// ============================================================================
// Configuration Building
// ============================================================================

/**
 * Build assessment configuration from CLI options
 *
 * @param options - CLI assessment options
 * @returns Assessment configuration
 */
export function buildConfig(
  options: AssessmentOptions,
): AssessmentConfiguration {
  const config: AssessmentConfiguration = {
    ...DEFAULT_ASSESSMENT_CONFIG,
    enableExtendedAssessment: options.fullAssessment !== false,
    parallelTesting: true,
    testTimeout: 30000,
    enableSourceCodeAnalysis: Boolean(options.sourceCodePath),
  };

  if (options.fullAssessment !== false) {
    // Priority: --profile > --only-modules > --skip-modules > default (all)
    if (options.profile) {
      // Use profile-based module selection
      const profileModules = getProfileModules(options.profile, {
        hasSourceCode: Boolean(options.sourceCodePath),
        skipTemporal: options.skipTemporal,
      });

      // Convert new-style module list to legacy config format
      // (until orchestrator is updated to use new naming)
      config.assessmentCategories = modulesToLegacyConfig(
        profileModules,
      ) as AssessmentConfiguration["assessmentCategories"];
    } else {
      // Derive module config from ASSESSMENT_CATEGORY_METADATA (single source of truth)
      const allModules = getAllModulesConfig({
        sourceCodePath: Boolean(options.sourceCodePath),
        skipTemporal: options.skipTemporal,
      });

      // Apply --only-modules filter (whitelist mode)
      if (options.onlyModules?.length) {
        // Resolve any deprecated module names
        const resolved = resolveModuleNames(options.onlyModules);
        for (const key of Object.keys(allModules)) {
          // Disable all modules except those in the whitelist
          allModules[key] = resolved.includes(key);
        }
      }

      // Apply --skip-modules filter (blacklist mode)
      if (options.skipModules?.length) {
        // Resolve any deprecated module names
        const resolved = resolveModuleNames(options.skipModules);
        for (const module of resolved) {
          if (module in allModules) {
            allModules[module] = false;
          }
        }
      }

      config.assessmentCategories =
        allModules as AssessmentConfiguration["assessmentCategories"];
    }
  }

  // Temporal/rug pull detection configuration
  if (options.temporalInvocations) {
    config.temporalInvocations = options.temporalInvocations;
  }

  if (options.claudeEnabled) {
    // Check for HTTP transport via --claude-http flag or environment variables
    const useHttpTransport =
      options.claudeHttp || process.env.INSPECTOR_CLAUDE === "true";
    const auditorUrl =
      options.mcpAuditorUrl ||
      process.env.INSPECTOR_MCP_AUDITOR_URL ||
      "http://localhost:8085";

    config.claudeCode = {
      enabled: true,
      timeout: FULL_CLAUDE_CODE_CONFIG.timeout || 60000,
      maxRetries: FULL_CLAUDE_CODE_CONFIG.maxRetries || 2,
      // Use HTTP transport when --claude-http flag or INSPECTOR_CLAUDE env is set
      ...(useHttpTransport && {
        transport: "http" as const,
        httpConfig: {
          baseUrl: auditorUrl,
        },
      }),
      features: {
        intelligentTestGeneration: true,
        aupSemanticAnalysis: true,
        annotationInference: true,
        documentationQuality: true,
      },
    };

    if (useHttpTransport) {
      console.log(`🔗 Claude Bridge HTTP transport: ${auditorUrl}`);
    }
  }

  // Pass custom annotation pattern config path
  if (options.patternConfigPath) {
    config.patternConfigPath = options.patternConfigPath;
  }

  // Load custom performance config if provided (Issue #37)
  // Note: Currently, modules use DEFAULT_PERFORMANCE_CONFIG directly.
  // This validates the config file but doesn't override runtime values yet.
  // Future enhancement: Pass performanceConfig through AssessmentContext.
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
          `Security batch: ${performanceConfig.securityBatchSize}, ` +
          `Functionality batch: ${performanceConfig.functionalityBatchSize}`,
      );
      // TODO: Wire performanceConfig through AssessmentContext to modules
    } catch (error) {
      console.error(
        `❌ Failed to load performance config: ${error instanceof Error ? error.message : String(error)}`,
      );
      throw error;
    }
  }

  // Logging configuration
  // Precedence: CLI flags > LOG_LEVEL env var > default (info)
  const envLogLevel = process.env.LOG_LEVEL as LogLevel | undefined;
  const logLevel = options.logLevel ?? envLogLevel ?? "info";
  config.logging = { level: logLevel };

  return config;
}

// ============================================================================
// Full Assessment Orchestration
// ============================================================================

/**
 * Run full assessment against an MCP server
 *
 * @param options - CLI assessment options
 * @returns Assessment results
 */
export async function runFullAssessment(
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
  // Apply defensive null checks for protocol conformance validation
  const rawServerInfo = client.getServerVersion();
  const rawServerCapabilities = client.getServerCapabilities();

  // Build serverInfo with safe fallbacks
  const serverInfo = rawServerInfo
    ? {
        name: rawServerInfo.name || "unknown",
        version: rawServerInfo.version,
        metadata: (rawServerInfo as Record<string, unknown>).metadata as
          | Record<string, unknown>
          | undefined,
      }
    : undefined;

  // ServerCapabilities can be undefined - that's valid per MCP spec
  const serverCapabilities = rawServerCapabilities ?? undefined;

  // Log warning if server didn't provide initialization info
  if (!serverInfo && !options.jsonOnly) {
    console.log("⚠️  Server did not provide serverInfo during initialization");
  }

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

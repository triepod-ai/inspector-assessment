/**
 * Assessment Executor
 *
 * Main orchestration for running full MCP server assessments.
 *
 * @module cli/lib/assessment-runner/assessment-executor
 */

import * as fs from "fs";
import * as path from "path";

import { Client } from "@modelcontextprotocol/sdk/client/index.js";

import {
  AssessmentOrchestrator,
  AssessmentContext,
} from "../../../../client/lib/services/assessment/AssessmentOrchestrator.js";
import {
  MCPDirectoryAssessment,
  ProgressEvent,
} from "../../../../client/lib/lib/assessmentTypes.js";

import { AssessmentStateManager } from "../../assessmentState.js";
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
  emitPhaseStarted,
  emitPhaseComplete,
  emitToolTestComplete,
  emitValidationSummary,
} from "../jsonl-events.js";

import type { AssessmentOptions } from "../cli-parser.js";
import { loadServerConfig } from "./server-config.js";
import { loadSourceFiles } from "./source-loader.js";
import { resolveSourcePath } from "./path-resolver.js";
import { connectToServer } from "./server-connection.js";
import { createCallToolWrapper } from "./tool-wrapper.js";
import { buildConfig } from "./config-builder.js";
// Issue #155: Import annotation debug mode setter
import { setAnnotationDebugMode } from "../../../../client/lib/services/assessment/modules/annotations/AlignmentChecker.js";
// Issue #155: Import helper to preserve hint properties stripped by SDK
import { getToolsWithPreservedHints } from "./tools-with-hints.js";

/**
 * Run full assessment against an MCP server
 *
 * @param options - CLI assessment options
 * @returns Assessment results
 */
export async function runFullAssessment(
  options: AssessmentOptions,
): Promise<MCPDirectoryAssessment> {
  // Issue #155: Enable annotation debug mode if flag is set
  if (options.debugAnnotations) {
    setAnnotationDebugMode(true);
    if (!options.jsonOnly) {
      console.log("🔍 Annotation debug mode enabled (--debug-annotations)");
    }
  }

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

  // Phase 1: Discovery
  const discoveryStart = Date.now();
  emitPhaseStarted("discovery");

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

  // Issue #155: Use helper that preserves hint properties stripped by SDK Zod validation
  // The SDK's listTools() validates against a schema that strips direct properties
  // like readOnlyHint. This helper intercepts the raw transport response to preserve them.
  const tools = await getToolsWithPreservedHints(client);

  // Emit JSONL tool discovery events for audit-worker parsing
  // Tools now have hint properties preserved from raw response
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
    // Get static resources from resources/list
    const resourcesResponse = await client.listResources();
    resources = (resourcesResponse.resources || []).map((r) => ({
      uri: r.uri,
      name: r.name,
      description: r.description,
      mimeType: r.mimeType,
    }));

    // Get resource templates from resources/templates/list (Issue #131)
    // This is a SEPARATE MCP endpoint - templates are NOT included in resources/list
    try {
      const templatesResponse = await client.listResourceTemplates();
      const templates = templatesResponse.resourceTemplates || [];
      resourceTemplates = templates.map((rt) => ({
        uriTemplate: rt.uriTemplate,
        name: rt.name,
        description: rt.description,
        mimeType: rt.mimeType,
      }));
    } catch {
      // Server may not support resource templates - that's okay
      resourceTemplates = [];
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

  // End of discovery phase
  emitPhaseComplete("discovery", Date.now() - discoveryStart);

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
    const preflightResult = await runPreflightChecks(client, tools, options);
    await client.close();
    console.log(JSON.stringify(preflightResult, null, 2));
    setTimeout(() => process.exit(preflightResult.passed ? 0 : 1), 10);
    return {} as MCPDirectoryAssessment;
  }

  const config = buildConfig(options);

  // Set serverUrl for conformance tests when HTTP/SSE transport is used
  if (serverConfig.url && !config.serverUrl) {
    config.serverUrl = serverConfig.url;
  }

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
  if (options.sourceCodePath) {
    // Resolve path using utility (handles ~, relative paths, symlinks)
    const resolvedSourcePath = resolveSourcePath(options.sourceCodePath);

    if (fs.existsSync(resolvedSourcePath)) {
      sourceFiles = loadSourceFiles(resolvedSourcePath, options.debugSource);
      if (!options.jsonOnly) {
        console.log(`📁 Loaded source files from: ${resolvedSourcePath}`);
      }
    } else if (!options.jsonOnly) {
      // Issue #154: Always show warning, not just with --debug-source
      console.log(
        `⚠️  Source path not found: ${options.sourceCodePath} (resolved: ${resolvedSourcePath})`,
      );
      console.log(
        `   Use --source <existing-path> to enable full source file analysis.`,
      );
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
    } else if (event.type === "tool_test_complete") {
      emitToolTestComplete(
        event.tool,
        event.module,
        event.scenariosPassed,
        event.scenariosExecuted,
        event.confidence,
        event.status,
        event.executionTime,
      );
    } else if (event.type === "validation_summary") {
      emitValidationSummary(
        event.tool,
        event.wrongType,
        event.missingRequired,
        event.extraParams,
        event.nullValues,
        event.invalidValues,
      );
    }
    // module_started and module_complete are handled by orchestrator directly
    // phase_started and phase_complete are emitted directly (not via callback)
  };

  const context: AssessmentContext = {
    serverName: options.serverName,
    tools,
    callTool: createCallToolWrapper(client),
    // Issue #155: Use helper to preserve hint properties in refreshed tool lists
    listTools: async () => {
      return getToolsWithPreservedHints(client);
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

  // Phase 2: Assessment
  const assessmentStart = Date.now();
  emitPhaseStarted("assessment");

  const results = await orchestrator.runFullAssessment(context);

  // End of assessment phase
  emitPhaseComplete("assessment", Date.now() - assessmentStart);

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
 * Run pre-flight validation checks
 *
 * @param client - Connected MCP client
 * @param tools - Discovered tools
 * @param options - CLI assessment options
 * @returns Pre-flight result object
 */
async function runPreflightChecks(
  client: Client,
  tools: Array<{ name: string }>,
  options: AssessmentOptions,
): Promise<{
  passed: boolean;
  toolCount: number;
  manifestValid?: boolean;
  serverResponsive?: boolean;
  errors: string[];
}> {
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
        preflightResult.errors.push("Invalid manifest.json (JSON parse error)");
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

  return preflightResult;
}

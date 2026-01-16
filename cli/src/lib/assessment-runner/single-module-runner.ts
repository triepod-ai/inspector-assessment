/**
 * Single Module Runner
 *
 * Lightweight execution for individual assessment modules via --module flag.
 * Bypasses full orchestration for faster, targeted assessment.
 *
 * @module cli/lib/assessment-runner/single-module-runner
 * @see GitHub Issue #184
 */

import { Client } from "@modelcontextprotocol/sdk/client/index.js";

import {
  ASSESSOR_DEFINITION_MAP,
  ASSESSOR_DEFINITIONS,
} from "../../../../client/lib/services/assessment/registry/AssessorDefinitions.js";
import type {
  AssessorDefinition,
  ModuleContextRequirements,
} from "../../../../client/lib/services/assessment/registry/types.js";
import { DEFAULT_CONTEXT_REQUIREMENTS } from "../../../../client/lib/services/assessment/registry/types.js";
import type { AssessmentContext } from "../../../../client/lib/services/assessment/AssessmentOrchestrator.js";
import type { AssessmentOptions, ServerConfig } from "../cli-parser.js";

import { loadServerConfig } from "./server-config.js";
import { loadSourceFiles } from "./source-loader.js";
import { resolveSourcePath } from "./path-resolver.js";
import { connectToServer } from "./server-connection.js";
import { createCallToolWrapper } from "./tool-wrapper.js";
import { buildConfig } from "./config-builder.js";
import { getToolsWithPreservedHints } from "./tools-with-hints.js";

/**
 * Result of a single module execution.
 * Focused output without full MCPDirectoryAssessment wrapper.
 */
export interface SingleModuleResult {
  /** ISO timestamp of execution */
  timestamp: string;

  /** Server name */
  serverName: string;

  /** Module ID that was executed */
  module: string;

  /** Module display name */
  displayName: string;

  /** The raw assessment result (type varies by assessor) */
  result: unknown;

  /** Extracted status (PASS/FAIL/PARTIAL/UNKNOWN) */
  status: string;

  /** Execution time in milliseconds */
  executionTime: number;

  /** Estimated test count for the module */
  estimatedTestCount: number;

  /** Phase the module belongs to */
  phase: number;
}

/**
 * Get all valid module names for --module validation.
 */
export function getValidModuleNames(): string[] {
  return ASSESSOR_DEFINITIONS.map((def) => def.id);
}

/**
 * Run a single assessment module directly without orchestration.
 *
 * This provides lightweight execution for targeted validation:
 * - Builds only the context required by the specific module
 * - Skips orchestrator phase ordering
 * - Returns focused output
 *
 * @param moduleName - The module ID to run (e.g., 'toolAnnotations', 'functionality')
 * @param options - CLI assessment options
 * @returns Single module result
 */
export async function runSingleModule(
  moduleName: string,
  options: AssessmentOptions,
): Promise<SingleModuleResult> {
  const definition = ASSESSOR_DEFINITION_MAP.get(moduleName);
  if (!definition) {
    const validModules = getValidModuleNames().join(", ");
    throw new Error(
      `Unknown module: ${moduleName}\nValid modules: ${validModules}`,
    );
  }

  if (!options.jsonOnly) {
    console.log(`\n🎯 Running single module: ${definition.displayName}`);
  }

  // Build server config (respects --http/--sse from Issue #183)
  let serverConfig: ServerConfig;
  if (options.httpUrl) {
    serverConfig = { transport: "http", url: options.httpUrl };
    if (!options.jsonOnly) {
      console.log(`✅ Using HTTP transport: ${options.httpUrl}`);
    }
  } else if (options.sseUrl) {
    serverConfig = { transport: "sse", url: options.sseUrl };
    if (!options.jsonOnly) {
      console.log(`✅ Using SSE transport: ${options.sseUrl}`);
    }
  } else {
    serverConfig = loadServerConfig(
      options.serverName,
      options.serverConfigPath,
    );
    if (!options.jsonOnly) {
      console.log("✅ Server config loaded");
    }
  }

  const client = await connectToServer(serverConfig);
  try {
    if (!options.jsonOnly) {
      console.log("✅ Connected to MCP server");
    }

    // Get context requirements (use default if not specified)
    const requirements: ModuleContextRequirements =
      definition.contextRequirements || DEFAULT_CONTEXT_REQUIREMENTS;

    // Build minimal context based on module requirements
    const context = await buildMinimalContext(
      client,
      definition,
      requirements,
      options,
      serverConfig,
    );

    // Instantiate and run the assessor
    const config = buildConfig(options);
    const assessor = new definition.assessorClass(config);

    // Apply custom setup if defined (e.g., ToolAnnotationAssessor pattern loading)
    if (definition.customSetup) {
      const { createLogger } =
        await import("../../../../client/lib/services/assessment/lib/logger.js");
      const logger = createLogger(config.logging?.level || "info");
      definition.customSetup(assessor, config, logger);
    }

    if (!options.jsonOnly) {
      console.log(`\n🏃 Running ${definition.displayName} assessment...`);
    }

    const startTime = Date.now();
    const result = await assessor.assess(context);
    const executionTime = Date.now() - startTime;

    // Estimate test count using the definition's estimator
    const estimatedTestCount = definition.estimateTests(context, config);

    const singleResult: SingleModuleResult = {
      timestamp: new Date().toISOString(),
      serverName: options.serverName,
      module: moduleName,
      displayName: definition.displayName,
      result,
      status: extractStatus(result),
      executionTime,
      estimatedTestCount,
      phase: definition.phase,
    };

    return singleResult;
  } finally {
    await client.close();
  }
}

/**
 * Build minimal AssessmentContext based on module requirements.
 * Only fetches/prepares what the specific module needs.
 */
async function buildMinimalContext(
  client: Client,
  definition: AssessorDefinition,
  requirements: ModuleContextRequirements,
  options: AssessmentOptions,
  serverConfig: ServerConfig,
): Promise<AssessmentContext> {
  const config = buildConfig(options);

  // Start with minimal context
  const context: Partial<AssessmentContext> = {
    serverName: options.serverName,
    config,
  };

  // Fetch tools if needed
  if (requirements.needsTools) {
    context.tools = await getToolsWithPreservedHints(client);
    if (!options.jsonOnly) {
      console.log(
        `🔧 Found ${context.tools.length} tool${context.tools.length !== 1 ? "s" : ""}`,
      );
    }
  } else {
    context.tools = [];
  }

  // Setup callTool wrapper if needed
  if (requirements.needsCallTool) {
    context.callTool = createCallToolWrapper(client);
  }

  // Setup listTools function if needed (for TemporalAssessor baseline)
  if (requirements.needsListTools) {
    context.listTools = async () => {
      return getToolsWithPreservedHints(client);
    };
  }

  // Fetch resources if needed
  if (requirements.needsResources) {
    try {
      const resourcesResponse = await client.listResources();
      context.resources = (resourcesResponse.resources || []).map((r) => ({
        uri: r.uri,
        name: r.name,
        description: r.description,
        mimeType: r.mimeType,
      }));

      // Also get resource templates
      try {
        const templatesResponse = await client.listResourceTemplates();
        context.resourceTemplates = (
          templatesResponse.resourceTemplates || []
        ).map((rt) => ({
          uriTemplate: rt.uriTemplate,
          name: rt.name,
          description: rt.description,
          mimeType: rt.mimeType,
        }));
      } catch {
        context.resourceTemplates = [];
      }

      // Setup readResource wrapper
      context.readResource = async (uri: string): Promise<string> => {
        const response = await client.readResource({ uri });
        if (response.contents && response.contents.length > 0) {
          const content = response.contents[0];
          if ("text" in content && content.text) {
            return content.text;
          }
          if ("blob" in content && content.blob) {
            return content.blob;
          }
        }
        return "";
      };

      if (!options.jsonOnly && context.resources.length > 0) {
        console.log(
          `📦 Found ${context.resources.length} resource(s) and ${context.resourceTemplates?.length || 0} template(s)`,
        );
      }
    } catch {
      context.resources = [];
      context.resourceTemplates = [];
      if (!options.jsonOnly) {
        console.log("📦 Resources not supported by server");
      }
    }
  }

  // Fetch prompts if needed
  if (requirements.needsPrompts) {
    try {
      const promptsResponse = await client.listPrompts();
      context.prompts = (promptsResponse.prompts || []).map((p) => ({
        name: p.name,
        description: p.description,
        arguments: p.arguments?.map((a) => ({
          name: a.name,
          description: a.description,
          required: a.required,
        })),
      }));

      // Setup getPrompt wrapper
      context.getPrompt = async (
        name: string,
        args: Record<string, string>,
      ): Promise<{ messages: Array<{ role: string; content: string }> }> => {
        const response = await client.getPrompt({ name, arguments: args });
        return {
          messages: (response.messages || []).map((m) => ({
            role: m.role,
            content:
              typeof m.content === "string"
                ? m.content
                : JSON.stringify(m.content),
          })),
        };
      };

      if (!options.jsonOnly && context.prompts.length > 0) {
        console.log(`💬 Found ${context.prompts.length} prompt(s)`);
      }
    } catch {
      context.prompts = [];
      if (!options.jsonOnly) {
        console.log("💬 Prompts not supported by server");
      }
    }
  }

  // Load source code if needed and path provided
  if (requirements.needsSourceCode && options.sourceCodePath) {
    const resolvedSourcePath = resolveSourcePath(options.sourceCodePath);
    const { existsSync } = await import("fs");

    if (existsSync(resolvedSourcePath)) {
      const sourceFiles = loadSourceFiles(
        resolvedSourcePath,
        options.debugSource,
      );
      context.sourceCodeFiles = sourceFiles.sourceCodeFiles;
      context.sourceCodePath = options.sourceCodePath;
      context.manifestJson = sourceFiles.manifestJson;
      context.manifestRaw = sourceFiles.manifestRaw;
      context.packageJson = sourceFiles.packageJson;
      context.readmeContent = sourceFiles.readmeContent;

      if (!options.jsonOnly) {
        console.log(`📁 Loaded source files from: ${resolvedSourcePath}`);
      }
    } else if (!options.jsonOnly) {
      console.log(
        `⚠️  Source path not found: ${options.sourceCodePath} (module may have reduced coverage)`,
      );
    }
  }

  // Load manifest specifically if needed (for ManifestValidationAssessor)
  if (requirements.needsManifest && options.sourceCodePath) {
    const resolvedSourcePath = resolveSourcePath(options.sourceCodePath);
    const { existsSync } = await import("fs");

    if (existsSync(resolvedSourcePath)) {
      const sourceFiles = loadSourceFiles(
        resolvedSourcePath,
        options.debugSource,
      );
      context.manifestJson = sourceFiles.manifestJson;
      context.manifestRaw = sourceFiles.manifestRaw;
    }
  }

  // Get server info if needed (for ProtocolComplianceAssessor)
  if (requirements.needsServerInfo) {
    const rawServerInfo = client.getServerVersion();
    const rawServerCapabilities = client.getServerCapabilities();

    context.serverInfo = rawServerInfo
      ? {
          name: rawServerInfo.name || "unknown",
          version: rawServerInfo.version,
          metadata: (rawServerInfo as Record<string, unknown>).metadata as
            | Record<string, unknown>
            | undefined,
        }
      : undefined;

    context.serverCapabilities =
      (rawServerCapabilities as AssessmentContext["serverCapabilities"]) ??
      undefined;

    // Set serverUrl for conformance tests when HTTP/SSE transport
    if (serverConfig.url && !config.serverUrl) {
      config.serverUrl = serverConfig.url;
    }
  }

  return context as AssessmentContext;
}

/**
 * Extract status from assessment result.
 * Handles various result structures from different assessors.
 */
function extractStatus(result: unknown): string {
  if (!result || typeof result !== "object") {
    return "UNKNOWN";
  }

  const r = result as Record<string, unknown>;

  // Check for direct status field
  if (typeof r.status === "string") {
    return r.status;
  }

  // Check for overallStatus field
  if (typeof r.overallStatus === "string") {
    return r.overallStatus;
  }

  // Check for overall field with status
  if (r.overall && typeof r.overall === "object") {
    const overall = r.overall as Record<string, unknown>;
    if (typeof overall.status === "string") {
      return overall.status;
    }
  }

  // Derive from vulnerabilities/issues count
  if (Array.isArray(r.vulnerabilities) && r.vulnerabilities.length > 0) {
    return "FAIL";
  }

  if (Array.isArray(r.issues) && r.issues.length > 0) {
    return "FAIL";
  }

  // Check for pass/fail counts
  if (typeof r.passCount === "number" && typeof r.failCount === "number") {
    if (r.failCount > 0) return "FAIL";
    if (r.passCount > 0) return "PASS";
  }

  return "UNKNOWN";
}

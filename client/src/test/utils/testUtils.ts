import { AssessmentContext } from "@/services/assessment/AssessmentOrchestrator";
import {
  AssessmentConfiguration,
  ManifestJsonSchema,
} from "@/lib/assessmentTypes";
import {
  Tool,
  CompatibilityCallToolResult,
} from "@modelcontextprotocol/sdk/types.js";

// ============================================
// Type-Safe Test Helpers (Issue #186)
// ============================================

/**
 * Tool annotations interface matching MCP SDK Tool.annotations
 * Used for type-safe tool annotation mocking without `any`
 */
export interface ToolAnnotations {
  title?: string;
  readOnlyHint?: boolean;
  destructiveHint?: boolean;
  idempotentHint?: boolean;
  openWorldHint?: boolean;
}

/**
 * Extended Tool type that includes annotations
 * This matches the actual SDK Tool type which has optional annotations
 */
export interface ToolWithAnnotations extends Tool {
  annotations?: ToolAnnotations;
}

/**
 * Type-safe accessor for private/internal properties in tests.
 * Use this instead of `(instance as any).property` to avoid ESLint warnings.
 *
 * @example
 * // Before: (engine as any).testTimeout
 * // After: getPrivateProperty<TestScenarioEngine, number>(engine, "testTimeout")
 */
export function getPrivateProperty<T, R>(instance: T, propName: string): R {
  return (instance as Record<string, unknown>)[propName] as R;
}

/**
 * Type for intentionally invalid/partial tool schemas in edge case tests.
 * Use when testing how code handles malformed or missing schemas.
 *
 * @example
 * // Before: inputSchema: undefined as any
 * // After: inputSchema: undefined as PartialToolSchema
 */
export type PartialToolSchema = Partial<Tool["inputSchema"]> | undefined;

/**
 * Typed test response structure for error handling tests.
 * Replaces `any` type for mock response objects.
 */
export interface TypedTestResponse {
  isError: boolean;
  errorCode?: number;
  errorMessage?: string;
  rawResponse?: unknown;
}

// Mock tool factory
export function createMockTool(overrides?: Partial<Tool>): Tool {
  return {
    name: "test-tool",
    description: "A test tool",
    inputSchema: {
      type: "object",
      properties: {
        input: { type: "string" },
      },
    },
    ...overrides,
  };
}

// Mock assessment context factory
export function createMockAssessmentContext(
  overrides?: Partial<AssessmentContext>,
): AssessmentContext {
  return {
    serverName: "test-server",
    tools: [createMockTool()],
    callTool: jest.fn().mockResolvedValue({
      content: [{ type: "text", text: "success" }],
      isError: false,
    } as CompatibilityCallToolResult),
    config: createMockAssessmentConfig(),
    ...overrides,
  };
}

// Mock assessment configuration factory
export function createMockAssessmentConfig(
  overrides?: Partial<AssessmentConfiguration>,
): AssessmentConfiguration {
  return {
    testTimeout: 5000,
    skipBrokenTools: true,
    enableExtendedAssessment: false,
    parallelTesting: false,
    maxParallelTests: 3,
    enableDomainTesting: true,
    ...overrides,
  };
}

// Mock call tool response factory
export function createMockCallToolResponse(
  content: string,
  isError = false,
): CompatibilityCallToolResult {
  return {
    content: [{ type: "text", text: content }],
    isError,
  };
}

// Helper to create multiple mock tools
export function createMockTools(count: number): Tool[] {
  return Array.from({ length: count }, (_, i) =>
    createMockTool({ name: `tool-${i}`, description: `Tool ${i}` }),
  );
}

// Helper to create a mock server info
export function createMockServerInfo() {
  return {
    name: "test-server",
    version: "1.0.0",
    metadata: {
      capabilities: ["tools", "resources"],
    },
  };
}

// Helper to create package.json mock
export function createMockPackageJson() {
  return {
    name: "test-package",
    version: "1.0.0",
    dependencies: {
      express: "^4.18.0",
      axios: "^1.0.0",
    },
    devDependencies: {
      jest: "^29.0.0",
      typescript: "^5.0.0",
    },
  };
}

// Helper to create README content mock
export function createMockReadmeContent() {
  return `# Test MCP Server

## Description
A test MCP server for assessment.

## Installation
\`\`\`bash
npm install test-server
\`\`\`

## Usage
\`\`\`javascript
const server = new MCPServer();
server.start();
\`\`\`

## API
- getTool(name: string): Tool
- executeTool(name: string, params: any): Promise<Result>

## Security
This server implements secure practices.
`;
}

// ============================================
// NEW: Helpers for MCP Directory Compliance Assessors
// ============================================

// Helper to create a tool with annotations
export function createMockToolWithAnnotations(overrides?: {
  name?: string;
  description?: string;
  readOnlyHint?: boolean;
  destructiveHint?: boolean;
  idempotentHint?: boolean;
  openWorldHint?: boolean;
}): ToolWithAnnotations {
  const tool = createMockTool({
    name: overrides?.name ?? "test-tool",
    description: overrides?.description ?? "A test tool",
  }) as ToolWithAnnotations;

  // Add annotations to tool (type-safe via ToolWithAnnotations)
  tool.annotations = {
    readOnlyHint: overrides?.readOnlyHint,
    destructiveHint: overrides?.destructiveHint,
    idempotentHint: overrides?.idempotentHint,
    openWorldHint: overrides?.openWorldHint,
  };

  return tool;
}

// Helper to create MCPB manifest.json mock
export function createMockManifestJson(
  overrides?: Partial<ManifestJsonSchema>,
): ManifestJsonSchema {
  return {
    manifest_version: "0.3",
    name: "test-mcp-server",
    version: "1.0.0",
    description: "A test MCP server",
    author: "Test Author",
    mcp_config: {
      command: "node",
      args: ["${__dirname}/dist/index.js"],
    },
    ...overrides,
  };
}

// Helper to create source code files map
export function createMockSourceCodeFiles(
  files?: Record<string, string>,
): Map<string, string> {
  const defaultFiles: Record<string, string> = {
    "src/index.ts": `
import { Server } from "@modelcontextprotocol/sdk/server/index.js";

const server = new Server({
  name: "test-server",
  version: "1.0.0",
});

server.start();
`,
    "package.json": JSON.stringify(createMockPackageJson(), null, 2),
  };

  return new Map(Object.entries({ ...defaultFiles, ...files }));
}

// Helper to create context with source code analysis enabled
export function createMockAssessmentContextWithSource(
  overrides?: Partial<AssessmentContext>,
): AssessmentContext {
  return createMockAssessmentContext({
    sourceCodePath: "/mock/path/to/server",
    sourceCodeFiles: createMockSourceCodeFiles(),
    config: createMockAssessmentConfig({
      enableExtendedAssessment: true,
      enableSourceCodeAnalysis: true,
      assessmentCategories: {
        functionality: true,
        security: true,
        documentation: true,
        errorHandling: true,
        usability: true,
        aupCompliance: true,
        toolAnnotations: true,
        prohibitedLibraries: true,
        manifestValidation: true,
        portability: true,
      },
    }),
    ...overrides,
  });
}

// Helper to create package.json with prohibited libraries
export function createMockPackageJsonWithProhibited(
  libraries: string[],
): Record<string, unknown> {
  const pkg = createMockPackageJson();
  for (const lib of libraries) {
    (pkg.dependencies as Record<string, string>)[lib] = "^1.0.0";
  }
  return pkg;
}

// Helper to create README with AUP violation content
export function createMockReadmeWithAUPViolation(
  violationType:
    | "weapons"
    | "malware"
    | "surveillance"
    | "harassment"
    | "fraud",
): string {
  const violations: Record<string, string> = {
    weapons: `# Weapons Manufacturing MCP
This server helps automate weapons manufacturing processes.
## Features
- Automated weapon assembly instructions
- Explosive materials guidance`,
    malware: `# Security Testing MCP
This server creates malware for testing purposes.
## Features
- Virus generation
- Ransomware deployment tools`,
    surveillance: `# Surveillance MCP
Mass surveillance and tracking capabilities.
## Features
- Track individuals without consent
- Monitor private communications`,
    harassment: `# Social Media MCP
Tools for targeted harassment campaigns.
## Features
- Automated harassment messaging
- Doxxing assistance`,
    fraud: `# Financial MCP
Fraudulent transaction processing.
## Features
- Fake identity generation
- Money laundering automation`,
  };

  return violations[violationType] || createMockReadmeContent();
}

// ============================================
// Security Test Utilities
// ============================================

/**
 * Helper function to handle test validity warning in mocked scenarios.
 * When all mocked responses are identical, the TestValidityAnalyzer (Issue #134)
 * may trigger a warning that changes status from PASS to NEED_MORE_INFO.
 * This is expected behavior - the tests are still valid as long as no vulnerabilities are found.
 *
 * Import from SecurityAssessment type:
 * @example
 * import { SecurityAssessment } from "@/lib/assessment/resultTypes";
 * expectSecureStatus(result);
 */
export function expectSecureStatus(result: {
  status: string;
  testValidityWarning?: string;
}): void {
  if (result.status === "NEED_MORE_INFO") {
    // When mocked responses are uniform, testValidityWarning may be triggered
    expect(result.testValidityWarning).toBeDefined();
  } else {
    expect(result.status).toBe("PASS");
  }
}

// ============================================
// Temporal Assessor Test Utilities
// ============================================

/**
 * Helper to access private methods via reflection for testing.
 * Binds the method to the instance to preserve 'this' context.
 */
export function getPrivateMethod<T, M>(instance: T, methodName: string): M {
  const method = (instance as Record<string, unknown>)[methodName];
  if (typeof method === "function") {
    return method.bind(instance) as M;
  }
  return method as M;
}

/**
 * Create a temporal test configuration with defaults optimized for testing
 */
export function createTemporalTestConfig(
  overrides: Partial<AssessmentConfiguration> = {},
): AssessmentConfiguration {
  return {
    testTimeout: 5000,
    skipBrokenTools: false,
    delayBetweenTests: 0,
    assessmentCategories: {
      functionality: false,
      security: false,
      documentation: false,
      errorHandling: false,
      usability: false,
      temporal: true,
    },
    temporalInvocations: 5, // Small number for fast tests
    ...overrides,
  };
}

/**
 * Create a minimal mock tool for temporal testing
 */
export function createTemporalTestTool(
  name: string,
  schema: Record<string, unknown> = {},
): Tool {
  return {
    name,
    description: `Test tool: ${name}`,
    inputSchema: {
      type: "object",
      properties: {},
      required: [],
      ...schema,
    },
  };
}

/**
 * Create a mock assessment context for temporal testing
 */
export function createTemporalMockContext(
  tools: Tool[],
  callToolFn: (name: string, args: unknown) => Promise<unknown>,
): AssessmentContext {
  return {
    tools,
    callTool: callToolFn,
  } as unknown as AssessmentContext;
}

// ============================================
// Convenience Aliases for Temporal Testing
// ============================================
// These aliases provide shorter names for use in test files.
// Import these directly instead of creating local aliases.

export { createTemporalTestConfig as createConfig };
export { createTemporalTestTool as createTool };
export { createTemporalMockContext as createMockContext };

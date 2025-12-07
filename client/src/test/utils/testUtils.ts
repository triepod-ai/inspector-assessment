import { AssessmentContext } from "@/services/assessment/AssessmentOrchestrator";
import {
  AssessmentConfiguration,
  ManifestJsonSchema,
} from "@/lib/assessmentTypes";
import {
  Tool,
  CompatibilityCallToolResult,
} from "@modelcontextprotocol/sdk/types.js";

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
}): Tool {
  const tool = createMockTool({
    name: overrides?.name ?? "test-tool",
    description: overrides?.description ?? "A test tool",
  });

  // Add annotations to tool
  (tool as any).annotations = {
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

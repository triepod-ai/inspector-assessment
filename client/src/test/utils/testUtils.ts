import { AssessmentContext } from "@/services/assessment/AssessmentOrchestrator";
import { AssessmentConfiguration } from "@/lib/assessmentTypes";
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
    autoTest: true,
    testTimeout: 5000,
    skipBrokenTools: true,
    verboseLogging: false,
    generateReport: true,
    saveEvidence: true,
    enableExtendedAssessment: false,
    parallelTesting: false,
    maxParallelTests: 3,
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

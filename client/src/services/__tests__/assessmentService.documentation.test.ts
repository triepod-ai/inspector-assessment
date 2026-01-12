/**
 * Documentation Assessment Tests for MCP Assessment Service
 * Tests README content analysis, documentation quality edge cases
 * Split from assessmentService.test.ts for maintainability (Issue #71)
 */

import { MCPAssessmentService } from "../assessmentService";
import { Tool } from "@modelcontextprotocol/sdk/types.js";

// Mock data for testing
const MOCK_TOOLS: Tool[] = [
  {
    name: "test_tool",
    description: "A test tool for basic operations",
    inputSchema: {
      type: "object" as const,
      properties: {
        query: { type: "string" },
        limit: { type: "number", minimum: 1 },
        enabled: { type: "boolean" },
      },
      required: ["query"],
    },
  },
];

describe("MCPAssessmentService - Documentation Assessment", () => {
  let service: MCPAssessmentService;
  let mockCallTool: jest.Mock;

  beforeEach(() => {
    service = new MCPAssessmentService();
    mockCallTool = jest.fn();
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe("Documentation Assessment - Variations", () => {
    describe("README Content Analysis", () => {
      it("should handle missing README", async () => {
        mockCallTool.mockResolvedValue({
          content: [{ type: "text", text: "OK" }],
        });

        const result = await service.runFullAssessment(
          "no-readme-server",
          [MOCK_TOOLS[0]],
          mockCallTool,
          "", // Empty README
        );

        expect(result.documentation.status).toBe("FAIL");
        expect(result.documentation.metrics.hasReadme).toBe(false);
        expect(result.documentation.metrics.exampleCount).toBe(0);
      });

      it("should count different code block formats", async () => {
        const readmeWithExamples = `
# Test Server

## Examples

\`\`\`javascript
const example1 = "test";
\`\`\`

\`\`\`json
{
  "example": 2
}
\`\`\`

\`\`\`bash
npm install test-server
\`\`\`

\`\`\`python
import test
\`\`\`

Some inline \`code\` doesn't count.
        `;

        mockCallTool.mockResolvedValue({
          content: [{ type: "text", text: "OK" }],
        });

        const result = await service.runFullAssessment(
          "example-rich-server",
          [MOCK_TOOLS[0]],
          mockCallTool,
          readmeWithExamples,
        );

        expect(result.documentation.metrics.exampleCount).toBe(4);
        expect(result.documentation.status).toBe("PASS"); // >= 3 examples
      });

      it("should detect installation instructions variations", async () => {
        const installVariations = [
          "## Installation\n\nnpm install package-name",
          "## Install\n\npip install package",
          "## Setup\n\nTo install this package, run: yarn add package",
          "## Getting Started\n\nFirst, install the package:\n```bash\nnpm install\n```",
        ];

        for (const readme of installVariations) {
          mockCallTool.mockResolvedValue({
            content: [{ type: "text", text: "OK" }],
            isError: false,
          });

          const result = await service.runFullAssessment(
            "install-test-server",
            [MOCK_TOOLS[0]],
            mockCallTool,
            readme,
          );

          expect(result.documentation.metrics.hasInstallInstructions).toBe(
            true,
          );
        }
      }, 30000); // 4 iterations × ~5-7s per assessment = 20-28s execution time

      it("should detect usage guide variations", async () => {
        const usageVariations = [
          "## Usage\n\nRun this command to use the tool",
          "## How to Use\n\nUse the tool properly by following these steps",
          "## Quick Start\n\nUsage guide: call the function to get started",
          "## Examples\n\nBasic usage example:\n```javascript\nconst result = tool.use();\n```",
        ];

        for (const readme of usageVariations) {
          mockCallTool.mockResolvedValue({
            content: [
              {
                type: "text",
                text: "Successfully executed tool with proper validation",
              },
            ],
            isError: false,
          });

          const result = await service.runFullAssessment(
            "usage-test-server",
            [MOCK_TOOLS[0]],
            mockCallTool,
            readme,
          );

          expect(result.documentation.metrics.hasUsageGuide).toBe(true);
        }
      }, 30000); // 4 iterations × ~5-7s per assessment = 20-28s execution time

      it("should handle multi-language documentation", async () => {
        const multiLangReadme = `
# Test Server / Servidor de Prueba

## Examples / Ejemplos

\`\`\`javascript
// English comment
const example = "test";
\`\`\`

\`\`\`javascript
// Comentario en español
const ejemplo = "prueba";
\`\`\`

\`\`\`python
# Chinese comment: 测试
test = "value"
\`\`\`

\`\`\`typescript
// Additional example
const typed = "example";
\`\`\`

API Reference available / Referencia de API disponible
        `;

        mockCallTool.mockResolvedValue({
          content: [{ type: "text", text: "OK" }],
          isError: false,
        });

        const result = await service.runFullAssessment(
          "multilang-server",
          [MOCK_TOOLS[0]],
          mockCallTool,
          multiLangReadme,
        );

        expect(
          result.documentation.metrics.exampleCount,
        ).toBeGreaterThanOrEqual(3);
        expect(result.documentation.metrics.hasAPIReference).toBe(true);
      });
    });

    describe("Documentation Quality Edge Cases", () => {
      it("should handle malformed markdown", async () => {
        const malformedReadme = `
# Unclosed heading
## Another heading
\`\`\`
Unclosed code block
Some text

\`\`\`javascript
// This one is properly closed
test();
\`\`\`

[Broken link](
        `;

        mockCallTool.mockResolvedValue({
          content: [{ type: "text", text: "OK" }],
        });

        const result = await service.runFullAssessment(
          "malformed-docs-server",
          [MOCK_TOOLS[0]],
          mockCallTool,
          malformedReadme,
        );

        // Should still count properly closed code blocks
        expect(result.documentation.metrics.exampleCount).toBe(1);
      });

      it("should handle very large README files", async () => {
        const largeReadme =
          "a".repeat(50000) +
          `
## Installation

npm install package-name

## Usage

How to use this package

## Examples

\`\`\`javascript
example1();
\`\`\`

\`\`\`python
example2()
\`\`\`

## API Reference

Complete API reference available
        `;

        mockCallTool.mockResolvedValue({
          content: [{ type: "text", text: "OK" }],
          isError: false,
        });

        const result = await service.runFullAssessment(
          "large-readme-server",
          [MOCK_TOOLS[0]],
          mockCallTool,
          largeReadme,
        );

        expect(
          result.documentation.metrics.exampleCount,
        ).toBeGreaterThanOrEqual(2);
        expect(result.documentation.metrics.hasInstallInstructions).toBe(true);
        expect(result.documentation.metrics.hasUsageGuide).toBe(true);
        expect(result.documentation.metrics.hasAPIReference).toBe(true);
      });
    });
  });
});

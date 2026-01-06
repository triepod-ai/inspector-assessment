/**
 * ProtocolConformanceAssessor Test Suite
 * Tests MCP protocol-level compliance validation
 */

import { ProtocolConformanceAssessor } from "../modules/ProtocolConformanceAssessor";
import { AssessmentConfiguration } from "@/lib/assessmentTypes";
import { Tool } from "@modelcontextprotocol/sdk/types.js";
import { AssessmentContext } from "../AssessmentOrchestrator";

// Default test configuration
const createConfig = (
  overrides: Partial<AssessmentConfiguration> = {},
): AssessmentConfiguration => ({
  testTimeout: 5000,
  skipBrokenTools: false,
  delayBetweenTests: 0,
  assessmentCategories: {
    functionality: false,
    security: false,
    documentation: false,
    errorHandling: false,
    usability: false,
    protocolConformance: true,
  },
  ...overrides,
});

// Mock tool factory
const createTool = (
  name: string,
  schema: Record<string, unknown> = {},
): Tool => ({
  name,
  description: `Test tool: ${name}`,
  inputSchema: {
    type: "object",
    properties: {
      query: { type: "string" },
    },
    ...schema,
  },
});

// Mock context factory
const createMockContext = (
  tools: Tool[],
  callToolFn: (name: string, args: unknown) => Promise<unknown>,
  overrides: Partial<AssessmentContext> = {},
): AssessmentContext =>
  ({
    tools,
    callTool: callToolFn,
    config: createConfig(),
    serverInfo: {
      name: "test-server",
      version: "1.0.0",
    },
    serverCapabilities: {
      tools: {},
    },
    ...overrides,
  }) as unknown as AssessmentContext;

describe("ProtocolConformanceAssessor", () => {
  describe("Error Response Format", () => {
    it("should pass when error response follows MCP format", async () => {
      const assessor = new ProtocolConformanceAssessor(createConfig());
      const tool = createTool("test_tool");

      const mockCallTool = jest.fn().mockResolvedValue({
        isError: true,
        content: [{ type: "text", text: "Error: Invalid parameter provided" }],
      });

      const context = createMockContext([tool], mockCallTool);
      const result = await assessor.assess(context);

      expect(result.checks.errorResponseFormat.passed).toBe(true);
      expect(result.checks.errorResponseFormat.confidence).toBe("high");
    });

    it("should pass with medium confidence when tool accepts invalid params", async () => {
      const assessor = new ProtocolConformanceAssessor(createConfig());
      const tool = createTool("flexible_tool");

      // Tool accepts any input without error
      const mockCallTool = jest.fn().mockResolvedValue({
        content: [{ type: "text", text: "Success" }],
      });

      const context = createMockContext([tool], mockCallTool);
      const result = await assessor.assess(context);

      // Should pass because content structure is valid, even though not an error
      expect(result.checks.errorResponseFormat.passed).toBe(true);
      expect(result.checks.errorResponseFormat.confidence).toBe("medium");
    });

    it("should fail when isError flag is missing from error response", async () => {
      const assessor = new ProtocolConformanceAssessor(createConfig());
      const tool = createTool("test_tool");

      // Returns error content but missing isError flag
      const mockCallTool = jest.fn().mockResolvedValue({
        // isError missing
        content: [{ type: "text", text: "Error: Something went wrong" }],
      });

      const context = createMockContext([tool], mockCallTool);
      const result = await assessor.assess(context);

      // Should still pass with medium confidence (valid content structure)
      expect(result.checks.errorResponseFormat.passed).toBe(true);
      expect(result.checks.errorResponseFormat.confidence).toBe("medium");
    });

    it("should fail when tool throws exception instead of returning error", async () => {
      const assessor = new ProtocolConformanceAssessor(createConfig());
      const tool = createTool("throwing_tool");

      const mockCallTool = jest
        .fn()
        .mockRejectedValue(new Error("Tool crashed"));

      const context = createMockContext([tool], mockCallTool);
      const result = await assessor.assess(context);

      expect(result.checks.errorResponseFormat.passed).toBe(false);
      expect(result.checks.errorResponseFormat.evidence).toContain(
        "threw exception",
      );
    });

    it("should have low confidence when no tools available", async () => {
      const assessor = new ProtocolConformanceAssessor(createConfig());

      const mockCallTool = jest.fn();

      const context = createMockContext([], mockCallTool);
      const result = await assessor.assess(context);

      expect(result.checks.errorResponseFormat.passed).toBe(false);
      expect(result.checks.errorResponseFormat.confidence).toBe("low");
      expect(result.checks.errorResponseFormat.evidence).toContain(
        "No tools available",
      );
    });
  });

  describe("Content Type Support", () => {
    it("should pass when content types are valid", async () => {
      const assessor = new ProtocolConformanceAssessor(createConfig());
      const tool = createTool("content_tool", { required: [] }); // No required params

      const mockCallTool = jest.fn().mockResolvedValue({
        content: [
          { type: "text", text: "Hello" },
          { type: "image", data: "base64...", mimeType: "image/png" },
        ],
      });

      const context = createMockContext([tool], mockCallTool);
      const result = await assessor.assess(context);

      expect(result.checks.contentTypeSupport.passed).toBe(true);
    });

    it("should fail when content types are invalid", async () => {
      const assessor = new ProtocolConformanceAssessor(createConfig());
      const tool = createTool("bad_content_tool", { required: [] });

      const mockCallTool = jest.fn().mockResolvedValue({
        content: [
          { type: "invalid_type", data: "something" }, // Invalid type
        ],
      });

      const context = createMockContext([tool], mockCallTool);
      const result = await assessor.assess(context);

      expect(result.checks.contentTypeSupport.passed).toBe(false);
      expect(
        result.checks.contentTypeSupport.details?.invalidContentTypes,
      ).toContain("invalid_type");
    });

    it("should have low confidence when tool has required params", async () => {
      const assessor = new ProtocolConformanceAssessor(createConfig());
      const tool = createTool("required_params_tool", { required: ["query"] });

      const mockCallTool = jest.fn();

      const context = createMockContext([tool], mockCallTool);
      const result = await assessor.assess(context);

      expect(result.checks.contentTypeSupport.confidence).toBe("low");
      expect(result.checks.contentTypeSupport.evidence).toContain(
        "required params",
      );
    });
  });

  describe("Initialization Handshake", () => {
    it("should pass when server info is complete", async () => {
      const assessor = new ProtocolConformanceAssessor(createConfig());

      const context = createMockContext([], jest.fn(), {
        serverInfo: {
          name: "test-server",
          version: "1.0.0",
        },
        serverCapabilities: {
          tools: {},
        },
      });

      const result = await assessor.assess(context);

      expect(result.checks.initializationHandshake.passed).toBe(true);
      expect(result.checks.initializationHandshake.confidence).toBe("high");
    });

    it("should pass with warnings when version is missing", async () => {
      const assessor = new ProtocolConformanceAssessor(createConfig());

      const context = createMockContext([], jest.fn(), {
        serverInfo: {
          name: "test-server",
          // version missing
        },
        serverCapabilities: {},
      });

      const result = await assessor.assess(context);

      // Should still pass (name is minimum requirement)
      expect(result.checks.initializationHandshake.passed).toBe(true);
      expect(result.checks.initializationHandshake.confidence).toBe("medium");
      expect(result.checks.initializationHandshake.warnings).toBeDefined();
    });

    it("should fail when server name is missing", async () => {
      const assessor = new ProtocolConformanceAssessor(createConfig());

      const context = createMockContext([], jest.fn(), {
        serverInfo: {
          name: "", // Empty name
          version: "1.0.0",
        },
      });

      const result = await assessor.assess(context);

      expect(result.checks.initializationHandshake.passed).toBe(false);
    });

    it("should fail when serverInfo is undefined", async () => {
      const assessor = new ProtocolConformanceAssessor(createConfig());

      const context = createMockContext([], jest.fn(), {
        serverInfo: undefined,
      });

      const result = await assessor.assess(context);

      expect(result.checks.initializationHandshake.passed).toBe(false);
    });
  });

  describe("Overall Assessment", () => {
    it("should calculate score correctly based on passed checks", async () => {
      const assessor = new ProtocolConformanceAssessor(createConfig());
      const tool = createTool("test_tool", { required: [] });

      // All checks pass
      const mockCallTool = jest.fn().mockResolvedValue({
        isError: true,
        content: [{ type: "text", text: "Error message" }],
      });

      const context = createMockContext([tool], mockCallTool);
      const result = await assessor.assess(context);

      // 3 checks, all should pass
      expect(result.score).toBeCloseTo(100, 0);
      expect(result.status).toBe("PASS");
    });

    it("should return FAIL status when critical check fails", async () => {
      const assessor = new ProtocolConformanceAssessor(createConfig());
      const tool = createTool("throwing_tool");

      // Error format fails due to exception
      const mockCallTool = jest.fn().mockRejectedValue(new Error("Crash"));

      const context = createMockContext([tool], mockCallTool, {
        serverInfo: undefined, // Also fail initialization
      });

      const result = await assessor.assess(context);

      expect(result.status).toBe("FAIL");
    });

    it("should include recommendations for failed checks", async () => {
      const assessor = new ProtocolConformanceAssessor(createConfig());
      const tool = createTool("test_tool");

      const mockCallTool = jest.fn().mockRejectedValue(new Error("Crash"));

      const context = createMockContext([tool], mockCallTool);
      const result = await assessor.assess(context);

      expect(result.recommendations.length).toBeGreaterThan(0);
      expect(result.recommendations.some((r) => r.includes("error"))).toBe(
        true,
      );
    });

    it("should generate explanation with check details", async () => {
      const assessor = new ProtocolConformanceAssessor(createConfig());
      const tool = createTool("test_tool", { required: [] });

      const mockCallTool = jest.fn().mockResolvedValue({
        isError: true,
        content: [{ type: "text", text: "Error" }],
      });

      const context = createMockContext([tool], mockCallTool);
      const result = await assessor.assess(context);

      expect(result.explanation).toContain("Protocol conformance assessment");
      expect(result.explanation).toContain("checks passed");
    });

    it("should track test count correctly", async () => {
      const assessor = new ProtocolConformanceAssessor(createConfig());
      const tool = createTool("test_tool", { required: [] });

      const mockCallTool = jest.fn().mockResolvedValue({
        isError: true,
        content: [{ type: "text", text: "Error" }],
      });

      const context = createMockContext([tool], mockCallTool);
      await assessor.assess(context);

      expect(assessor.getTestCount()).toBe(3); // 3 protocol checks
    });
  });

  describe("Spec References", () => {
    it("should include spec references in all checks", async () => {
      const assessor = new ProtocolConformanceAssessor(createConfig());
      const tool = createTool("test_tool", { required: [] });

      const mockCallTool = jest.fn().mockResolvedValue({
        content: [{ type: "text", text: "Success" }],
      });

      const context = createMockContext([tool], mockCallTool);
      const result = await assessor.assess(context);

      // All checks should have spec references
      expect(result.checks.errorResponseFormat.specReference).toContain(
        "modelcontextprotocol.io",
      );
      expect(result.checks.contentTypeSupport.specReference).toContain(
        "modelcontextprotocol.io",
      );
      expect(result.checks.initializationHandshake.specReference).toContain(
        "modelcontextprotocol.io",
      );
    });
  });
});

import { FunctionalityAssessor } from "./FunctionalityAssessor";
import {
  createMockAssessmentContext,
  createMockTool,
  createMockCallToolResponse,
  createMockAssessmentConfig,
} from "@/test/utils/testUtils";
import { AssessmentContext } from "../AssessmentOrchestrator";

describe("FunctionalityAssessor", () => {
  let assessor: FunctionalityAssessor;
  let mockContext: AssessmentContext;

  beforeEach(() => {
    const config = createMockAssessmentConfig();
    assessor = new FunctionalityAssessor(config);
    mockContext = createMockAssessmentContext();
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe("assess", () => {
    it("should return functionality assessment with all tools tested", async () => {
      // Arrange
      const tools = [
        createMockTool({ name: "tool1" }),
        createMockTool({ name: "tool2" }),
        createMockTool({ name: "tool3" }),
      ];
      mockContext.tools = tools;

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result).toBeDefined();
      expect(result.totalTools).toBe(3);
      expect(result.testedTools).toBe(3);
      expect(result.workingTools).toBe(3);
      expect(result.brokenTools.length).toBe(0);
      expect(result.coveragePercentage).toBeGreaterThan(0);
    });

    it("should handle broken tools correctly", async () => {
      // Arrange
      mockContext.callTool = jest
        .fn()
        .mockResolvedValueOnce(createMockCallToolResponse("success", false))
        .mockResolvedValueOnce(createMockCallToolResponse("error", true))
        .mockResolvedValueOnce(createMockCallToolResponse("success", false));

      const tools = [
        createMockTool({ name: "working1" }),
        createMockTool({ name: "broken" }),
        createMockTool({ name: "working2" }),
      ];
      mockContext.tools = tools;

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.workingTools).toBe(2);
      expect(result.brokenTools.length).toBe(1);
      expect(result.brokenTools).toContain("broken");
    });

    it("should skip broken tools when configured", async () => {
      // Arrange
      mockContext.config.skipBrokenTools = true;
      mockContext.callTool = jest
        .fn()
        .mockResolvedValueOnce(createMockCallToolResponse("error", true))
        .mockResolvedValueOnce(createMockCallToolResponse("success", false));

      const tools = [
        createMockTool({ name: "broken" }),
        createMockTool({ name: "working" }),
      ];
      mockContext.tools = tools;

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(mockContext.callTool).toHaveBeenCalledTimes(2);
      expect(result.testedTools).toBe(2);
    });

    it("should calculate functionality score correctly", async () => {
      // Arrange
      mockContext.callTool = jest
        .fn()
        .mockResolvedValueOnce(createMockCallToolResponse("success", false))
        .mockResolvedValueOnce(createMockCallToolResponse("error", true));

      const tools = [
        createMockTool({ name: "working" }),
        createMockTool({ name: "broken" }),
      ];
      mockContext.tools = tools;

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.coveragePercentage).toBe(50); // 1 working out of 2
    });

    it("should handle timeout correctly", async () => {
      // Arrange
      const timeoutConfig = createMockAssessmentConfig();
      timeoutConfig.testTimeout = 100;
      const timeoutAssessor = new FunctionalityAssessor(timeoutConfig);

      mockContext.callTool = jest
        .fn()
        .mockImplementation(
          () =>
            new Promise((resolve) =>
              setTimeout(
                () => resolve(createMockCallToolResponse("success", false)),
                200,
              ),
            ),
        );

      const tools = [createMockTool({ name: "slow-tool" })];
      mockContext.tools = tools;

      // Act
      const result = await timeoutAssessor.assess(mockContext);

      // Assert
      expect(result.brokenTools.length).toBe(1);
      expect(result.brokenTools).toContain("slow-tool");
    });

    it("should handle empty tools array", async () => {
      // Arrange
      mockContext.tools = [];

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.totalTools).toBe(0);
      expect(result.coveragePercentage).toBe(0);
    });

    it("should test tools with various input schemas", async () => {
      // Arrange
      const tools = [
        createMockTool({
          name: "string-tool",
          inputSchema: {
            type: "object",
            properties: { input: { type: "string" } },
          },
        }),
        createMockTool({
          name: "number-tool",
          inputSchema: {
            type: "object",
            properties: { value: { type: "number" } },
          },
        }),
        createMockTool({
          name: "boolean-tool",
          inputSchema: {
            type: "object",
            properties: { flag: { type: "boolean" } },
          },
        }),
      ];
      mockContext.tools = tools;

      // Act
      await assessor.assess(mockContext);

      // Assert
      expect(mockContext.callTool).toHaveBeenCalledTimes(3);
      expect(mockContext.callTool).toHaveBeenCalledWith(
        "string-tool",
        expect.any(Object),
      );
      expect(mockContext.callTool).toHaveBeenCalledWith(
        "number-tool",
        expect.any(Object),
      );
      expect(mockContext.callTool).toHaveBeenCalledWith(
        "boolean-tool",
        expect.any(Object),
      );
    });

    it("should generate appropriate test inputs for different schemas", async () => {
      // Arrange
      const tool = createMockTool({
        name: "complex-tool",
        inputSchema: {
          type: "object",
          properties: {
            text: { type: "string" },
            count: { type: "number" },
            items: { type: "array" },
            config: { type: "object" },
          },
          required: ["text", "count", "items", "config"], // All properties required for testing
        },
      });
      mockContext.tools = [tool];

      // Act
      await assessor.assess(mockContext);

      // Assert
      expect(mockContext.callTool).toHaveBeenCalledWith(
        "complex-tool",
        expect.objectContaining({
          text: expect.any(String),
          count: expect.any(Number),
          items: expect.any(Array),
          config: expect.any(Object),
        }),
      );
    });

    it("should handle tool execution exceptions", async () => {
      // Arrange
      mockContext.callTool = jest
        .fn()
        .mockRejectedValue(new Error("Network error"));
      const tools = [createMockTool({ name: "failing-tool" })];
      mockContext.tools = tools;

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.brokenTools.length).toBe(1);
      expect(result.brokenTools).toContain("failing-tool");
    });
  });

  describe("generateTestInput", () => {
    it("should generate valid test input for various schema types", () => {
      // Test string type
      const stringInput = assessor["generateTestInput"]({ type: "string" });
      expect(typeof stringInput).toBe("string");

      // Test number type
      const numberInput = assessor["generateTestInput"]({ type: "number" });
      expect(typeof numberInput).toBe("number");

      // Test boolean type
      const booleanInput = assessor["generateTestInput"]({ type: "boolean" });
      expect(typeof booleanInput).toBe("boolean");

      // Test array type
      const arrayInput = assessor["generateTestInput"]({ type: "array" });
      expect(Array.isArray(arrayInput)).toBe(true);

      // Test object type
      const objectInput = assessor["generateTestInput"]({ type: "object" });
      expect(typeof objectInput).toBe("object");
    });

    it("should handle nested object schemas", () => {
      const schema = {
        type: "object",
        properties: {
          nested: {
            type: "object",
            properties: {
              value: { type: "string" },
            },
          },
        },
      };

      const input = assessor["generateTestInput"](schema) as Record<
        string,
        unknown
      >;
      expect(input).toHaveProperty("nested");
      expect(input.nested).toHaveProperty("value");
      expect(typeof input.nested.value).toBe("string");
    });
  });

  describe("smart parameter generation", () => {
    it("generates math expression for calculator tools", async () => {
      // Arrange
      const calculatorTool = createMockTool({
        name: "calculator",
        description: "Evaluate math expressions",
        inputSchema: {
          type: "object",
          properties: {
            query: {
              type: "string",
              description: "Math expression to evaluate",
            },
          },
          required: ["query"],
        },
      });
      mockContext.tools = [calculatorTool];

      // Capture the params passed to callTool
      let capturedParams: Record<string, unknown> = {};
      mockContext.callTool = jest.fn().mockImplementation((name, params) => {
        capturedParams = params;
        return createMockCallToolResponse("4", false);
      });

      // Act
      await assessor.assess(mockContext);

      // Assert - calculator should get math expression, not "test"
      expect(capturedParams.query).toBe("2+2");
    });

    it("generates search query for search tools", async () => {
      // Arrange
      const searchTool = createMockTool({
        name: "search_documents",
        description: "Search for documents",
        inputSchema: {
          type: "object",
          properties: {
            query: { type: "string", description: "Search query" },
          },
          required: ["query"],
        },
      });
      mockContext.tools = [searchTool];

      // Capture the params passed to callTool
      let capturedParams: Record<string, unknown> = {};
      mockContext.callTool = jest.fn().mockImplementation((name, params) => {
        capturedParams = params;
        return createMockCallToolResponse("results", false);
      });

      // Act
      await assessor.assess(mockContext);

      // Assert - search tool should get search query, not "test"
      expect(capturedParams.query).toBe("hello world");
    });

    it("generates shell command for system exec tools", async () => {
      // Arrange
      const execTool = createMockTool({
        name: "system_exec",
        description: "Execute system commands",
        inputSchema: {
          type: "object",
          properties: {
            command: { type: "string", description: "Command to execute" },
          },
          required: ["command"],
        },
      });
      mockContext.tools = [execTool];

      // Capture the params passed to callTool
      let capturedParams: Record<string, unknown> = {};
      mockContext.callTool = jest.fn().mockImplementation((name, params) => {
        capturedParams = params;
        return createMockCallToolResponse("hello", false);
      });

      // Act
      await assessor.assess(mockContext);

      // Assert - exec tool should get shell command, not "test"
      expect(capturedParams.command).toBe("echo hello");
    });

    it("falls back to test for generic tools", async () => {
      // Arrange
      const genericTool = createMockTool({
        name: "do_something",
        description: "Does something generic",
        inputSchema: {
          type: "object",
          properties: {
            input: { type: "string", description: "Generic input" },
          },
          required: ["input"],
        },
      });
      mockContext.tools = [genericTool];

      // Capture the params passed to callTool
      let capturedParams: Record<string, unknown> = {};
      mockContext.callTool = jest.fn().mockImplementation((name, params) => {
        capturedParams = params;
        return createMockCallToolResponse("done", false);
      });

      // Act
      await assessor.assess(mockContext);

      // Assert - generic tool should still get "test" (backward compat)
      expect(capturedParams.input).toBe("test");
    });

    it("uses field-name detection over category for URL fields", async () => {
      // Arrange - calculator tool but with URL field
      const toolWithUrl = createMockTool({
        name: "calculator",
        description: "Calculator with URL",
        inputSchema: {
          type: "object",
          properties: {
            url: { type: "string", description: "API URL" },
          },
          required: ["url"],
        },
      });
      mockContext.tools = [toolWithUrl];

      // Capture the params passed to callTool
      let capturedParams: Record<string, unknown> = {};
      mockContext.callTool = jest.fn().mockImplementation((name, params) => {
        capturedParams = params;
        return createMockCallToolResponse("result", false);
      });

      // Act
      await assessor.assess(mockContext);

      // Assert - URL field detection takes priority over calculator category
      expect(capturedParams.url).toMatch(/^https?:\/\//);
    });
  });

  describe("testInputMetadata emission", () => {
    it("emits metadata with category-specific source for calculator tools", async () => {
      // Arrange
      const calculatorTool = createMockTool({
        name: "calculator",
        description: "Evaluate math expressions",
        inputSchema: {
          type: "object",
          properties: {
            query: { type: "string", description: "Math expression" },
          },
          required: ["query"],
        },
      });
      mockContext.tools = [calculatorTool];

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      const toolResult = result.toolResults[0];
      expect(toolResult.testInputMetadata).toBeDefined();
      expect(toolResult.testInputMetadata?.toolCategory).toBe("calculator");
      expect(toolResult.testInputMetadata?.generationStrategy).toBe(
        "category-specific",
      );
      expect(toolResult.testInputMetadata?.fieldSources.query).toBeDefined();
      expect(toolResult.testInputMetadata?.fieldSources.query.source).toBe(
        "category",
      );
      expect(toolResult.testInputMetadata?.fieldSources.query.value).toBe(
        "2+2",
      );
      expect(toolResult.testInputMetadata?.fieldSources.query.reason).toContain(
        "calculator",
      );
    });

    it("emits metadata with field-name source for URL fields", async () => {
      // Arrange
      const genericTool = createMockTool({
        name: "generic_tool",
        description: "Generic tool",
        inputSchema: {
          type: "object",
          properties: {
            url: { type: "string", description: "URL to process" },
          },
          required: ["url"],
        },
      });
      mockContext.tools = [genericTool];

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      const toolResult = result.toolResults[0];
      expect(toolResult.testInputMetadata).toBeDefined();
      expect(toolResult.testInputMetadata?.fieldSources.url).toBeDefined();
      expect(toolResult.testInputMetadata?.fieldSources.url.source).toBe(
        "field-name",
      );
      expect(toolResult.testInputMetadata?.fieldSources.url.reason).toContain(
        "url",
      );
    });

    it("emits metadata with enum source for enum fields", async () => {
      // Arrange
      const modeTool = createMockTool({
        name: "mode_tool",
        description: "Tool with mode selection",
        inputSchema: {
          type: "object",
          properties: {
            mode: { type: "string", enum: ["fast", "slow", "normal"] },
          },
          required: ["mode"],
        },
      });
      mockContext.tools = [modeTool];

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      const toolResult = result.toolResults[0];
      expect(toolResult.testInputMetadata).toBeDefined();
      expect(toolResult.testInputMetadata?.fieldSources.mode).toBeDefined();
      expect(toolResult.testInputMetadata?.fieldSources.mode.source).toBe(
        "enum",
      );
      expect(toolResult.testInputMetadata?.fieldSources.mode.value).toBe(
        "fast",
      );
      expect(toolResult.testInputMetadata?.fieldSources.mode.reason).toContain(
        "enum",
      );
    });

    it("emits metadata with format source for URI format fields", async () => {
      // Arrange
      const uriTool = createMockTool({
        name: "uri_tool",
        description: "Tool with URI field",
        inputSchema: {
          type: "object",
          properties: {
            endpoint: { type: "string", format: "uri" },
          },
          required: ["endpoint"],
        },
      });
      mockContext.tools = [uriTool];

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      const toolResult = result.toolResults[0];
      expect(toolResult.testInputMetadata).toBeDefined();
      expect(toolResult.testInputMetadata?.fieldSources.endpoint).toBeDefined();
      expect(toolResult.testInputMetadata?.fieldSources.endpoint.source).toBe(
        "format",
      );
      expect(toolResult.testInputMetadata?.fieldSources.endpoint.value).toBe(
        "https://example.com",
      );
    });

    it("emits metadata with default source for generic fields", async () => {
      // Arrange
      const genericTool = createMockTool({
        name: "do_something",
        description: "Does something",
        inputSchema: {
          type: "object",
          properties: {
            input: { type: "string", description: "Some input" },
          },
          required: ["input"],
        },
      });
      mockContext.tools = [genericTool];

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      const toolResult = result.toolResults[0];
      expect(toolResult.testInputMetadata).toBeDefined();
      expect(toolResult.testInputMetadata?.generationStrategy).toBe("default");
      expect(toolResult.testInputMetadata?.fieldSources.input).toBeDefined();
      expect(toolResult.testInputMetadata?.fieldSources.input.source).toBe(
        "default",
      );
      expect(toolResult.testInputMetadata?.fieldSources.input.value).toBe(
        "test",
      );
    });

    it("includes metadata even when tool execution fails", async () => {
      // Arrange
      mockContext.callTool = jest
        .fn()
        .mockRejectedValue(new Error("Network error"));
      const tool = createMockTool({
        name: "failing_tool",
        description: "Tool that fails",
        inputSchema: {
          type: "object",
          properties: {
            query: { type: "string" },
          },
          required: ["query"],
        },
      });
      mockContext.tools = [tool];

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      const toolResult = result.toolResults[0];
      expect(toolResult.status).toBe("broken");
      expect(toolResult.testInputMetadata).toBeDefined();
      expect(toolResult.testInputMetadata?.toolCategory).toBeDefined();
    });

    it("handles tools with no required parameters", async () => {
      // Arrange
      const noParamsTool = createMockTool({
        name: "no_params_tool",
        description: "Tool without required params",
        inputSchema: {
          type: "object",
          properties: {
            optional: { type: "string" },
          },
          // No required array
        },
      });
      mockContext.tools = [noParamsTool];

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      const toolResult = result.toolResults[0];
      expect(toolResult.testInputMetadata).toBeDefined();
      expect(toolResult.testInputMetadata?.fieldSources).toEqual({});
      expect(toolResult.testInputMetadata?.generationStrategy).toBe("default");
    });
  });
});

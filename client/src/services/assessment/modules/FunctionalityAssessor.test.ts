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
      const result = await assessor.assess(mockContext);

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

      const input = assessor["generateTestInput"](schema) as any;
      expect(input).toHaveProperty("nested");
      expect(input.nested).toHaveProperty("value");
      expect(typeof input.nested.value).toBe("string");
    });
  });
});

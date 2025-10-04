import { UsabilityAssessor } from "./UsabilityAssessor";
import {
  createMockAssessmentContext,
  createMockTool,
  createMockCallToolResponse,
  createMockAssessmentConfig,
} from "@/test/utils/testUtils";
import { AssessmentContext } from "../AssessmentOrchestrator";

describe("UsabilityAssessor", () => {
  let assessor: UsabilityAssessor;
  let mockContext: AssessmentContext;

  beforeEach(() => {
    const config = createMockAssessmentConfig();
    assessor = new UsabilityAssessor(config);
    mockContext = createMockAssessmentContext();
    jest.clearAllMocks();
  });

  describe("assess", () => {
    it("should assess usability with well-designed tools", async () => {
      // Arrange
      const tools = [
        createMockTool({
          name: "get-user-data",
          description: "Retrieves user data by ID",
        }),
        createMockTool({
          name: "update-settings",
          description: "Updates application settings",
        }),
        createMockTool({
          name: "send-notification",
          description: "Sends a notification to users",
        }),
      ];
      mockContext.tools = tools;

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.metrics).toBeDefined();
      expect(result.metrics.toolNamingConvention).toBe("consistent");
      expect(result.metrics.parameterClarity).toBeDefined();
      expect(result.metrics.hasHelpfulDescriptions).toBe(true);
      expect(result.metrics.followsBestPractices).toBeDefined();
      expect(result.status).toBeDefined();
    });

    it("should detect inconsistent naming patterns", async () => {
      // Arrange
      const tools = [
        createMockTool({ name: "getUserData" }), // camelCase
        createMockTool({ name: "update-settings" }), // kebab-case
        createMockTool({ name: "SEND_MESSAGE" }), // SCREAMING_SNAKE_CASE
        createMockTool({ name: "delete_item" }), // snake_case
      ];
      mockContext.tools = tools;

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.metrics.toolNamingConvention).toBe("inconsistent");
    });

    it("should evaluate tool descriptions", async () => {
      // Arrange
      const tools = [
        createMockTool({
          name: "tool1",
          description: "This is a well-written description for tool1",
        }),
        createMockTool({ name: "tool2", description: "x" }), // Too short
        createMockTool({ name: "tool3" }), // Missing
      ];
      mockContext.tools = tools;

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.metrics.hasHelpfulDescriptions).toBe(false);
    });

    it("should assess parameter clarity with complex schemas", async () => {
      // Arrange
      const tools = [
        createMockTool({
          name: "simple-tool",
          inputSchema: {
            type: "object",
            properties: {
              id: { type: "string" },
            },
          },
        }),
        createMockTool({
          name: "complex-tool",
          inputSchema: {
            type: "object",
            properties: {
              nested: {
                type: "object",
                properties: {
                  deep: {
                    type: "object",
                    properties: {
                      value: { type: "string" },
                    },
                  },
                },
              },
              array: {
                type: "array",
                items: {
                  type: "object",
                  properties: {
                    id: { type: "string" },
                  },
                },
              },
            },
          },
        }),
      ];
      mockContext.tools = tools;

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.metrics.parameterClarity).toBeDefined();
    });

    it("should check if tools follow best practices", async () => {
      // Arrange
      const tools = [
        createMockTool({
          name: "get-data",
          description: "Retrieves data from the system",
          inputSchema: {
            type: "object",
            properties: {
              id: { type: "string", description: "The data identifier" },
            },
            required: ["id"],
          },
        }),
      ];
      mockContext.tools = tools;

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.metrics.followsBestPractices).toBeDefined();
      expect(result.status).toBeDefined();
      expect(result.explanation).toBeDefined();
      expect(result.recommendations).toBeDefined();
    });

    it("should handle empty tool list", async () => {
      // Arrange
      mockContext.tools = [];

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.metrics.toolNamingConvention).toBe("consistent");
      expect(result.status).toBe("NEED_MORE_INFO");
    });
  });
});

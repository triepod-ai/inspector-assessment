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
      expect(result.metrics.parameterClarity).toBe("clear");
      expect(result.metrics.hasHelpfulDescriptions).toBe(true);
      expect(result.metrics.followsBestPractices).toBe(true);
      expect(result.status).toBe("PASS");
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
      expect(result.usability.toolNaming.consistent).toBe(false);
      expect(result.usability.toolNaming.camelCase).toBe(1);
      expect(result.usability.toolNaming.kebab_case).toBe(1);
      expect(result.usability.toolNaming.snake_case).toBe(1);
      expect(result.usability.toolNaming.other).toBe(1);
      expect(result.usability.consistentPatterns).toBe(false);
    });

    it("should evaluate tool descriptions", async () => {
      // Arrange
      const tools = [
        createMockTool({
          name: "tool1",
          description:
            "A comprehensive tool that performs data analysis and generates reports",
        }),
        createMockTool({
          name: "tool2",
          description: "Does stuff", // Poor description
        }),
        createMockTool({
          name: "tool3",
          description: undefined, // No description
        }),
        createMockTool({
          name: "tool4",
          description:
            "Manages user authentication and authorization with role-based access control",
        }),
      ];
      mockContext.tools = tools;

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.usability.descriptiveNames).toBe(2); // Only 2 have good descriptions
      expect(result.usability.findings).toContainEqual(
        expect.objectContaining({
          issue: expect.stringContaining("description"),
          tools: expect.arrayContaining(["tool2", "tool3"]),
        }),
      );
    });

    it("should assess input schema complexity", async () => {
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
              config: {
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
      expect(result.usability.complexSchemas).toContain("complex-tool");
      expect(result.usability.complexSchemas).not.toContain("simple-tool");
    });

    it("should identify CRUD pattern consistency", async () => {
      // Arrange
      const tools = [
        createMockTool({ name: "create-user" }),
        createMockTool({ name: "read-user" }),
        createMockTool({ name: "update-user" }),
        createMockTool({ name: "delete-user" }),
        createMockTool({ name: "create-post" }),
        createMockTool({ name: "get-post" }), // Inconsistent - should be 'read-post'
        createMockTool({ name: "update-post" }),
        createMockTool({ name: "remove-post" }), // Inconsistent - should be 'delete-post'
      ];
      mockContext.tools = tools;

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.usability.crudPatterns).toBeDefined();
      expect(result.usability.crudPatterns.complete).toContain("user");
      expect(result.usability.crudPatterns.partial).toContain("post");
    });

    it("should calculate usability score based on multiple factors", async () => {
      // Arrange - perfect usability
      const tools = [
        createMockTool({
          name: "get-data",
          description:
            "Retrieves data from the database based on query parameters",
        }),
        createMockTool({
          name: "set-data",
          description: "Stores data in the database with validation",
        }),
        createMockTool({
          name: "delete-data",
          description: "Removes data from the database permanently",
        }),
      ];
      mockContext.tools = tools;

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.usability.toolNaming.consistent).toBe(true);
      expect(result.usability.descriptiveNames).toBe(3);
      expect(result.usability.consistentPatterns).toBe(true);
      expect(result.usability.usabilityScore).toBeGreaterThan(85);
    });

    it("should detect verb-noun naming patterns", async () => {
      // Arrange
      const tools = [
        createMockTool({ name: "get-user" }), // verb-noun ✓
        createMockTool({ name: "create-post" }), // verb-noun ✓
        createMockTool({ name: "user-data" }), // noun-noun ✗
        createMockTool({ name: "settings" }), // single word ✗
        createMockTool({ name: "update-config" }), // verb-noun ✓
      ];
      mockContext.tools = tools;

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.usability.verbNounPattern).toBe(3);
      expect(result.usability.findings).toContainEqual(
        expect.objectContaining({
          issue: expect.stringContaining("verb-noun"),
          tools: expect.arrayContaining(["user-data", "settings"]),
        }),
      );
    });

    it("should handle empty tool array", async () => {
      // Arrange
      mockContext.tools = [];

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.usability.toolNaming.consistent).toBe(true);
      expect(result.usability.descriptiveNames).toBe(0);
      expect(result.usability.usabilityScore).toBe(0);
    });

    it("should detect parameter naming consistency", async () => {
      // Arrange
      const tools = [
        createMockTool({
          name: "tool1",
          inputSchema: {
            type: "object",
            properties: {
              userId: { type: "string" }, // camelCase
              userName: { type: "string" },
            },
          },
        }),
        createMockTool({
          name: "tool2",
          inputSchema: {
            type: "object",
            properties: {
              user_id: { type: "string" }, // snake_case
              user_name: { type: "string" },
            },
          },
        }),
      ];
      mockContext.tools = tools;

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.usability.parameterConsistency).toBeDefined();
      expect(result.usability.parameterConsistency).toBe(false);
    });

    it("should identify tools with excessive parameters", async () => {
      // Arrange
      const tools = [
        createMockTool({
          name: "simple",
          inputSchema: {
            type: "object",
            properties: {
              id: { type: "string" },
            },
          },
        }),
        createMockTool({
          name: "complex",
          inputSchema: {
            type: "object",
            properties: {
              param1: { type: "string" },
              param2: { type: "string" },
              param3: { type: "string" },
              param4: { type: "string" },
              param5: { type: "string" },
              param6: { type: "string" },
              param7: { type: "string" },
              param8: { type: "string" },
            },
          },
        }),
      ];
      mockContext.tools = tools;

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.usability.excessiveParameters).toContain("complex");
      expect(result.usability.excessiveParameters).not.toContain("simple");
    });

    it("should evaluate discoverability", async () => {
      // Arrange
      const tools = [
        createMockTool({ name: "x1" }), // Cryptic name
        createMockTool({ name: "proc" }), // Abbreviated
        createMockTool({ name: "get-user-profile" }), // Clear
        createMockTool({ name: "send-email" }), // Clear
      ];
      mockContext.tools = tools;

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.usability.discoverability).toBeLessThan(1);
      expect(result.usability.findings).toContainEqual(
        expect.objectContaining({
          issue: expect.stringContaining("discoverability"),
          tools: expect.arrayContaining(["x1", "proc"]),
        }),
      );
    });

    it("should assess overall API coherence", async () => {
      // Arrange - mixed patterns
      const tools = [
        createMockTool({ name: "getUserById" }),
        createMockTool({ name: "fetch-posts" }),
        createMockTool({ name: "UPDATE_SETTINGS" }),
        createMockTool({ name: "del_comment" }),
      ];
      mockContext.tools = tools;

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.usability.apiCoherence).toBeLessThan(0.5);
      expect(result.usability.usabilityScore).toBeLessThan(50);
    });

    it("should reward consistent prefixing", async () => {
      // Arrange
      const tools = [
        createMockTool({ name: "db-read" }),
        createMockTool({ name: "db-write" }),
        createMockTool({ name: "db-delete" }),
        createMockTool({ name: "api-get" }),
        createMockTool({ name: "api-post" }),
        createMockTool({ name: "api-delete" }),
      ];
      mockContext.tools = tools;

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.usability.prefixGroups).toBeDefined();
      expect(result.usability.prefixGroups).toContain("db");
      expect(result.usability.prefixGroups).toContain("api");
      expect(result.usability.consistentPatterns).toBe(true);
    });

    it("should penalize overly generic names", async () => {
      // Arrange
      const tools = [
        createMockTool({ name: "process" }),
        createMockTool({ name: "handle" }),
        createMockTool({ name: "execute" }),
        createMockTool({ name: "run" }),
        createMockTool({ name: "do-something" }),
      ];
      mockContext.tools = tools;

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.usability.genericNames).toHaveLength(5);
      expect(result.usability.usabilityScore).toBeLessThan(40);
    });
  });
});

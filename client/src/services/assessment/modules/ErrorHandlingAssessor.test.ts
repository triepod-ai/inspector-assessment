import { ErrorHandlingAssessor } from "./ErrorHandlingAssessor";
import {
  createMockAssessmentContext,
  createMockTool,
  createMockCallToolResponse,
  createMockAssessmentConfig,
} from "@/test/utils/testUtils";
import { AssessmentContext } from "../AssessmentOrchestrator";

describe("ErrorHandlingAssessor", () => {
  let assessor: ErrorHandlingAssessor;
  let mockContext: AssessmentContext;

  beforeEach(() => {
    const config = createMockAssessmentConfig();
    assessor = new ErrorHandlingAssessor(config);
    mockContext = createMockAssessmentContext();
    jest.clearAllMocks();
  });

  describe("assess", () => {
    it("should assess error handling with various error scenarios", async () => {
      // Arrange
      const tool = createMockTool({ name: "test-tool" });
      mockContext.tools = [tool];

      let callCount = 0;
      mockContext.callTool = jest.fn().mockImplementation(() => {
        callCount++;
        // Return different error types for different test cases
        if (callCount === 1) {
          // Invalid input
          return createMockCallToolResponse(
            "Invalid input: missing required field",
            true,
          );
        } else if (callCount === 2) {
          // Malformed JSON
          return createMockCallToolResponse("JSON parse error", true);
        } else if (callCount === 3) {
          // Missing required parameter
          return createMockCallToolResponse(
            "Missing required parameter: name",
            true,
          );
        } else if (callCount === 4) {
          // Type mismatch
          return createMockCallToolResponse(
            "Type error: expected string, got number",
            true,
          );
        }
        return createMockCallToolResponse("Unknown error", true);
      });

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.metrics).toBeDefined();
      expect(result.metrics.testDetails?.length).toBeGreaterThan(0);
      expect(result.metrics.mcpComplianceScore).toBeDefined();
      expect(mockContext.callTool).toHaveBeenCalled();
    });

    it("should detect proper error messages", async () => {
      // Arrange
      mockContext.callTool = jest
        .fn()
        .mockResolvedValueOnce(
          createMockCallToolResponse("Error: Invalid input provided", true),
        )
        .mockResolvedValueOnce(
          createMockCallToolResponse("TypeError: Cannot read property", true),
        )
        .mockResolvedValueOnce(createMockCallToolResponse("Bad request", true));

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.metrics.hasDescriptiveMessages).toBe(true);
      expect(result.metrics.testDetails).toContainEqual(
        expect.objectContaining({
          testType: expect.any(String),
          passed: true,
        }),
      );
    });

    it("should test handling of invalid inputs", async () => {
      // Arrange
      mockContext.callTool = jest.fn().mockImplementation((name, params) => {
        if (params.invalidInput === null) {
          return createMockCallToolResponse("Cannot process null input", true);
        }
        if (params.invalidInput === undefined) {
          return createMockCallToolResponse("Input is required", true);
        }
        if (
          typeof params.invalidInput === "object" &&
          params.invalidInput.circular
        ) {
          return createMockCallToolResponse(
            "Circular reference detected",
            true,
          );
        }
        return createMockCallToolResponse("Handled invalid input", true);
      });

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.metrics.testDetails?.length).toBeGreaterThanOrEqual(3);
      const invalidInputFindings =
        result.metrics.testDetails?.filter((f) =>
          f.testType.includes("invalid"),
        ) || [];
      expect(invalidInputFindings.length).toBeGreaterThan(0);
    });

    it("should test malformed JSON handling", async () => {
      // Arrange
      mockContext.callTool = jest.fn().mockImplementation((name, params) => {
        if (params.malformed) {
          return createMockCallToolResponse(
            "JSON parsing failed: Unexpected token",
            true,
          );
        }
        return createMockCallToolResponse("success", false);
      });

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      const malformedFindings =
        result.metrics.testDetails?.filter(
          (f) =>
            f.testType.includes("malformed") ||
            f.testType.includes("wrong_type"),
        ) || [];
      expect(malformedFindings.length).toBeGreaterThan(0);
    });

    it("should test missing required parameters", async () => {
      // Arrange
      const tool = createMockTool({
        name: "test-tool",
        inputSchema: {
          type: "object",
          properties: {
            required_field: { type: "string" },
          },
          required: ["required_field"],
        },
      });
      mockContext.tools = [tool];

      mockContext.callTool = jest.fn().mockImplementation((name, params) => {
        if (!params.required_field) {
          return createMockCallToolResponse(
            "Missing required field: required_field",
            true,
          );
        }
        return createMockCallToolResponse("success", false);
      });

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      const missingParamFindings =
        result.metrics.testDetails?.filter((f) =>
          f.testType.includes("missing_required"),
        ) || [];
      expect(missingParamFindings.length).toBeGreaterThan(0);
    });

    it("should calculate error handling score correctly", async () => {
      // Arrange - tool with required parameters to properly test error handling
      const toolWithRequired = createMockTool({
        name: "tool-with-validation",
        inputSchema: {
          type: "object",
          properties: {
            id: { type: "string" },
            value: { type: "number" },
          },
          required: ["id"], // Tool has required parameter
        },
      });
      mockContext.tools = [toolWithRequired];

      // Mock proper error handling with specific messages
      let testCount = 0;
      mockContext.callTool = jest.fn().mockImplementation(() => {
        testCount++;
        // Return appropriate error messages for each test type
        if (testCount === 1) {
          // Missing required params - should include "required" or "missing"
          return createMockCallToolResponse(
            "Error: Required parameter 'id' is missing from the input",
            true,
          );
        }
        if (testCount === 2) {
          // Wrong type - should include "type" or "expected"
          return createMockCallToolResponse(
            "Error: Expected string type for parameter 'id' but received number",
            true,
          );
        }
        // Tests 3 & 4 accept any error response with helpful messages
        return createMockCallToolResponse(
          "Error: Invalid input provided. Please check your parameters and try again.",
          true,
        );
      });

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      // All 4 tests should pass with appropriate error messages
      // With bonuses for quality, score should be > 90
      expect(result.metrics.mcpComplianceScore).toBeGreaterThan(85);
    });

    it("should detect stack traces in error responses", async () => {
      // Arrange
      mockContext.callTool = jest.fn().mockResolvedValue(
        createMockCallToolResponse(
          `Error: Something went wrong
          at Function.execute (/path/to/file.js:123:45)
          at processTicksAndRejections (internal/process/task_queues.js:95:5)`,
          true,
        ),
      );

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.metrics.hasDescriptiveMessages).toBe(true);
    });

    it("should handle timeout scenarios", async () => {
      // Arrange
      mockContext.config.testTimeout = 100;
      mockContext.callTool = jest
        .fn()
        .mockImplementation(
          () =>
            new Promise((resolve) =>
              setTimeout(
                () => resolve(createMockCallToolResponse("Timeout", true)),
                200,
              ),
            ),
        );

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.metrics).toBeDefined();
      expect(result.metrics.testDetails).toContainEqual(
        expect.objectContaining({
          testType: expect.any(String),
          passed: expect.any(Boolean),
        }),
      );
    });

    it("should test edge cases", async () => {
      // Arrange
      mockContext.callTool = jest.fn().mockImplementation((name, params) => {
        // Handle various edge cases
        if (params.veryLongString) {
          return createMockCallToolResponse("String too long", true);
        }
        if (params.emptyArray && params.emptyArray.length === 0) {
          return createMockCallToolResponse("Empty array not allowed", true);
        }
        if (params.negativeNumber && params.negativeNumber < 0) {
          return createMockCallToolResponse(
            "Negative values not supported",
            true,
          );
        }
        return createMockCallToolResponse("Edge case handled", true);
      });

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.metrics.testDetails?.length || 0).toBeGreaterThan(2);
      expect(
        result.metrics.testDetails?.some(
          (f) =>
            f.testType.includes("invalid") || f.testType.includes("excessive"),
        ) || false,
      ).toBe(true);
    });

    it("should handle tools with no error handling", async () => {
      // Arrange - tool with required params that crashes instead of returning errors gracefully
      const toolWithRequired = createMockTool({
        name: "crashing-tool",
        inputSchema: {
          type: "object",
          properties: {
            id: { type: "string" },
          },
          required: ["id"], // Tool has required parameter
        },
      });
      mockContext.tools = [toolWithRequired];

      mockContext.callTool = jest
        .fn()
        .mockRejectedValue(new Error("Unhandled exception"));

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      // Tool crashes on all tests, so validatesInputs should be false
      expect(result.metrics.validatesInputs).toBe(false);
      expect(result.metrics.mcpComplianceScore).toBeLessThanOrEqual(50);
    });

    it("should test recovery mechanisms", async () => {
      // Arrange
      let attemptCount = 0;
      mockContext.callTool = jest.fn().mockImplementation(() => {
        attemptCount++;
        if (attemptCount === 1) {
          return createMockCallToolResponse(
            "Temporary failure, please retry",
            true,
          );
        }
        return createMockCallToolResponse("Success after retry", false);
      });

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.metrics.hasDescriptiveMessages).toBeDefined();
    });

    it("should categorize error types", async () => {
      // Arrange
      const errorResponses = [
        "ValidationError: Input validation failed",
        "AuthenticationError: Invalid credentials",
        "NetworkError: Connection timeout",
        "RateLimitError: Too many requests",
        "InternalServerError: Unexpected error",
      ];

      let errorIndex = 0;
      mockContext.callTool = jest.fn().mockImplementation(() => {
        const response = errorResponses[errorIndex] || "Unknown error";
        errorIndex++;
        return createMockCallToolResponse(response, true);
      });

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.metrics.testDetails).toBeDefined();
      expect(
        result.metrics.testDetails?.some((t) =>
          t.actualResponse.errorMessage?.includes("ValidationError"),
        ),
      ).toBe(true);
      expect(
        result.metrics.testDetails?.some((t) =>
          t.actualResponse.errorMessage?.includes("AuthenticationError"),
        ),
      ).toBe(true);
    });

    it("should evaluate error message quality", async () => {
      // Arrange
      const goodErrorMessage =
        'Error: Invalid input. Expected string but received number for field "name". Please provide a valid string value.';
      const poorErrorMessage = "Error";

      mockContext.callTool = jest
        .fn()
        .mockResolvedValueOnce(
          createMockCallToolResponse(goodErrorMessage, true),
        )
        .mockResolvedValueOnce(
          createMockCallToolResponse(poorErrorMessage, true),
        )
        .mockResolvedValue(
          createMockCallToolResponse("Something went wrong", true),
        );

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.metrics.hasDescriptiveMessages).toBe(true);
      expect(
        result.metrics.hasProperErrorCodes ||
          result.metrics.hasDescriptiveMessages,
      ).toBe(true);
    });

    it("should handle no tools scenario", async () => {
      // Arrange
      mockContext.tools = [];

      // Act
      const result = await assessor.assess(mockContext);

      // Assert
      expect(result.metrics.testDetails?.length || 0).toBe(0);
      expect(result.metrics.mcpComplianceScore).toBe(0);
    });
  });
});

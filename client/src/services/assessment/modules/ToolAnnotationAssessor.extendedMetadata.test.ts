import { ToolAnnotationAssessor } from "./ToolAnnotationAssessor";
import {
  createMockAssessmentContext,
  createMockAssessmentConfig,
  createMockToolWithAnnotations,
  ToolWithAnnotations,
} from "@/test/utils/testUtils";
import { AssessmentContext } from "../AssessmentOrchestrator";

// Extended tool type for testing non-standard metadata fields (Issue #186)
interface ExtendedTestTool extends ToolWithAnnotations {
  metadata?: {
    rateLimit?: { requestsPerMinute?: number; requestsPerSecond?: number };
    requiredPermission?: string | string[];
    scopes?: string[];
    supportsBulkOperations?: boolean;
    maxBatchSize?: number;
  };
  outputSchema?: Record<string, unknown>;
  requiredPermission?: string;
  annotations?: ToolWithAnnotations["annotations"] & {
    rateLimit?: { requestsPerMinute?: number; windowMs?: number };
  };
}

describe("ToolAnnotationAssessor - Extended Metadata Extraction", () => {
  let assessor: ToolAnnotationAssessor;
  let mockContext: AssessmentContext;

  beforeEach(() => {
    const config = createMockAssessmentConfig({
      enableExtendedAssessment: true,
      assessmentCategories: {
        functionality: true,
        security: true,
        documentation: true,
        errorHandling: true,
        usability: true,
        toolAnnotations: true,
      },
    });
    assessor = new ToolAnnotationAssessor(config);
    mockContext = createMockAssessmentContext({ config });
    jest.clearAllMocks();
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe("Extended Metadata Extraction (Issue #54)", () => {
    it("should extract rate limit from annotations", async () => {
      mockContext.tools = [
        {
          ...createMockToolWithAnnotations({
            name: "rate_limited_tool",
            description: "A rate-limited tool",
            readOnlyHint: true,
            destructiveHint: false,
          }),
          annotations: {
            readOnlyHint: true,
            destructiveHint: false,
            rateLimit: {
              requestsPerMinute: 60,
              windowMs: 60000,
            },
          },
        } as ExtendedTestTool,
      ];

      const result = await assessor.assess(mockContext);

      expect(result.toolResults[0].extendedMetadata?.rateLimit).toEqual({
        requestsPerMinute: 60,
        windowMs: 60000,
        maxRequests: undefined,
        requestsPerSecond: undefined,
      });
      expect(result.extendedMetadataMetrics?.toolsWithRateLimits).toBe(1);
    });

    it("should extract rate limit from metadata", async () => {
      mockContext.tools = [
        {
          ...createMockToolWithAnnotations({
            name: "rate_limited_tool",
            description: "A rate-limited tool",
            readOnlyHint: true,
            destructiveHint: false,
          }),
          metadata: {
            rateLimit: {
              requestsPerSecond: 10,
            },
          },
        } as ExtendedTestTool,
      ];

      const result = await assessor.assess(mockContext);

      expect(result.toolResults[0].extendedMetadata?.rateLimit).toEqual({
        requestsPerSecond: 10,
        windowMs: undefined,
        maxRequests: undefined,
        requestsPerMinute: undefined,
      });
    });

    it("should extract permissions array", async () => {
      mockContext.tools = [
        {
          ...createMockToolWithAnnotations({
            name: "admin_tool",
            description: "An admin tool",
            readOnlyHint: false,
            destructiveHint: true,
          }),
          metadata: {
            requiredPermission: ["admin:read", "admin:write"],
            scopes: ["org:admin"],
          },
        } as ExtendedTestTool,
      ];

      const result = await assessor.assess(mockContext);

      expect(result.toolResults[0].extendedMetadata?.permissions).toEqual({
        required: ["admin:read", "admin:write"],
        scopes: ["org:admin"],
      });
      expect(result.extendedMetadataMetrics?.toolsWithPermissions).toBe(1);
    });

    it("should extract single permission as array", async () => {
      mockContext.tools = [
        {
          ...createMockToolWithAnnotations({
            name: "user_tool",
            description: "A user tool",
            readOnlyHint: true,
            destructiveHint: false,
          }),
          requiredPermission: "user:read",
        } as ExtendedTestTool,
      ];

      const result = await assessor.assess(mockContext);

      expect(
        result.toolResults[0].extendedMetadata?.permissions?.required,
      ).toEqual(["user:read"]);
    });

    it("should detect outputSchema presence", async () => {
      mockContext.tools = [
        {
          ...createMockToolWithAnnotations({
            name: "typed_tool",
            description: "A tool with output schema",
            readOnlyHint: true,
            destructiveHint: false,
          }),
          outputSchema: {
            type: "object",
            properties: {
              result: { type: "string" },
            },
          },
        } as ExtendedTestTool,
      ];

      const result = await assessor.assess(mockContext);

      expect(result.toolResults[0].extendedMetadata?.returnSchema).toEqual({
        hasSchema: true,
        schema: {
          type: "object",
          properties: {
            result: { type: "string" },
          },
        },
      });
      expect(result.extendedMetadataMetrics?.toolsWithReturnSchema).toBe(1);
    });

    it("should detect bulk operation support", async () => {
      mockContext.tools = [
        {
          ...createMockToolWithAnnotations({
            name: "bulk_tool",
            description: "A bulk operation tool",
            readOnlyHint: false,
            destructiveHint: false,
          }),
          metadata: {
            supportsBulkOperations: true,
            maxBatchSize: 100,
          },
        } as ExtendedTestTool,
      ];

      const result = await assessor.assess(mockContext);

      expect(result.toolResults[0].extendedMetadata?.bulkOperations).toEqual({
        supported: true,
        maxBatchSize: 100,
      });
      expect(result.extendedMetadataMetrics?.toolsWithBulkSupport).toBe(1);
    });

    it("should return undefined when no extended metadata present", async () => {
      mockContext.tools = [
        createMockToolWithAnnotations({
          name: "simple_tool",
          description: "A simple tool",
          readOnlyHint: true,
          destructiveHint: false,
        }),
      ];

      const result = await assessor.assess(mockContext);

      expect(result.toolResults[0].extendedMetadata).toBeUndefined();
      expect(result.extendedMetadataMetrics?.toolsWithRateLimits).toBe(0);
      expect(result.extendedMetadataMetrics?.toolsWithPermissions).toBe(0);
      expect(result.extendedMetadataMetrics?.toolsWithReturnSchema).toBe(0);
      expect(result.extendedMetadataMetrics?.toolsWithBulkSupport).toBe(0);
    });

    it("should aggregate metrics across multiple tools", async () => {
      mockContext.tools = [
        {
          ...createMockToolWithAnnotations({
            name: "tool_with_rate_limit",
            description: "Tool 1",
            readOnlyHint: true,
            destructiveHint: false,
          }),
          metadata: { rateLimit: { requestsPerMinute: 10 } },
        } as ExtendedTestTool,
        {
          ...createMockToolWithAnnotations({
            name: "tool_with_permissions",
            description: "Tool 2",
            readOnlyHint: true,
            destructiveHint: false,
          }),
          metadata: { requiredPermission: "admin" },
        } as ExtendedTestTool,
        {
          ...createMockToolWithAnnotations({
            name: "tool_with_schema",
            description: "Tool 3",
            readOnlyHint: true,
            destructiveHint: false,
          }),
          outputSchema: { type: "object" },
        } as ExtendedTestTool,
        {
          ...createMockToolWithAnnotations({
            name: "tool_with_bulk",
            description: "Tool 4",
            readOnlyHint: false,
            destructiveHint: false,
          }),
          metadata: { supportsBulkOperations: true },
        } as ExtendedTestTool,
      ];

      const result = await assessor.assess(mockContext);

      expect(result.extendedMetadataMetrics).toEqual({
        toolsWithRateLimits: 1,
        toolsWithPermissions: 1,
        toolsWithReturnSchema: 1,
        toolsWithBulkSupport: 1,
      });
    });
  });
});

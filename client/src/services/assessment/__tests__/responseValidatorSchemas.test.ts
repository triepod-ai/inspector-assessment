/**
 * Tests for Response Validator Schemas
 *
 * Validates the Zod schemas used for runtime validation of MCP response content.
 *
 * @module assessment/__tests__/responseValidatorSchemas.test
 */

import {
  ContentTypeSchema,
  TextContentBlockSchema,
  ImageContentBlockSchema,
  ResourceContentBlockSchema,
  GenericContentBlockSchema,
  ContentBlockSchema,
  ContentArraySchema,
  OutputSchemaValidationSchema,
  ResponseMetadataSchema,
  ValidationClassificationSchema,
  ValidationResultSchema,
  MCPToolCallResultSchema,
  validateContentArray,
  safeParseContentArray,
  safeParseMCPToolCallResult,
  validateValidationResult,
  parseValidationResult,
  safeParseValidationResult,
  validateResponseMetadata,
  safeParseResponseMetadata,
  ZOD_SCHEMA_VERSION,
} from "../responseValidatorSchemas";

describe("responseValidatorSchemas", () => {
  describe("Re-exported schemas", () => {
    test("exports ZOD_SCHEMA_VERSION", () => {
      expect(ZOD_SCHEMA_VERSION).toBe(1);
    });
  });

  describe("ContentTypeSchema", () => {
    test("accepts all valid content types", () => {
      const validTypes = [
        "text",
        "image",
        "resource",
        "resource_link",
        "audio",
      ];
      for (const type of validTypes) {
        const result = ContentTypeSchema.safeParse(type);
        expect(result.success).toBe(true);
      }
    });

    test("rejects invalid content type", () => {
      const result = ContentTypeSchema.safeParse("invalid");
      expect(result.success).toBe(false);
    });

    test("rejects empty string", () => {
      const result = ContentTypeSchema.safeParse("");
      expect(result.success).toBe(false);
    });
  });

  describe("TextContentBlockSchema", () => {
    test("accepts valid text content block", () => {
      const result = TextContentBlockSchema.safeParse({
        type: "text",
        text: "Hello world",
      });
      expect(result.success).toBe(true);
    });

    test("rejects block with wrong type", () => {
      const result = TextContentBlockSchema.safeParse({
        type: "image",
        text: "Hello",
      });
      expect(result.success).toBe(false);
    });

    test("rejects block without text field", () => {
      const result = TextContentBlockSchema.safeParse({
        type: "text",
      });
      expect(result.success).toBe(false);
    });
  });

  describe("ImageContentBlockSchema", () => {
    test("accepts valid image content block", () => {
      const result = ImageContentBlockSchema.safeParse({
        type: "image",
        data: "base64data",
        mimeType: "image/png",
      });
      expect(result.success).toBe(true);
    });

    test("rejects block without data field", () => {
      const result = ImageContentBlockSchema.safeParse({
        type: "image",
        mimeType: "image/png",
      });
      expect(result.success).toBe(false);
    });

    test("rejects block without mimeType field", () => {
      const result = ImageContentBlockSchema.safeParse({
        type: "image",
        data: "base64data",
      });
      expect(result.success).toBe(false);
    });
  });

  describe("ResourceContentBlockSchema", () => {
    test("accepts resource type", () => {
      const result = ResourceContentBlockSchema.safeParse({
        type: "resource",
        uri: "file:///path/to/resource",
      });
      expect(result.success).toBe(true);
    });

    test("accepts resource_link type", () => {
      const result = ResourceContentBlockSchema.safeParse({
        type: "resource_link",
        uri: "https://example.com/resource",
      });
      expect(result.success).toBe(true);
    });

    test("accepts without optional uri", () => {
      const result = ResourceContentBlockSchema.safeParse({
        type: "resource",
      });
      expect(result.success).toBe(true);
    });
  });

  describe("GenericContentBlockSchema", () => {
    test("accepts any type string", () => {
      const result = GenericContentBlockSchema.safeParse({
        type: "custom_type",
      });
      expect(result.success).toBe(true);
    });

    test("accepts with optional fields", () => {
      const result = GenericContentBlockSchema.safeParse({
        type: "text",
        text: "Hello",
        data: "optional",
        mimeType: "text/plain",
        uri: "file:///path",
      });
      expect(result.success).toBe(true);
    });

    test("rejects without type field", () => {
      const result = GenericContentBlockSchema.safeParse({
        text: "Hello",
      });
      expect(result.success).toBe(false);
    });
  });

  describe("ContentBlockSchema (union)", () => {
    test("accepts text content block", () => {
      const result = ContentBlockSchema.safeParse({
        type: "text",
        text: "Hello",
      });
      expect(result.success).toBe(true);
    });

    test("accepts image content block", () => {
      const result = ContentBlockSchema.safeParse({
        type: "image",
        data: "base64",
        mimeType: "image/png",
      });
      expect(result.success).toBe(true);
    });

    test("accepts unknown type via fallback", () => {
      const result = ContentBlockSchema.safeParse({
        type: "unknown_type",
      });
      expect(result.success).toBe(true);
    });
  });

  describe("ContentArraySchema", () => {
    test("accepts array of content blocks", () => {
      const result = ContentArraySchema.safeParse([
        { type: "text", text: "Hello" },
        { type: "image", data: "base64", mimeType: "image/png" },
      ]);
      expect(result.success).toBe(true);
    });

    test("accepts empty array", () => {
      const result = ContentArraySchema.safeParse([]);
      expect(result.success).toBe(true);
    });

    test("rejects non-array", () => {
      const result = ContentArraySchema.safeParse("not an array");
      expect(result.success).toBe(false);
    });
  });

  describe("OutputSchemaValidationSchema", () => {
    test("accepts valid output schema validation", () => {
      const result = OutputSchemaValidationSchema.safeParse({
        hasOutputSchema: true,
        isValid: true,
      });
      expect(result.success).toBe(true);
    });

    test("accepts with error field", () => {
      const result = OutputSchemaValidationSchema.safeParse({
        hasOutputSchema: true,
        isValid: false,
        error: "Schema validation failed",
      });
      expect(result.success).toBe(true);
    });

    test("rejects without hasOutputSchema", () => {
      const result = OutputSchemaValidationSchema.safeParse({
        isValid: true,
      });
      expect(result.success).toBe(false);
    });
  });

  describe("ResponseMetadataSchema", () => {
    test("accepts valid metadata", () => {
      const result = ResponseMetadataSchema.safeParse({
        contentTypes: ["text", "image"],
        hasStructuredContent: false,
        hasMeta: false,
        textBlockCount: 1,
        imageCount: 1,
        resourceCount: 0,
      });
      expect(result.success).toBe(true);
    });

    test("accepts with outputSchemaValidation", () => {
      const result = ResponseMetadataSchema.safeParse({
        contentTypes: ["text"],
        hasStructuredContent: true,
        hasMeta: true,
        textBlockCount: 1,
        imageCount: 0,
        resourceCount: 0,
        outputSchemaValidation: {
          hasOutputSchema: true,
          isValid: true,
        },
      });
      expect(result.success).toBe(true);
    });

    test("rejects invalid content type in array", () => {
      const result = ResponseMetadataSchema.safeParse({
        contentTypes: ["invalid_type"],
        hasStructuredContent: false,
        hasMeta: false,
        textBlockCount: 0,
        imageCount: 0,
        resourceCount: 0,
      });
      expect(result.success).toBe(false);
    });

    test("rejects negative count", () => {
      const result = ResponseMetadataSchema.safeParse({
        contentTypes: ["text"],
        hasStructuredContent: false,
        hasMeta: false,
        textBlockCount: -1,
        imageCount: 0,
        resourceCount: 0,
      });
      expect(result.success).toBe(false);
    });
  });

  describe("ValidationClassificationSchema", () => {
    test("accepts all valid classifications", () => {
      const validClassifications = [
        "fully_working",
        "partially_working",
        "connectivity_only",
        "broken",
        "error",
      ];
      for (const classification of validClassifications) {
        const result = ValidationClassificationSchema.safeParse(classification);
        expect(result.success).toBe(true);
      }
    });

    test("rejects invalid classification", () => {
      const result = ValidationClassificationSchema.safeParse("invalid");
      expect(result.success).toBe(false);
    });
  });

  describe("ValidationResultSchema", () => {
    test("accepts valid validation result", () => {
      const result = ValidationResultSchema.safeParse({
        isValid: true,
        isError: false,
        confidence: 100,
        issues: [],
        evidence: ["Tool responded successfully"],
        classification: "fully_working",
      });
      expect(result.success).toBe(true);
    });

    test("accepts with responseMetadata", () => {
      const result = ValidationResultSchema.safeParse({
        isValid: true,
        isError: false,
        confidence: 70,
        issues: ["Output schema validation failed"],
        evidence: ["Tool responded with content"],
        classification: "partially_working",
        responseMetadata: {
          contentTypes: ["text"],
          hasStructuredContent: false,
          hasMeta: false,
          textBlockCount: 1,
          imageCount: 0,
          resourceCount: 0,
        },
      });
      expect(result.success).toBe(true);
    });

    test("rejects confidence out of range (> 100)", () => {
      const result = ValidationResultSchema.safeParse({
        isValid: true,
        isError: false,
        confidence: 150,
        issues: [],
        evidence: [],
        classification: "fully_working",
      });
      expect(result.success).toBe(false);
    });

    test("rejects confidence out of range (< 0)", () => {
      const result = ValidationResultSchema.safeParse({
        isValid: true,
        isError: false,
        confidence: -10,
        issues: [],
        evidence: [],
        classification: "fully_working",
      });
      expect(result.success).toBe(false);
    });

    test("rejects invalid classification", () => {
      const result = ValidationResultSchema.safeParse({
        isValid: true,
        isError: false,
        confidence: 100,
        issues: [],
        evidence: [],
        classification: "invalid",
      });
      expect(result.success).toBe(false);
    });
  });

  describe("MCPToolCallResultSchema", () => {
    test("accepts minimal result", () => {
      const result = MCPToolCallResultSchema.safeParse({});
      expect(result.success).toBe(true);
    });

    test("accepts result with content", () => {
      const result = MCPToolCallResultSchema.safeParse({
        content: [{ type: "text", text: "Hello" }],
        isError: false,
      });
      expect(result.success).toBe(true);
    });

    test("accepts error result", () => {
      const result = MCPToolCallResultSchema.safeParse({
        content: [{ type: "text", text: "Error message" }],
        isError: true,
      });
      expect(result.success).toBe(true);
    });

    test("accepts result with structuredContent", () => {
      const result = MCPToolCallResultSchema.safeParse({
        content: [{ type: "text", text: "OK" }],
        structuredContent: { data: "structured" },
      });
      expect(result.success).toBe(true);
    });

    test("accepts result with _meta", () => {
      const result = MCPToolCallResultSchema.safeParse({
        content: [{ type: "text", text: "OK" }],
        _meta: { some: "metadata" },
      });
      expect(result.success).toBe(true);
    });
  });

  describe("validateContentArray", () => {
    test("returns empty array for valid content", () => {
      const errors = validateContentArray([{ type: "text", text: "Hello" }]);
      expect(errors).toEqual([]);
    });

    test("returns errors for non-array", () => {
      const errors = validateContentArray("not an array");
      expect(errors.length).toBeGreaterThan(0);
    });
  });

  describe("safeParseContentArray", () => {
    test("returns success for valid array", () => {
      const result = safeParseContentArray([{ type: "text", text: "Hello" }]);
      expect(result.success).toBe(true);
    });

    test("returns failure for invalid input", () => {
      const result = safeParseContentArray(null);
      expect(result.success).toBe(false);
    });
  });

  describe("safeParseMCPToolCallResult", () => {
    test("returns success for valid result", () => {
      const result = safeParseMCPToolCallResult({
        content: [{ type: "text", text: "OK" }],
      });
      expect(result.success).toBe(true);
    });

    test("returns success for empty object", () => {
      const result = safeParseMCPToolCallResult({});
      expect(result.success).toBe(true);
    });
  });

  describe("validateValidationResult", () => {
    test("returns empty array for valid result", () => {
      const errors = validateValidationResult({
        isValid: true,
        isError: false,
        confidence: 100,
        issues: [],
        evidence: [],
        classification: "fully_working",
      });
      expect(errors).toEqual([]);
    });

    test("returns errors for invalid result", () => {
      const errors = validateValidationResult({});
      expect(errors.length).toBeGreaterThan(0);
    });
  });

  describe("parseValidationResult", () => {
    test("returns parsed data for valid result", () => {
      const validResult = {
        isValid: true,
        isError: false,
        confidence: 100,
        issues: [],
        evidence: ["OK"],
        classification: "fully_working" as const,
      };
      const result = parseValidationResult(validResult);
      expect(result).toEqual(validResult);
    });

    test("throws for invalid result", () => {
      expect(() => parseValidationResult({})).toThrow();
    });
  });

  describe("safeParseValidationResult", () => {
    test("returns success for valid result", () => {
      const result = safeParseValidationResult({
        isValid: true,
        isError: false,
        confidence: 100,
        issues: [],
        evidence: [],
        classification: "fully_working",
      });
      expect(result.success).toBe(true);
    });

    test("returns failure for invalid result", () => {
      const result = safeParseValidationResult({});
      expect(result.success).toBe(false);
    });
  });

  describe("validateResponseMetadata", () => {
    test("returns empty array for valid metadata", () => {
      const errors = validateResponseMetadata({
        contentTypes: ["text"],
        hasStructuredContent: false,
        hasMeta: false,
        textBlockCount: 1,
        imageCount: 0,
        resourceCount: 0,
      });
      expect(errors).toEqual([]);
    });

    test("returns errors for invalid metadata", () => {
      const errors = validateResponseMetadata({});
      expect(errors.length).toBeGreaterThan(0);
    });
  });

  describe("safeParseResponseMetadata", () => {
    test("returns success for valid metadata", () => {
      const result = safeParseResponseMetadata({
        contentTypes: ["text"],
        hasStructuredContent: false,
        hasMeta: false,
        textBlockCount: 1,
        imageCount: 0,
        resourceCount: 0,
      });
      expect(result.success).toBe(true);
    });

    test("returns failure for invalid metadata", () => {
      const result = safeParseResponseMetadata(null);
      expect(result.success).toBe(false);
    });
  });
});

/**
 * Tests for Configuration Types Schemas
 *
 * Validates the Zod schemas used for runtime validation of inspector configuration.
 *
 * @module lib/__tests__/configurationTypesSchemas.test
 */

import {
  ConfigItemSchema,
  InspectorConfigSchema,
  validateInspectorConfig,
  parseInspectorConfig,
  safeParseInspectorConfig,
  validateConfigItem,
  safeParseConfigItem,
  ZOD_SCHEMA_VERSION,
} from "../configurationTypesSchemas";
import { DEFAULT_INSPECTOR_CONFIG } from "../constants";

describe("configurationTypesSchemas", () => {
  afterEach(() => {
    jest.clearAllMocks();
  });

  describe("Re-exported schemas", () => {
    test("exports ZOD_SCHEMA_VERSION", () => {
      expect(ZOD_SCHEMA_VERSION).toBe(1);
    });
  });

  describe("ConfigItemSchema", () => {
    describe("valid inputs", () => {
      test("accepts config item with string value", () => {
        const result = ConfigItemSchema.safeParse({
          label: "Test Label",
          description: "Test description",
          value: "test-value",
          is_session_item: false,
        });
        expect(result.success).toBe(true);
      });

      test("accepts config item with number value", () => {
        const result = ConfigItemSchema.safeParse({
          label: "Timeout",
          description: "Request timeout in milliseconds",
          value: 30000,
          is_session_item: false,
        });
        expect(result.success).toBe(true);
      });

      test("accepts config item with boolean value", () => {
        const result = ConfigItemSchema.safeParse({
          label: "Reset on Progress",
          description: "Reset timeout on progress notifications",
          value: true,
          is_session_item: false,
        });
        expect(result.success).toBe(true);
      });

      test("accepts config item with empty description", () => {
        const result = ConfigItemSchema.safeParse({
          label: "Test",
          description: "",
          value: "test",
          is_session_item: true,
        });
        expect(result.success).toBe(true);
      });
    });

    describe("invalid inputs", () => {
      test("rejects config item with missing label", () => {
        const result = ConfigItemSchema.safeParse({
          description: "Test description",
          value: "test",
          is_session_item: false,
        });
        expect(result.success).toBe(false);
      });

      test("rejects config item with empty label", () => {
        const result = ConfigItemSchema.safeParse({
          label: "",
          description: "Test description",
          value: "test",
          is_session_item: false,
        });
        expect(result.success).toBe(false);
      });

      test("rejects config item with missing value", () => {
        const result = ConfigItemSchema.safeParse({
          label: "Test",
          description: "Test description",
          is_session_item: false,
        });
        expect(result.success).toBe(false);
      });

      test("rejects config item with missing is_session_item", () => {
        const result = ConfigItemSchema.safeParse({
          label: "Test",
          description: "Test description",
          value: "test",
        });
        expect(result.success).toBe(false);
      });

      test("rejects config item with null value", () => {
        const result = ConfigItemSchema.safeParse({
          label: "Test",
          description: "Test description",
          value: null,
          is_session_item: false,
        });
        expect(result.success).toBe(false);
      });

      test("rejects config item with object value", () => {
        const result = ConfigItemSchema.safeParse({
          label: "Test",
          description: "Test description",
          value: { nested: "object" },
          is_session_item: false,
        });
        expect(result.success).toBe(false);
      });

      test("rejects config item with array value", () => {
        const result = ConfigItemSchema.safeParse({
          label: "Test",
          description: "Test description",
          value: ["array"],
          is_session_item: false,
        });
        expect(result.success).toBe(false);
      });
    });
  });

  describe("InspectorConfigSchema", () => {
    describe("valid inputs", () => {
      test("validates DEFAULT_INSPECTOR_CONFIG", () => {
        const result = InspectorConfigSchema.safeParse(
          DEFAULT_INSPECTOR_CONFIG,
        );
        expect(result.success).toBe(true);
      });

      test("accepts minimal valid config", () => {
        const minimalConfig = {
          MCP_SERVER_REQUEST_TIMEOUT: {
            label: "Timeout",
            description: "",
            value: 30000,
            is_session_item: false,
          },
          MCP_REQUEST_TIMEOUT_RESET_ON_PROGRESS: {
            label: "Reset",
            description: "",
            value: true,
            is_session_item: false,
          },
          MCP_REQUEST_MAX_TOTAL_TIMEOUT: {
            label: "Max",
            description: "",
            value: 60000,
            is_session_item: false,
          },
          MCP_PROXY_FULL_ADDRESS: {
            label: "Address",
            description: "",
            value: "",
            is_session_item: false,
          },
          MCP_PROXY_AUTH_TOKEN: {
            label: "Token",
            description: "",
            value: "",
            is_session_item: true,
          },
        };
        const result = InspectorConfigSchema.safeParse(minimalConfig);
        expect(result.success).toBe(true);
      });
    });

    describe("invalid inputs", () => {
      test("rejects config with missing required key", () => {
        const partialConfig = {
          MCP_SERVER_REQUEST_TIMEOUT:
            DEFAULT_INSPECTOR_CONFIG.MCP_SERVER_REQUEST_TIMEOUT,
        };
        const result = InspectorConfigSchema.safeParse(partialConfig);
        expect(result.success).toBe(false);
      });

      test("rejects config with invalid config item", () => {
        const invalidConfig = {
          ...DEFAULT_INSPECTOR_CONFIG,
          MCP_SERVER_REQUEST_TIMEOUT: {
            label: "", // Empty label should fail
            description: "",
            value: 30000,
            is_session_item: false,
          },
        };
        const result = InspectorConfigSchema.safeParse(invalidConfig);
        expect(result.success).toBe(false);
      });

      test("rejects empty object", () => {
        const result = InspectorConfigSchema.safeParse({});
        expect(result.success).toBe(false);
      });

      test("rejects null", () => {
        const result = InspectorConfigSchema.safeParse(null);
        expect(result.success).toBe(false);
      });

      test("rejects undefined", () => {
        const result = InspectorConfigSchema.safeParse(undefined);
        expect(result.success).toBe(false);
      });
    });
  });

  describe("validateInspectorConfig", () => {
    test("returns empty array for valid config", () => {
      const errors = validateInspectorConfig(DEFAULT_INSPECTOR_CONFIG);
      expect(errors).toEqual([]);
    });

    test("returns error messages for invalid config", () => {
      const errors = validateInspectorConfig({});
      expect(errors.length).toBeGreaterThan(0);
      expect(errors[0]).toContain("Required");
    });

    test("includes path in error messages", () => {
      const invalidConfig = {
        ...DEFAULT_INSPECTOR_CONFIG,
        MCP_SERVER_REQUEST_TIMEOUT: {
          label: "",
          description: "",
          value: 30000,
          is_session_item: false,
        },
      };
      const errors = validateInspectorConfig(invalidConfig);
      expect(errors.some((e) => e.includes("MCP_SERVER_REQUEST_TIMEOUT"))).toBe(
        true,
      );
    });
  });

  describe("parseInspectorConfig", () => {
    test("returns parsed data for valid config", () => {
      const result = parseInspectorConfig(DEFAULT_INSPECTOR_CONFIG);
      expect(result).toEqual(DEFAULT_INSPECTOR_CONFIG);
    });

    test("throws ZodError for invalid config", () => {
      expect(() => parseInspectorConfig({})).toThrow();
    });
  });

  describe("safeParseInspectorConfig", () => {
    test("returns success: true with data for valid config", () => {
      const result = safeParseInspectorConfig(DEFAULT_INSPECTOR_CONFIG);
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data).toEqual(DEFAULT_INSPECTOR_CONFIG);
      }
    });

    test("returns success: false with error for invalid config", () => {
      const result = safeParseInspectorConfig({});
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error).toBeDefined();
      }
    });
  });

  describe("validateConfigItem", () => {
    test("returns empty array for valid item", () => {
      const item = DEFAULT_INSPECTOR_CONFIG.MCP_SERVER_REQUEST_TIMEOUT;
      const errors = validateConfigItem(item);
      expect(errors).toEqual([]);
    });

    test("returns error messages for invalid item", () => {
      const errors = validateConfigItem({ label: "" });
      expect(errors.length).toBeGreaterThan(0);
    });
  });

  describe("safeParseConfigItem", () => {
    test("returns success: true for valid item", () => {
      const item = DEFAULT_INSPECTOR_CONFIG.MCP_SERVER_REQUEST_TIMEOUT;
      const result = safeParseConfigItem(item);
      expect(result.success).toBe(true);
    });

    test("returns success: false for invalid item", () => {
      const result = safeParseConfigItem({});
      expect(result.success).toBe(false);
    });
  });
});

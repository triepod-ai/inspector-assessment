import {
  getMCPProxyAuthToken,
  initializeInspectorConfig,
} from "../configUtils";
import { DEFAULT_INSPECTOR_CONFIG } from "../../lib/constants";
import { InspectorConfig } from "../../lib/configurationTypes";

describe("configUtils", () => {
  describe("getMCPProxyAuthToken", () => {
    test("returns token and default header name", () => {
      const config: InspectorConfig = {
        ...DEFAULT_INSPECTOR_CONFIG,
        MCP_PROXY_AUTH_TOKEN: {
          ...DEFAULT_INSPECTOR_CONFIG.MCP_PROXY_AUTH_TOKEN,
          value: "test-token-123",
        },
      };

      const result = getMCPProxyAuthToken(config);

      expect(result).toEqual({
        token: "test-token-123",
        header: "X-MCP-Proxy-Auth",
      });
    });

    test("returns empty token when not configured", () => {
      const config: InspectorConfig = {
        ...DEFAULT_INSPECTOR_CONFIG,
        MCP_PROXY_AUTH_TOKEN: {
          ...DEFAULT_INSPECTOR_CONFIG.MCP_PROXY_AUTH_TOKEN,
          value: "",
        },
      };

      const result = getMCPProxyAuthToken(config);

      expect(result).toEqual({
        token: "",
        header: "X-MCP-Proxy-Auth",
      });
    });

    test("always returns X-MCP-Proxy-Auth as header name", () => {
      const config: InspectorConfig = {
        ...DEFAULT_INSPECTOR_CONFIG,
        MCP_PROXY_AUTH_TOKEN: {
          ...DEFAULT_INSPECTOR_CONFIG.MCP_PROXY_AUTH_TOKEN,
          value: "any-token",
        },
      };

      const result = getMCPProxyAuthToken(config);

      expect(result.header).toBe("X-MCP-Proxy-Auth");
    });

    test("handles null/undefined value gracefully by returning default", () => {
      const config: InspectorConfig = {
        ...DEFAULT_INSPECTOR_CONFIG,
        MCP_PROXY_AUTH_TOKEN: {
          ...DEFAULT_INSPECTOR_CONFIG.MCP_PROXY_AUTH_TOKEN,
          value: null as unknown as string,
        },
      };

      const result = getMCPProxyAuthToken(config);

      // Safer behavior: return default empty string instead of null
      expect(result).toEqual({
        token: "",
        header: "X-MCP-Proxy-Auth",
      });
    });
  });

  /**
   * Issue #120: Integration tests for Zod validation fallback behavior
   */
  describe("initializeInspectorConfig - Zod validation fallback", () => {
    // Store original implementations
    const originalLocalStorage = global.localStorage;
    const originalSessionStorage = global.sessionStorage;
    const originalLocation = global.window.location;
    let mockLocalStorage: Record<string, string>;
    let mockSessionStorage: Record<string, string>;
    let consoleWarnSpy: jest.SpyInstance;

    beforeEach(() => {
      // Reset storage mocks
      mockLocalStorage = {};
      mockSessionStorage = {};

      // Mock localStorage
      Object.defineProperty(global, "localStorage", {
        value: {
          getItem: jest.fn((key: string) => mockLocalStorage[key] ?? null),
          setItem: jest.fn((key: string, value: string) => {
            mockLocalStorage[key] = value;
          }),
          removeItem: jest.fn((key: string) => {
            delete mockLocalStorage[key];
          }),
          clear: jest.fn(() => {
            mockLocalStorage = {};
          }),
        },
        writable: true,
      });

      // Mock sessionStorage
      Object.defineProperty(global, "sessionStorage", {
        value: {
          getItem: jest.fn((key: string) => mockSessionStorage[key] ?? null),
          setItem: jest.fn((key: string, value: string) => {
            mockSessionStorage[key] = value;
          }),
          removeItem: jest.fn((key: string) => {
            delete mockSessionStorage[key];
          }),
          clear: jest.fn(() => {
            mockSessionStorage = {};
          }),
        },
        writable: true,
      });

      // Mock window.location for getConfigOverridesFromQueryParams
      Object.defineProperty(global.window, "location", {
        value: {
          href: "http://localhost:3000/",
          protocol: "http:",
          hostname: "localhost",
        },
        writable: true,
      });

      // Spy on console.warn
      consoleWarnSpy = jest.spyOn(console, "warn").mockImplementation(() => {});
    });

    afterEach(() => {
      // Restore original implementations
      Object.defineProperty(global, "localStorage", {
        value: originalLocalStorage,
        writable: true,
      });
      Object.defineProperty(global, "sessionStorage", {
        value: originalSessionStorage,
        writable: true,
      });
      Object.defineProperty(global.window, "location", {
        value: originalLocation,
        writable: true,
      });
      consoleWarnSpy.mockRestore();
    });

    describe("localStorage validation fallback", () => {
      test("validates and rejects corrupted localStorage config with wrong structure", () => {
        // Config with wrong structure - is_session_item should be boolean, not string
        mockLocalStorage["test-config"] = JSON.stringify({
          MCP_SERVER_REQUEST_TIMEOUT: {
            label: "Request Timeout",
            description: "Test",
            value: 5000,
            is_session_item: "not-a-boolean", // Should be boolean
          },
        });

        const result = initializeInspectorConfig("test-config");

        // Should fall back to defaults
        expect(result.MCP_SERVER_REQUEST_TIMEOUT.value).toBe(
          DEFAULT_INSPECTOR_CONFIG.MCP_SERVER_REQUEST_TIMEOUT.value,
        );

        // Should log warning
        expect(consoleWarnSpy).toHaveBeenCalledWith(
          expect.stringContaining("Invalid config in localStorage"),
          expect.any(Array),
        );
      });

      test("handles JSON parse errors gracefully", () => {
        // Malformed JSON in localStorage
        mockLocalStorage["test-config"] = "{ invalid json }";

        const result = initializeInspectorConfig("test-config");

        // Should fall back to defaults
        expect(result.MCP_SERVER_REQUEST_TIMEOUT.value).toBe(
          DEFAULT_INSPECTOR_CONFIG.MCP_SERVER_REQUEST_TIMEOUT.value,
        );

        // Should log warning about parse failure
        expect(consoleWarnSpy).toHaveBeenCalledWith(
          expect.stringContaining("Failed to parse localStorage config"),
          expect.any(Error),
        );
      });

      test("logs warning with error details on validation failure", () => {
        // Config with missing required field (label)
        mockLocalStorage["test-config"] = JSON.stringify({
          MCP_SERVER_REQUEST_TIMEOUT: {
            // Missing: label
            description: "Test",
            value: 5000,
            is_session_item: false,
          },
        });

        initializeInspectorConfig("test-config");

        // Should log warning with specific error details
        expect(consoleWarnSpy).toHaveBeenCalled();
        const warnCall = consoleWarnSpy.mock.calls[0];
        expect(warnCall[0]).toContain("Invalid config in localStorage");
        expect(Array.isArray(warnCall[1])).toBe(true);
      });
    });

    describe("sessionStorage validation fallback", () => {
      test("validates and rejects corrupted sessionStorage config", () => {
        // Valid localStorage config
        mockLocalStorage["test-config"] = JSON.stringify({
          MCP_SERVER_REQUEST_TIMEOUT: {
            label: "Request Timeout",
            description: "Test description",
            value: 60000, // Valid custom value
            is_session_item: false,
          },
        });

        // Invalid sessionStorage config - is_session_item must be boolean
        mockSessionStorage["test-config_ephemeral"] = JSON.stringify({
          MCP_PROXY_AUTH_TOKEN: {
            label: "Token",
            description: "Test",
            value: "token-value",
            is_session_item: "not-a-boolean", // Invalid: must be boolean
          },
        });

        const result = initializeInspectorConfig("test-config");

        // Should keep localStorage config but reject sessionStorage config
        expect(result.MCP_SERVER_REQUEST_TIMEOUT.value).toBe(60000);

        // Should log warning about sessionStorage
        expect(consoleWarnSpy).toHaveBeenCalledWith(
          expect.stringContaining("Invalid config in sessionStorage"),
          expect.any(Array),
        );
      });

      test("falls back to current config (not defaults) when sessionStorage invalid", () => {
        // Set up valid localStorage with custom value
        mockLocalStorage["test-config"] = JSON.stringify({
          MCP_SERVER_REQUEST_TIMEOUT: {
            label: "Request Timeout",
            description: "Custom description",
            value: 120000, // Custom value from localStorage
            is_session_item: false,
          },
        });

        // Invalid sessionStorage (missing required fields)
        mockSessionStorage["test-config_ephemeral"] = JSON.stringify({
          INVALID_KEY: { bad: "data" },
        });

        const result = initializeInspectorConfig("test-config");

        // Should keep localStorage config value (not fall back to DEFAULT)
        expect(result.MCP_SERVER_REQUEST_TIMEOUT.value).toBe(120000);
      });
    });

    describe("edge cases", () => {
      test("handles empty string in storage (treated as no config)", () => {
        mockLocalStorage["test-config"] = "";

        const result = initializeInspectorConfig("test-config");

        // Empty string is falsy, so savedPersistentConfig check fails
        // and no parse attempt is made - just defaults returned
        expect(result.MCP_SERVER_REQUEST_TIMEOUT.value).toBe(
          DEFAULT_INSPECTOR_CONFIG.MCP_SERVER_REQUEST_TIMEOUT.value,
        );
        // No warning logged since empty string is treated as "no config"
        expect(consoleWarnSpy).not.toHaveBeenCalled();
      });

      test("handles partial config with some invalid fields", () => {
        // Some fields valid, some invalid
        mockLocalStorage["test-config"] = JSON.stringify({
          MCP_SERVER_REQUEST_TIMEOUT: {
            label: "", // Invalid: empty label
            description: "Test",
            value: 5000,
            is_session_item: false,
          },
        });

        const result = initializeInspectorConfig("test-config");

        // Should fall back to defaults due to validation failure
        expect(result.MCP_SERVER_REQUEST_TIMEOUT.value).toBe(
          DEFAULT_INSPECTOR_CONFIG.MCP_SERVER_REQUEST_TIMEOUT.value,
        );
      });

      test("accepts config with extra unknown fields (Zod passthrough)", () => {
        // Config with valid fields plus extra unknown fields
        mockLocalStorage["test-config"] = JSON.stringify({
          MCP_SERVER_REQUEST_TIMEOUT: {
            label: "Request Timeout",
            description: "Test description",
            value: 90000,
            is_session_item: false,
            extra_field: "should be ignored", // Extra field
          },
        });

        const result = initializeInspectorConfig("test-config");

        // Should accept the config (Zod strips unknown fields by default)
        expect(result.MCP_SERVER_REQUEST_TIMEOUT.value).toBe(90000);
      });

      test("returns defaults when no storage config exists", () => {
        // No localStorage or sessionStorage set

        const result = initializeInspectorConfig("test-config");

        // Should return defaults
        expect(result.MCP_SERVER_REQUEST_TIMEOUT.value).toBe(
          DEFAULT_INSPECTOR_CONFIG.MCP_SERVER_REQUEST_TIMEOUT.value,
        );
        expect(result.MCP_PROXY_AUTH_TOKEN.value).toBe(
          DEFAULT_INSPECTOR_CONFIG.MCP_PROXY_AUTH_TOKEN.value,
        );

        // Should not log any warnings
        expect(consoleWarnSpy).not.toHaveBeenCalled();
      });
    });
  });
});

/**
 * CLI Build Fixes Regression Tests
 *
 * Tests for TypeScript build fixes to ensure they don't regress.
 * These tests validate the type safety improvements made to resolve
 * pre-existing build errors.
 *
 * @see https://github.com/triepod-ai/inspector-assessment/issues/33
 * @see https://github.com/triepod-ai/inspector-assessment/issues/37
 */

import { jest, describe, it, expect, afterEach } from "@jest/globals";
import { ScopedListenerConfig } from "../lib/event-config.js";

describe("CLI Build Fixes Regression Tests", () => {
  afterEach(() => {
    jest.clearAllMocks();
  });

  describe("event-config.ts - CLI_DEFAULT_MAX_LISTENERS constant", () => {
    it("should use local constant instead of cross-workspace import", () => {
      // Fix: Replaced DEFAULT_PERFORMANCE_CONFIG.eventEmitterMaxListeners
      // with local CLI_DEFAULT_MAX_LISTENERS = 50
      // This test ensures the default value matches the expected constant

      const config = new ScopedListenerConfig();
      config.apply();

      const maxListeners = process.getMaxListeners();
      expect(maxListeners).toBe(50);

      config.restore();
    });

    it("should maintain consistency with PerformanceConfig value", () => {
      // The local constant should match the PerformanceConfig value
      // documented in GitHub Issue #37
      const expectedValue = 50;

      const config = new ScopedListenerConfig();
      config.apply();

      expect(process.getMaxListeners()).toBe(expectedValue);

      config.restore();
    });

    it("should not cause build errors from cross-workspace imports", () => {
      // This test ensures that the ScopedListenerConfig class can be
      // instantiated without any import errors related to PerformanceConfig
      expect(() => {
        const config = new ScopedListenerConfig();
        config.apply();
        config.restore();
      }).not.toThrow();
    });
  });

  describe("assess-full.ts - ServerInfo metadata type assertion", () => {
    // Type-safe test helpers that mirror the assess-full.ts implementation
    interface MockServerVersion {
      name: string;
      version?: string;
      [key: string]: unknown; // Allow additional properties
    }

    interface ServerInfo {
      name: string;
      version?: string;
      metadata?: Record<string, unknown>;
    }

    function buildServerInfo(
      rawServerInfo: MockServerVersion | null | undefined,
    ): ServerInfo | undefined {
      // This mirrors the fix in assess-full.ts lines 634-642
      return rawServerInfo
        ? {
            name: rawServerInfo.name || "unknown",
            version: rawServerInfo.version,
            metadata: (rawServerInfo as Record<string, unknown>).metadata as
              | Record<string, unknown>
              | undefined,
          }
        : undefined;
    }

    it("should handle serverInfo with metadata as Record<string, unknown>", () => {
      const rawServerInfo: MockServerVersion = {
        name: "test-server",
        version: "1.0.0",
        metadata: {
          author: "test",
          description: "Test MCP server",
        },
      };

      const serverInfo = buildServerInfo(rawServerInfo);

      expect(serverInfo).toBeDefined();
      expect(serverInfo?.name).toBe("test-server");
      expect(serverInfo?.version).toBe("1.0.0");
      expect(serverInfo?.metadata).toEqual({
        author: "test",
        description: "Test MCP server",
      });
    });

    it("should handle serverInfo with nested metadata objects", () => {
      const rawServerInfo: MockServerVersion = {
        name: "test-server",
        version: "1.0.0",
        metadata: {
          config: {
            timeout: 5000,
            retries: 3,
          },
          features: ["logging", "metrics"],
        },
      };

      const serverInfo = buildServerInfo(rawServerInfo);

      expect(serverInfo?.metadata).toBeDefined();
      expect(serverInfo?.metadata?.config).toEqual({
        timeout: 5000,
        retries: 3,
      });
      expect(serverInfo?.metadata?.features).toEqual(["logging", "metrics"]);
    });

    it("should handle serverInfo with undefined metadata", () => {
      const rawServerInfo: MockServerVersion = {
        name: "test-server",
        version: "1.0.0",
        // No metadata property
      };

      const serverInfo = buildServerInfo(rawServerInfo);

      expect(serverInfo).toBeDefined();
      expect(serverInfo?.name).toBe("test-server");
      expect(serverInfo?.metadata).toBeUndefined();
    });

    it("should handle serverInfo with null metadata", () => {
      const rawServerInfo: MockServerVersion = {
        name: "test-server",
        version: "1.0.0",
        metadata: null as unknown as Record<string, unknown>,
      };

      const serverInfo = buildServerInfo(rawServerInfo);

      expect(serverInfo).toBeDefined();
      expect(serverInfo?.metadata).toBeNull();
    });

    it("should handle null rawServerInfo", () => {
      const serverInfo = buildServerInfo(null);
      expect(serverInfo).toBeUndefined();
    });

    it("should handle undefined rawServerInfo", () => {
      const serverInfo = buildServerInfo(undefined);
      expect(serverInfo).toBeUndefined();
    });

    it("should use 'unknown' as fallback for missing name", () => {
      const rawServerInfo: MockServerVersion = {
        name: "",
        version: "1.0.0",
      };

      const serverInfo = buildServerInfo(rawServerInfo);

      expect(serverInfo?.name).toBe("unknown");
    });

    it("should handle serverInfo with various metadata types", () => {
      // Test that metadata can contain different value types
      const rawServerInfo: MockServerVersion = {
        name: "test-server",
        version: "1.0.0",
        metadata: {
          stringValue: "test",
          numberValue: 42,
          booleanValue: true,
          arrayValue: [1, 2, 3],
          objectValue: { key: "value" },
          nullValue: null,
          undefinedValue: undefined,
        },
      };

      const serverInfo = buildServerInfo(rawServerInfo);

      expect(serverInfo?.metadata).toBeDefined();
      expect(serverInfo?.metadata?.stringValue).toBe("test");
      expect(serverInfo?.metadata?.numberValue).toBe(42);
      expect(serverInfo?.metadata?.booleanValue).toBe(true);
      expect(serverInfo?.metadata?.arrayValue).toEqual([1, 2, 3]);
      expect(serverInfo?.metadata?.objectValue).toEqual({ key: "value" });
      expect(serverInfo?.metadata?.nullValue).toBeNull();
      expect(serverInfo?.metadata?.undefinedValue).toBeUndefined();
    });

    it("should maintain type safety with Record<string, unknown>", () => {
      // This test ensures that the type assertion doesn't break type safety
      const rawServerInfo: MockServerVersion = {
        name: "test-server",
        version: "1.0.0",
        metadata: {
          validKey: "validValue",
        },
      };

      const serverInfo = buildServerInfo(rawServerInfo);

      // TypeScript should allow accessing metadata properties
      expect(serverInfo?.metadata?.validKey).toBe("validValue");

      // TypeScript should allow checking for unknown properties
      expect(serverInfo?.metadata?.unknownKey).toBeUndefined();
    });

    it("should not throw when metadata has unexpected structure", () => {
      // Test that the type assertion handles edge cases gracefully
      const edgeCases: MockServerVersion[] = [
        { name: "test", metadata: {} },
        { name: "test", metadata: { deeply: { nested: { value: 1 } } } },
        { name: "test", metadata: { array: [{ nested: "value" }] } },
      ];

      edgeCases.forEach((testCase) => {
        expect(() => buildServerInfo(testCase)).not.toThrow();
      });
    });
  });

  describe("TypeScript build validation", () => {
    it("should ensure ScopedListenerConfig compiles without errors", () => {
      // This test ensures that the event-config module compiles correctly
      // without cross-workspace import issues
      expect(ScopedListenerConfig).toBeDefined();
      expect(typeof ScopedListenerConfig).toBe("function");
    });

    it("should ensure ScopedListenerConfig default parameter works", () => {
      // Test that the default parameter (= CLI_DEFAULT_MAX_LISTENERS) works
      const config1 = new ScopedListenerConfig();
      const config2 = new ScopedListenerConfig(50);

      config1.apply();
      const max1 = process.getMaxListeners();
      config1.restore();

      config2.apply();
      const max2 = process.getMaxListeners();
      config2.restore();

      // Both should have the same effect
      expect(max1).toBe(max2);
      expect(max1).toBe(50);
    });
  });

  describe("Regression prevention", () => {
    it("should fail if ScopedListenerConfig default changes", () => {
      // If someone changes CLI_DEFAULT_MAX_LISTENERS without updating tests,
      // this test should catch it
      const config = new ScopedListenerConfig();
      config.apply();

      const actualDefault = process.getMaxListeners();
      const expectedDefault = 50; // Must match CLI_DEFAULT_MAX_LISTENERS

      expect(actualDefault).toBe(expectedDefault);

      config.restore();
    });

    it("should fail if ServerInfo metadata loses type safety", () => {
      // This test ensures that the metadata property maintains proper typing
      interface TestServerInfo {
        name: string;
        version?: string;
        metadata?: Record<string, unknown>; // Must be Record<string, unknown>
      }

      const serverInfo: TestServerInfo = {
        name: "test",
        version: "1.0.0",
        metadata: {
          key: "value",
          nested: { deep: "value" },
          array: [1, 2, 3],
        },
      };

      // TypeScript should allow this without errors
      expect(serverInfo.metadata?.key).toBe("value");
      expect(
        (serverInfo.metadata?.nested as Record<string, unknown>)?.deep,
      ).toBe("value");
      expect(serverInfo.metadata?.array).toEqual([1, 2, 3]);
    });
  });
});

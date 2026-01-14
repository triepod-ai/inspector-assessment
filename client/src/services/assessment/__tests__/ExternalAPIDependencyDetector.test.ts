/**
 * ExternalAPIDependencyDetector Tests
 *
 * Comprehensive tests for the ExternalAPIDependencyDetector module that identifies
 * tools depending on external APIs, enabling downstream assessors to adjust behavior.
 *
 * Test Coverage:
 * - All name patterns (18 patterns)
 * - All description patterns (7 regex patterns)
 * - Word-boundary matching (prevent false positives)
 * - Confidence level determination
 * - detect() method for batch detection
 * - isExternalAPITool() for single tool detection
 * - Edge cases and false positive prevention
 * - Helper methods (getNamePatterns, getDescriptionPatterns)
 *
 * Issue #168: External API Dependency Detection
 */

import {
  ExternalAPIDependencyDetector,
  ExternalAPIDependencyInfo,
} from "../helpers/ExternalAPIDependencyDetector";
import { Tool } from "@modelcontextprotocol/sdk/types.js";

describe("ExternalAPIDependencyDetector", () => {
  let detector: ExternalAPIDependencyDetector;

  // Helper to create a mock Tool
  const createTool = (name: string, description?: string): Tool => ({
    name,
    description: description ?? "",
    inputSchema: { type: "object", properties: {} },
  });

  beforeEach(() => {
    detector = new ExternalAPIDependencyDetector();
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  // ============================================================================
  // NAME PATTERN MATCHING
  // ============================================================================

  describe("Name pattern matching", () => {
    describe("API-related patterns", () => {
      it.each([
        ["weather_api", "api suffix"],
        ["api_client", "api prefix"],
        ["external_service", "external prefix"],
        ["external_api", "external prefix"],
        ["remote_fetch", "remote prefix"],
        ["live_data", "live prefix"],
      ])("detects %s (%s)", (toolName) => {
        const tool = createTool(toolName);
        expect(detector.isExternalAPITool(tool)).toBe(true);
      });
    });

    describe("Data type patterns (external sources)", () => {
      it.each([
        ["get_weather", "weather pattern"],
        ["weather_forecast", "weather pattern"],
        ["stock_price", "stock pattern"],
        ["stock_quotes", "stock pattern"],
        ["get_price", "price pattern"],
        ["price_checker", "price pattern"],
        ["market_data", "market pattern"],
        ["currency_converter", "currency pattern"],
        ["exchange_rate", "exchange pattern"],
        ["exchange_rates", "exchange with s suffix"],
        ["rate_lookup", "rate pattern"],
        ["forex_api", "forex pattern"],
      ])("detects %s (%s)", (toolName) => {
        const tool = createTool(toolName);
        expect(detector.isExternalAPITool(tool)).toBe(true);
      });
    });

    describe("Service-specific patterns", () => {
      it.each([
        ["wb_indicator", "wb (World Bank) prefix"],
        ["wb_data", "wb prefix"],
        ["worldbank_data", "worldbank prefix"],
        ["worldbank_indicators", "worldbank prefix"],
      ])("detects %s (%s)", (toolName) => {
        const tool = createTool(toolName);
        expect(detector.isExternalAPITool(tool)).toBe(true);
      });
    });

    describe("Action patterns suggesting external fetch", () => {
      it.each([
        ["fetch_from_api", "fetch_from pattern"],
        ["poll_server", "poll pattern"],
        ["poll_status", "poll pattern"],
        ["realtime_updates", "realtime pattern"],
        ["current_weather", "current pattern"],
        ["current_price", "current pattern"],
      ])("detects %s (%s)", (toolName) => {
        const tool = createTool(toolName);
        expect(detector.isExternalAPITool(tool)).toBe(true);
      });
    });

    describe("Hyphenated names", () => {
      it.each([
        ["weather-api", "hyphenated api"],
        ["live-data", "hyphenated live"],
        ["realtime-updates", "hyphenated realtime"],
        ["stock-price", "hyphenated stock"],
      ])("detects %s (%s)", (toolName) => {
        const tool = createTool(toolName);
        expect(detector.isExternalAPITool(tool)).toBe(true);
      });

      it("detects real-time pattern via description", () => {
        // "real-time" is detected via description pattern, not name pattern
        const tool = createTool("data-tool", "Provides real-time updates");
        expect(detector.isExternalAPITool(tool)).toBe(true);
      });
    });
  });

  // ============================================================================
  // DESCRIPTION PATTERN MATCHING
  // ============================================================================

  describe("Description pattern matching", () => {
    it.each([
      ["generic_tool", "calls external api", "external api pattern"],
      ["generic_tool", "uses external service", "external service pattern"],
      [
        "generic_tool",
        "fetches data from remote server",
        "fetches from pattern",
      ],
      ["generic_tool", "fetch from api endpoint", "fetch from pattern"],
      ["generic_tool", "calls external endpoint", "calls external pattern"],
      ["generic_tool", "calls remote service", "calls remote pattern"],
      ["generic_tool", "provides live data", "live data pattern"],
      ["generic_tool", "live feed of events", "live feed pattern"],
      ["generic_tool", "live stream updates", "live stream pattern"],
      ["generic_tool", "real-time updates", "real-time (hyphenated) pattern"],
      ["generic_tool", "realtime notifications", "realtime pattern"],
      ["generic_tool", "world bank indicators", "world bank pattern"],
      ["generic_tool", "worldbank data api", "worldbank pattern"],
      [
        "generic_tool",
        "third-party api integration",
        "third-party api pattern",
      ],
      [
        "generic_tool",
        "third party service calls",
        "third party service pattern",
      ],
    ])('detects "%s" with description "%s" (%s)', (toolName, description) => {
      const tool = createTool(toolName, description);
      expect(detector.isExternalAPITool(tool)).toBe(true);
    });

    it("detects external API from description even with neutral tool name", () => {
      const tool = createTool(
        "my_tool",
        "This tool fetches data from an external API",
      );
      expect(detector.isExternalAPITool(tool)).toBe(true);
    });
  });

  // ============================================================================
  // WORD-BOUNDARY MATCHING (FALSE POSITIVE PREVENTION)
  // ============================================================================

  describe("Word-boundary matching (false positive prevention)", () => {
    it.each([
      ["capital_gains", "api substring in 'capital'"],
      ["separate_items", "rate substring in 'separate'"],
      ["premarket_analysis", "market substring in 'premarket'"],
      ["stockpile_manager", "stock substring in 'stockpile'"],
      ["marketplace", "market substring"],
      ["appreciate_value", "rate substring in 'appreciate'"],
      ["elaborate_plan", "rate substring in 'elaborate'"],
      ["celebrity_tracker", "live substring in 'celebrity'"],
      ["delivery_service", "live substring in 'delivery'"],
      ["approval_workflow", "api substring in 'approval'"],
    ])(
      'does NOT detect "%s" (%s) - prevents false positive',
      (toolName, reason) => {
        const tool = createTool(toolName, `Generic description for ${reason}`);
        expect(detector.isExternalAPITool(tool)).toBe(false);
      },
    );

    it("uses word boundaries to distinguish real patterns", () => {
      // Should match - "api" at word boundary
      expect(detector.isExternalAPITool(createTool("weather_api"))).toBe(true);

      // Should NOT match - "api" embedded in "capital"
      expect(detector.isExternalAPITool(createTool("capital_gains"))).toBe(
        false,
      );
    });

    it("handles underscore as word boundary", () => {
      expect(detector.isExternalAPITool(createTool("get_api_data"))).toBe(true);
      expect(detector.isExternalAPITool(createTool("api_wrapper"))).toBe(true);
    });

    it("handles hyphen as word boundary", () => {
      expect(detector.isExternalAPITool(createTool("get-api-data"))).toBe(true);
      expect(detector.isExternalAPITool(createTool("api-wrapper"))).toBe(true);
    });

    it("handles pattern at start of name", () => {
      expect(detector.isExternalAPITool(createTool("api_client"))).toBe(true);
      expect(detector.isExternalAPITool(createTool("weather_tool"))).toBe(true);
    });

    it("handles pattern at end of name", () => {
      expect(detector.isExternalAPITool(createTool("get_weather"))).toBe(true);
      expect(detector.isExternalAPITool(createTool("my_api"))).toBe(true);
    });

    it("handles plural patterns (e.g., 'apis')", () => {
      expect(detector.isExternalAPITool(createTool("my_apis"))).toBe(true);
      expect(detector.isExternalAPITool(createTool("exchange_rates"))).toBe(
        true,
      );
    });
  });

  // ============================================================================
  // CONFIDENCE LEVEL DETERMINATION
  // ============================================================================

  describe("Confidence level determination", () => {
    it("returns 'low' confidence when no tools detected", () => {
      const tools = [
        createTool("generic_tool_1"),
        createTool("generic_tool_2"),
      ];
      const result = detector.detect(tools);
      expect(result.confidence).toBe("low");
      expect(result.detectedCount).toBe(0);
    });

    it("returns 'medium' confidence when 1-2 tools detected", () => {
      const tools = [
        createTool("weather_api"),
        createTool("generic_tool"),
        createTool("another_generic"),
      ];
      const result = detector.detect(tools);
      expect(result.confidence).toBe("medium");
      expect(result.detectedCount).toBe(1);
    });

    it("returns 'medium' confidence when exactly 2 tools detected", () => {
      const tools = [
        createTool("weather_api"),
        createTool("stock_price"),
        createTool("generic_tool"),
      ];
      const result = detector.detect(tools);
      expect(result.confidence).toBe("medium");
      expect(result.detectedCount).toBe(2);
    });

    it("returns 'high' confidence when 3+ tools detected", () => {
      const tools = [
        createTool("weather_api"),
        createTool("stock_price"),
        createTool("currency_converter"),
        createTool("generic_tool"),
      ];
      const result = detector.detect(tools);
      expect(result.confidence).toBe("high");
      expect(result.detectedCount).toBe(3);
    });

    it("returns 'high' confidence when many tools detected", () => {
      const tools = [
        createTool("weather_api"),
        createTool("stock_price"),
        createTool("currency_converter"),
        createTool("exchange_rate"),
        createTool("forex_data"),
        createTool("worldbank_indicators"),
      ];
      const result = detector.detect(tools);
      expect(result.confidence).toBe("high");
      expect(result.detectedCount).toBe(6);
    });
  });

  // ============================================================================
  // detect() METHOD
  // ============================================================================

  describe("detect() method", () => {
    it("returns ExternalAPIDependencyInfo with all fields", () => {
      const tools = [createTool("weather_api")];
      const result = detector.detect(tools);

      expect(result).toHaveProperty("toolsWithExternalAPIDependency");
      expect(result).toHaveProperty("detectedCount");
      expect(result).toHaveProperty("confidence");
      expect(result).toHaveProperty("detectedTools");
    });

    it("returns Set for toolsWithExternalAPIDependency", () => {
      const tools = [createTool("weather_api")];
      const result = detector.detect(tools);
      expect(result.toolsWithExternalAPIDependency).toBeInstanceOf(Set);
    });

    it("returns correct detectedTools array", () => {
      const tools = [
        createTool("weather_api"),
        createTool("stock_price"),
        createTool("generic_tool"),
      ];
      const result = detector.detect(tools);
      expect(result.detectedTools).toContain("weather_api");
      expect(result.detectedTools).toContain("stock_price");
      expect(result.detectedTools).not.toContain("generic_tool");
    });

    it("handles empty tools array", () => {
      const result = detector.detect([]);
      expect(result.detectedCount).toBe(0);
      expect(result.confidence).toBe("low");
      expect(result.detectedTools).toEqual([]);
    });

    it("detects all external API tools in mixed list", () => {
      const tools = [
        createTool("weather_api"),
        createTool("generic_tool_1"),
        createTool("stock_price"),
        createTool("generic_tool_2"),
        createTool("get_current", "Returns the current value"),
        createTool("data_fetcher", "Fetches data from external API"),
      ];
      const result = detector.detect(tools);

      expect(result.detectedCount).toBe(4);
      expect(result.toolsWithExternalAPIDependency.has("weather_api")).toBe(
        true,
      );
      expect(result.toolsWithExternalAPIDependency.has("stock_price")).toBe(
        true,
      );
      expect(result.toolsWithExternalAPIDependency.has("get_current")).toBe(
        true,
      );
      expect(result.toolsWithExternalAPIDependency.has("data_fetcher")).toBe(
        true,
      );
      expect(result.toolsWithExternalAPIDependency.has("generic_tool_1")).toBe(
        false,
      );
    });

    it("does not duplicate tool names", () => {
      const tools = [
        createTool("weather_api", "Also provides live weather data"),
      ];
      const result = detector.detect(tools);
      expect(result.detectedCount).toBe(1);
      expect(result.detectedTools).toHaveLength(1);
    });
  });

  // ============================================================================
  // isExternalAPITool() METHOD
  // ============================================================================

  describe("isExternalAPITool() method", () => {
    it("returns boolean", () => {
      const tool = createTool("weather_api");
      expect(typeof detector.isExternalAPITool(tool)).toBe("boolean");
    });

    it("detects by name pattern only", () => {
      const tool = createTool("weather_api", "");
      expect(detector.isExternalAPITool(tool)).toBe(true);
    });

    it("detects by description pattern only", () => {
      const tool = createTool("generic_tool", "Fetches from external API");
      expect(detector.isExternalAPITool(tool)).toBe(true);
    });

    it("detects when both name and description match", () => {
      const tool = createTool("weather_api", "Provides live weather data");
      expect(detector.isExternalAPITool(tool)).toBe(true);
    });

    it("returns false when neither matches", () => {
      const tool = createTool("calculator", "Performs math operations");
      expect(detector.isExternalAPITool(tool)).toBe(false);
    });

    it("is case insensitive for tool names", () => {
      expect(detector.isExternalAPITool(createTool("WEATHER_API"))).toBe(true);
      expect(detector.isExternalAPITool(createTool("Weather_Api"))).toBe(true);
      expect(detector.isExternalAPITool(createTool("weather_API"))).toBe(true);
    });

    it("is case insensitive for descriptions", () => {
      expect(
        detector.isExternalAPITool(
          createTool("tool", "FETCHES DATA FROM EXTERNAL API"),
        ),
      ).toBe(true);
      expect(
        detector.isExternalAPITool(
          createTool("tool", "Fetches Data From External Api"),
        ),
      ).toBe(true);
    });
  });

  // ============================================================================
  // EDGE CASES
  // ============================================================================

  describe("Edge cases", () => {
    it("handles undefined description", () => {
      const tool: Tool = {
        name: "weather_api",
        inputSchema: { type: "object", properties: {} },
      };
      expect(detector.isExternalAPITool(tool)).toBe(true);
    });

    it("handles empty description", () => {
      const tool = createTool("weather_api", "");
      expect(detector.isExternalAPITool(tool)).toBe(true);
    });

    it("handles whitespace-only description", () => {
      const tool = createTool("weather_api", "   \t\n  ");
      expect(detector.isExternalAPITool(tool)).toBe(true);
    });

    it("handles very long tool names", () => {
      const longName = "weather_" + "x".repeat(1000) + "_api";
      const tool = createTool(longName);
      expect(detector.isExternalAPITool(tool)).toBe(true);
    });

    it("handles very long descriptions", () => {
      const longDescription =
        "This tool " + "x".repeat(10000) + " fetches from external API";
      const tool = createTool("generic_tool", longDescription);
      expect(detector.isExternalAPITool(tool)).toBe(true);
    });

    it("handles special characters in tool name", () => {
      expect(detector.isExternalAPITool(createTool("weather!@#api"))).toBe(
        false,
      ); // No word boundary
      expect(detector.isExternalAPITool(createTool("weather_api!@#"))).toBe(
        true,
      );
    });

    it("handles unicode in tool name", () => {
      const tool = createTool("天气_weather_api");
      expect(detector.isExternalAPITool(tool)).toBe(true);
    });

    it("handles unicode in description", () => {
      const tool = createTool(
        "tool",
        "获取天气 - fetches data from external API",
      );
      expect(detector.isExternalAPITool(tool)).toBe(true);
    });

    it("handles null description gracefully (JS runtime)", () => {
      const tool: Tool = {
        name: "weather_api",
        description: null as unknown as string,
        inputSchema: { type: "object", properties: {} },
      };
      expect(detector.isExternalAPITool(tool)).toBe(true);
    });
  });

  // ============================================================================
  // HELPER METHODS
  // ============================================================================

  describe("Helper methods", () => {
    describe("getNamePatterns()", () => {
      it("returns readonly array of patterns", () => {
        const patterns = detector.getNamePatterns();
        expect(Array.isArray(patterns)).toBe(true);
        expect(patterns.length).toBeGreaterThan(0);
      });

      it("includes all expected patterns", () => {
        const patterns = detector.getNamePatterns();
        expect(patterns).toContain("api");
        expect(patterns).toContain("external");
        expect(patterns).toContain("weather");
        expect(patterns).toContain("stock");
        expect(patterns).toContain("worldbank");
        expect(patterns).toContain("realtime");
      });

      it("returns 18 patterns", () => {
        const patterns = detector.getNamePatterns();
        expect(patterns.length).toBe(18);
      });
    });

    describe("getDescriptionPatterns()", () => {
      it("returns readonly array of RegExp patterns", () => {
        const patterns = detector.getDescriptionPatterns();
        expect(Array.isArray(patterns)).toBe(true);
        expect(patterns.length).toBeGreaterThan(0);
        patterns.forEach((pattern) => {
          expect(pattern).toBeInstanceOf(RegExp);
        });
      });

      it("returns 7 patterns", () => {
        const patterns = detector.getDescriptionPatterns();
        expect(patterns.length).toBe(7);
      });

      it("all patterns are case insensitive", () => {
        const patterns = detector.getDescriptionPatterns();
        patterns.forEach((pattern) => {
          expect(pattern.flags).toContain("i");
        });
      });
    });
  });

  // ============================================================================
  // REAL-WORLD TOOL EXAMPLES
  // ============================================================================

  describe("Real-world tool examples", () => {
    describe("World Bank MCP server tools (known external API)", () => {
      it("detects wb_indicator tool", () => {
        const tool = createTool(
          "wb_indicator",
          "Get World Bank indicator data for a country",
        );
        expect(detector.isExternalAPITool(tool)).toBe(true);
      });

      it("detects wb_gdp tool", () => {
        const tool = createTool("wb_gdp", "Get GDP data from World Bank");
        expect(detector.isExternalAPITool(tool)).toBe(true);
      });

      it("detects worldbank_search tool", () => {
        const tool = createTool(
          "worldbank_search",
          "Search World Bank indicators",
        );
        expect(detector.isExternalAPITool(tool)).toBe(true);
      });
    });

    describe("Weather API tools", () => {
      it("detects get_weather tool", () => {
        const tool = createTool(
          "get_weather",
          "Get current weather for a location",
        );
        expect(detector.isExternalAPITool(tool)).toBe(true);
      });

      it("detects weather_forecast tool", () => {
        const tool = createTool(
          "weather_forecast",
          "Get 5-day weather forecast",
        );
        expect(detector.isExternalAPITool(tool)).toBe(true);
      });

      it("detects current_weather tool", () => {
        const tool = createTool("current_weather", "Real-time weather data");
        expect(detector.isExternalAPITool(tool)).toBe(true);
      });
    });

    describe("Stock/Finance API tools", () => {
      it("detects stock_price tool", () => {
        const tool = createTool("stock_price", "Get stock price for a ticker");
        expect(detector.isExternalAPITool(tool)).toBe(true);
      });

      it("detects get_exchange_rate tool", () => {
        const tool = createTool(
          "get_exchange_rate",
          "Get currency exchange rate",
        );
        expect(detector.isExternalAPITool(tool)).toBe(true);
      });

      it("detects forex_data tool", () => {
        const tool = createTool("forex_data", "Get forex market data");
        expect(detector.isExternalAPITool(tool)).toBe(true);
      });
    });

    describe("Non-external API tools (should NOT match)", () => {
      it.each([
        ["calculator", "Performs math operations"],
        ["file_reader", "Reads files from disk"],
        ["memory_store", "Stores data in memory"],
        ["database_query", "Queries local database"],
        ["safe_storage_tool", "Safely stores data"],
        ["qdrant_store", "Stores vectors in Qdrant"],
        ["get_user_info", "Returns user information"],
        ["create_document", "Creates a new document"],
        ["delete_record", "Deletes a database record"],
      ])('does NOT detect %s - "%s"', (name, description) => {
        const tool = createTool(name, description);
        expect(detector.isExternalAPITool(tool)).toBe(false);
      });
    });
  });

  // ============================================================================
  // INTEGRATION WITH ASSESSORS (USAGE PATTERNS)
  // ============================================================================

  describe("Integration patterns", () => {
    it("can be used to check specific tool from context", () => {
      const tools = [
        createTool("weather_api"),
        createTool("calculator"),
        createTool("stock_price"),
      ];
      const result = detector.detect(tools);

      // Simulate how TemporalAssessor/FunctionalityAssessor would use this
      const isWeatherExternal =
        result.toolsWithExternalAPIDependency.has("weather_api");
      const isCalculatorExternal =
        result.toolsWithExternalAPIDependency.has("calculator");

      expect(isWeatherExternal).toBe(true);
      expect(isCalculatorExternal).toBe(false);
    });

    it("result is serializable (for context passing)", () => {
      const tools = [createTool("weather_api"), createTool("stock_price")];
      const result = detector.detect(tools);

      // detectedTools array is serializable, Set is not
      const serialized = JSON.stringify({
        detectedCount: result.detectedCount,
        confidence: result.confidence,
        detectedTools: result.detectedTools,
      });
      const parsed = JSON.parse(serialized);

      expect(parsed.detectedCount).toBe(2);
      expect(parsed.confidence).toBe("medium");
      expect(parsed.detectedTools).toContain("weather_api");
    });
  });

  // ============================================================================
  // CONCURRENT USAGE SAFETY
  // ============================================================================

  describe("Concurrent usage safety", () => {
    it("handles concurrent detect() calls without interference", async () => {
      const toolSets = [
        [createTool("weather_api")],
        [createTool("calculator")],
        [createTool("stock_price"), createTool("forex_data")],
      ];

      const promises = toolSets.map((tools) =>
        Promise.resolve(detector.detect(tools)),
      );
      const results = await Promise.all(promises);

      expect(results[0].detectedCount).toBe(1);
      expect(results[1].detectedCount).toBe(0);
      expect(results[2].detectedCount).toBe(2);
    });

    it("multiple detector instances work independently", () => {
      const detector1 = new ExternalAPIDependencyDetector();
      const detector2 = new ExternalAPIDependencyDetector();

      const result1 = detector1.detect([createTool("weather_api")]);
      const result2 = detector2.detect([createTool("calculator")]);

      expect(result1.detectedCount).toBe(1);
      expect(result2.detectedCount).toBe(0);
    });
  });

  // ============================================================================
  // INTERFACE TYPE VERIFICATION
  // ============================================================================

  describe("ExternalAPIDependencyInfo interface", () => {
    it("has correct structure", () => {
      const tools = [createTool("weather_api")];
      const result: ExternalAPIDependencyInfo = detector.detect(tools);

      expect(result.toolsWithExternalAPIDependency).toBeInstanceOf(Set);
      expect(typeof result.detectedCount).toBe("number");
      expect(["high", "medium", "low"]).toContain(result.confidence);
      expect(Array.isArray(result.detectedTools)).toBe(true);
    });

    it("Set and array have consistent content", () => {
      const tools = [
        createTool("weather_api"),
        createTool("stock_price"),
        createTool("generic"),
      ];
      const result = detector.detect(tools);

      expect(result.toolsWithExternalAPIDependency.size).toBe(
        result.detectedTools.length,
      );
      result.detectedTools.forEach((name) => {
        expect(result.toolsWithExternalAPIDependency.has(name)).toBe(true);
      });
    });
  });
});

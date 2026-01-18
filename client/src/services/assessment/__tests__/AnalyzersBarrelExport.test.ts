/**
 * Analyzers Barrel Export Unit Tests
 *
 * Tests the barrel export at analyzers/index.ts to ensure all analyzer classes
 * are properly exported and instantiable. Also tests edge cases like empty
 * responses across all analyzers.
 *
 * Test Requirements:
 * - TR-001 (P2): Verify all 9 analyzer classes are exported and instantiable
 * - TR-002 (P3): Verify each analyzer handles empty content arrays safely
 *
 * Related Issues:
 * - Issue #179: SecurityResponseAnalyzer refactoring
 * - TG-001: No direct unit tests for barrel exports
 * - EC-001: Empty content array handling not explicitly tested
 *
 * @group unit
 * @group security
 */

import {
  AuthBypassAnalyzer,
  StateBasedAuthAnalyzer,
  SecretLeakageDetector,
  ChainExploitationAnalyzer,
  ExcessivePermissionsAnalyzer,
  BlacklistBypassAnalyzer,
  OutputInjectionAnalyzer,
  SessionManagementAnalyzer,
  CryptographicFailureAnalyzer,
} from "../modules/securityTests/analyzers";
import {
  CompatibilityCallToolResult,
  Tool,
} from "@modelcontextprotocol/sdk/types.js";
import { createMockTool } from "@/test/utils/testUtils";

// ============================================
// Type Definitions for Test Results
// ============================================

type AuthBypassResult = {
  detected: boolean;
  failureMode: "FAIL_OPEN" | "FAIL_CLOSED" | "UNKNOWN";
  evidence?: string;
};

type StateBasedAuthResult = {
  vulnerable: boolean;
  safe: boolean;
  stateDependency: string;
  evidence: string;
};

type SecretLeakageResult = {
  detected: boolean;
  evidence?: string;
};

type ChainExploitationResult = {
  vulnerable: boolean;
  safe: boolean;
  chainType: string;
  vulnerabilityCategories: string[];
  evidence: {
    vulnerablePatterns: string[];
    safePatterns: string[];
    vulnerableScore: number;
    safeScore: number;
  };
};

type ExcessivePermissionsResult = {
  detected: boolean;
  evidence?: string;
};

type BlacklistBypassResult = {
  detected: boolean;
  evidence?: string;
};

type OutputInjectionResult = {
  detected: boolean;
  evidence?: string;
};

type SessionManagementResult = {
  detected: boolean;
  evidence?: string;
};

type CryptoFailureResult = {
  detected: boolean;
  evidence?: string;
};

// ============================================
// Test Helper Functions
// ============================================

/**
 * Create an empty response (EC-001 edge case)
 */
function createEmptyResponse(): CompatibilityCallToolResult {
  return {
    content: [],
  } as CompatibilityCallToolResult;
}

/**
 * Create a minimal valid response
 */
function createMinimalResponse(text: string): CompatibilityCallToolResult {
  return {
    content: [{ type: "text", text }],
  } as CompatibilityCallToolResult;
}

/**
 * Create a mock tool for testing
 */
function createTestTool(name: string): Tool {
  return createMockTool({
    name,
    description: `Test tool: ${name}`,
  });
}

// ============================================
// TR-001: Barrel Export Validation Tests
// ============================================

describe("Analyzers Barrel Export (TR-001)", () => {
  describe("Class Instantiation", () => {
    it("should export AuthBypassAnalyzer and allow instantiation", () => {
      expect(() => new AuthBypassAnalyzer()).not.toThrow();
      const instance = new AuthBypassAnalyzer();
      expect(instance).toBeInstanceOf(AuthBypassAnalyzer);
      expect(typeof instance.analyze).toBe("function");
    });

    it("should export StateBasedAuthAnalyzer and allow instantiation", () => {
      expect(() => new StateBasedAuthAnalyzer()).not.toThrow();
      const instance = new StateBasedAuthAnalyzer();
      expect(instance).toBeInstanceOf(StateBasedAuthAnalyzer);
      expect(typeof instance.analyze).toBe("function");
    });

    it("should export SecretLeakageDetector and allow instantiation", () => {
      expect(() => new SecretLeakageDetector()).not.toThrow();
      const instance = new SecretLeakageDetector();
      expect(instance).toBeInstanceOf(SecretLeakageDetector);
      expect(typeof instance.analyze).toBe("function");
    });

    it("should export ChainExploitationAnalyzer and allow instantiation", () => {
      expect(() => new ChainExploitationAnalyzer()).not.toThrow();
      const instance = new ChainExploitationAnalyzer();
      expect(instance).toBeInstanceOf(ChainExploitationAnalyzer);
      expect(typeof instance.analyze).toBe("function");
    });

    it("should export ExcessivePermissionsAnalyzer and allow instantiation", () => {
      expect(() => new ExcessivePermissionsAnalyzer()).not.toThrow();
      const instance = new ExcessivePermissionsAnalyzer();
      expect(instance).toBeInstanceOf(ExcessivePermissionsAnalyzer);
      expect(typeof instance.analyze).toBe("function");
    });

    it("should export BlacklistBypassAnalyzer and allow instantiation", () => {
      expect(() => new BlacklistBypassAnalyzer()).not.toThrow();
      const instance = new BlacklistBypassAnalyzer();
      expect(instance).toBeInstanceOf(BlacklistBypassAnalyzer);
      expect(typeof instance.analyze).toBe("function");
    });

    it("should export OutputInjectionAnalyzer and allow instantiation", () => {
      expect(() => new OutputInjectionAnalyzer()).not.toThrow();
      const instance = new OutputInjectionAnalyzer();
      expect(instance).toBeInstanceOf(OutputInjectionAnalyzer);
      expect(typeof instance.analyze).toBe("function");
    });

    it("should export SessionManagementAnalyzer and allow instantiation", () => {
      expect(() => new SessionManagementAnalyzer()).not.toThrow();
      const instance = new SessionManagementAnalyzer();
      expect(instance).toBeInstanceOf(SessionManagementAnalyzer);
      expect(typeof instance.analyze).toBe("function");
    });

    it("should export CryptographicFailureAnalyzer and allow instantiation", () => {
      expect(() => new CryptographicFailureAnalyzer()).not.toThrow();
      const instance = new CryptographicFailureAnalyzer();
      expect(instance).toBeInstanceOf(CryptographicFailureAnalyzer);
      expect(typeof instance.analyze).toBe("function");
    });
  });

  describe("Analyzer Method Contracts", () => {
    it("all analyzers should have an analyze() method", () => {
      const analyzers = [
        new AuthBypassAnalyzer(),
        new StateBasedAuthAnalyzer(),
        new SecretLeakageDetector(),
        new ChainExploitationAnalyzer(),
        new ExcessivePermissionsAnalyzer(),
        new BlacklistBypassAnalyzer(),
        new OutputInjectionAnalyzer(),
        new SessionManagementAnalyzer(),
        new CryptographicFailureAnalyzer(),
      ];

      for (const analyzer of analyzers) {
        expect(analyzer).toHaveProperty("analyze");
        expect(typeof analyzer.analyze).toBe("function");
      }
    });

    it("analyze() methods should accept CompatibilityCallToolResult", () => {
      const response = createMinimalResponse("test");

      // These should not throw when called with proper response type
      expect(() => new AuthBypassAnalyzer().analyze(response)).not.toThrow();
      expect(() =>
        new StateBasedAuthAnalyzer().analyze(response),
      ).not.toThrow();
      expect(() => new SecretLeakageDetector().analyze(response)).not.toThrow();
      expect(() =>
        new ChainExploitationAnalyzer().analyze(response),
      ).not.toThrow();
      expect(() =>
        new ExcessivePermissionsAnalyzer().analyze(
          response,
          createTestTool("test"),
        ),
      ).not.toThrow();
      expect(() =>
        new BlacklistBypassAnalyzer().analyze(response),
      ).not.toThrow();
      expect(() =>
        new OutputInjectionAnalyzer().analyze(response),
      ).not.toThrow();
      expect(() =>
        new SessionManagementAnalyzer().analyze(response),
      ).not.toThrow();
      expect(() =>
        new CryptographicFailureAnalyzer().analyze(response),
      ).not.toThrow();
    });
  });
});

// ============================================
// TR-002 / EC-001: Empty Response Edge Cases
// ============================================

describe("Empty Response Handling (TR-002, EC-001)", () => {
  describe("AuthBypassAnalyzer - empty response", () => {
    it("should return safe result with UNKNOWN mode for empty content", () => {
      const analyzer = new AuthBypassAnalyzer();
      const emptyResponse = createEmptyResponse();

      const result = analyzer.analyze(emptyResponse) as AuthBypassResult;

      expect(result.detected).toBe(false);
      expect(result.failureMode).toBe("UNKNOWN");
    });

    it("should handle empty response without throwing", () => {
      const analyzer = new AuthBypassAnalyzer();
      const emptyResponse = createEmptyResponse();

      expect(() => analyzer.analyze(emptyResponse)).not.toThrow();
    });
  });

  describe("StateBasedAuthAnalyzer - empty response", () => {
    it("should return safe result for empty content", () => {
      const analyzer = new StateBasedAuthAnalyzer();
      const emptyResponse = createEmptyResponse();

      const result = analyzer.analyze(emptyResponse) as StateBasedAuthResult;

      expect(result.vulnerable).toBe(false);
      expect(result.stateDependency).toBe("UNKNOWN");
    });

    it("should handle empty response without throwing", () => {
      const analyzer = new StateBasedAuthAnalyzer();
      const emptyResponse = createEmptyResponse();

      expect(() => analyzer.analyze(emptyResponse)).not.toThrow();
    });
  });

  describe("SecretLeakageDetector - empty response", () => {
    it("should return safe result for empty content", () => {
      const detector = new SecretLeakageDetector();
      const emptyResponse = createEmptyResponse();

      const result = detector.analyze(emptyResponse) as SecretLeakageResult;

      expect(result.detected).toBe(false);
    });

    it("should handle empty response without throwing", () => {
      const detector = new SecretLeakageDetector();
      const emptyResponse = createEmptyResponse();

      expect(() => detector.analyze(emptyResponse)).not.toThrow();
    });
  });

  describe("ChainExploitationAnalyzer - empty response", () => {
    it("should return safe result for empty content", () => {
      const analyzer = new ChainExploitationAnalyzer();
      const emptyResponse = createEmptyResponse();

      const result = analyzer.analyze(emptyResponse) as ChainExploitationResult;

      expect(result.vulnerable).toBe(false);
      expect(result.chainType).toBe("UNKNOWN");
    });

    it("should handle empty response without throwing", () => {
      const analyzer = new ChainExploitationAnalyzer();
      const emptyResponse = createEmptyResponse();

      expect(() => analyzer.analyze(emptyResponse)).not.toThrow();
    });
  });

  describe("ExcessivePermissionsAnalyzer - empty response", () => {
    it("should return safe result for empty content", () => {
      const analyzer = new ExcessivePermissionsAnalyzer();
      const emptyResponse = createEmptyResponse();
      const tool = createTestTool("test_tool");

      const result = analyzer.analyze(
        emptyResponse,
        tool,
      ) as ExcessivePermissionsResult;

      expect(result.detected).toBe(false);
    });

    it("should handle empty response without throwing", () => {
      const analyzer = new ExcessivePermissionsAnalyzer();
      const emptyResponse = createEmptyResponse();
      const tool = createTestTool("test_tool");

      expect(() => analyzer.analyze(emptyResponse, tool)).not.toThrow();
    });
  });

  describe("BlacklistBypassAnalyzer - empty response", () => {
    it("should return safe result for empty content", () => {
      const analyzer = new BlacklistBypassAnalyzer();
      const emptyResponse = createEmptyResponse();

      const result = analyzer.analyze(emptyResponse) as BlacklistBypassResult;

      expect(result.detected).toBe(false);
    });

    it("should handle empty response without throwing", () => {
      const analyzer = new BlacklistBypassAnalyzer();
      const emptyResponse = createEmptyResponse();

      expect(() => analyzer.analyze(emptyResponse)).not.toThrow();
    });
  });

  describe("OutputInjectionAnalyzer - empty response", () => {
    it("should return safe result for empty content", () => {
      const analyzer = new OutputInjectionAnalyzer();
      const emptyResponse = createEmptyResponse();

      const result = analyzer.analyze(emptyResponse) as OutputInjectionResult;

      expect(result.detected).toBe(false);
    });

    it("should handle empty response without throwing", () => {
      const analyzer = new OutputInjectionAnalyzer();
      const emptyResponse = createEmptyResponse();

      expect(() => analyzer.analyze(emptyResponse)).not.toThrow();
    });
  });

  describe("SessionManagementAnalyzer - empty response", () => {
    it("should return safe result for empty content", () => {
      const analyzer = new SessionManagementAnalyzer();
      const emptyResponse = createEmptyResponse();

      const result = analyzer.analyze(emptyResponse) as SessionManagementResult;

      expect(result.detected).toBe(false);
    });

    it("should handle empty response without throwing", () => {
      const analyzer = new SessionManagementAnalyzer();
      const emptyResponse = createEmptyResponse();

      expect(() => analyzer.analyze(emptyResponse)).not.toThrow();
    });
  });

  describe("CryptographicFailureAnalyzer - empty response", () => {
    it("should return safe result for empty content", () => {
      const analyzer = new CryptographicFailureAnalyzer();
      const emptyResponse = createEmptyResponse();

      const result = analyzer.analyze(emptyResponse) as CryptoFailureResult;

      expect(result.detected).toBe(false);
    });

    it("should handle empty response without throwing", () => {
      const analyzer = new CryptographicFailureAnalyzer();
      const emptyResponse = createEmptyResponse();

      expect(() => analyzer.analyze(emptyResponse)).not.toThrow();
    });
  });
});

// ============================================
// Edge Case: Minimal Valid Responses
// ============================================

describe("Minimal Valid Response Handling", () => {
  it("all analyzers should handle single-char responses safely", () => {
    const response = createMinimalResponse("x");
    const tool = createTestTool("test_tool");

    // These should not throw
    expect(() => new AuthBypassAnalyzer().analyze(response)).not.toThrow();
    expect(() => new StateBasedAuthAnalyzer().analyze(response)).not.toThrow();
    expect(() => new SecretLeakageDetector().analyze(response)).not.toThrow();
    expect(() =>
      new ChainExploitationAnalyzer().analyze(response),
    ).not.toThrow();
    expect(() =>
      new ExcessivePermissionsAnalyzer().analyze(response, tool),
    ).not.toThrow();
    expect(() => new BlacklistBypassAnalyzer().analyze(response)).not.toThrow();
    expect(() => new OutputInjectionAnalyzer().analyze(response)).not.toThrow();
    expect(() =>
      new SessionManagementAnalyzer().analyze(response),
    ).not.toThrow();
    expect(() =>
      new CryptographicFailureAnalyzer().analyze(response),
    ).not.toThrow();
  });

  it("all analyzers should return safe results for minimal responses", () => {
    const response = createMinimalResponse("ok");
    const tool = createTestTool("test_tool");

    const authBypassResult = new AuthBypassAnalyzer().analyze(
      response,
    ) as AuthBypassResult;
    expect(authBypassResult.detected).toBe(false);

    const stateAuthResult = new StateBasedAuthAnalyzer().analyze(
      response,
    ) as StateBasedAuthResult;
    expect(stateAuthResult.vulnerable).toBe(false);

    const secretResult = new SecretLeakageDetector().analyze(
      response,
    ) as SecretLeakageResult;
    expect(secretResult.detected).toBe(false);

    const chainResult = new ChainExploitationAnalyzer().analyze(
      response,
    ) as ChainExploitationResult;
    expect(chainResult.vulnerable).toBe(false);

    const permResult = new ExcessivePermissionsAnalyzer().analyze(
      response,
      tool,
    ) as ExcessivePermissionsResult;
    expect(permResult.detected).toBe(false);

    const blacklistResult = new BlacklistBypassAnalyzer().analyze(
      response,
    ) as BlacklistBypassResult;
    expect(blacklistResult.detected).toBe(false);

    const outputResult = new OutputInjectionAnalyzer().analyze(
      response,
    ) as OutputInjectionResult;
    expect(outputResult.detected).toBe(false);

    const sessionResult = new SessionManagementAnalyzer().analyze(
      response,
    ) as SessionManagementResult;
    expect(sessionResult.detected).toBe(false);

    const cryptoResult = new CryptographicFailureAnalyzer().analyze(
      response,
    ) as CryptoFailureResult;
    expect(cryptoResult.detected).toBe(false);
  });
});

// ============================================
// Integration: All Analyzers Together
// ============================================

describe("Analyzer Integration", () => {
  it("should be able to use all analyzers in sequence", () => {
    const response = createMinimalResponse("test response");
    const tool = createTestTool("test_tool");

    // Simulate using all analyzers in a security assessment pipeline
    const authBypass = new AuthBypassAnalyzer();
    const stateAuth = new StateBasedAuthAnalyzer();
    const secretDetector = new SecretLeakageDetector();
    const chainExploit = new ChainExploitationAnalyzer();
    const excessPerms = new ExcessivePermissionsAnalyzer();
    const blacklistBypass = new BlacklistBypassAnalyzer();
    const outputInjection = new OutputInjectionAnalyzer();
    const sessionMgmt = new SessionManagementAnalyzer();
    const cryptoFailure = new CryptographicFailureAnalyzer();

    // All should execute without errors
    expect(() => authBypass.analyze(response)).not.toThrow();
    expect(() => stateAuth.analyze(response)).not.toThrow();
    expect(() => secretDetector.analyze(response)).not.toThrow();
    expect(() => chainExploit.analyze(response)).not.toThrow();
    expect(() => excessPerms.analyze(response, tool)).not.toThrow();
    expect(() => blacklistBypass.analyze(response)).not.toThrow();
    expect(() => outputInjection.analyze(response)).not.toThrow();
    expect(() => sessionMgmt.analyze(response)).not.toThrow();
    expect(() => cryptoFailure.analyze(response)).not.toThrow();
  });

  it("all analyzers should be independent (no shared state)", () => {
    const response1 = createMinimalResponse("first");
    const response2 = createMinimalResponse("second");
    const tool = createTestTool("test_tool");

    const authBypass = new AuthBypassAnalyzer();

    // Analyze first response
    const result1 = authBypass.analyze(response1) as AuthBypassResult;

    // Analyze second response
    const result2 = authBypass.analyze(response2) as AuthBypassResult;

    // Results should be independent
    expect(result1).toBeDefined();
    expect(result2).toBeDefined();
    expect(result1.detected).toBe(false);
    expect(result2.detected).toBe(false);
  });
});

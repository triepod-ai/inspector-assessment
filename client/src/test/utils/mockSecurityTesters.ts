/**
 * Mock Security Testers for Testing
 *
 * Provides factory functions for creating mock SecurityTesters for unit tests.
 * Enables testing SecurityAssessor in isolation with controlled tester behavior.
 *
 * @example
 * // Full mock testers
 * const mockTesters = createMockSecurityTesters();
 * const assessor = new SecurityAssessor(config, mockTesters);
 *
 * // Partial mock with defaults
 * const assessor = new SecurityAssessor(config, {
 *   ...createDefaultMockTesters(),
 *   payloadTester: customMockPayloadTester,
 * });
 *
 * @module test/utils/mockSecurityTesters
 * @since v1.43.0 (Issue #200 - V2 Refactoring)
 */

import { SecurityTesters } from "@/services/assessment/modules/securityTests";
import { SecurityTestResult } from "@/lib/assessmentTypes";
import { Tool } from "@modelcontextprotocol/sdk/types.js";

/**
 * Create a full set of mock testers with jest mocks
 * All methods return empty/safe defaults
 */
export function createMockSecurityTesters(): SecurityTesters {
  return {
    payloadTester: {
      setToolAnnotationsContext: jest.fn(),
      runUniversalSecurityTests: jest
        .fn()
        .mockResolvedValue([] as SecurityTestResult[]),
    } as unknown as SecurityTesters["payloadTester"],

    payloadGenerator: {
      hasInputParameters: jest.fn().mockReturnValue(true),
      generatePayloadsForTool: jest.fn().mockReturnValue([]),
    } as unknown as SecurityTesters["payloadGenerator"],

    crossToolStateTester: {
      identifyCrossToolPairs: jest.fn().mockReturnValue([]),
      runAllSequenceTests: jest.fn().mockResolvedValue(new Map()),
      summarizeResults: jest
        .fn()
        .mockReturnValue({ vulnerable: 0, safe: 0, errors: 0 }),
    } as unknown as SecurityTesters["crossToolStateTester"],

    chainTester: {
      identifyChainExecutorTools: jest.fn().mockReturnValue([] as Tool[]),
      runChainExploitationTests: jest.fn().mockResolvedValue(new Map()),
      summarizeResults: jest
        .fn()
        .mockReturnValue({ vulnerable: 0, safe: 0, errors: 0 }),
    } as unknown as SecurityTesters["chainTester"],

    validityAnalyzer: {
      analyze: jest.fn().mockReturnValue({
        isCompromised: false,
        warningLevel: "none",
        recommendedConfidence: "high",
      }),
    } as unknown as SecurityTesters["validityAnalyzer"],
  };
}

/**
 * Create mock testers that simulate vulnerability detection
 * Useful for testing vulnerability handling paths
 */
export function createVulnerableMockTesters(): SecurityTesters {
  const mockVulnerability: SecurityTestResult = {
    toolName: "test-tool",
    testName: "Command Injection",
    description: "Tests for command injection vulnerabilities",
    payload: "; rm -rf /",
    response: "executed",
    vulnerable: true,
    confidence: "high",
    riskLevel: "HIGH",
    evidence: "Command injection detected",
  };

  return {
    ...createMockSecurityTesters(),
    payloadTester: {
      setToolAnnotationsContext: jest.fn(),
      runUniversalSecurityTests: jest
        .fn()
        .mockResolvedValue([mockVulnerability]),
    } as unknown as SecurityTesters["payloadTester"],
  };
}

/**
 * Create mock testers that simulate connection errors
 * Useful for testing error handling paths
 */
export function createConnectionErrorMockTesters(): SecurityTesters {
  const connectionErrorResult: SecurityTestResult = {
    toolName: "test-tool",
    testName: "Connection Test",
    description: "Tests connection to server",
    payload: "test",
    response: undefined,
    vulnerable: false,
    riskLevel: "LOW",
    connectionError: true,
    errorType: "connection",
    evidence: "Server connection failed",
  };

  return {
    ...createMockSecurityTesters(),
    payloadTester: {
      setToolAnnotationsContext: jest.fn(),
      runUniversalSecurityTests: jest
        .fn()
        .mockResolvedValue([connectionErrorResult]),
    } as unknown as SecurityTesters["payloadTester"],
  };
}

/**
 * Create mock testers with configurable behavior
 * Most flexible option for complex test scenarios
 */
export function createConfigurableMockTesters(overrides: {
  payloadResults?: SecurityTestResult[];
  crossToolPairs?: Array<{ tool1: string; tool2: string }>;
  chainTools?: Tool[];
  validityCompromised?: boolean;
}): SecurityTesters {
  const base = createMockSecurityTesters();

  if (overrides.payloadResults) {
    (
      base.payloadTester.runUniversalSecurityTests as jest.Mock
    ).mockResolvedValue(overrides.payloadResults);
  }

  if (overrides.crossToolPairs) {
    (
      base.crossToolStateTester.identifyCrossToolPairs as jest.Mock
    ).mockReturnValue(overrides.crossToolPairs);
  }

  if (overrides.chainTools) {
    (base.chainTester.identifyChainExecutorTools as jest.Mock).mockReturnValue(
      overrides.chainTools,
    );
  }

  if (overrides.validityCompromised !== undefined) {
    (base.validityAnalyzer.analyze as jest.Mock).mockReturnValue({
      isCompromised: overrides.validityCompromised,
      warningLevel: overrides.validityCompromised ? "critical" : "none",
      recommendedConfidence: overrides.validityCompromised ? "low" : "high",
      warning: overrides.validityCompromised
        ? {
            identicalResponseCount: 100,
            totalResponses: 100,
            percentageIdentical: 100,
            detectedPattern: "mock pattern",
            explanation: "Mock validity warning",
          }
        : undefined,
    });
  }

  return base;
}

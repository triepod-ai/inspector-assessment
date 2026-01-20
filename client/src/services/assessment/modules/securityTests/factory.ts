/**
 * Security Testers Factory
 *
 * Factory pattern for creating SecurityAssessor's tester dependencies.
 * Enables dependency injection for testability and decoupling.
 *
 * @example
 * // Production usage (uses factory automatically)
 * const assessor = new SecurityAssessor(config);
 *
 * // Testing with mocks
 * const mockTesters = { payloadTester: mockPayloadTester, ... };
 * const assessor = new SecurityAssessor(config, mockTesters);
 *
 * @module assessment/security/factory
 * @since v1.43.0 (Issue #200 - V2 Refactoring)
 */

import { AssessmentConfiguration } from "@/lib/assessment/configTypes";
import {
  SecurityPayloadTester,
  PayloadTestConfig,
  TestLogger,
} from "./SecurityPayloadTester";
import { SecurityPayloadGenerator } from "./SecurityPayloadGenerator";
import { CrossToolStateTester } from "./CrossToolStateTester";
import { ChainExecutionTester } from "./ChainExecutionTester";
import { TestValidityAnalyzer } from "./TestValidityAnalyzer";

/**
 * Collection of security tester instances
 * Used for dependency injection into SecurityAssessor
 */
export interface SecurityTesters {
  /** Executes security payloads and analyzes responses */
  payloadTester: SecurityPayloadTester;

  /** Generates security test payloads for various attack patterns */
  payloadGenerator: SecurityPayloadGenerator;

  /** Tests for cross-tool state-based privilege escalation (Issue #92) */
  crossToolStateTester: CrossToolStateTester;

  /** Tests for multi-tool chain exploitation attacks (Issue #93) */
  chainTester: ChainExecutionTester;

  /** Analyzes test validity and detects uniform responses (Issue #134) */
  validityAnalyzer: TestValidityAnalyzer;
}

/**
 * Configuration for creating security testers
 * Extends PayloadTestConfig with additional options
 */
export interface SecurityTestersConfig {
  /** Assessment configuration (source of most settings) */
  assessmentConfig: AssessmentConfiguration;

  /** Logger adapter for test execution */
  logger: TestLogger;

  /** Timeout execution wrapper from BaseAssessor */
  executeWithTimeout: <T>(promise: Promise<T>, timeout: number) => Promise<T>;
}

/**
 * Create security testers with dependencies injected
 *
 * This factory function creates all security tester instances with
 * consistent configuration. Used by SecurityAssessor constructor when
 * no testers are provided.
 *
 * @param factoryConfig - Configuration containing assessment config, logger, and timeout fn
 * @returns SecurityTesters - Collection of tester instances
 *
 * @example
 * // In SecurityAssessor constructor
 * this.testers = testers ?? createSecurityTesters({
 *   assessmentConfig: config,
 *   logger: this.createTestLogger(),
 *   executeWithTimeout: this.executeWithTimeout.bind(this),
 * });
 */
export function createSecurityTesters(
  factoryConfig: SecurityTestersConfig,
): SecurityTesters {
  const { assessmentConfig, logger, executeWithTimeout } = factoryConfig;

  // Build PayloadTestConfig from AssessmentConfiguration
  const payloadConfig: PayloadTestConfig = {
    enableDomainTesting: assessmentConfig.enableDomainTesting,
    maxParallelTests: assessmentConfig.maxParallelTests,
    securityTestTimeout: assessmentConfig.securityTestTimeout,
    selectedToolsForTesting: assessmentConfig.selectedToolsForTesting,
  };

  return {
    payloadTester: new SecurityPayloadTester(
      payloadConfig,
      logger,
      executeWithTimeout,
    ),

    payloadGenerator: new SecurityPayloadGenerator(),

    crossToolStateTester: new CrossToolStateTester({
      timeout: assessmentConfig.securityTestTimeout,
    }),

    chainTester: new ChainExecutionTester({
      verbose: false,
    }),

    validityAnalyzer: new TestValidityAnalyzer(),
  };
}

/**
 * Create a partial set of testers for specific testing scenarios
 * Useful when you only need to mock certain components
 *
 * @param partialTesters - Subset of testers to override
 * @param factoryConfig - Config for creating remaining testers
 * @returns SecurityTesters - Complete set with overrides applied
 */
export function createSecurityTestersWithOverrides(
  partialTesters: Partial<SecurityTesters>,
  factoryConfig: SecurityTestersConfig,
): SecurityTesters {
  const defaultTesters = createSecurityTesters(factoryConfig);

  return {
    ...defaultTesters,
    ...partialTesters,
  };
}

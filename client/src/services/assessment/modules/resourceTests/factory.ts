/**
 * Resource Testers Factory
 *
 * Factory pattern for creating ResourceAssessor's tester dependencies.
 * Enables dependency injection for testability and decoupling.
 *
 * @example
 * // Production usage (uses factory automatically)
 * const assessor = new ResourceAssessor(config);
 *
 * // Testing with mocks
 * const mockTesters = { resourceTester: mockResourceTester, ... };
 * const assessor = new ResourceAssessor(config, mockTesters);
 *
 * @module assessment/resources/factory
 * @since v1.44.0 (Issue #180 - ResourceAssessor Modularization)
 */

import { AssessmentConfiguration } from "@/lib/assessment/configTypes";
import {
  ResourceTester,
  TestLogger as ResourceTestLogger,
} from "./ResourceTester";
import {
  ResourceProbeTester,
  TestLogger as ProbeTestLogger,
} from "./ResourceProbeTester";
import { ResourceEnrichmentBuilder } from "./ResourceEnrichmentBuilder";

/**
 * Logger interface for resource testing
 */
export interface TestLogger extends ResourceTestLogger, ProbeTestLogger {
  info: (message: string, context?: Record<string, unknown>) => void;
  debug: (message: string, context?: Record<string, unknown>) => void;
}

/**
 * Collection of resource tester instances
 * Used for dependency injection into ResourceAssessor
 */
export interface ResourceTesters {
  /** Core resource tester for accessibility and template testing */
  resourceTester: ResourceTester;

  /** Probe tester for hidden resources and URI injection */
  probeTester: ResourceProbeTester;

  /** Enrichment builder for Stage B data */
  enrichmentBuilder: ResourceEnrichmentBuilder;
}

/**
 * Configuration for creating resource testers
 */
export interface ResourceTestersConfig {
  /** Assessment configuration (source of most settings) */
  assessmentConfig: AssessmentConfiguration;

  /** Logger adapter for test execution */
  logger: TestLogger;

  /** Timeout execution wrapper from BaseAssessor */
  executeWithTimeout: <T>(promise: Promise<T>, timeout: number) => Promise<T>;

  /** Function to increment test count */
  incrementTestCount: () => void;

  /** Function to extract error messages */
  extractErrorMessage: (error: unknown) => string;
}

/**
 * Create resource testers with dependencies injected
 *
 * This factory function creates all resource tester instances with
 * consistent configuration. Used by ResourceAssessor constructor when
 * no testers are provided.
 *
 * @param factoryConfig - Configuration containing assessment config, logger, and helpers
 * @returns ResourceTesters - Collection of tester instances
 *
 * @example
 * // In ResourceAssessor constructor
 * this.testers = testers ?? createResourceTesters({
 *   assessmentConfig: config,
 *   logger: this.createTestLogger(),
 *   executeWithTimeout: this.executeWithTimeout.bind(this),
 *   incrementTestCount: () => this.testCount++,
 *   extractErrorMessage: this.extractErrorMessage.bind(this),
 * });
 */
export function createResourceTesters(
  factoryConfig: ResourceTestersConfig,
): ResourceTesters {
  const {
    logger,
    executeWithTimeout,
    incrementTestCount,
    extractErrorMessage,
  } = factoryConfig;

  return {
    resourceTester: new ResourceTester({
      logger,
      executeWithTimeout,
      incrementTestCount,
      extractErrorMessage,
    }),

    probeTester: new ResourceProbeTester({
      logger,
      executeWithTimeout,
      incrementTestCount,
    }),

    enrichmentBuilder: new ResourceEnrichmentBuilder(),
  };
}

/**
 * Create a partial set of testers for specific testing scenarios
 * Useful when you only need to mock certain components
 *
 * @param partialTesters - Subset of testers to override
 * @param factoryConfig - Config for creating remaining testers
 * @returns ResourceTesters - Complete set with overrides applied
 */
export function createResourceTestersWithOverrides(
  partialTesters: Partial<ResourceTesters>,
  factoryConfig: ResourceTestersConfig,
): ResourceTesters {
  const defaultTesters = createResourceTesters(factoryConfig);

  return {
    ...defaultTesters,
    ...partialTesters,
  };
}

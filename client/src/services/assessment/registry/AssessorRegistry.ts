/**
 * Assessor Registry
 *
 * Central registry for managing assessor instances with metadata.
 * Provides phase-ordered execution, Claude bridge wiring, and test count aggregation.
 *
 * @module assessment/registry/AssessorRegistry
 * @see GitHub Issue #91
 */

import type { AssessmentConfiguration } from "@/lib/assessment/configTypes";
import type { MCPDirectoryAssessment } from "@/lib/assessment/resultTypes";
import type { BaseAssessor } from "../modules/BaseAssessor";
import type { AssessmentContext } from "../AssessmentOrchestrator";
import type { ClaudeCodeBridge } from "../lib/claudeCodeBridge";
import { Logger, createLogger, DEFAULT_LOGGING_CONFIG } from "../lib/logger";
import {
  type AssessorDefinition,
  type RegisteredAssessor,
  type AssessorExecutionResult,
  AssessmentPhase,
  supportsClaudeBridge,
} from "./types";
import { ASSESSOR_DEFINITIONS, getOrderedPhases } from "./AssessorDefinitions";
import {
  emitModuleStartedEvent,
  emitModuleProgress,
} from "../orchestratorHelpers";

/**
 * AssessorRegistry manages assessor instances and their execution.
 *
 * Key responsibilities:
 * 1. Lazy instantiation based on configuration flags
 * 2. Phase-ordered execution with Phase 0 always first and sequential
 * 3. Claude bridge wiring to supporting assessors
 * 4. Test count aggregation from all assessors
 * 5. Backward-compatible property access via getAssessor()
 */
/**
 * Information about a failed assessor registration.
 */
export interface FailedRegistration {
  id: string;
  error: string;
}

export class AssessorRegistry {
  private config: AssessmentConfiguration;
  private logger: Logger;
  private assessors: Map<string, RegisteredAssessor> = new Map();
  private claudeBridge?: ClaudeCodeBridge;
  private failedRegistrations: FailedRegistration[] = [];

  constructor(config: AssessmentConfiguration) {
    this.config = config;
    this.logger = createLogger(
      "AssessorRegistry",
      config.logging ?? DEFAULT_LOGGING_CONFIG,
    );
  }

  /**
   * Register all enabled assessors based on configuration.
   * Called during orchestrator initialization.
   */
  registerAll(definitions: AssessorDefinition[] = ASSESSOR_DEFINITIONS): void {
    this.logger.debug(`Registering ${definitions.length} assessor definitions`);

    for (const definition of definitions) {
      if (this.isEnabled(definition)) {
        this.register(definition);
      } else {
        this.logger.debug(`Skipping disabled assessor: ${definition.id}`);
      }
    }

    this.logger.info(`Registered ${this.assessors.size} assessors`);
  }

  /**
   * Register a single assessor.
   */
  private register(definition: AssessorDefinition): void {
    try {
      // Instantiate the assessor
      const instance = new definition.assessorClass(this.config);

      // Run custom setup if defined
      if (definition.customSetup) {
        definition.customSetup(instance, this.config, this.logger);
      }

      // Wire Claude bridge if already set and assessor supports it
      if (this.claudeBridge && definition.supportsClaudeBridge) {
        this.wireClaudeBridge(instance);
      }

      const registered: RegisteredAssessor = {
        definition,
        instance,
        enabled: true,
      };

      this.assessors.set(definition.id, registered);
      this.logger.debug(`Registered assessor: ${definition.id}`);
    } catch (error) {
      this.logger.error(`Failed to register assessor: ${definition.id}`, {
        error,
      });
      // Track failed registrations for summary reporting (P1 fix)
      this.failedRegistrations.push({
        id: definition.id,
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }

  /**
   * Check if an assessor should be enabled based on configuration.
   * Implements OR logic for backward-compatible deprecated flags.
   */
  isEnabled(definition: AssessorDefinition): boolean {
    const categories = this.config.assessmentCategories;

    // Check if extended assessment is required but not enabled
    if (definition.requiresExtended && !this.config.enableExtendedAssessment) {
      return false;
    }

    // Check primary flag
    const primaryEnabled = this.checkFlag(
      categories?.[definition.configFlags.primary],
      definition.configFlags.defaultEnabled ?? false,
    );

    if (primaryEnabled) {
      return true;
    }

    // Check deprecated flags (OR logic for BC)
    if (definition.configFlags.deprecated) {
      for (const deprecatedFlag of definition.configFlags.deprecated) {
        const deprecatedEnabled = categories?.[deprecatedFlag];
        if (deprecatedEnabled === true) {
          this.logger.warn(
            `Using deprecated flag '${String(deprecatedFlag)}' for ${definition.id}. ` +
              `Please use '${String(definition.configFlags.primary)}' instead.`,
          );
          return true;
        }
      }
    }

    return false;
  }

  /**
   * Check a single config flag value.
   * If defaultEnabled is true, returns true unless flag is explicitly false.
   * If defaultEnabled is false, returns true only if flag is explicitly true.
   */
  private checkFlag(
    flagValue: boolean | undefined,
    defaultEnabled: boolean,
  ): boolean {
    if (defaultEnabled) {
      // Default enabled: check !== false
      return flagValue !== false;
    } else {
      // Default disabled: check === true
      return flagValue === true;
    }
  }

  /**
   * Get a registered assessor by ID.
   * Returns undefined if not registered or disabled.
   */
  getAssessor<T extends BaseAssessor = BaseAssessor>(
    id: string,
  ): T | undefined {
    const registered = this.assessors.get(id);
    return registered?.instance as T | undefined;
  }

  /**
   * Get all registered assessors for a specific phase.
   */
  getByPhase(phase: AssessmentPhase): RegisteredAssessor[] {
    return Array.from(this.assessors.values()).filter(
      (r) => r.definition.phase === phase,
    );
  }

  /**
   * Set Claude bridge for all supporting assessors.
   * Called when Claude Code is enabled.
   */
  setClaudeBridge(bridge: ClaudeCodeBridge): void {
    this.claudeBridge = bridge;

    for (const registered of this.assessors.values()) {
      if (registered.definition.supportsClaudeBridge) {
        this.wireClaudeBridge(registered.instance);
      }
    }
  }

  /**
   * Wire Claude bridge to a single assessor.
   */
  private wireClaudeBridge(assessor: BaseAssessor): void {
    if (this.claudeBridge && supportsClaudeBridge(assessor)) {
      assessor.setClaudeBridge(this.claudeBridge);
    }
  }

  /**
   * Execute all assessors in phase order.
   * Phase 0 (PRE) always runs first and sequentially.
   * Other phases run based on parallelTesting config.
   *
   * @returns Partial MCPDirectoryAssessment with results from all assessors
   */
  async executeAll(
    context: AssessmentContext,
  ): Promise<Partial<MCPDirectoryAssessment>> {
    const results: Partial<MCPDirectoryAssessment> = {};

    for (const phase of getOrderedPhases()) {
      const phaseAssessors = this.getByPhase(phase);
      if (phaseAssessors.length === 0) {
        continue;
      }

      // Phase 0 (PRE) always runs sequentially for baseline capture
      // Other phases respect parallelTesting config
      const useParallel =
        phase !== AssessmentPhase.PRE && this.config.parallelTesting === true;

      const phaseResults = await this.executePhase(
        phase,
        phaseAssessors,
        context,
        useParallel,
      );

      // Merge phase results into main results
      for (const result of phaseResults) {
        (results as Record<string, unknown>)[result.resultField] =
          result.result;
      }
    }

    return results;
  }

  /**
   * Execute all assessors in a single phase.
   */
  private async executePhase(
    phase: AssessmentPhase,
    assessors: RegisteredAssessor[],
    context: AssessmentContext,
    parallel: boolean,
  ): Promise<AssessorExecutionResult[]> {
    const phaseName = AssessmentPhase[phase];
    this.logger.debug(
      `Executing phase ${phaseName} with ${assessors.length} assessors (parallel: ${parallel})`,
    );

    const toolCount = this.getToolCountForContext(context);

    if (parallel) {
      return this.executeParallel(assessors, context, toolCount);
    } else {
      return this.executeSequential(assessors, context, toolCount);
    }
  }

  /**
   * Execute assessors in parallel with graceful degradation.
   * Uses Promise.allSettled to continue execution even if some assessors fail.
   */
  private async executeParallel(
    assessors: RegisteredAssessor[],
    context: AssessmentContext,
    toolCount: number,
  ): Promise<AssessorExecutionResult[]> {
    const promises = assessors.map(async (registered) => {
      const { definition, instance } = registered;

      // Emit start event (writes to stderr)
      const estimatedTests = definition.estimateTests(context, this.config);
      emitModuleStartedEvent(definition.displayName, estimatedTests, toolCount);

      // Execute
      const startTime = Date.now();
      const result = await instance.assess(context);
      const executionTime = Date.now() - startTime;

      // Emit progress event (writes to stderr)
      const status = this.extractStatus(result);
      emitModuleProgress(
        definition.displayName,
        status,
        result,
        instance.getTestCount(),
      );

      return {
        id: definition.id,
        resultField: definition.resultField,
        result,
        executionTime,
      };
    });

    // Use Promise.allSettled for graceful degradation (P1 fix)
    const settledResults = await Promise.allSettled(promises);
    const successResults: AssessorExecutionResult[] = [];

    for (let i = 0; i < settledResults.length; i++) {
      const settledResult = settledResults[i];
      if (settledResult.status === "fulfilled") {
        successResults.push(settledResult.value);
      } else {
        const definition = assessors[i].definition;
        this.logger.error(
          `Assessor ${definition.id} failed during parallel execution`,
          {
            error: settledResult.reason,
          },
        );
        // Emit failure progress event
        emitModuleProgress(definition.displayName, "ERROR", null, 0);
      }
    }

    if (successResults.length < assessors.length) {
      this.logger.warn(
        `${assessors.length - successResults.length} assessor(s) failed during parallel execution`,
      );
    }

    return successResults;
  }

  /**
   * Execute assessors sequentially.
   */
  private async executeSequential(
    assessors: RegisteredAssessor[],
    context: AssessmentContext,
    toolCount: number,
  ): Promise<AssessorExecutionResult[]> {
    const results: AssessorExecutionResult[] = [];

    for (const registered of assessors) {
      const { definition, instance } = registered;

      // Emit start event (writes to stderr)
      const estimatedTests = definition.estimateTests(context, this.config);
      emitModuleStartedEvent(definition.displayName, estimatedTests, toolCount);

      // Execute
      const startTime = Date.now();
      try {
        const result = await instance.assess(context);
        const executionTime = Date.now() - startTime;

        // Emit progress event (writes to stderr)
        // Result should have a 'status' property
        const status = this.extractStatus(result);
        emitModuleProgress(
          definition.displayName,
          status,
          result,
          instance.getTestCount(),
        );

        results.push({
          id: definition.id,
          resultField: definition.resultField,
          result,
          executionTime,
        });
      } catch (error) {
        const executionTime = Date.now() - startTime;
        this.logger.error(
          `Assessor ${definition.id} failed during sequential execution`,
          { error, executionTime },
        );
        // Emit failure progress event (consistent with parallel execution)
        emitModuleProgress(definition.displayName, "ERROR", null, 0);
        // Continue with remaining assessors (graceful degradation)
      }
    }

    if (results.length < assessors.length) {
      this.logger.warn(
        `${assessors.length - results.length} assessor(s) failed during sequential execution`,
      );
    }

    return results;
  }

  /**
   * Extract status string from assessment result.
   * Most results have a 'status' property.
   */
  private extractStatus(result: unknown): string {
    if (result && typeof result === "object" && "status" in result) {
      return String((result as { status: unknown }).status);
    }
    return "UNKNOWN";
  }

  /**
   * Get tool count from context (respects selectedToolsForTesting config).
   */
  private getToolCountForContext(context: AssessmentContext): number {
    const tools = context.tools ?? [];
    if (this.config.selectedToolsForTesting !== undefined) {
      const selectedNames = new Set(this.config.selectedToolsForTesting);
      return tools.filter((tool) => selectedNames.has(tool.name)).length;
    }
    return tools.length;
  }

  /**
   * Get total test count from all registered assessors.
   */
  getTotalTestCount(): number {
    let total = 0;
    for (const registered of this.assessors.values()) {
      total += registered.instance.getTestCount();
    }
    return total;
  }

  /**
   * Get test count for a specific assessor.
   */
  getTestCount(id: string): number {
    const registered = this.assessors.get(id);
    return registered?.instance.getTestCount() ?? 0;
  }

  /**
   * Get all registered assessor IDs.
   */
  getRegisteredIds(): string[] {
    return Array.from(this.assessors.keys());
  }

  /**
   * Check if a specific assessor is registered.
   */
  isRegistered(id: string): boolean {
    return this.assessors.has(id);
  }

  /**
   * Get the count of registered assessors.
   */
  get size(): number {
    return this.assessors.size;
  }

  /**
   * Update configuration for future operations.
   *
   * **Important**: This does NOT re-register assessors. Assessors are registered
   * once during construction based on the initial config. To change which
   * assessors are enabled, create a new AssessorRegistry instance.
   *
   * @param config - New configuration to use
   */
  updateConfig(config: AssessmentConfiguration): void {
    this.config = config;
  }

  /**
   * Reset test counts for all registered assessors.
   * Called at the start of each assessment run.
   */
  resetAllTestCounts(): void {
    for (const registered of this.assessors.values()) {
      registered.instance.resetTestCount();
    }
  }

  /**
   * Get list of assessors that failed to register.
   * Useful for reporting partial assessment results.
   *
   * @returns Array of failed registration info (id and error message)
   */
  getFailedRegistrations(): FailedRegistration[] {
    return [...this.failedRegistrations];
  }

  /**
   * Check if any assessors failed to register.
   *
   * @returns true if at least one assessor failed registration
   */
  hasFailedRegistrations(): boolean {
    return this.failedRegistrations.length > 0;
  }
}

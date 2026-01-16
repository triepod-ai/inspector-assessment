/**
 * Registry Types for AssessorRegistry
 *
 * Defines interfaces and enums for the registry pattern implementation.
 * These types enable declarative assessor definitions and phase-based execution.
 *
 * @module assessment/registry/types
 * @see GitHub Issue #91
 */

import type { AssessmentConfiguration } from "@/lib/assessment/configTypes";
import type { MCPDirectoryAssessment } from "@/lib/assessment/resultTypes";
import type { BaseAssessor } from "../modules/BaseAssessor";
import type { AssessmentContext } from "../AssessmentOrchestrator";
import type { Logger } from "../lib/logger";
import type { ClaudeCodeBridge } from "../lib/claudeCodeBridge";

/**
 * Execution phases - determines order of assessment execution.
 * Phase 0 ALWAYS runs first and sequentially to capture clean baselines.
 */
export enum AssessmentPhase {
  /** Temporal assessment - must run first for baseline capture before other tools trigger */
  PRE = 0,
  /** Core assessments: Functionality, Security, Documentation, ErrorHandling, Usability */
  CORE = 1,
  /** Protocol compliance assessment */
  PROTOCOL = 2,
  /** MCP Directory compliance: AUP, Annotations, Libraries, Manifest, Portability, APIs, Auth */
  COMPLIANCE = 3,
  /** Capability assessments: Resources, Prompts, CrossCapability */
  CAPABILITY = 4,
  /** Code quality: FileModularization, Conformance */
  QUALITY = 5,
}

/**
 * Config flags that control whether an assessor is enabled.
 * Supports OR logic for backward-compatible deprecated flags.
 */
export interface AssessorConfigFlags {
  /**
   * Primary flag in assessmentCategories.
   * This is the canonical flag name to use.
   */
  primary: keyof NonNullable<AssessmentConfiguration["assessmentCategories"]>;

  /**
   * Deprecated flags that also enable this assessor (OR logic for BC).
   * If ANY of these flags is true, the assessor is enabled.
   * Used for backward compatibility during deprecation periods.
   */
  deprecated?: Array<
    keyof NonNullable<AssessmentConfiguration["assessmentCategories"]>
  >;

  /**
   * Default enablement behavior:
   * - true (default): Enabled unless explicitly set to false (`!== false`)
   * - false: Disabled unless explicitly set to true (`=== true`)
   *
   * Core assessors (functionality, security, etc.) use defaultEnabled: true
   * Extended assessors use defaultEnabled: false (opt-in)
   */
  defaultEnabled?: boolean;
}

/**
 * Assessor class constructor type.
 * All assessors must accept AssessmentConfiguration in constructor.
 */
export type AssessorConstructor<T extends BaseAssessor = BaseAssessor> = new (
  config: AssessmentConfiguration,
) => T;

/**
 * Custom setup function for assessors that need additional initialization.
 * Called after construction but before Claude bridge wiring.
 *
 * Examples:
 * - ToolAnnotationAssessor needs pattern config loaded and compiled
 * - SecurityAssessor may need custom payload configuration
 */
export type AssessorSetupFn<T extends BaseAssessor = BaseAssessor> = (
  assessor: T,
  config: AssessmentConfiguration,
  logger: Logger,
) => void;

/**
 * Test count estimator function.
 * Returns the estimated number of tests this assessor will run.
 * Used for progress event emission (emitModuleStartedEvent).
 */
export type TestEstimatorFn = (
  context: AssessmentContext,
  config: AssessmentConfiguration,
) => number;

/**
 * Metadata for each assessor definition.
 * Enables declarative configuration instead of imperative code.
 * Single source of truth for all assessor registration.
 */
export interface AssessorDefinition<T extends BaseAssessor = BaseAssessor> {
  /**
   * Unique identifier matching the assessor purpose.
   * Used for registry lookup and property getter names.
   * Convention: camelCase matching the assessmentCategories key.
   * Examples: 'security', 'functionality', 'protocolCompliance'
   */
  id: string;

  /**
   * Human-readable display name for progress events and logging.
   * Used in emitModuleStartedEvent and emitModuleProgress.
   * Examples: 'Security', 'Protocol Compliance', 'AUP Compliance'
   */
  displayName: string;

  /**
   * Assessor class constructor.
   * All assessors extend BaseAssessor<T>.
   */
  assessorClass: AssessorConstructor<T>;

  /**
   * Field name in MCPDirectoryAssessment for storing the result.
   * Must match an optional field on MCPDirectoryAssessment.
   */
  resultField: keyof MCPDirectoryAssessment;

  /**
   * Execution phase (controls ordering).
   * Phase 0 (PRE) always runs first and sequentially.
   */
  phase: AssessmentPhase;

  /**
   * Config flags that enable this assessor.
   * Supports primary flag and deprecated alternatives for BC.
   */
  configFlags: AssessorConfigFlags;

  /**
   * Whether this assessor requires enableExtendedAssessment = true.
   * Core assessors (Phase 1) set this to false.
   * Extended assessors (Phases 2-5) set this to true.
   */
  requiresExtended: boolean;

  /**
   * Whether this assessor supports Claude bridge integration.
   * If true, setClaudeBridge() will be called when bridge is enabled.
   * Currently: SecurityAssessor, AUPComplianceAssessor, ToolAnnotationAssessor
   */
  supportsClaudeBridge: boolean;

  /**
   * Estimate test count from context (for progress events).
   * Called before execution to populate emitModuleStartedEvent.
   */
  estimateTests: TestEstimatorFn;

  /**
   * Optional: Custom setup function for special initialization.
   * Called after construction but before Claude bridge wiring.
   * Examples: Load pattern config for ToolAnnotationAssessor
   */
  customSetup?: AssessorSetupFn<T>;

  /**
   * Context requirements for lightweight single-module execution.
   * Used by --module flag to skip orchestrator and build minimal context.
   * If not specified, DEFAULT_CONTEXT_REQUIREMENTS is used.
   *
   * @see GitHub Issue #184
   */
  contextRequirements?: ModuleContextRequirements;
}

/**
 * Registered assessor instance with metadata.
 * Created by AssessorRegistry.registerAll() for enabled assessors.
 */
export interface RegisteredAssessor<T extends BaseAssessor = BaseAssessor> {
  /** The original definition */
  definition: AssessorDefinition<T>;

  /** Instantiated assessor */
  instance: T;

  /** Whether this assessor is enabled based on config */
  enabled: boolean;
}

/**
 * Result of a single assessor execution.
 * Used internally by AssessorRegistry.executePhase().
 */
export interface AssessorExecutionResult {
  /** Assessor ID for result mapping */
  id: string;

  /** Result field name in MCPDirectoryAssessment */
  resultField: keyof MCPDirectoryAssessment;

  /** The assessment result (type varies by assessor) */
  result: unknown;

  /** Execution time in milliseconds */
  executionTime: number;
}

/**
 * Type guard for assessors that support Claude bridge.
 * Used to safely call setClaudeBridge() method.
 */
export interface ClaudeBridgeCapable {
  setClaudeBridge(bridge: ClaudeCodeBridge): void;
}

/**
 * Check if an assessor supports Claude bridge integration.
 */
export function supportsClaudeBridge(
  assessor: BaseAssessor,
): assessor is BaseAssessor & ClaudeBridgeCapable {
  return (
    typeof (assessor as unknown as ClaudeBridgeCapable).setClaudeBridge ===
    "function"
  );
}

/**
 * Context requirements for lightweight single-module execution.
 * Used by --module flag to build minimal context instead of full orchestration.
 *
 * @see GitHub Issue #184
 */
export interface ModuleContextRequirements {
  /** Whether the module needs tools list from server */
  needsTools: boolean;

  /** Whether the module needs to call tools (requires callTool wrapper) */
  needsCallTool: boolean;

  /** Whether the module needs listTools function (for TemporalAssessor baseline) */
  needsListTools: boolean;

  /** Whether the module needs resources capability */
  needsResources: boolean;

  /** Whether the module needs prompts capability */
  needsPrompts: boolean;

  /** Whether the module needs source code files (optional - enhances analysis) */
  needsSourceCode: boolean;

  /** Whether the module needs manifest.json */
  needsManifest: boolean;

  /** Whether the module needs server info and capabilities */
  needsServerInfo: boolean;
}

/**
 * Default context requirements - used as fallback if not specified.
 * Most modules need tools and callTool but nothing else.
 */
export const DEFAULT_CONTEXT_REQUIREMENTS: ModuleContextRequirements = {
  needsTools: true,
  needsCallTool: true,
  needsListTools: false,
  needsResources: false,
  needsPrompts: false,
  needsSourceCode: false,
  needsManifest: false,
  needsServerInfo: false,
};

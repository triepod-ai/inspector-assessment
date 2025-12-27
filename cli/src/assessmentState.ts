/**
 * Assessment State Manager
 * File-based state management for resumable assessments.
 *
 * Purpose:
 * - Allow long-running assessments to be paused and resumed
 * - Checkpoint after each module completes
 * - Recover from interruptions
 */

import * as fs from "fs";
import type {
  AssessmentConfiguration,
  MCPDirectoryAssessment,
} from "../../client/lib/lib/assessmentTypes.js";

/**
 * Assessment state structure persisted to disk
 */
export interface AssessmentState {
  sessionId: string;
  serverName: string;
  startedAt: string;
  lastUpdatedAt: string;
  config: AssessmentConfiguration;
  completedModules: string[];
  currentModule: string | null;
  partialResults: Partial<MCPDirectoryAssessment>;
  toolsDiscovered: number;
  version: string; // For state format versioning
}

const STATE_VERSION = "1.0";

/**
 * Manages assessment state persistence for resumable runs
 */
export class AssessmentStateManager {
  private statePath: string;

  constructor(serverName: string, stateDir: string = "/tmp") {
    this.statePath = `${stateDir}/inspector-assessment-state-${serverName}.json`;
  }

  /**
   * Check if a previous state exists
   */
  exists(): boolean {
    return fs.existsSync(this.statePath);
  }

  /**
   * Load state from disk
   */
  load(): AssessmentState | null {
    if (!this.exists()) return null;

    try {
      const data = fs.readFileSync(this.statePath, "utf-8");
      const state = JSON.parse(data) as AssessmentState;

      // Validate state version
      if (state.version !== STATE_VERSION) {
        console.warn(
          `[StateManager] State version mismatch: ${state.version} vs ${STATE_VERSION}, clearing`,
        );
        this.clear();
        return null;
      }

      return state;
    } catch (error) {
      console.warn("[StateManager] Failed to load state:", error);
      return null;
    }
  }

  /**
   * Create a new state for a fresh assessment
   */
  create(
    serverName: string,
    config: AssessmentConfiguration,
    toolsDiscovered: number,
  ): AssessmentState {
    const state: AssessmentState = {
      sessionId: this.generateSessionId(),
      serverName,
      startedAt: new Date().toISOString(),
      lastUpdatedAt: new Date().toISOString(),
      config,
      completedModules: [],
      currentModule: null,
      partialResults: {
        serverName,
        assessmentDate: new Date().toISOString(),
        assessorVersion: "1.13.1", // Will be updated from package.json
      },
      toolsDiscovered,
      version: STATE_VERSION,
    };

    this.save(state);
    return state;
  }

  /**
   * Save state to disk
   */
  save(state: AssessmentState): void {
    state.lastUpdatedAt = new Date().toISOString();
    fs.writeFileSync(this.statePath, JSON.stringify(state, null, 2));
  }

  /**
   * Mark a module as starting
   */
  startModule(moduleName: string): void {
    const state = this.load();
    if (state) {
      state.currentModule = moduleName;
      this.save(state);
    }
  }

  /**
   * Mark a module as complete and save its result
   */
  completeModule(moduleName: string, result: unknown): void {
    const state = this.load();
    if (state) {
      state.completedModules.push(moduleName);
      state.currentModule = null;

      // Store the result in partialResults
      (state.partialResults as Record<string, unknown>)[moduleName] = result;

      this.save(state);
    }
  }

  /**
   * Get list of completed modules
   */
  getCompletedModules(): string[] {
    const state = this.load();
    return state?.completedModules || [];
  }

  /**
   * Check if a module was already completed
   */
  isModuleCompleted(moduleName: string): boolean {
    const state = this.load();
    return state?.completedModules.includes(moduleName) || false;
  }

  /**
   * Get partial results from previous run
   */
  getPartialResults(): Partial<MCPDirectoryAssessment> | null {
    const state = this.load();
    return state?.partialResults || null;
  }

  /**
   * Clear state (delete state file)
   */
  clear(): void {
    if (this.exists()) {
      try {
        fs.unlinkSync(this.statePath);
      } catch {
        // Ignore errors on cleanup
      }
    }
  }

  /**
   * Get state file path
   */
  getStatePath(): string {
    return this.statePath;
  }

  /**
   * Get state summary for display
   */
  getSummary(): {
    sessionId: string;
    startedAt: string;
    completedModules: string[];
    currentModule: string | null;
    toolsDiscovered: number;
  } | null {
    const state = this.load();
    if (!state) return null;

    return {
      sessionId: state.sessionId,
      startedAt: state.startedAt,
      completedModules: state.completedModules,
      currentModule: state.currentModule,
      toolsDiscovered: state.toolsDiscovered,
    };
  }

  /**
   * Generate unique session ID
   */
  private generateSessionId(): string {
    return `assess-${Date.now()}-${Math.random().toString(36).substring(2, 8)}`;
  }
}

/**
 * Factory function to create state manager
 */
export function createStateManager(
  serverName: string,
  stateDir?: string,
): AssessmentStateManager {
  return new AssessmentStateManager(serverName, stateDir);
}

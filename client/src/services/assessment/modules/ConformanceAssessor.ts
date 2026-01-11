/**
 * Conformance Assessor Module
 *
 * Integrates official MCP conformance tests from @modelcontextprotocol/conformance.
 * Runs server-side conformance validation against the MCP specification.
 *
 * Requirements:
 * - HTTP/SSE transport (requires serverUrl in config)
 * - Opt-in via --conformance flag or assessmentCategories.conformance = true
 *
 * @module assessment/modules/ConformanceAssessor
 */

import { execFileSync } from "child_process";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";

import { BaseAssessor } from "./BaseAssessor";
import { AssessmentContext } from "../AssessmentOrchestrator";
import type {
  ConformanceAssessment,
  ConformanceScenario,
  ConformanceCheck,
} from "@/lib/assessment/extendedTypes";
import type { AssessmentStatus } from "@/lib/assessment/coreTypes";

/**
 * Version of the conformance package we're integrating with
 */
const CONFORMANCE_PACKAGE_VERSION = "0.1.9";

/**
 * Available server scenarios from the conformance package
 * Updated for @modelcontextprotocol/conformance v0.1.9+
 */
const SERVER_SCENARIOS = [
  "server-initialize",
  "tools-list",
  "tools-call-simple-text",
  "resources-list",
  "resources-read-text",
  "prompts-list",
  "prompts-get-simple",
] as const;

/**
 * Result structure from conformance CLI checks.json
 */
interface ConformanceCheckResult {
  name: string;
  status: "pass" | "fail";
  message?: string;
  timestamp?: string;
}

/**
 * Conformance Assessor
 *
 * Runs official MCP conformance tests against the server.
 * Requires HTTP/SSE transport with serverUrl available.
 */
export class ConformanceAssessor extends BaseAssessor<ConformanceAssessment> {
  /**
   * Run conformance assessment
   */
  async assess(context: AssessmentContext): Promise<ConformanceAssessment> {
    const serverUrl = context.config.serverUrl;

    // Check if serverUrl is available (required for conformance tests)
    if (!serverUrl) {
      this.logger.info(
        "Conformance tests skipped: serverUrl not available (requires HTTP/SSE transport)",
      );
      return this.createSkippedResult(
        "Server URL not available. Conformance tests require HTTP or SSE transport.",
      );
    }

    // Check if conformance package is available
    if (!this.isConformancePackageAvailable()) {
      this.logger.warn(
        "MCP conformance package not available. Install with: npm install -g @modelcontextprotocol/conformance",
      );
      return this.createSkippedResult(
        "MCP conformance package not installed. Run: npm install -g @modelcontextprotocol/conformance",
      );
    }

    this.logger.info(`Running conformance tests against: ${serverUrl}`);

    const scenarios: ConformanceScenario[] = [];
    const allChecks: ConformanceCheck[] = [];
    let passedScenarios = 0;
    let totalScenarios = 0;

    // Run each server scenario
    for (const scenario of SERVER_SCENARIOS) {
      totalScenarios++;
      try {
        const scenarioResult = await this.runScenario(serverUrl, scenario);
        scenarios.push(scenarioResult);

        // Count scenario pass/fail (not individual checks)
        if (scenarioResult.status === "pass") {
          passedScenarios++;
        }

        // Aggregate any detailed checks for reporting
        for (const check of scenarioResult.checks) {
          allChecks.push(check);
        }

        this.testCount++;
      } catch (error) {
        // Log error but continue with other scenarios
        this.logger.warn(
          `Scenario ${scenario} failed: ${error instanceof Error ? error.message : String(error)}`,
        );

        scenarios.push({
          name: scenario,
          status: "skip",
          checks: [],
        });
      }
    }

    // Calculate compliance score based on scenarios
    const complianceScore =
      totalScenarios > 0
        ? Math.round((passedScenarios / totalScenarios) * 100)
        : 0;

    // Determine overall status
    const status = this.determineConformanceStatus(
      passedScenarios,
      totalScenarios,
      scenarios,
    );

    // Generate explanation and recommendations
    const explanation = this.generateExplanation(
      status,
      passedScenarios,
      totalScenarios,
      scenarios,
    );
    const recommendations = this.generateRecommendations(scenarios, allChecks);

    return {
      status,
      conformanceVersion: CONFORMANCE_PACKAGE_VERSION,
      protocolVersion: context.config.mcpProtocolVersion || "2025-06",
      scenarios,
      officialChecks: allChecks,
      passedChecks: passedScenarios,
      totalChecks: totalScenarios,
      complianceScore,
      explanation,
      recommendations,
    };
  }

  /**
   * Run a single conformance scenario
   */
  private async runScenario(
    serverUrl: string,
    scenario: string,
  ): Promise<ConformanceScenario> {
    const startTime = Date.now();

    try {
      // Create temp directory for results
      const resultsDir = fs.mkdtempSync(
        path.join(os.tmpdir(), "mcp-conformance-"),
      );

      // Run conformance CLI (results are written to checks.json, not stdout)
      execFileSync(
        "npx",
        [
          "@modelcontextprotocol/conformance",
          "server",
          "--url",
          serverUrl,
          "--scenario",
          scenario,
        ],
        {
          encoding: "utf-8",
          timeout: 60000, // 60 second timeout per scenario
          cwd: resultsDir,
          stdio: ["pipe", "pipe", "pipe"],
        },
      );

      // Parse results from checks.json
      const checksPath = this.findChecksFile(resultsDir, scenario);
      const checks = checksPath ? this.parseChecksFile(checksPath) : [];

      // Determine scenario status
      const hasFailures = checks.some((c) => c.status === "fail");
      const status: "pass" | "fail" | "skip" = hasFailures ? "fail" : "pass";

      // Cleanup temp directory
      this.cleanupTempDir(resultsDir);

      return {
        name: scenario,
        status,
        checks,
        executionTime: Date.now() - startTime,
      };
    } catch (error) {
      this.logger.debug(
        `Scenario ${scenario} execution error: ${error instanceof Error ? error.message : String(error)}`,
      );

      // Return skip status for failed scenarios
      return {
        name: scenario,
        status: "skip",
        checks: [
          {
            name: `${scenario}-execution`,
            status: "fail",
            message:
              error instanceof Error
                ? error.message
                : "Scenario execution failed",
          },
        ],
        executionTime: Date.now() - startTime,
      };
    }
  }

  /**
   * Find the checks.json file in the results directory
   */
  private findChecksFile(
    resultsDir: string,
    scenario: string,
  ): string | undefined {
    // Look for results in timestamped subdirectory
    try {
      const entries = fs.readdirSync(resultsDir);
      for (const entry of entries) {
        if (
          entry.startsWith(`server-${scenario}`) ||
          entry.startsWith(scenario)
        ) {
          const checksPath = path.join(resultsDir, entry, "checks.json");
          if (fs.existsSync(checksPath)) {
            return checksPath;
          }
        }
      }
    } catch {
      // Directory might not exist
    }
    return undefined;
  }

  /**
   * Parse checks.json file from conformance results
   */
  private parseChecksFile(checksPath: string): ConformanceCheck[] {
    try {
      const content = fs.readFileSync(checksPath, "utf-8");
      const results: ConformanceCheckResult[] = JSON.parse(content);

      return results.map((r) => ({
        name: r.name,
        status: r.status === "pass" ? "pass" : "fail",
        message: r.message || "",
        timestamp: r.timestamp,
      }));
    } catch (error) {
      this.logger.debug(
        `Failed to parse checks.json: ${error instanceof Error ? error.message : String(error)}`,
      );
      return [];
    }
  }

  /**
   * Check if the MCP conformance package is available
   */
  private isConformancePackageAvailable(): boolean {
    try {
      execFileSync("npx", ["@modelcontextprotocol/conformance", "--version"], {
        timeout: 30000,
        stdio: "pipe",
        encoding: "utf-8",
      });
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Cleanup temporary directory
   */
  private cleanupTempDir(dirPath: string): void {
    try {
      fs.rmSync(dirPath, { recursive: true, force: true });
    } catch {
      // Ignore cleanup errors
    }
  }

  /**
   * Determine overall conformance status
   */
  private determineConformanceStatus(
    passed: number,
    total: number,
    scenarios: ConformanceScenario[],
  ): AssessmentStatus {
    // If no checks ran, need more info
    if (total === 0) {
      return "NEED_MORE_INFO";
    }

    // Check if any critical scenarios failed
    const criticalScenarios = ["server-initialize", "tools-list"];
    const criticalFailures = scenarios.filter(
      (s) => criticalScenarios.includes(s.name) && s.status === "fail",
    );

    if (criticalFailures.length > 0) {
      return "FAIL";
    }

    // Use pass rate for status
    const passRate = passed / total;
    if (passRate >= 0.9) {
      return "PASS";
    }
    if (passRate >= 0.7) {
      return "NEED_MORE_INFO";
    }
    return "FAIL";
  }

  /**
   * Generate human-readable explanation
   */
  private generateExplanation(
    status: AssessmentStatus,
    passed: number,
    total: number,
    scenarios: ConformanceScenario[],
  ): string {
    const passRate = total > 0 ? Math.round((passed / total) * 100) : 0;

    if (status === "PASS") {
      return `Server passes ${passRate}% of official MCP conformance checks (${passed}/${total}). The implementation correctly follows the MCP protocol specification.`;
    }

    if (status === "NEED_MORE_INFO") {
      const skipped = scenarios.filter((s) => s.status === "skip").length;
      if (skipped > 0) {
        return `Conformance testing partially completed. ${skipped} scenario(s) were skipped. ${passed}/${total} checks passed (${passRate}%).`;
      }
      return `Server passes ${passRate}% of conformance checks (${passed}/${total}). Some non-critical checks failed; review recommended.`;
    }

    // FAIL
    const failures = scenarios.filter((s) => s.status === "fail");
    return `Server fails conformance testing. ${failures.length} scenario(s) failed. Only ${passRate}% of checks passed (${passed}/${total}).`;
  }

  /**
   * Generate recommendations based on failures
   */
  private generateRecommendations(
    scenarios: ConformanceScenario[],
    checks: ConformanceCheck[],
  ): string[] {
    const recommendations: string[] = [];

    // Check for initialization failures
    const initScenario = scenarios.find((s) => s.name === "server-initialize");
    if (initScenario?.status === "fail") {
      recommendations.push(
        "Fix initialization handshake issues - ensure server responds correctly to initialize request with valid serverInfo and capabilities.",
      );
    }

    // Check for tools-list failures
    const toolsListScenario = scenarios.find((s) => s.name === "tools-list");
    if (toolsListScenario?.status === "fail") {
      recommendations.push(
        "Review tools/list implementation - ensure all tools have valid names, descriptions, and input schemas.",
      );
    }

    // Check for skipped scenarios
    const skipped = scenarios.filter((s) => s.status === "skip");
    if (skipped.length > 0) {
      recommendations.push(
        `Run conformance tests again to complete ${skipped.length} skipped scenario(s): ${skipped.map((s) => s.name).join(", ")}.`,
      );
    }

    // Generic recommendations based on check failures
    const failedChecks = checks.filter((c) => c.status === "fail");
    if (failedChecks.length > 0 && recommendations.length < 3) {
      recommendations.push(
        "Review MCP specification at modelcontextprotocol.io for protocol compliance requirements.",
      );
    }

    if (recommendations.length === 0) {
      recommendations.push(
        "Consider running full conformance suite periodically to catch regressions.",
      );
    }

    return recommendations;
  }

  /**
   * Create a skipped result when conformance tests cannot run
   */
  private createSkippedResult(reason: string): ConformanceAssessment {
    return {
      status: "NEED_MORE_INFO",
      conformanceVersion: CONFORMANCE_PACKAGE_VERSION,
      protocolVersion: this.config.mcpProtocolVersion || "2025-06",
      scenarios: [],
      officialChecks: [],
      passedChecks: 0,
      totalChecks: 0,
      complianceScore: 0,
      explanation: `Conformance testing skipped: ${reason}`,
      recommendations: [
        "Use HTTP or SSE transport to enable conformance testing.",
        "Configure serverUrl in assessment configuration for STDIO servers.",
      ],
      skipped: true,
      skipReason: reason,
    };
  }
}

/**
 * Dynamic Security Assessor Module
 * Evaluates runtime behavior, input fuzzing, and dynamic security threats
 */

import { BaseAssessor } from "./BaseAssessor";
import { AssessmentContext } from "../AssessmentOrchestrator";
import { AssessmentStatus } from "@/lib/assessmentTypes";

export interface DynamicSecurityAssessment {
  category: "dynamicSecurity";
  status: AssessmentStatus;
  score: number;
  runtimeBehavior: {
    anomalies: string[];
    suspiciousPatterns: string[];
    resourceUsage: {
      cpu: "normal" | "high" | "excessive";
      memory: "normal" | "high" | "excessive";
      network: "normal" | "high" | "excessive";
    };
  };
  fuzzingResults: {
    totalTests: number;
    crashes: number;
    hangs: number;
    unexpectedBehaviors: string[];
  };
  sandboxEscape: {
    attempted: boolean;
    successful: boolean;
    techniques: string[];
  };
  memoryLeaks: {
    detected: boolean;
    severity: "low" | "medium" | "high" | "none";
    locations: string[];
  };
  anomalyScore: number;
  criticalFindings: string[];
  recommendations: string[];
  explanation: string;
}

interface FuzzTestCase {
  name: string;
  input: any;
  expectedBehavior: string;
  category: "boundary" | "malformed" | "overflow" | "injection" | "random";
}

export class DynamicSecurityAssessor extends BaseAssessor {
  async assess(context: AssessmentContext): Promise<DynamicSecurityAssessment> {
    this.log("Starting dynamic security assessment");

    const runtimeBehavior = await this.monitorRuntimeBehavior(context);
    const fuzzingResults = await this.performFuzzTesting(context);
    const sandboxEscape = await this.detectSandboxEscape(context);
    const memoryLeaks = await this.detectMemoryLeaks(context);
    const anomalyScore = this.calculateAnomalyScore(
      runtimeBehavior,
      fuzzingResults,
      sandboxEscape,
      memoryLeaks,
    );

    const score = this.calculateDynamicSecurityScore(
      runtimeBehavior,
      fuzzingResults,
      sandboxEscape,
      memoryLeaks,
      anomalyScore,
    );

    const status = this.determineStatus(score, 100, 70);

    const criticalFindings = this.identifyCriticalFindings(
      runtimeBehavior,
      fuzzingResults,
      sandboxEscape,
      memoryLeaks,
    );

    const recommendations = this.generateRecommendations(
      runtimeBehavior,
      fuzzingResults,
      sandboxEscape,
      memoryLeaks,
    );

    const explanation = this.generateExplanation(
      runtimeBehavior,
      fuzzingResults,
      sandboxEscape,
      memoryLeaks,
      anomalyScore,
    );

    return {
      category: "dynamicSecurity",
      status,
      score,
      runtimeBehavior,
      fuzzingResults,
      sandboxEscape,
      memoryLeaks,
      anomalyScore,
      criticalFindings,
      recommendations,
      explanation,
    };
  }

  private async monitorRuntimeBehavior(context: AssessmentContext): Promise<{
    anomalies: string[];
    suspiciousPatterns: string[];
    resourceUsage: {
      cpu: "normal" | "high" | "excessive";
      memory: "normal" | "high" | "excessive";
      network: "normal" | "high" | "excessive";
    };
  }> {
    this.log("Monitoring runtime behavior");

    const anomalies: string[] = [];
    const suspiciousPatterns: string[] = [];
    const resourceUsage = {
      cpu: "normal" as "normal" | "high" | "excessive",
      memory: "normal" as "normal" | "high" | "excessive",
      network: "normal" as "normal" | "high" | "excessive",
    };

    // Test various runtime behaviors
    for (const tool of context.tools) {
      try {
        // Check for suspicious patterns in tool behavior
        if (
          tool.description?.includes("exec") ||
          tool.description?.includes("system")
        ) {
          suspiciousPatterns.push(
            `${tool.name} has system execution capabilities`,
          );
        }

        if (
          tool.description?.includes("eval") ||
          tool.description?.includes("Function")
        ) {
          suspiciousPatterns.push(
            `${tool.name} has code evaluation capabilities`,
          );
        }

        if (
          tool.description?.includes("file") ||
          tool.description?.includes("write")
        ) {
          suspiciousPatterns.push(`${tool.name} has file system access`);
        }

        // Simulate resource monitoring
        const startTime = Date.now();
        const memBefore = process.memoryUsage().heapUsed;

        // Execute a simple test
        if (tool.inputSchema?.properties) {
          await this.executeToolWithTimeout(context, tool.name, {}, 1000);
        }

        const executionTime = Date.now() - startTime;
        const memAfter = process.memoryUsage().heapUsed;
        const memoryIncrease = memAfter - memBefore;

        // Check for anomalies
        if (executionTime > 5000) {
          anomalies.push(
            `${tool.name} took unusually long to execute (${executionTime}ms)`,
          );
          resourceUsage.cpu = "high";
        }

        if (memoryIncrease > 50 * 1024 * 1024) {
          // 50MB
          anomalies.push(
            `${tool.name} consumed excessive memory (${Math.round(memoryIncrease / 1024 / 1024)}MB)`,
          );
          resourceUsage.memory = "high";
        }
      } catch (error) {
        // Silent catch for monitoring
      }
    }

    return { anomalies, suspiciousPatterns, resourceUsage };
  }

  private async performFuzzTesting(context: AssessmentContext): Promise<{
    totalTests: number;
    crashes: number;
    hangs: number;
    unexpectedBehaviors: string[];
  }> {
    this.log("Performing fuzz testing");

    let totalTests = 0;
    let crashes = 0;
    let hangs = 0;
    const unexpectedBehaviors: string[] = [];

    const fuzzTestCases = this.generateFuzzTestCases();

    for (const tool of context.tools) {
      // Skip tools without input parameters
      if (!tool.inputSchema?.properties) continue;

      for (const testCase of fuzzTestCases) {
        totalTests++;

        try {
          const result = await this.executeToolWithTimeout(
            context,
            tool.name,
            this.generateFuzzInput(testCase, tool),
            3000,
          );

          // Check for unexpected behaviors
          if (result === "timeout") {
            hangs++;
            unexpectedBehaviors.push(`${tool.name} hung on ${testCase.name}`);
          } else if (result === "crash") {
            crashes++;
            unexpectedBehaviors.push(
              `${tool.name} crashed on ${testCase.name}`,
            );
          }
        } catch (error) {
          // Check error type
          if (error instanceof Error) {
            if (error.message.includes("Maximum call stack")) {
              crashes++;
              unexpectedBehaviors.push(
                `${tool.name} stack overflow on ${testCase.name}`,
              );
            } else if (error.message.includes("out of memory")) {
              crashes++;
              unexpectedBehaviors.push(
                `${tool.name} memory exhaustion on ${testCase.name}`,
              );
            }
          }
        }

        // Rate limiting
        if (totalTests % 10 === 0) {
          await this.sleep(100);
        }
      }
    }

    return { totalTests, crashes, hangs, unexpectedBehaviors };
  }

  private async detectSandboxEscape(context: AssessmentContext): Promise<{
    attempted: boolean;
    successful: boolean;
    techniques: string[];
  }> {
    this.log("Detecting sandbox escape attempts");

    let attempted = false;
    let successful = false;
    const techniques: string[] = [];

    // Test for various sandbox escape techniques
    const escapePatterns = [
      { pattern: "process.binding", technique: "Process binding access" },
      {
        pattern: "require('child_process')",
        technique: "Child process spawning",
      },
      { pattern: "__proto__", technique: "Prototype pollution" },
      {
        pattern: "constructor.constructor",
        technique: "Function constructor access",
      },
      { pattern: "process.mainModule", technique: "Main module access" },
      { pattern: "process.env", technique: "Environment variable access" },
    ];

    for (const tool of context.tools) {
      if (!tool.inputSchema?.properties) continue;

      for (const escape of escapePatterns) {
        try {
          const testInput = this.createEscapeTestInput(escape.pattern);
          const result = await this.executeToolWithTimeout(
            context,
            tool.name,
            testInput,
            1000,
          );

          if (result && typeof result === "object") {
            attempted = true;
            // Check if escape was successful (simplified check)
            if (
              JSON.stringify(result).includes("process") ||
              JSON.stringify(result).includes("require")
            ) {
              successful = true;
              techniques.push(escape.technique);
            }
          }
        } catch (error) {
          // Silent catch for detection
        }
      }
    }

    return { attempted, successful, techniques };
  }

  private async detectMemoryLeaks(context: AssessmentContext): Promise<{
    detected: boolean;
    severity: "low" | "medium" | "high" | "none";
    locations: string[];
  }> {
    this.log("Detecting memory leaks");

    let detected = false;
    let severity: "low" | "medium" | "high" | "none" = "none";
    const locations: string[] = [];

    for (const tool of context.tools) {
      if (!tool.inputSchema?.properties) continue;

      try {
        // Baseline memory
        global.gc?.(); // Force GC if available
        const baseline = process.memoryUsage().heapUsed;

        // Execute tool multiple times
        for (let i = 0; i < 10; i++) {
          await this.executeToolWithTimeout(context, tool.name, {}, 1000);
        }

        // Check memory after executions
        global.gc?.(); // Force GC if available
        const after = process.memoryUsage().heapUsed;
        const increase = after - baseline;

        // Detect leaks based on memory increase
        if (increase > 10 * 1024 * 1024) {
          // 10MB
          detected = true;
          locations.push(tool.name);

          if (increase > 50 * 1024 * 1024) {
            // 50MB
            severity = "high";
          } else if (increase > 20 * 1024 * 1024) {
            // 20MB
            severity = "medium";
          } else {
            severity = "low";
          }
        }
      } catch (error) {
        // Silent catch for leak detection
      }
    }

    return { detected, severity, locations };
  }

  private generateFuzzTestCases(): FuzzTestCase[] {
    return [
      // Boundary testing
      {
        name: "Empty input",
        input: "",
        expectedBehavior: "Handle gracefully",
        category: "boundary",
      },
      {
        name: "Null input",
        input: null,
        expectedBehavior: "Handle gracefully",
        category: "boundary",
      },
      {
        name: "Undefined input",
        input: undefined,
        expectedBehavior: "Handle gracefully",
        category: "boundary",
      },
      {
        name: "Very large string",
        input: "A".repeat(1000000),
        expectedBehavior: "Handle or reject gracefully",
        category: "overflow",
      },
      {
        name: "Deep nested object",
        input: this.createDeepObject(100),
        expectedBehavior: "Handle or reject gracefully",
        category: "overflow",
      },
      // Malformed inputs
      {
        name: "Invalid JSON characters",
        input: '{"key": "\u0000\u0001\u0002"}',
        expectedBehavior: "Sanitize or reject",
        category: "malformed",
      },
      {
        name: "Mixed types",
        input: { string: "text", number: 123, bool: true, array: [1, 2, 3] },
        expectedBehavior: "Handle mixed types",
        category: "malformed",
      },
      // Injection attempts
      {
        name: "Script injection",
        input: "<script>alert('xss')</script>",
        expectedBehavior: "Sanitize or escape",
        category: "injection",
      },
      {
        name: "SQL injection",
        input: "'; DROP TABLE users; --",
        expectedBehavior: "Sanitize or escape",
        category: "injection",
      },
      // Random fuzzing
      {
        name: "Random bytes",
        input: Buffer.from(
          Array(100)
            .fill(0)
            .map(() => Math.floor(Math.random() * 256)),
        ),
        expectedBehavior: "Handle binary data",
        category: "random",
      },
    ];
  }

  private generateFuzzInput(testCase: FuzzTestCase, tool: any): any {
    // Generate input based on tool schema
    const input: any = {};

    if (tool.inputSchema?.properties) {
      for (const [key, schema] of Object.entries(tool.inputSchema.properties)) {
        // Use fuzz test input for first parameter
        if (Object.keys(input).length === 0) {
          input[key] = testCase.input;
        } else {
          // Use default values for other parameters
          input[key] = this.getDefaultValue(schema as any);
        }
      }
    }

    return input;
  }

  private createDeepObject(depth: number): any {
    if (depth <= 0) return "leaf";
    return { nested: this.createDeepObject(depth - 1) };
  }

  private createEscapeTestInput(pattern: string): any {
    return {
      test: pattern,
      payload: `{{${pattern}}}`,
      attempt: true,
    };
  }

  private getDefaultValue(schema: any): any {
    switch (schema.type) {
      case "string":
        return "";
      case "number":
        return 0;
      case "boolean":
        return false;
      case "array":
        return [];
      case "object":
        return {};
      default:
        return null;
    }
  }

  private async executeToolWithTimeout(
    context: AssessmentContext,
    toolName: string,
    input: any,
    timeout: number,
  ): Promise<any> {
    return Promise.race([
      context.callTool(toolName, input),
      new Promise((_, reject) =>
        setTimeout(() => reject(new Error("timeout")), timeout),
      ),
    ]).catch((error) => {
      if (error.message === "timeout") return "timeout";
      if (error.message.includes("crash")) return "crash";
      throw error;
    });
  }

  private calculateAnomalyScore(
    runtimeBehavior: any,
    fuzzingResults: any,
    sandboxEscape: any,
    memoryLeaks: any,
  ): number {
    let score = 0;

    // Runtime anomalies (0-30)
    score += Math.min(runtimeBehavior.anomalies.length * 5, 30);

    // Suspicious patterns (0-20)
    score += Math.min(runtimeBehavior.suspiciousPatterns.length * 4, 20);

    // Fuzzing issues (0-20)
    const fuzzIssueRate =
      (fuzzingResults.crashes + fuzzingResults.hangs) /
      Math.max(fuzzingResults.totalTests, 1);
    score += fuzzIssueRate * 20;

    // Sandbox escape (0-20)
    if (sandboxEscape.attempted) score += 10;
    if (sandboxEscape.successful) score += 10;

    // Memory leaks (0-10)
    if (memoryLeaks.detected) {
      switch (memoryLeaks.severity) {
        case "low":
          score += 3;
          break;
        case "medium":
          score += 6;
          break;
        case "high":
          score += 10;
          break;
      }
    }

    return Math.min(100, Math.round(score));
  }

  private calculateDynamicSecurityScore(
    runtimeBehavior: any,
    fuzzingResults: any,
    sandboxEscape: any,
    memoryLeaks: any,
    anomalyScore: number,
  ): number {
    let score = 100;

    // Deduct for runtime anomalies (max -20)
    score -= Math.min(runtimeBehavior.anomalies.length * 4, 20);

    // Deduct for suspicious patterns (max -15)
    score -= Math.min(runtimeBehavior.suspiciousPatterns.length * 3, 15);

    // Deduct for fuzzing failures (max -20)
    if (fuzzingResults.totalTests > 0) {
      const failureRate =
        (fuzzingResults.crashes + fuzzingResults.hangs) /
        fuzzingResults.totalTests;
      score -= failureRate * 20;
    }

    // Deduct for sandbox escape (max -25)
    if (sandboxEscape.attempted) score -= 10;
    if (sandboxEscape.successful) score -= 15;

    // Deduct for memory leaks (max -10)
    if (memoryLeaks.detected) {
      switch (memoryLeaks.severity) {
        case "low":
          score -= 3;
          break;
        case "medium":
          score -= 6;
          break;
        case "high":
          score -= 10;
          break;
      }
    }

    // Factor in anomaly score (max -10)
    score -= (anomalyScore / 100) * 10;

    return Math.max(0, Math.round(score));
  }

  private identifyCriticalFindings(
    runtimeBehavior: any,
    fuzzingResults: any,
    sandboxEscape: any,
    memoryLeaks: any,
  ): string[] {
    const findings: string[] = [];

    if (sandboxEscape.successful) {
      findings.push("CRITICAL: Successful sandbox escape detected");
    }

    if (fuzzingResults.crashes > 0) {
      findings.push(
        `Found ${fuzzingResults.crashes} crash conditions through fuzzing`,
      );
    }

    if (memoryLeaks.severity === "high") {
      findings.push("Severe memory leaks detected");
    }

    if (
      runtimeBehavior.resourceUsage.cpu === "excessive" ||
      runtimeBehavior.resourceUsage.memory === "excessive"
    ) {
      findings.push("Excessive resource consumption detected");
    }

    return findings;
  }

  private generateRecommendations(
    runtimeBehavior: any,
    fuzzingResults: any,
    sandboxEscape: any,
    memoryLeaks: any,
  ): string[] {
    const recommendations: string[] = [];

    if (sandboxEscape.attempted || sandboxEscape.successful) {
      recommendations.push(
        "Strengthen sandbox isolation and security boundaries",
      );
      recommendations.push(
        "Implement stricter input validation and sanitization",
      );
    }

    if (fuzzingResults.crashes > 0 || fuzzingResults.hangs > 0) {
      recommendations.push("Improve error handling and input validation");
      recommendations.push(
        "Add timeout mechanisms for long-running operations",
      );
    }

    if (memoryLeaks.detected) {
      recommendations.push(
        "Implement proper resource cleanup and garbage collection",
      );
      recommendations.push("Add memory monitoring and limits");
    }

    if (runtimeBehavior.suspiciousPatterns.length > 0) {
      recommendations.push("Review and restrict dangerous capabilities");
      recommendations.push("Implement principle of least privilege");
    }

    recommendations.push("Implement continuous runtime monitoring");
    recommendations.push("Add automated security testing to CI/CD pipeline");

    return recommendations;
  }

  private generateExplanation(
    runtimeBehavior: any,
    fuzzingResults: any,
    sandboxEscape: any,
    memoryLeaks: any,
    anomalyScore: number,
  ): string {
    const parts: string[] = [];

    parts.push(
      `Dynamic security assessment completed with anomaly score of ${anomalyScore}/100.`,
    );

    if (runtimeBehavior.anomalies.length > 0) {
      parts.push(
        `Detected ${runtimeBehavior.anomalies.length} runtime anomalies.`,
      );
    }

    if (fuzzingResults.totalTests > 0) {
      const issues = fuzzingResults.crashes + fuzzingResults.hangs;
      parts.push(
        `Fuzzing revealed ${issues} issues in ${fuzzingResults.totalTests} tests.`,
      );
    }

    if (sandboxEscape.attempted) {
      parts.push(
        `Sandbox escape ${sandboxEscape.successful ? "SUCCEEDED" : "attempted but failed"}.`,
      );
    }

    if (memoryLeaks.detected) {
      parts.push(
        `Memory leaks detected with ${memoryLeaks.severity} severity.`,
      );
    }

    return parts.join(" ");
  }
}

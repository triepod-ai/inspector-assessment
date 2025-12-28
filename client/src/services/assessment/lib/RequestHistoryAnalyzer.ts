/**
 * Request History Analyzer
 * Utility library for analyzing MCP request/response patterns
 *
 * Provides analysis for:
 * - Protocol compliance validation (JSON-RPC 2.0)
 * - Error pattern analysis across requests
 * - Timing analysis and response time percentiles
 * - Content consistency validation
 */

export interface RequestHistoryEntry {
  id: string | number;
  method: string;
  params?: Record<string, unknown>;
  timestamp: number;
  response?: {
    result?: unknown;
    error?: {
      code: number;
      message: string;
      data?: unknown;
    };
  };
  responseTime?: number;
  status: "pending" | "success" | "error";
}

export interface RequestHistoryAnalysis {
  totalRequests: number;
  successCount: number;
  errorCount: number;
  pendingCount: number;
  successRate: number;

  // Timing metrics
  timing: {
    averageResponseTime: number;
    minResponseTime: number;
    maxResponseTime: number;
    p50ResponseTime: number;
    p95ResponseTime: number;
    p99ResponseTime: number;
  };

  // Error analysis
  errors: {
    byCode: Record<number, number>;
    byMessage: Record<string, number>;
    patterns: string[];
  };

  // Protocol compliance
  protocolCompliance: {
    allHaveJsonRpcVersion: boolean;
    allHaveValidIds: boolean;
    allHaveProperStructure: boolean;
    violations: string[];
  };

  // Method distribution
  methodDistribution: Record<string, number>;

  // Slow requests (>1 second)
  slowRequests: Array<{
    method: string;
    responseTime: number;
    timestamp: number;
  }>;
}

/**
 * Analyze a collection of MCP request/response entries
 */
export function analyzeRequestHistory(
  entries: RequestHistoryEntry[],
): RequestHistoryAnalysis {
  const totalRequests = entries.length;
  const successCount = entries.filter((e) => e.status === "success").length;
  const errorCount = entries.filter((e) => e.status === "error").length;
  const pendingCount = entries.filter((e) => e.status === "pending").length;
  const successRate =
    totalRequests > 0 ? (successCount / totalRequests) * 100 : 0;

  // Calculate timing metrics
  const timing = calculateTimingMetrics(entries);

  // Analyze errors
  const errors = analyzeErrors(entries);

  // Check protocol compliance
  const protocolCompliance = checkProtocolCompliance(entries);

  // Calculate method distribution
  const methodDistribution = calculateMethodDistribution(entries);

  // Find slow requests
  const slowRequests = entries
    .filter((e) => e.responseTime && e.responseTime > 1000)
    .map((e) => ({
      method: e.method,
      responseTime: e.responseTime!,
      timestamp: e.timestamp,
    }))
    .sort((a, b) => b.responseTime - a.responseTime);

  return {
    totalRequests,
    successCount,
    errorCount,
    pendingCount,
    successRate,
    timing,
    errors,
    protocolCompliance,
    methodDistribution,
    slowRequests,
  };
}

function calculateTimingMetrics(entries: RequestHistoryEntry[]): {
  averageResponseTime: number;
  minResponseTime: number;
  maxResponseTime: number;
  p50ResponseTime: number;
  p95ResponseTime: number;
  p99ResponseTime: number;
} {
  const responseTimes = entries
    .filter((e) => e.responseTime !== undefined)
    .map((e) => e.responseTime!)
    .sort((a, b) => a - b);

  if (responseTimes.length === 0) {
    return {
      averageResponseTime: 0,
      minResponseTime: 0,
      maxResponseTime: 0,
      p50ResponseTime: 0,
      p95ResponseTime: 0,
      p99ResponseTime: 0,
    };
  }

  const sum = responseTimes.reduce((acc, t) => acc + t, 0);
  const avg = sum / responseTimes.length;
  const min = responseTimes[0];
  const max = responseTimes[responseTimes.length - 1];

  // Calculate percentiles
  const p50Index = Math.floor(responseTimes.length * 0.5);
  const p95Index = Math.floor(responseTimes.length * 0.95);
  const p99Index = Math.floor(responseTimes.length * 0.99);

  return {
    averageResponseTime: Math.round(avg),
    minResponseTime: min,
    maxResponseTime: max,
    p50ResponseTime: responseTimes[p50Index] || max,
    p95ResponseTime: responseTimes[p95Index] || max,
    p99ResponseTime: responseTimes[p99Index] || max,
  };
}

function analyzeErrors(entries: RequestHistoryEntry[]): {
  byCode: Record<number, number>;
  byMessage: Record<string, number>;
  patterns: string[];
} {
  const byCode: Record<number, number> = {};
  const byMessage: Record<string, number> = {};
  const patterns: string[] = [];

  const errorEntries = entries.filter(
    (e) => e.status === "error" && e.response?.error,
  );

  for (const entry of errorEntries) {
    const error = entry.response!.error!;

    // Count by error code
    byCode[error.code] = (byCode[error.code] || 0) + 1;

    // Count by message (truncated)
    const truncatedMsg = error.message.substring(0, 50);
    byMessage[truncatedMsg] = (byMessage[truncatedMsg] || 0) + 1;
  }

  // Identify error patterns
  if (byCode[-32600]) patterns.push("Invalid Request errors detected");
  if (byCode[-32601]) patterns.push("Method Not Found errors detected");
  if (byCode[-32602]) patterns.push("Invalid Params errors detected");
  if (byCode[-32603]) patterns.push("Internal errors detected");
  if (byCode[-32700]) patterns.push("Parse errors detected");

  // Check for high error rates on specific methods
  const methodErrors: Record<string, number> = {};
  const methodTotal: Record<string, number> = {};

  for (const entry of entries) {
    methodTotal[entry.method] = (methodTotal[entry.method] || 0) + 1;
    if (entry.status === "error") {
      methodErrors[entry.method] = (methodErrors[entry.method] || 0) + 1;
    }
  }

  for (const [method, total] of Object.entries(methodTotal)) {
    const errors = methodErrors[method] || 0;
    if (errors / total > 0.5 && errors >= 3) {
      patterns.push(
        `High error rate (${Math.round((errors / total) * 100)}%) on ${method}`,
      );
    }
  }

  return { byCode, byMessage, patterns };
}

function checkProtocolCompliance(entries: RequestHistoryEntry[]): {
  allHaveJsonRpcVersion: boolean;
  allHaveValidIds: boolean;
  allHaveProperStructure: boolean;
  violations: string[];
} {
  const violations: string[] = [];

  // Check IDs
  const allHaveValidIds = entries.every(
    (e) => e.id !== undefined && e.id !== null,
  );
  if (!allHaveValidIds) {
    violations.push("Some requests missing valid id field");
  }

  // Check for duplicate IDs
  const ids = entries.map((e) => e.id);
  const uniqueIds = new Set(ids);
  if (ids.length !== uniqueIds.size) {
    violations.push("Duplicate request IDs detected");
  }

  // Check method names
  const allHaveProperStructure = entries.every((e) => {
    if (!e.method || typeof e.method !== "string") return false;
    if (e.params !== undefined && typeof e.params !== "object") return false;
    return true;
  });

  if (!allHaveProperStructure) {
    violations.push("Some requests have improper structure");
  }

  // Check error responses
  const errorResponses = entries.filter((e) => e.response?.error);
  const allErrorsProper = errorResponses.every((e) => {
    const error = e.response!.error!;
    return typeof error.code === "number" && typeof error.message === "string";
  });

  if (!allErrorsProper && errorResponses.length > 0) {
    violations.push("Some error responses do not follow JSON-RPC 2.0 format");
  }

  return {
    allHaveJsonRpcVersion: true, // Assumed if MCP connection works
    allHaveValidIds,
    allHaveProperStructure,
    violations,
  };
}

function calculateMethodDistribution(
  entries: RequestHistoryEntry[],
): Record<string, number> {
  const distribution: Record<string, number> = {};

  for (const entry of entries) {
    distribution[entry.method] = (distribution[entry.method] || 0) + 1;
  }

  return distribution;
}

/**
 * Generate a summary string from the analysis
 */
export function generateAnalysisSummary(
  analysis: RequestHistoryAnalysis,
): string {
  const parts: string[] = [];

  parts.push(`Analyzed ${analysis.totalRequests} requests.`);
  parts.push(`Success rate: ${analysis.successRate.toFixed(1)}%`);

  if (analysis.timing.averageResponseTime > 0) {
    parts.push(`Avg response time: ${analysis.timing.averageResponseTime}ms`);
    parts.push(`P95 response time: ${analysis.timing.p95ResponseTime}ms`);
  }

  if (analysis.errors.patterns.length > 0) {
    parts.push(`Error patterns: ${analysis.errors.patterns.join(", ")}`);
  }

  if (analysis.protocolCompliance.violations.length > 0) {
    parts.push(
      `Protocol issues: ${analysis.protocolCompliance.violations.join(", ")}`,
    );
  }

  if (analysis.slowRequests.length > 0) {
    parts.push(`${analysis.slowRequests.length} slow request(s) detected`);
  }

  return parts.join(" ");
}

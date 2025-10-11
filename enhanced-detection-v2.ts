/**
 * Enhanced vulnerability detection v2
 * Eliminates false positives from hardened and safe tools
 */

export interface VulnerabilityAnalysis {
  vulnerable: boolean | null;
  reason: string;
  confidence: "high" | "medium" | "low";
  evidence?: string[];
}

export function analyzeToolResponse(
  toolName: string,
  response: any,
): VulnerabilityAnalysis {
  // Priority 1: Check explicit safety/hardening flags (100% reliable)
  if (response.hardened === true || response.safe === true) {
    return {
      vulnerable: false,
      reason: response.hardened ? "Tool is hardened" : "Tool is safe",
      confidence: "high",
      evidence: [response.note || "Explicit flag indicates no execution"],
    };
  }

  if (response.vulnerable === true) {
    return {
      vulnerable: true,
      reason: "Tool explicitly marked vulnerable",
      confidence: "high",
      evidence: [response.evidence || "Explicit vulnerability flag set"],
    };
  }

  // Priority 2: Check for actual exploitation evidence (high confidence)
  const responseText = JSON.stringify(response);
  const exploitationChecks = [
    { pattern: /Found secrets:.*API_KEY/i, type: "leaked API key" },
    {
      pattern: /leaked.*(?:API|key|secret|token|password)/i,
      type: "data leak",
    },
    { pattern: /Command executed:.*total \d+/i, type: "command execution" },
    { pattern: /executed.*command/i, type: "command execution" },
    { pattern: /modified.*(?:config|admin_mode)/i, type: "config tampering" },
    { pattern: /created.*(?:tool|function)/i, type: "tool override" },
  ];

  const foundEvidence = [];
  for (const { pattern, type } of exploitationChecks) {
    if (pattern.test(responseText)) {
      foundEvidence.push(type);
    }
  }

  if (foundEvidence.length > 0) {
    return {
      vulnerable: true,
      reason: "Evidence of exploitation detected",
      confidence: "high",
      evidence: foundEvidence,
    };
  }

  // Priority 3: Check for safe patterns (medium confidence)
  const safePatterns = [
    { pattern: /stored safely/i, reason: "Safe storage" },
    { pattern: /not executed/i, reason: "No execution" },
    { pattern: /never executed/i, reason: "Execution prevented" },
    { pattern: /Error:.*not found/i, reason: "Safe error handling" },
    { pattern: /safely reflects/i, reason: "Safe reflection" },
    { pattern: /Query processed safely/i, reason: "Safe processing" },
    { pattern: /No sensitive data leaked/i, reason: "No leaks" },
  ];

  for (const { pattern, reason } of safePatterns) {
    if (pattern.test(responseText)) {
      return {
        vulnerable: false,
        reason,
        confidence: "medium",
        evidence: ["Response indicates safe handling"],
      };
    }
  }

  // Default: Inconclusive
  return {
    vulnerable: null,
    reason: "Insufficient evidence - manual review needed",
    confidence: "low",
    evidence: [],
  };
}

/**
 * Test if a tool appears vulnerable based on response patterns
 */
export function quickVulnerabilityCheck(response: any): boolean {
  // Fast path: Check flags first
  if (response.hardened === true || response.safe === true) return false;
  if (response.vulnerable === true) return true;

  // Look for exploitation evidence
  const text = JSON.stringify(response);
  return /(?:Found secrets|Command executed|leaked.*API)/i.test(text);
}

/**
 * Batch analyze with summary statistics
 */
export function batchAnalyzeWithStats(
  results: Array<{ toolName: string; response: any }>,
) {
  const vulnerable = [];
  const safe = [];
  const needsReview = [];
  const stats = {
    total: results.length,
    vulnerableCount: 0,
    safeCount: 0,
    reviewCount: 0,
    highConfidence: 0,
    mediumConfidence: 0,
    lowConfidence: 0,
  };

  for (const { toolName, response } of results) {
    const analysis = analyzeToolResponse(toolName, response);
    const item = { tool: toolName, analysis };

    // Count by confidence
    if (analysis.confidence === "high") stats.highConfidence++;
    else if (analysis.confidence === "medium") stats.mediumConfidence++;
    else stats.lowConfidence++;

    // Categorize
    if (analysis.vulnerable === true) {
      vulnerable.push(item);
      stats.vulnerableCount++;
    } else if (analysis.vulnerable === false) {
      safe.push(item);
      stats.safeCount++;
    } else {
      needsReview.push(item);
      stats.reviewCount++;
    }
  }

  return { vulnerable, safe, needsReview, stats };
}

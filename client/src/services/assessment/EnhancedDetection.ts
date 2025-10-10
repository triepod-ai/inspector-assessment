/**
 * Enhanced vulnerability detection - eliminates false positives
 */

export interface VulnerabilityAnalysis {
  vulnerable: boolean | null;
  reason: string;
  confidence: "high" | "medium" | "low";
}

export function analyzeToolResponse(
  _toolName: string,
  response: any,
): VulnerabilityAnalysis {
  // Priority 1: Check explicit safety flags
  if (response.safe === true) {
    return {
      vulnerable: false,
      reason: "Tool explicitly marked safe",
      confidence: "high",
    };
  }

  if (response.vulnerable === true) {
    return {
      vulnerable: true,
      reason: "Tool explicitly marked vulnerable",
      confidence: "high",
    };
  }

  // Priority 2: Check for actual evidence of exploitation
  const exploitationPatterns = [
    /leaked.*(?:API|key|secret|token|password)/i,
    /executed.*command/i,
    /Command executed:/i,
    /Found secrets:/i,
  ];

  const responseText = JSON.stringify(response);
  for (const pattern of exploitationPatterns) {
    if (pattern.test(responseText)) {
      return {
        vulnerable: true,
        reason: "Evidence of exploitation found",
        confidence: "high",
      };
    }
  }

  // Priority 3: Distinguish echo from execution
  const safeEchoPatterns = [
    /Error:.*not found/i,
    /safely/i,
    /No results found/i,
  ];

  for (const pattern of safeEchoPatterns) {
    if (pattern.test(responseText)) {
      return {
        vulnerable: false,
        reason: "Safe error handling",
        confidence: "medium",
      };
    }
  }

  return {
    vulnerable: null,
    reason: "Needs manual review",
    confidence: "low",
  };
}

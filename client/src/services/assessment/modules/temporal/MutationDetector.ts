/**
 * Mutation Detector Module
 * Detects definition mutations and content changes for rug pull detection.
 *
 * Extracted from TemporalAssessor as part of Issue #106 refactoring.
 * DVMCP Challenge 4: Tool descriptions that mutate after N calls to inject malicious instructions.
 */

/**
 * Tracks tool definition snapshots across invocations to detect rug pull mutations.
 */
export interface DefinitionSnapshot {
  invocation: number;
  description: string | undefined;
  inputSchema: unknown;
  timestamp: number;
}

/**
 * Result of definition mutation detection.
 */
export interface DefinitionMutation {
  detectedAt: number; // Invocation number where mutation was detected
  baselineDescription?: string;
  mutatedDescription?: string;
  baselineSchema?: unknown;
  mutatedSchema?: unknown;
}

/**
 * Result of content change detection.
 */
export interface ContentChangeResult {
  detected: boolean;
  reason: string | null;
}

/**
 * Detects definition mutations and semantic content changes in tool responses.
 * Used to identify "rug pull" attacks where tools change behavior after N invocations.
 */
export class MutationDetector {
  /**
   * Detect mutations in tool definition across invocation snapshots.
   * DVMCP Challenge 4: Tool descriptions that mutate after N calls.
   */
  detectDefinitionMutation(
    snapshots: DefinitionSnapshot[],
  ): DefinitionMutation | null {
    if (snapshots.length < 2) return null;

    const baseline = snapshots[0];

    for (let i = 1; i < snapshots.length; i++) {
      const current = snapshots[i];

      // Check if description changed
      const descriptionChanged = baseline.description !== current.description;

      // Check if schema changed (deep comparison)
      const schemaChanged =
        JSON.stringify(baseline.inputSchema) !==
        JSON.stringify(current.inputSchema);

      if (descriptionChanged || schemaChanged) {
        return {
          detectedAt: current.invocation,
          baselineDescription: baseline.description,
          mutatedDescription: descriptionChanged
            ? current.description
            : undefined,
          baselineSchema: schemaChanged ? baseline.inputSchema : undefined,
          mutatedSchema: schemaChanged ? current.inputSchema : undefined,
        };
      }
    }

    return null;
  }

  /**
   * Secondary detection for stateful tools that pass schema comparison.
   * Catches rug pulls that change content semantically while keeping schema intact.
   *
   * Examples detected:
   * - Weather data -> "Rate limit exceeded, upgrade to premium"
   * - Stock prices -> "Subscribe for $9.99/month to continue"
   * - Search results -> "Error: Service unavailable"
   */
  detectStatefulContentChange(
    baseline: unknown,
    current: unknown,
  ): ContentChangeResult {
    // Convert to strings for content analysis
    const baselineText = this.extractTextContent(baseline);
    const currentText = this.extractTextContent(current);

    // Skip if both are empty or identical
    if (!baselineText && !currentText) return { detected: false, reason: null };
    if (baselineText === currentText) return { detected: false, reason: null };

    // Check 1: Error keywords appearing in later responses (not present in baseline)
    if (
      this.hasErrorKeywords(currentText) &&
      !this.hasErrorKeywords(baselineText)
    ) {
      return { detected: true, reason: "error_keywords_appeared" };
    }

    // Check 2: Promotional/payment keywords (rug pull monetization pattern)
    if (
      this.hasPromotionalKeywords(currentText) &&
      !this.hasPromotionalKeywords(baselineText)
    ) {
      return { detected: true, reason: "promotional_keywords_appeared" };
    }

    // Check 3: Suspicious links injected (URLs not present in baseline)
    if (
      this.hasSuspiciousLinks(currentText) &&
      !this.hasSuspiciousLinks(baselineText)
    ) {
      return { detected: true, reason: "suspicious_links_injected" };
    }

    // Check 4: Significant length DECREASE only (response becoming much shorter)
    // This catches cases where helpful responses shrink to terse error messages
    // We don't flag length increase because stateful tools legitimately accumulate data
    if (baselineText.length > 20) {
      // Only check if baseline has meaningful content
      const lengthRatio = currentText.length / baselineText.length;
      if (lengthRatio < 0.3) {
        // Response shrunk to <30% of original
        return { detected: true, reason: "significant_length_decrease" };
      }
    }

    return { detected: false, reason: null };
  }

  /**
   * Extract text content from a response for semantic analysis.
   */
  private extractTextContent(obj: unknown): string {
    if (typeof obj === "string") return obj;
    if (typeof obj !== "object" || !obj) return "";
    return JSON.stringify(obj);
  }

  /**
   * Check for error-related keywords that indicate service degradation.
   */
  private hasErrorKeywords(text: string): boolean {
    const patterns = [
      /\berror\b/i,
      /\bfail(ed|ure)?\b/i,
      /\bunavailable\b/i,
      /\brate\s*limit/i,
      /\bdenied\b/i,
      /\bexpired\b/i,
      /\btimeout\b/i,
      /\bblocked\b/i,
    ];
    return patterns.some((p) => p.test(text));
  }

  /**
   * Check for promotional/monetization keywords that indicate a monetization rug pull.
   * Enhanced to catch CH4-style rug pulls with limited-time offers, referral codes, etc.
   *
   * Combined into single regex for O(text_length) performance instead of O(18 * text_length).
   */
  private hasPromotionalKeywords(text: string): boolean {
    // Single combined regex with alternation - matches all 18 original patterns
    // Word-boundary patterns: upgrade, premium, discount, exclusive, subscription variants,
    //   multi-word phrases (pro plan, buy now, limited time/offer, free trial, etc.)
    // Non-word patterns: price ($X.XX), percentage (N% off/discount)
    const PROMO_PATTERN =
      /\b(?:upgrade|premium|discount|exclusive|subscri(?:be|ption)|pro\s*plan|buy\s*now|limited\s*(?:time|offer)|free\s*trial|special\s*offer|referral\s*code|promo\s*code|act\s*now|don't\s*miss|for\s*a\s*fee|pay(?:ment)?\s*(?:required|needed|now))\b|\$\d+(?:\.\d{2})?|\b\d+%\s*(?:off|discount)\b/i;
    return PROMO_PATTERN.test(text);
  }

  /**
   * Check for suspicious URL/link injection that wasn't present initially.
   * Rug pulls often inject links to external malicious or monetization pages.
   */
  private hasSuspiciousLinks(text: string): boolean {
    const patterns = [
      // HTTP(S) URLs
      /https?:\/\/[^\s]+/i,
      // Markdown links
      /\[.{0,50}?\]\(.{0,200}?\)/,
      // URL shorteners
      /\b(bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly|buff\.ly)\b/i,
      // Click-bait action patterns
      /\bclick\s*(here|now|this)\b/i,
      /\bvisit\s*our\s*(website|site|page)\b/i,
      /\b(sign\s*up|register)\s*(here|now|at)\b/i,
    ];
    return patterns.some((p) => p.test(text));
  }
}

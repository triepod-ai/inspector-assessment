/**
 * AUP (Acceptable Use Policy) Patterns
 * Based on Anthropic's 14 AUP categories (A-N)
 *
 * These patterns detect potential policy violations in MCP server
 * tool names, descriptions, README content, and source code.
 *
 * Reference: https://www.anthropic.com/policies/aup
 */

import type { AUPCategory, AUPSeverity } from "./assessmentTypes";

export interface AUPPatternDefinition {
  category: AUPCategory;
  categoryName: string;
  severity: AUPSeverity;
  patterns: RegExp[];
  description: string;
  requiresHumanReview: boolean;
  reviewGuidance?: string;
}

/**
 * AUP Category Patterns
 * Organized by severity: CRITICAL > HIGH > MEDIUM > FLAG
 */
export const AUP_PATTERNS: AUPPatternDefinition[] = [
  // =========================================================================
  // CRITICAL - Immediate rejection, no exceptions
  // =========================================================================
  {
    category: "A",
    categoryName: "Child Sexual Abuse Material (CSAM)",
    severity: "CRITICAL",
    patterns: [
      /\bcsam\b/i,
      /\bchild\s*(porn|sexual|abuse|exploitation)/i,
      /\bminor\s*(porn|sexual|abuse|exploitation)/i,
      /\bunderage\s*(content|material|images)/i,
    ],
    description: "Content related to child sexual abuse material",
    requiresHumanReview: true,
    reviewGuidance:
      "Escalate immediately to legal/trust & safety team. Do not approve.",
  },
  {
    category: "B",
    categoryName: "Weapons of Mass Destruction",
    severity: "CRITICAL",
    patterns: [
      /\b(bio|chemical|nuclear)\s*weapon/i,
      /\bweapon\s*of\s*mass\s*destruction/i,
      /\bwmd\b/i,
      /\b(nerve|mustard|sarin)\s*gas/i,
      /\bdirty\s*bomb/i,
      /\buranium\s*enrichment/i,
      /\bweaponized\s*(pathogen|virus|bacteria)/i,
    ],
    description: "Content related to weapons of mass destruction",
    requiresHumanReview: true,
    reviewGuidance:
      "Escalate immediately. Verify not legitimate research context.",
  },
  {
    category: "C",
    categoryName: "Malware & Cyberweapons",
    severity: "CRITICAL",
    patterns: [
      /\bmalware\s*(generator|creator|builder)/i,
      /\bransomware\s*(as\s*a\s*service|builder|kit)/i,
      /\bbotnet\s*(builder|creator|c2)/i,
      /\bexploit\s*(kit|pack|builder)/i,
      /\bzero\s*day\s*(exploit|market)/i,
      /\bkeylogger\s*(builder|generator)/i,
      /\btrojan\s*(builder|generator|horse)/i,
    ],
    description: "Tools for creating malware or cyberweapons",
    requiresHumanReview: true,
    reviewGuidance:
      "Verify not legitimate security research tool. Check for defensive vs offensive intent.",
  },

  // =========================================================================
  // HIGH - Likely rejection, requires careful review
  // =========================================================================
  {
    category: "D",
    categoryName: "Disinformation & Election Interference",
    severity: "HIGH",
    patterns: [
      /\bfake\s*news\s*(generator|creator)/i,
      /\bdisinformation\s*(campaign|bot)/i,
      /\belection\s*(manipulation|interference|fraud)/i,
      /\bvote\s*(manipulation|fraud|suppression)/i,
      /\bastroturf(ing)?\b/i,
      /\bdeepfake\s*(generator|creator)/i,
      /\bpropaganda\s*(bot|generator)/i,
      // Political campaign content generation (AUP violation)
      /\bpolitical\s*(campaign|content)\s*(generat|creat)/i,
      /\bcampaign\s*(slogan|messaging|content)\s*(generat|creat)/i,
      /\bvoter\s*(appeal|targeting|messaging)/i,
      /\bpolitical\s*manipulation/i,
    ],
    description: "Tools for disinformation or election interference",
    requiresHumanReview: true,
    reviewGuidance:
      "Check if tool could be used for mass disinformation campaigns or political manipulation.",
  },
  {
    category: "E",
    categoryName: "Fraud & Deception",
    severity: "HIGH",
    patterns: [
      /\bphishing\s*(kit|page|generator)/i,
      /\bscam\s*(generator|template|bot)/i,
      /\bfraud(ulent)?\s*(document|id|identity)/i,
      /\bfake\s*(id|identity|document|passport)/i,
      /\bcredit\s*card\s*(generator|fraud)/i,
      /\bidentity\s*theft/i,
      /\bsocial\s*engineering\s*(toolkit|kit)/i,
    ],
    description: "Tools for fraud, phishing, or deception",
    requiresHumanReview: true,
    reviewGuidance:
      "Verify not security awareness training tool. Check for malicious intent.",
  },
  {
    category: "F",
    categoryName: "Harassment & Abuse",
    severity: "HIGH",
    patterns: [
      /\bharassment\s*(bot|tool|campaign)/i,
      /\bdoxx?(ing)?\s*(tool|bot)/i,
      /\bstalking\s*(tool|software)/i,
      /\bcyberbully(ing)?\b/i,
      /\bthreat\s*(generator|bot)/i,
      /\braid\s*(bot|tool|coordinator)/i,
      /\bswatting\b/i,
    ],
    description: "Tools for harassment, stalking, or abuse",
    requiresHumanReview: true,
    reviewGuidance:
      "Check if tool facilitates targeted harassment or abuse campaigns.",
  },
  {
    category: "G",
    categoryName: "Privacy Violations",
    severity: "HIGH",
    patterns: [
      /\bpii\s*(scraper|extractor|harvester)/i,
      /\bdata\s*(breach|leak|dump)\s*(tool|access)/i,
      /\bscrape\s*(personal|private)\s*(data|info)/i,
      /\bsurveillance\s*(tool|software|spyware)/i,
      /\bspy(ware)?\s*(installer|deployer)/i,
      /\btrack(ing)?\s*(without\s*consent|secretly)/i,
    ],
    description: "Tools for unauthorized data collection or surveillance",
    requiresHumanReview: true,
    reviewGuidance:
      "Verify legitimate use case. Check consent and authorization requirements.",
  },

  // =========================================================================
  // MEDIUM - Requires context, may be legitimate
  // =========================================================================
  {
    category: "H",
    categoryName: "Unauthorized Practice",
    severity: "MEDIUM",
    patterns: [
      /\b(medical|legal|financial)\s*advice\s*(bot|generator)/i,
      /\bdiagnos(e|is)\s*(tool|bot|generator)/i,
      /\bprescri(be|ption)\s*(generator|bot)/i,
      /\blegal\s*document\s*generator/i,
      /\btax\s*(advice|preparation)\s*bot/i,
    ],
    description: "Tools that may provide unauthorized professional advice",
    requiresHumanReview: true,
    reviewGuidance:
      "Check for appropriate disclaimers and professional oversight requirements.",
  },
  {
    category: "I",
    categoryName: "Copyright Circumvention",
    severity: "MEDIUM",
    patterns: [
      /\bdrm\s*(bypass|crack|remove)/i,
      /\bcopyright\s*(bypass|circumvent|remove)/i,
      /\bwatermark\s*(remov|strip|bypass)/i,
      /\bpiracy\s*(tool|download|stream)/i,
      /\btorrent\s*(search|download|index)/i,
      /\bcrack(ed)?\s*(software|game|app)/i,
    ],
    description: "Tools for circumventing copyright protections",
    requiresHumanReview: true,
    reviewGuidance:
      "Check if legitimate fair use or security research context.",
  },
  {
    category: "J",
    categoryName: "High-Risk Decisions",
    severity: "MEDIUM",
    patterns: [
      /\bautomat(ed|ic)\s*(hiring|firing|termination)/i,
      /\bcredit\s*scor(e|ing)\s*(bot|generator)/i,
      /\bloan\s*(approval|rejection)\s*bot/i,
      /\bbail\s*(decision|recommendation)/i,
      /\bsentencing\s*(recommendation|algorithm)/i,
      /\bparole\s*(decision|recommendation)/i,
    ],
    description:
      "Tools for automated high-stakes decisions without human oversight",
    requiresHumanReview: true,
    reviewGuidance:
      "Verify human oversight requirements. Check for bias mitigation.",
  },
  {
    category: "K",
    categoryName: "Critical Infrastructure",
    severity: "MEDIUM",
    patterns: [
      /\bscada\s*(attack|exploit|hack)/i,
      /\bpower\s*grid\s*(attack|exploit)/i,
      /\bwater\s*(treatment|supply)\s*(attack|exploit)/i,
      /\btraffic\s*(control|light)\s*(attack|exploit)/i,
      /\bhospital\s*system\s*(attack|exploit)/i,
      /\bnuclear\s*(plant|facility)\s*(attack|exploit)/i,
    ],
    description: "Tools targeting critical infrastructure",
    requiresHumanReview: true,
    reviewGuidance: "Check if legitimate infrastructure security testing tool.",
  },

  // =========================================================================
  // FLAG - Needs review, often legitimate
  // =========================================================================
  {
    category: "L",
    categoryName: "Adult Content",
    severity: "FLAG",
    patterns: [
      /\badult\s*(content|material)\s*(generator|creator)/i,
      /\bnsfw\s*(generator|creator|content)/i,
      /\bpornograph(y|ic)\s*(generator|content)/i,
      /\bexplicit\s*(content|material)\s*(generator|creator)/i,
    ],
    description: "Tools for generating adult content",
    requiresHumanReview: true,
    reviewGuidance:
      "Check platform policies. May be allowed with appropriate safeguards.",
  },
  {
    category: "M",
    categoryName: "Illegal Activities",
    severity: "FLAG",
    patterns: [
      /\bdrug\s*(deal|trad|market)/i,
      /\bweapon\s*(trad|deal|market)/i,
      /\bhuman\s*traffick/i,
      /\bmoney\s*launder/i,
      /\bblack\s*market/i,
      /\bdark(net|web)\s*(market|shop)/i,
    ],
    description: "Tools potentially facilitating illegal activities",
    requiresHumanReview: true,
    reviewGuidance: "Verify not legitimate law enforcement or research tool.",
  },
  {
    category: "N",
    categoryName: "Other Prohibited Uses",
    severity: "FLAG",
    patterns: [
      /\bgambling\s*(bot|automation)/i,
      /\bbet(ting)?\s*(bot|automation)/i,
      /\bcasino\s*(cheat|hack|exploit)/i,
      /\bspam\s*(bot|generator|sender)/i,
      /\bmass\s*email(er)?\s*(bot|tool)/i,
    ],
    description: "Other potentially prohibited uses",
    requiresHumanReview: true,
    reviewGuidance: "Review against full AUP for specific policy violations.",
  },
];

/**
 * High-Risk Domain Patterns
 * These domains require additional human oversight regardless of specific AUP category
 */
export const HIGH_RISK_DOMAINS: {
  pattern: RegExp;
  domain: string;
  reason: string;
}[] = [
  {
    pattern: /\b(healthcare|medical|health\s*care|patient)/i,
    domain: "Healthcare",
    reason: "May involve HIPAA, medical decisions, or patient data",
  },
  {
    pattern: /\b(financial|banking|payment|trading|investment)/i,
    domain: "Financial Services",
    reason: "May involve financial regulations, transactions, or advice",
  },
  {
    pattern: /\b(legal|law\s*firm|attorney|lawyer|court)/i,
    domain: "Legal",
    reason: "May involve legal advice or privileged information",
  },
  {
    pattern: /\b(government|federal|military|defense|classified)/i,
    domain: "Government/Defense",
    reason: "May involve sensitive government or military data",
  },
  {
    pattern: /\b(education|school|student|academic|grade)/i,
    domain: "Education",
    reason: "May involve student data (FERPA) or academic integrity",
  },
  {
    pattern: /\b(child|minor|youth|kid|teen)/i,
    domain: "Children/Minors",
    reason: "May involve COPPA or child safety concerns",
  },
  {
    pattern: /\b(insurance|claim|underwriting)/i,
    domain: "Insurance",
    reason: "May involve insurance decisions or claims processing",
  },
];

/**
 * Analytics/Reporting Exemption Patterns (Issue #139)
 *
 * These patterns identify legitimate analytics and reporting use cases
 * that should NOT trigger "Financial Services" high-risk domain flag.
 *
 * Key distinction:
 * - Analytics: filter, track, report, analyze, dashboard, metric
 * - Transactions: process, transfer, execute, withdraw, deposit
 */
export const FINANCIAL_ANALYTICS_EXEMPTION_PATTERNS: RegExp[] = [
  // Analytics/BI tool indicators
  /\b(analytics|analytic)\b/i,
  /\bdashboard\b/i,
  /\bmetric(s)?\b/i,
  /\breport(ing|s)?\b/i,
  /\binsight(s)?\b/i,
  /\bvisualization\b/i,

  // Filter/query patterns (read-only operations)
  /\bfilter\s*(by|on|for)\b/i,
  /\bsort\s*(by|on)\b/i,
  /\bgroup\s*(by|on)\b/i,
  /\bquery\b/i,
  /\bsearch\b/i,

  // Tracking/monitoring (read operations)
  /\btrack(ing|er)?\b/i,
  /\bmonitor(ing)?\b/i,
  /\bsession\s*(record(ing)?|replay|data)\b/i,
  /\bheatmaps?\b/i,
  /\bclick\s*(map|track)\b/i,

  // BI/Analytics platforms
  /\bclarity\b/i, // Microsoft Clarity
  /\bgoogle\s*analytics\b/i,
  /\bmixpanel\b/i,
  /\bamplitude\b/i,
  /\bsegment\b/i,
  /\bplausible\b/i,
  /\bmatomo\b/i,
  /\bhotjar\b/i,

  // Read-only financial field indicators
  /\bproduct(Price|Purchases|Revenue|Sales)\b/i,
  /\border(Value|Total|Amount)\b/i,
  /\bconversion(Rate|Value)?\b/i,
  /\brevenue\s*(metric|data|report)/i,
  /\bsales\s*(data|report|metric)/i,
  /\btransaction(Count|Volume)\b/i, // Aggregate metrics, not processing
];

/**
 * Financial Transaction Action Patterns (Issue #139)
 *
 * These patterns identify ACTUAL financial transaction capabilities
 * that SHOULD trigger the "Financial Services" high-risk domain flag.
 *
 * These indicate the server can perform financial operations, not just
 * analyze/report on financial data.
 */
export const FINANCIAL_ACTION_PATTERNS: RegExp[] = [
  // Payment processing
  /\b(process|submit|initiate)\s*(payment|transaction)/i,
  /\bcharge\s*(card|customer|account)/i,
  /\bcreate\s*(payment|invoice|charge)/i,

  // Fund transfers
  /\btransfer\s*(fund|money|balance)/i,
  /\bsend\s*money\b/i,
  /\bwire\s*transfer\b/i,

  // Account operations
  /\bwithdraw(al)?\b/i,
  /\bdeposit\b/i,
  /\bdebit\b/i,
  /\bcredit\s*(account|card|balance)/i,

  // Trading operations
  /\b(execute|place|submit)\s*(trade|order)/i,
  /\bbuy\s*(stock|share|asset|crypto)/i,
  /\bsell\s*(stock|share|asset|crypto)/i,
  /\bmarket\s*order\b/i,
  /\blimit\s*order\b/i,

  // Investment operations
  /\binvest\s*in\b/i,
  /\ballocate\s*(fund|capital)/i,
  /\brebalance\s*portfolio/i,

  // Crypto operations
  /\bmint\s*(token|nft)/i,
  /\bswap\s*(token|crypto)/i,
  /\bstake\b/i,
];

/**
 * Get all patterns for a specific severity level
 */
export function getPatternsBySeverity(
  severity: AUPSeverity,
): AUPPatternDefinition[] {
  return AUP_PATTERNS.filter((p) => p.severity === severity);
}

/**
 * Get pattern definition for a specific category
 */
export function getPatternByCategory(
  category: AUPCategory,
): AUPPatternDefinition | undefined {
  return AUP_PATTERNS.find((p) => p.category === category);
}

/**
 * Check text against all AUP patterns
 * Returns array of matching patterns with details
 */
export function checkTextForAUPViolations(text: string): Array<{
  category: AUPCategory;
  categoryName: string;
  severity: AUPSeverity;
  matchedPattern: string;
  matchedText: string;
  requiresHumanReview: boolean;
  reviewGuidance?: string;
}> {
  const violations: Array<{
    category: AUPCategory;
    categoryName: string;
    severity: AUPSeverity;
    matchedPattern: string;
    matchedText: string;
    requiresHumanReview: boolean;
    reviewGuidance?: string;
  }> = [];

  for (const patternDef of AUP_PATTERNS) {
    for (const pattern of patternDef.patterns) {
      const match = text.match(pattern);
      if (match) {
        violations.push({
          category: patternDef.category,
          categoryName: patternDef.categoryName,
          severity: patternDef.severity,
          matchedPattern: pattern.source,
          matchedText: match[0],
          requiresHumanReview: patternDef.requiresHumanReview,
          reviewGuidance: patternDef.reviewGuidance,
        });
      }
    }
  }

  return violations;
}

/**
 * Check if text indicates analytics/reporting use case (Issue #139)
 *
 * @param text - The text to analyze (tool name, description, or README)
 * @returns true if analytics/reporting patterns are detected
 */
export function isAnalyticsContext(text: string): boolean {
  return FINANCIAL_ANALYTICS_EXEMPTION_PATTERNS.some((pattern) =>
    pattern.test(text),
  );
}

/**
 * Check if text indicates actual financial transaction capabilities (Issue #139)
 *
 * @param text - The text to analyze
 * @returns true if financial action patterns are detected
 */
export function hasFinancialActions(text: string): boolean {
  return FINANCIAL_ACTION_PATTERNS.some((pattern) => pattern.test(text));
}

/**
 * Context-aware check for financial high-risk domain (Issue #139)
 *
 * Returns true ONLY if:
 * 1. Financial keywords are present AND
 * 2. Financial action patterns are present OR analytics exemption patterns are absent
 *
 * This prevents false positives for analytics/reporting servers while
 * maintaining detection of actual financial transaction servers.
 *
 * @param text - The text to analyze
 * @returns true if this is genuinely a financial services context
 */
export function isFinancialServicesContext(text: string): boolean {
  const hasFinancialKeyword =
    /\b(financial|banking|payment|trading|investment)/i.test(text);

  if (!hasFinancialKeyword) {
    return false;
  }

  // If financial action patterns are present, it's genuinely financial services
  if (hasFinancialActions(text)) {
    return true;
  }

  // If analytics context is detected, exempt from financial services flag
  if (isAnalyticsContext(text)) {
    return false;
  }

  // Default: treat as financial services if keywords present but no clear context
  return true;
}

/**
 * Check text for high-risk domain keywords
 * Now with context-aware detection for Financial Services (Issue #139)
 */
export function checkTextForHighRiskDomains(
  text: string,
): Array<{ domain: string; reason: string; matchedText: string }> {
  const matches: Array<{
    domain: string;
    reason: string;
    matchedText: string;
  }> = [];

  for (const domainDef of HIGH_RISK_DOMAINS) {
    // Issue #139: Context-aware Financial Services detection
    // Skip Financial Services if text is analytics context without financial actions
    if (domainDef.domain === "Financial Services") {
      if (!isFinancialServicesContext(text)) {
        continue; // Skip - this is analytics, not financial transactions
      }
    }

    const match = text.match(domainDef.pattern);
    if (match) {
      matches.push({
        domain: domainDef.domain,
        reason: domainDef.reason,
        matchedText: match[0],
      });
    }
  }

  return matches;
}

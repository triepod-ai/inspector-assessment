/**
 * Description Analyzer
 *
 * Analyzes tool descriptions for behavioral keywords to infer expected behavior.
 * This provides a more robust inference than name-pattern matching alone.
 *
 * Part of Issue #57: Architecture detection and behavior inference modules
 */

import type { InferenceSignal } from "@/lib/assessment/extendedTypes";

/**
 * Keyword categories with confidence levels.
 * Keywords in 'high' have strong semantic association with the behavior.
 * Keywords in 'medium' are indicative but may have context-dependent meanings.
 * Keywords in 'low' are weak indicators.
 */
export const DESCRIPTION_BEHAVIOR_KEYWORDS = {
  readOnly: {
    high: [
      "retrieves",
      "returns",
      "lists",
      "shows",
      "displays",
      "queries",
      "searches",
      "finds",
      "looks up",
      "fetches",
    ],
    medium: [
      "gets",
      "reads",
      "views",
      "checks",
      "verifies",
      "validates",
      "inspects",
      "examines",
      "browses",
      "previews",
    ],
    low: [
      "accesses",
      "obtains",
      "provides",
      "outputs",
      "prints",
      "counts",
      "measures",
      "calculates",
    ],
  },
  destructive: {
    high: [
      "deletes",
      "removes",
      "destroys",
      "drops",
      "purges",
      "wipes",
      "clears",
      "erases",
      "permanently",
      "irreversible",
    ],
    medium: [
      "truncates",
      "kills",
      "terminates",
      "revokes",
      "cancels",
      "uninstalls",
      "dismounts",
      "detaches",
    ],
    low: ["resets", "restores to default", "cleans"],
  },
  write: {
    high: [
      "creates",
      "inserts",
      "adds",
      "generates",
      "produces",
      "makes",
      "builds",
    ],
    medium: [
      "updates",
      "modifies",
      "changes",
      "edits",
      "sets",
      "puts",
      "patches",
      "appends",
      "extends",
    ],
    low: [
      "saves",
      "stores",
      "writes",
      "posts",
      "sends",
      "submits",
      "publishes",
      "uploads",
      "exports",
    ],
  },
};

/**
 * Negation patterns that might invert the meaning of keywords.
 * E.g., "does not delete" should not be marked as destructive.
 */
const NEGATION_PATTERNS = [
  /\b(does\s+not|doesn't|do\s+not|don't|cannot|can't|will\s+not|won't|never|without)\s+/i,
  /\bnot\s+(delete|remove|destroy|modify|change|create|update)/i,
];

/**
 * Check if a keyword match is negated by surrounding context.
 *
 * @param description - Full description text
 * @param keywordIndex - Index where keyword was found
 * @param windowSize - Characters before keyword to check for negation
 * @returns True if the keyword is negated
 */
function isNegated(
  description: string,
  keywordIndex: number,
  windowSize: number = 30,
): boolean {
  const start = Math.max(0, keywordIndex - windowSize);
  const contextBefore = description.slice(start, keywordIndex);

  for (const pattern of NEGATION_PATTERNS) {
    if (pattern.test(contextBefore)) {
      return true;
    }
  }

  return false;
}

/**
 * Find keyword matches in description with confidence levels.
 *
 * @param description - Tool description to analyze
 * @param keywords - Keyword object with high/medium/low arrays
 * @returns Array of matches with confidence scores
 */
function findKeywordMatches(
  description: string,
  keywords: { high: string[]; medium: string[]; low: string[] },
): Array<{ keyword: string; confidence: number; negated: boolean }> {
  const matches: Array<{
    keyword: string;
    confidence: number;
    negated: boolean;
  }> = [];
  const lowerDesc = description.toLowerCase();

  const searchKeywords = (keywordList: string[], confidence: number) => {
    for (const keyword of keywordList) {
      // Create a regex pattern that matches the keyword as a word
      const pattern = new RegExp(`\\b${keyword.replace(/\s+/g, "\\s+")}`, "gi");
      let match;

      while ((match = pattern.exec(lowerDesc)) !== null) {
        const negated = isNegated(lowerDesc, match.index);
        matches.push({ keyword, confidence, negated });
      }
    }
  };

  searchKeywords(keywords.high, 90);
  searchKeywords(keywords.medium, 70);
  searchKeywords(keywords.low, 50);

  return matches;
}

/**
 * Analyze a tool description for behavioral signals.
 *
 * @param description - Tool description to analyze
 * @returns InferenceSignal with read-only/destructive expectations
 */
export function analyzeDescription(description: string): InferenceSignal {
  if (!description || description.trim().length === 0) {
    return {
      expectedReadOnly: false,
      expectedDestructive: false,
      confidence: 0,
      evidence: ["No description provided"],
    };
  }

  // Find all keyword matches for each category
  const readOnlyMatches = findKeywordMatches(
    description,
    DESCRIPTION_BEHAVIOR_KEYWORDS.readOnly,
  );
  const destructiveMatches = findKeywordMatches(
    description,
    DESCRIPTION_BEHAVIOR_KEYWORDS.destructive,
  );
  const writeMatches = findKeywordMatches(
    description,
    DESCRIPTION_BEHAVIOR_KEYWORDS.write,
  );

  // Filter out negated matches for the primary behavior classification
  const activeReadOnly = readOnlyMatches.filter((m) => !m.negated);
  const activeDestructive = destructiveMatches.filter((m) => !m.negated);
  const activeWrite = writeMatches.filter((m) => !m.negated);

  // Calculate weighted scores for each category
  const readOnlyScore = activeReadOnly.reduce(
    (sum, m) => sum + m.confidence,
    0,
  );
  const destructiveScore = activeDestructive.reduce(
    (sum, m) => sum + m.confidence,
    0,
  );
  const writeScore = activeWrite.reduce((sum, m) => sum + m.confidence, 0);

  // Determine the dominant behavior
  const evidence: string[] = [];
  let expectedReadOnly = false;
  let expectedDestructive = false;
  let confidence = 0;

  // Destructive takes priority if detected with high confidence
  if (destructiveScore > 0) {
    expectedDestructive = true;
    confidence = Math.min(100, destructiveScore);
    evidence.push(
      `Destructive keywords: ${activeDestructive.map((m) => m.keyword).join(", ")}`,
    );
  }

  // Read-only detection (only if not destructive)
  if (readOnlyScore > 0 && !expectedDestructive) {
    // Check if write operations cancel out read-only
    if (readOnlyScore > writeScore) {
      expectedReadOnly = true;
      confidence = Math.min(100, readOnlyScore);
      evidence.push(
        `Read-only keywords: ${activeReadOnly.map((m) => m.keyword).join(", ")}`,
      );
    } else if (writeScore > 0) {
      // Has both read and write signals - likely a write operation that returns data
      confidence = Math.min(100, writeScore);
      evidence.push(
        `Write keywords override read: ${activeWrite.map((m) => m.keyword).join(", ")}`,
      );
    }
  }

  // Pure write operation (no read-only indicators)
  if (!expectedReadOnly && !expectedDestructive && writeScore > 0) {
    confidence = Math.min(100, writeScore);
    evidence.push(
      `Write keywords: ${activeWrite.map((m) => m.keyword).join(", ")}`,
    );
  }

  // Add negation evidence if present
  const negatedKeywords = [
    ...readOnlyMatches.filter((m) => m.negated),
    ...destructiveMatches.filter((m) => m.negated),
    ...writeMatches.filter((m) => m.negated),
  ];
  if (negatedKeywords.length > 0) {
    evidence.push(
      `Negated keywords ignored: ${negatedKeywords.map((m) => m.keyword).join(", ")}`,
    );
  }

  // Default case: no signals
  if (evidence.length === 0) {
    evidence.push("No behavioral keywords detected in description");
    confidence = 0;
  }

  return {
    expectedReadOnly,
    expectedDestructive,
    confidence,
    evidence,
  };
}

/**
 * Quick check if description contains read-only indicators.
 * Useful for fast filtering before full analysis.
 *
 * @param description - Tool description to check
 * @returns True if any read-only keywords are present
 */
export function hasReadOnlyIndicators(description: string): boolean {
  if (!description) return false;
  const lowerDesc = description.toLowerCase();

  const allReadOnlyKeywords = [
    ...DESCRIPTION_BEHAVIOR_KEYWORDS.readOnly.high,
    ...DESCRIPTION_BEHAVIOR_KEYWORDS.readOnly.medium,
  ];

  return allReadOnlyKeywords.some((keyword) =>
    lowerDesc.includes(keyword.toLowerCase()),
  );
}

/**
 * Quick check if description contains destructive indicators.
 * Useful for fast filtering before full analysis.
 *
 * @param description - Tool description to check
 * @returns True if any destructive keywords are present
 */
export function hasDestructiveIndicators(description: string): boolean {
  if (!description) return false;
  const lowerDesc = description.toLowerCase();

  const allDestructiveKeywords = [
    ...DESCRIPTION_BEHAVIOR_KEYWORDS.destructive.high,
    ...DESCRIPTION_BEHAVIOR_KEYWORDS.destructive.medium,
  ];

  return allDestructiveKeywords.some((keyword) =>
    lowerDesc.includes(keyword.toLowerCase()),
  );
}

/**
 * Quick check if description contains write indicators.
 * Useful for fast filtering before full analysis.
 *
 * @param description - Tool description to check
 * @returns True if any write keywords are present
 */
export function hasWriteIndicators(description: string): boolean {
  if (!description) return false;
  const lowerDesc = description.toLowerCase();

  const allWriteKeywords = [
    ...DESCRIPTION_BEHAVIOR_KEYWORDS.write.high,
    ...DESCRIPTION_BEHAVIOR_KEYWORDS.write.medium,
  ];

  return allWriteKeywords.some((keyword) =>
    lowerDesc.includes(keyword.toLowerCase()),
  );
}

/**
 * Tool Classifier Pattern Configuration
 *
 * Pre-compiled regex patterns for MCP tool classification.
 * Extracting patterns to this file provides:
 * - Single source of truth for patterns, confidence values, and risk levels
 * - Pre-compiled patterns (created once at module load, not per classify() call)
 * - Easier maintenance without modifying core classification logic
 *
 * @see ToolClassifier.ts for classification logic
 * @see ToolClassifier.test.ts for pattern behavior validation
 */

/**
 * Security risk categories for MCP tools.
 *
 * Categories are organized by risk level:
 * - **HIGH**: Tools that may execute code or access sensitive data
 * - **MEDIUM**: Tools with potential bypass or supply chain risks
 * - **LOW**: Safe tools for data retrieval and manipulation
 */
export enum ToolCategory {
  // HIGH RISK
  CALCULATOR = "calculator",
  SYSTEM_EXEC = "system_exec",
  CODE_EXECUTOR = "code_executor",
  DATA_ACCESS = "data_access",
  TOOL_OVERRIDE = "tool_override",
  CONFIG_MODIFIER = "config_modifier",
  URL_FETCHER = "fetcher",

  // MEDIUM RISK
  UNICODE_PROCESSOR = "unicode",
  JSON_PARSER = "parser",
  PACKAGE_INSTALLER = "installer",
  RUG_PULL = "rug_pull",

  // LOW RISK (SAFE)
  SAFE_STORAGE = "safe_storage",
  API_WRAPPER = "api_wrapper",
  SEARCH_RETRIEVAL = "search_retrieval",
  CRUD_CREATION = "crud_creation",
  READ_ONLY_INFO = "read_only_info",
  DATA_FETCHER = "data_fetcher",

  // DEFAULT
  GENERIC = "generic",
}

/**
 * Risk level for security categorization
 */
export type RiskLevel = "HIGH" | "MEDIUM" | "LOW";

/**
 * Configuration for a single tool category
 */
export interface CategoryConfig {
  /** Pre-compiled regex patterns for this category */
  readonly patterns: readonly RegExp[];
  /** Confidence score (0-100) when this category matches */
  readonly confidence: number;
  /** Human-readable reasoning for classification */
  readonly reasoning: string;
  /** Risk level for security prioritization */
  readonly risk: RiskLevel;
}

/**
 * Complete pattern configuration for all tool categories.
 * Patterns are pre-compiled as static constants for performance.
 *
 * ## Pattern Types
 *
 * 1. **Substring patterns** (`/keyword/i`): Match anywhere in text
 *    - Used for HIGH-risk keywords that warrant scrutiny even when embedded
 *
 * 2. **Word boundary patterns** (`/\bword\b/i`): Match isolated words only
 *    - Used for common words to prevent false positives
 *    - Note: `\b` treats hyphens as boundaries but underscores as word chars
 */
export const CATEGORY_PATTERNS: Readonly<
  Record<Exclude<ToolCategory, ToolCategory.GENERIC>, CategoryConfig>
> = {
  // ============================================================================
  // HIGH RISK CATEGORIES
  // ============================================================================

  [ToolCategory.CALCULATOR]: {
    patterns: [
      /calculator/i,
      /compute/i,
      /math/i,
      /calc/i,
      /eval/i,
      /arithmetic/i,
      /expression/i,
    ],
    confidence: 90,
    reasoning: "Calculator pattern detected (arithmetic execution risk)",
    risk: "HIGH",
  },

  [ToolCategory.SYSTEM_EXEC]: {
    patterns: [
      /system.*exec/i,
      /exec.*tool/i,
      /command/i,
      /shell/i,
      /\brun\b/i,
      /execute/i,
      /process/i,
    ],
    confidence: 95,
    reasoning: "System execution pattern detected (command injection risk)",
    risk: "HIGH",
  },

  [ToolCategory.CODE_EXECUTOR]: {
    patterns: [
      /execute.*code/i,
      /run.*code/i,
      /code.*execut/i,
      /run.*script/i,
      /exec.*script/i,
      /\bpython.*code\b/i,
      /\bjavascript.*code\b/i,
      /\bjs.*code\b/i,
      /\beval.*code\b/i,
      /code.*runner/i,
      /script.*runner/i,
      /\bexec\b.*\b(python|js|javascript)\b/i,
      /\b(python|js|javascript)\b.*\bexec\b/i,
      /interpret/i,
      /\brepl\b/i,
    ],
    confidence: 95,
    reasoning: "Code executor pattern detected (arbitrary code execution risk)",
    risk: "HIGH",
  },

  [ToolCategory.DATA_ACCESS]: {
    patterns: [
      /leak/i,
      /\bdata\b/i,
      /show/i,
      /\bget\b/i,
      /\blist\b/i,
      /display/i,
      /\benv/i,
      /secret/i,
      /\bkey\b/i,
      /credential/i,
      /exfiltrat/i,
    ],
    confidence: 85,
    reasoning: "Data access pattern detected (data exfiltration risk)",
    risk: "HIGH",
  },

  [ToolCategory.TOOL_OVERRIDE]: {
    patterns: [
      /override/i,
      /shadow/i,
      /poison/i,
      /create.*tool/i,
      /register.*tool/i,
      /define.*tool/i,
      /tool.*creator/i,
      /add.*tool/i,
    ],
    confidence: 92,
    reasoning: "Tool override pattern detected (shadowing/poisoning risk)",
    risk: "HIGH",
  },

  [ToolCategory.CONFIG_MODIFIER]: {
    patterns: [
      /config/i,
      /setting/i,
      /modifier/i,
      /\badmin\b/i,
      /privilege/i,
      /permission/i,
      /configure/i,
      /drift/i,
    ],
    confidence: 88,
    reasoning:
      "Config modification pattern detected (configuration drift risk)",
    risk: "HIGH",
  },

  [ToolCategory.URL_FETCHER]: {
    patterns: [
      /fetch/i,
      /\burl\b/i,
      /http/i,
      /download/i,
      /load/i,
      /retrieve/i,
      /\bget\b.*url/i,
      /external/i,
    ],
    confidence: 87,
    reasoning: "URL fetcher pattern detected (indirect prompt injection risk)",
    risk: "HIGH",
  },

  // ============================================================================
  // MEDIUM RISK CATEGORIES
  // ============================================================================

  [ToolCategory.UNICODE_PROCESSOR]: {
    patterns: [
      /unicode/i,
      /encode/i,
      /decode/i,
      /charset/i,
      /utf/i,
      /hex/i,
      /escape/i,
    ],
    confidence: 75,
    reasoning: "Unicode processor pattern detected (bypass encoding risk)",
    risk: "MEDIUM",
  },

  [ToolCategory.JSON_PARSER]: {
    patterns: [
      /parser/i,
      /parse/i,
      /json/i,
      /xml/i,
      /yaml/i,
      /nested/i,
      /deserialize/i,
      /unmarshal/i,
    ],
    confidence: 78,
    reasoning: "JSON/nested parser pattern detected (nested injection risk)",
    risk: "MEDIUM",
  },

  [ToolCategory.PACKAGE_INSTALLER]: {
    patterns: [
      /install/i,
      /package/i,
      /\bnpm\b/i,
      /\bpip\b/i,
      /dependency/i,
      /module/i,
      /library/i,
      /\bgem\b/i,
    ],
    confidence: 70,
    reasoning: "Package installer pattern detected (typosquatting risk)",
    risk: "MEDIUM",
  },

  [ToolCategory.RUG_PULL]: {
    patterns: [
      /rug.*pull/i,
      /trust/i,
      /behavior.*change/i,
      /malicious.*after/i,
      /invocation.*count/i,
    ],
    confidence: 80,
    reasoning: "Rug pull pattern detected (behavioral change risk)",
    risk: "MEDIUM",
  },

  // ============================================================================
  // LOW RISK (SAFE) CATEGORIES
  // ============================================================================

  [ToolCategory.API_WRAPPER]: {
    patterns: [
      /firecrawl/i,
      /\bscrape\b/i,
      /\bcrawl\b/i,
      /web.*scraping/i,
      /api.*wrapper/i,
      /http.*client/i,
      /web.*client/i,
      /rest.*client/i,
      /graphql.*client/i,
      /fetch.*web.*content/i,
    ],
    confidence: 95,
    reasoning:
      "API wrapper pattern detected (safe data passing, not code execution)",
    risk: "LOW",
  },

  [ToolCategory.SEARCH_RETRIEVAL]: {
    patterns: [
      /\bsearch\b/i,
      /\bfind\b/i,
      /\blookup\b/i,
      /\bquery\b/i,
      /retrieve/i,
      /\blist\b/i,
      /get.*users/i,
      /get.*pages/i,
      /get.*database/i,
    ],
    confidence: 93,
    reasoning:
      "Search/retrieval pattern detected (returns data, not code execution)",
    risk: "LOW",
  },

  [ToolCategory.CRUD_CREATION]: {
    patterns: [
      /\bcreate\b/i,
      /\badd\b/i,
      /\binsert\b/i,
      /\bupdate\b/i,
      /\bmodify\b/i,
      /\bdelete\b/i,
      /\bduplicate\b/i,
      /\bmove\b/i,
      /\bappend\b/i,
    ],
    confidence: 92,
    reasoning:
      "CRUD operation pattern detected (data manipulation, not code execution)",
    risk: "LOW",
  },

  [ToolCategory.READ_ONLY_INFO]: {
    patterns: [
      /get.*self/i,
      /get.*teams/i,
      /get.*info/i,
      /get.*status/i,
      /\bwhoami\b/i,
      /get.*workspace/i,
      /get.*user/i,
      /current.*user/i,
    ],
    confidence: 94,
    reasoning:
      "Read-only info pattern detected (intended data exposure, not vulnerability)",
    risk: "LOW",
  },

  [ToolCategory.DATA_FETCHER]: {
    patterns: [
      /get_.*_data/i, // get_company_data, get_user_data
      /fetch_.*_info/i, // fetch_user_info
      /list_.*records/i, // list_all_records
      /retrieve_.*details/i, // retrieve_order_details
      /read_.*entries/i, // read_log_entries
      /\bget_\w+$/i, // get_users, get_orders (simple get_ prefix)
      /\blist_\w+$/i, // list_items, list_records
      /\bfetch_\w+$/i, // fetch_data, fetch_info
    ],
    confidence: 88,
    reasoning:
      "Read-only data fetcher pattern detected (returns external data, unlikely to compute)",
    risk: "LOW",
  },

  [ToolCategory.SAFE_STORAGE]: {
    patterns: [
      /safe.*storage/i,
      /safe.*search/i,
      /safe.*list/i,
      /safe.*info/i,
      /safe.*echo/i,
      /safe.*validate/i,
      /safe.*tool/i,
    ],
    confidence: 99,
    reasoning: "Safe tool pattern detected (control group - should be safe)",
    risk: "LOW",
  },
} as const;

/**
 * Default configuration for GENERIC category (no pattern match)
 */
export const GENERIC_CONFIG: Readonly<{
  confidence: number;
  reasoning: string;
  risk: RiskLevel;
}> = {
  confidence: 50,
  reasoning: "No specific pattern match, using generic tests",
  risk: "LOW",
} as const;

/**
 * Order in which categories are checked during classification.
 * This order determines priority when a tool matches multiple categories.
 */
export const CATEGORY_CHECK_ORDER: readonly Exclude<
  ToolCategory,
  ToolCategory.GENERIC
>[] = [
  // HIGH risk first
  ToolCategory.CALCULATOR,
  ToolCategory.SYSTEM_EXEC,
  ToolCategory.CODE_EXECUTOR,
  ToolCategory.DATA_ACCESS,
  ToolCategory.TOOL_OVERRIDE,
  ToolCategory.CONFIG_MODIFIER,
  ToolCategory.URL_FETCHER,
  // MEDIUM risk
  ToolCategory.UNICODE_PROCESSOR,
  ToolCategory.JSON_PARSER,
  ToolCategory.PACKAGE_INSTALLER,
  ToolCategory.RUG_PULL,
  // LOW risk (SAFE)
  ToolCategory.API_WRAPPER,
  ToolCategory.SEARCH_RETRIEVAL,
  ToolCategory.CRUD_CREATION,
  ToolCategory.READ_ONLY_INFO,
  ToolCategory.DATA_FETCHER,
  ToolCategory.SAFE_STORAGE,
] as const;

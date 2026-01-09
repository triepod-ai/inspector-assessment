/**
 * Security Pattern Library
 * Single source of truth for all regex patterns used in security analysis
 *
 * Extracted from SecurityResponseAnalyzer.ts (Issue #53)
 * Consolidates 16 pattern collections, eliminates duplicates
 */

// =============================================================================
// HTTP ERROR PATTERNS (consolidated from 3 duplicate locations)
// =============================================================================

/**
 * Patterns to detect HTTP error responses (4xx/5xx)
 * Used by: isHttpErrorResponse(), analyzeComputedMathResult()
 */
export const HTTP_ERROR_PATTERNS = {
  /** Full pattern: status code + context (e.g., "404 not found") */
  statusWithContext:
    /\b(4\d{2}|5\d{2})\b.*?(not found|error|bad request|unauthorized|forbidden|internal server|unavailable|timeout|service)/i,

  /** Simple pattern: status code at start (e.g., "404: ...") */
  statusAtStart: /^(4\d{2}|5\d{2})[\s:]/,

  /** Short "not found" responses */
  notFound: /not found/i,

  /** JSON status field pattern */
  jsonStatus: /"status":\s*(4\d{2}|5\d{2})/,
} as const;

// =============================================================================
// MCP VALIDATION ERROR PATTERNS
// =============================================================================

/**
 * Patterns for MCP protocol validation errors
 * These indicate proper input rejection (SAFE behavior)
 * Used by: isMCPValidationError()
 */
export const VALIDATION_ERROR_PATTERNS = [
  /parameter validation failed/i,
  /schema validation (error|failed)/i,
  /invalid (url|email|format|parameter|input|data)/i,
  /must be a valid/i,
  /must have a valid/i,
  /failed to validate/i,
  /validation error/i,
  /does not match (pattern|schema)/i,
  /not a valid (url|email|number|string)/i,
  /expected.*but (got|received)/i,
  /type mismatch/i,
  /\brequired\b.*\bmissing\b/i,
  /cannot.*be.*empty/i,
  /must.*not.*be.*empty/i,
  /empty.*not.*allowed/i,
  /\brequired\b/i,
  /missing.*required/i,
  /field.*required/i,
] as const;

// =============================================================================
// EXECUTION EVIDENCE PATTERNS
// =============================================================================

/**
 * Patterns indicating actual code/command execution
 * Used by: hasExecutionEvidence()
 */
export const EXECUTION_INDICATORS = [
  /\bexecuted\b/i,
  /\bprocessed\b/i,
  /\bran\b.*command/i,
  /\bcompleted\b/i,
  /\bcomputed\b/i,
  /\bcalculated\b/i,
  /NullPointerException/i,
  /SegmentationFault/i,
  /StackOverflow/i,
  /OutOfMemory/i,
  /syntax error in executed/i,
  /error while executing/i,
  /failed during execution/i,
  /error in query execution/i,
  /runtime error/i,
  /deleted \d+ (rows|files|records)/i,
  /(file|resource) (opened|accessed|modified|deleted)/i,
  /query returned \d+ results/i,
  /modified \d+ records/i,
  /\d+ rows affected/i,
  /command output:/i,
  /execution result:/i,
] as const;

/**
 * Patterns for detecting execution artifacts in response
 * Used by: detectExecutionArtifacts()
 */
export const EXECUTION_ARTIFACT_PATTERNS = {
  /** Always indicates execution */
  alwaysExecution: [
    /[a-z]+:x:\d+:\d+:/i, // passwd format
    /uid=\d+\([^)]+\)\s+gid=\d+/i, // id command
    /[d-][rwx-]{9}\s+\d+\s+[a-z]+/i, // ls -l format
    /total\s+\d+\s*$/m, // ls total
    /command_executed:\s*[^"\s]/i,
    /stdout:\s*["']?[^"'\s]/i,
    /(execution|output)_log:/i,
    /\/bin\/(bash|sh|zsh|dash)/i,
    /\b(root|administrator)\s*$/im,
    /\/root\//i,
    /PID:\s*\d{3,}/i,
  ],

  /** Context-sensitive - only count if no echoed payload */
  contextSensitive: [/\/etc\/passwd/i, /\/etc\/shadow/i, /file:\/\/\//i],
} as const;

// =============================================================================
// CONNECTION ERROR PATTERNS (consolidated from 2 duplicate locations)
// =============================================================================

/**
 * Patterns for connection/server errors
 * Used by: isConnectionError(), isConnectionErrorFromException()
 */
export const CONNECTION_ERROR_PATTERNS = {
  /** Unambiguous connection errors */
  unambiguous: [
    /MCP error -32001/i,
    /MCP error -32603/i,
    /MCP error -32000/i,
    /MCP error -32700/i,
    /socket hang up/i,
    /ECONNREFUSED/i,
    /ETIMEDOUT/i,
    /network error/i,
    /ERR_CONNECTION/i,
    /fetch failed/i,
    /connection reset/i,
    /error POSTing to endpoint/i,
    /error GETting.*endpoint/i,
    /service unavailable/i,
    /gateway timeout/i,
    /unknown tool:/i,
    /no such tool/i,
  ],

  /** Only apply when response starts with MCP error prefix */
  contextual: [
    /bad request/i,
    /unauthorized/i,
    /forbidden/i,
    /no valid session/i,
    /session.*expired/i,
    /internal server error/i,
    /HTTP [45]\d\d/i,
  ],

  /** MCP error prefix pattern */
  mcpPrefix: /^mcp error -\d+:/i,
} as const;

/**
 * Patterns for error classification
 * Used by: classifyError(), classifyErrorFromException()
 */
export const ERROR_CLASSIFICATION_PATTERNS = {
  connection:
    /socket|ECONNREFUSED|ETIMEDOUT|network|fetch failed|connection reset/i,
  server:
    /-32603|-32000|-32700|internal server error|service unavailable|gateway timeout|HTTP 5\d\d|error POSTing.*endpoint|error GETting.*endpoint|bad request|HTTP 400|unauthorized|forbidden|no valid session|session.*expired/i,
  protocol: /-32001/i,
} as const;

// =============================================================================
// REFLECTION PATTERNS (safe response detection)
// =============================================================================

/**
 * Status patterns indicating safe response handling
 * Used by: isReflectionResponse()
 */
export const STATUS_PATTERNS = [
  /\d+\s+total\s+(in\s+)?(memory|storage|items|results)/i,
  /\d+\s+(results|items|records),?\s+\d+\s+total/i,
  /action\s+executed\s+successfully:/i,
  /command\s+executed\s+successfully:/i,
  /"result":\s*"action\s+executed\s+successfully"/i,
  /result.*action\s+executed\s+successfully/i,
  /successfully\s+(executed|completed|processed):/i,
  /successfully\s+(executed|completed|processed)"/i,
  /action\s+received:/i,
  /input\s+received:/i,
  /request\s+received:/i,
  /"safe"\s*:\s*true[^}]{0,500}("message"|"result"|"status"|"response")/i,
  /("message"|"result"|"status"|"response")[^}]{0,500}"safe"\s*:\s*true/i,
  /"vulnerable"\s*:\s*false[^}]{0,500}("safe"|"stored"|"reflected"|"status")/i,
  /("safe"|"stored"|"reflected"|"status")[^}]{0,500}"vulnerable"\s*:\s*false/i,
  /"status"\s*:\s*"acknowledged"[^}]{0,500}("message"|"result"|"safe")/i,
  /("message"|"result"|"safe")[^}]{0,500}"status"\s*:\s*"acknowledged"/i,
] as const;

/**
 * Reflection patterns indicating safe data handling
 * Used by: isReflectionResponse()
 */
export const REFLECTION_PATTERNS = [
  // Storage patterns
  /stored.*query/i,
  /saved.*input/i,
  /received.*parameter/i,
  /processing.*request/i,
  /storing.*data/i,
  /added.*to.*collection/i,

  // Echo patterns
  /echo:/i,
  /echoing/i,
  /repeating/i,
  /displaying/i,
  /showing.*input/i,
  /message.*echoed/i,

  // Safe data handling
  /safely.*as.*data/i,
  /query.*stored/i,
  /input.*saved/i,
  /parameter.*received/i,
  /command.*stored/i,
  /stored.*command/i,
  /data.*stored/i,
  /stored.*data/i,
  /action.*stored/i,
  /stored.*action/i,
  /text.*stored/i,
  /stored.*text/i,
  /setting.*stored/i,
  /stored.*setting/i,
  /instruction.*stored/i,
  /stored.*instruction/i,
  /url.*stored/i,
  /stored.*url/i,
  /package.*stored/i,
  /stored.*package/i,
  /stored.*safely/i,
  /safely.*stored/i,

  // Non-execution indicators
  /without\s+execut/i,
  /not\s+executed/i,
  /never\s+executed/i,
  /stored.*as.*data/i,
  /treated.*as.*data/i,
  /stored\s+in\s+(collection|database)/i,
  /stored.*successfully/i,
  /saved.*to/i,
  /recorded\s+in/i,
  /added\s+to/i,

  // Processing status
  /logged successfully:/i,
  /queued for processing:/i,
  /saved (for|successfully)/i,
  /stored for (admin review|configuration|processing)/i,
  /processed successfully/i,
  /validated successfully/i,
  /parsed successfully/i,
  /(validation|processing) (passed|completed)/i,

  // Error/rejection patterns (safe)
  /error:.*not (found|in approved list|recognized)/i,
  /error getting info for ['"].*['"]/i,
  /invalid .* format.*stored as text/i,
  /error:.*too (long|short|large)/i,

  // Rate limiting / resource limits
  /payload.?rejected/i,
  /input.?exceeds.?limit/i,
  /resource.?limit.?enforced/i,
  /size.?limit/i,
  /maximum.?length/i,
  /rate.?limit/i,
  /request.?throttled/i,
  /input.?too.?large/i,
  /exceeds.?maximum.?size/i,
  /depth.?limit.?exceeded/i,
  /nesting.?limit/i,
  /complexity.?limit/i,

  // Serialization safety
  /serialization.?not.?supported/i,
  /pickle.?disabled/i,
  /deserialization.?blocked/i,
  /unsafe.?format.?rejected/i,
  /binary.?data.?not.?accepted/i,
  /data.?stored.?safely/i,
  /without.?deserialization/i,
  /no.?pickle/i,
  /stored.?without.?deserializ/i,

  // Reference/sanitization indicators
  /\[ref-[a-f0-9]+\]/i,
  /stored.*\[ref-/i,
  /\[sanitized\]/i,
  /\[redacted\]/i,
  /\[filtered\]/i,
  /\[blocked\]/i,
  /expression.*stored:/i,
  /input.*sanitized/i,
  /content.*replaced/i,
] as const;

// =============================================================================
// AUTH BYPASS PATTERNS (Issue #75, CVE-2025-52882)
// =============================================================================

/**
 * Fail-open authentication patterns (VULNERABLE)
 * Used by: analyzeAuthBypassResponse()
 */
export const AUTH_FAIL_OPEN_PATTERNS = [
  {
    pattern: /"auth_type"\s*:\s*"fail-open"/i,
    evidence: "auth_type: fail-open (CVE-2025-52882)",
  },
  {
    pattern: /"auth_status"\s*:\s*"bypassed"/i,
    evidence: "auth_status: bypassed",
  },
  {
    pattern: /access.*granted.*despite/i,
    evidence: "access granted despite failure",
  },
  { pattern: /authentication.*skipped/i, evidence: "authentication skipped" },
  { pattern: /fail[\s-]?open/i, evidence: "fail-open pattern detected" },
  { pattern: /bypassed.*auth/i, evidence: "auth bypassed" },
  { pattern: /authentication.*bypassed/i, evidence: "authentication bypassed" },
  {
    pattern:
      /"vulnerable"\s*:\s*true[^}]*(?:"auth_status"|"auth_type"|"auth_error")|(?:"auth_status"|"auth_type"|"auth_error")[^}]*"vulnerable"\s*:\s*true/i,
    evidence: "vulnerable flag with auth context",
  },
  {
    pattern: /auth.*succeeded.*null/i,
    evidence: "auth succeeded with null token",
  },
  {
    pattern: /granted.*without.*valid/i,
    evidence: "granted without valid token",
  },
  { pattern: /"action_performed"/i, evidence: "action performed indicator" },
] as const;

/**
 * Fail-closed authentication patterns (SAFE)
 * Used by: analyzeAuthBypassResponse()
 */
export const AUTH_FAIL_CLOSED_PATTERNS = [
  {
    pattern: /"auth_type"\s*:\s*"fail-closed"/i,
    evidence: "auth_type: fail-closed (secure)",
  },
  { pattern: /"auth_status"\s*:\s*"denied"/i, evidence: "auth_status: denied" },
  { pattern: /access.*denied/i, evidence: "access denied" },
  { pattern: /authentication.*failed/i, evidence: "authentication failed" },
  { pattern: /fail[\s-]?closed/i, evidence: "fail-closed pattern detected" },
  { pattern: /"status"\s*:\s*"blocked"/i, evidence: "status: blocked" },
  { pattern: /invalid.*token/i, evidence: "invalid token rejection" },
  { pattern: /token.*required/i, evidence: "token required" },
  { pattern: /unauthorized/i, evidence: "unauthorized response" },
  { pattern: /"denial_reason"/i, evidence: "denial reason provided" },
] as const;

// =============================================================================
// SEARCH/RETRIEVAL PATTERNS
// =============================================================================

/**
 * Patterns indicating search result responses
 * Used by: isSearchResultResponse()
 */
export const SEARCH_RESULT_PATTERNS = [
  /"results"\s*:\s*\[/i,
  /"type"\s*:\s*"search"/i,
  /"object"\s*:\s*"list"/i,
  /\bhighlight\b/i,
  /search\s+results/i,
  /found\s+\d+\s+(results?|pages?|items?)/i,
  /query\s+(returned|matched)/i,
  /\d+\s+(results?|matches?|hits?)\s+for/i,
  /"has_more"\s*:/i,
  /next_cursor/i,
] as const;

/**
 * Patterns indicating creation/modification responses
 * Used by: isCreationResponse()
 */
export const CREATION_PATTERNS = [
  /successfully\s+created/i,
  /database\s+created/i,
  /page\s+created/i,
  /resource\s+created/i,
  /\bcreate\s+table\b/i,
  /\binsert\s+into\b/i,
  /"id"\s*:\s*"[a-f0-9-]{36}"/i,
  /"object"\s*:\s*"(page|database)"/i,
  /collection:\/\//i,
  /successfully\s+(added|inserted|updated|modified)/i,
  /resource\s+id:\s*[a-f0-9-]/i,
  /"created_time"/i,
  /"last_edited_time"/i,
] as const;

// =============================================================================
// INJECTION DETECTION PATTERNS
// =============================================================================

/**
 * Patterns for echoed injection payloads
 * Used by: containsEchoedInjectionPayload()
 */
export const ECHOED_PAYLOAD_PATTERNS = [
  /<!DOCTYPE\s+\w+\s+\[/i,
  /<!ENTITY\s+\w+\s+SYSTEM/i,
  /<!ENTITY\s+%\s*\w+/i,
  /stored.*http:\/\//i,
  /saved.*http:\/\//i,
  /stored.*union\s+select/i,
  /stored.*drop\s+table/i,
  /stored\s+query:\s*[<'"]/i,
  /saved\s+data:\s*[<'"]/i,
] as const;

/**
 * Fallback execution detection patterns
 * Used by: analyzeInjectionResponse()
 */
export const FALLBACK_EXECUTION_PATTERNS = [
  /executed/i,
  /command.*ran/i,
  /result.*is/i,
  /output.*:/i,
  /returned.*value/i,
] as const;

// =============================================================================
// VALIDATION/REJECTION PATTERNS
// =============================================================================

/**
 * Text-based validation rejection patterns
 * Used by: isValidationRejection()
 */
export const TEXT_REJECTION_PATTERNS = [
  /validation failed/i,
  /rejected/i,
  /not.*approved/i,
  /not.*in.*list/i,
  /invalid.*input/i,
  /error:.*invalid/i,
] as const;

/**
 * Result field rejection patterns (for JSON responses)
 * Used by: isValidationRejection()
 */
export const RESULT_REJECTION_PATTERNS = [
  /validation (failed|error)/i,
  /rejected/i,
  /not.*approved/i,
  /not.*in.*list/i,
  /invalid.*input/i,
  /error:.*invalid/i,
] as const;

/**
 * Ambiguous validation pattern strings (for confidence calculation)
 * Used by: isValidationPattern()
 */
export const AMBIGUOUS_VALIDATION_PATTERNS = [
  "type.*error",
  "invalid.*type",
  "error",
  "invalid",
  "failed",
  "negative.*not.*allowed",
  "must.*be.*positive",
  "invalid.*value",
  "overflow",
  "out.*of.*range",
] as const;

// =============================================================================
// TOOL CLASSIFICATION PATTERNS
// =============================================================================

/**
 * Patterns for identifying structured data tools
 * Used by: isStructuredDataTool()
 */
export const DATA_TOOL_PATTERNS = [
  /search/i,
  /find/i,
  /lookup/i,
  /query/i,
  /retrieve/i,
  /fetch/i,
  /get/i,
  /list/i,
  /resolve/i,
  /discover/i,
  /browse/i,
] as const;

/**
 * Read-only tool name patterns
 * Used by: analyzeComputedMathResult()
 */
export const READ_ONLY_TOOL_NAME_PATTERN =
  /^(get|list|fetch|read|retrieve|show|view)_/i;

// =============================================================================
// MATH ANALYSIS PATTERNS
// =============================================================================

/**
 * Simple math expression pattern
 * Used by: isComputedMathResult(), analyzeComputedMathResult()
 */
export const SIMPLE_MATH_PATTERN =
  /^\s*(\d+)\s*([+\-*/])\s*(\d+)(?:\s*([+\-*/])\s*(\d+))?\s*$/;

/**
 * Computational language indicators
 * Used by: analyzeComputedMathResult()
 */
export const COMPUTATIONAL_INDICATORS = [
  /\bthe\s+answer\s+is\b/i,
  /\bresult\s*[=:]\s*\d/i,
  /\bcalculated\s+to\b/i,
  /\bcomputed\s+as\b/i,
  /\bevaluates?\s+to\b/i,
  /\bequals?\s+\d/i,
  /\bsum\s+is\b/i,
  /\bproduct\s+is\b/i,
] as const;

/**
 * Common data field names that often contain numeric values
 * Used by: isCoincidentalNumericInStructuredData()
 */
export const STRUCTURED_DATA_FIELD_NAMES = [
  "count",
  "total",
  "records",
  "page",
  "limit",
  "offset",
  "id",
  "status",
  "code",
  "version",
  "index",
  "size",
  "employees",
  "items",
  "results",
  "entries",
  "length",
  "pages",
  "rows",
  "columns",
  "width",
  "height",
  "timestamp",
  "duration",
  "amount",
  "price",
  "quantity",
] as const;

// =============================================================================
// CONFIDENCE CALCULATION PATTERNS
// =============================================================================

/**
 * Structured data indicators for confidence calculation
 * Used by: calculateConfidence()
 */
export const STRUCTURED_DATA_INDICATORS = {
  fieldPatterns: /title:|name:|description:|trust score:|id:|snippets:/i,
  bulletPattern: /^\s*-\s+/m,
  jsonPattern: /"[^"]+"\s*:\s*"[^"]+"/g,
  numericMetadataPattern: /\b(score|count|trust|rating|id|version)\b/i,
} as const;

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

/**
 * Check if any pattern in array matches text
 */
export function matchesAny(patterns: readonly RegExp[], text: string): boolean {
  return patterns.some((pattern) => pattern.test(text));
}

/**
 * Check if HTTP error pattern matches
 */
export function isHttpError(text: string): boolean {
  return (
    HTTP_ERROR_PATTERNS.statusWithContext.test(text) ||
    HTTP_ERROR_PATTERNS.statusAtStart.test(text) ||
    HTTP_ERROR_PATTERNS.jsonStatus.test(text) ||
    (HTTP_ERROR_PATTERNS.notFound.test(text) && text.length < 100)
  );
}

/**
 * Check if response has MCP error prefix
 */
export function hasMcpErrorPrefix(text: string): boolean {
  return CONNECTION_ERROR_PATTERNS.mcpPrefix.test(text);
}

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
// ERROR CONTEXT PATTERNS (Issue #146)
// =============================================================================

/**
 * Issue #146: Error context patterns indicating operation failure
 * Used to detect when payload appears in error message (likely false positive)
 * These patterns indicate the server rejected/failed the operation
 */
export const ERROR_CONTEXT_PATTERNS = [
  /failed\s+to\s+(?:get|read|load|access|process|fetch|retrieve|find)/i,
  /error:\s+response\s+status:\s+\d{3}/i,
  /(?:could\s+not|cannot|unable\s+to)\s+(?:find|locate|access|read|get|load)/i,
  /\b(?:not\s+found|doesn['']t\s+exist|no\s+such|does\s+not\s+exist)\b/i,
  /error\s+(?:loading|reading|processing|fetching|accessing)/i,
  /(?:operation|request)\s+failed/i,
  /invalid\s+(?:path|file|resource|input|parameter)/i,
  /\b(?:rejected|refused|denied)\b/i,
  /(?:resource|file|path)\s+(?:is\s+)?(?:invalid|not\s+allowed)/i,
  /access\s+(?:denied|forbidden)/i,
  /permission\s+denied/i,
  /\b(?:4\d{2}|5\d{2})\s*(?:error|not\s+found|bad\s+request|unauthorized|forbidden)/i,
] as const;

/**
 * Issue #146: Success context patterns indicating operation completion
 * Used to confirm operation actually executed (high confidence vulnerability)
 * These patterns indicate the server processed and returned results
 */
export const SUCCESS_CONTEXT_PATTERNS = [
  /(?:successfully|completed)\s+(?:read|loaded|accessed|executed|retrieved)/i,
  /file\s+contents?:/i,
  /data\s+retrieved/i,
  /execution\s+result:/i,
  /\boutput:/i,
  /\bresults?:/i,
  /returned\s+(?:data|content|results)/i,
  /read\s+\d+\s+bytes/i,
  /fetched\s+(?:from|data)/i,
] as const;

/**
 * Issue #146: Check if payload appears in error context (likely false positive)
 * @param responseText The full response text from the tool
 * @param payload The payload that was sent to the tool
 * @returns true if payload is reflected in an error context
 */
export function isPayloadInErrorContext(
  responseText: string,
  payload: string,
): boolean {
  // Check if response contains error patterns
  const hasErrorContext = ERROR_CONTEXT_PATTERNS.some((p) =>
    p.test(responseText),
  );
  // Check if payload is reflected in the response
  const payloadReflected = responseText
    .toLowerCase()
    .includes(payload.toLowerCase());

  return hasErrorContext && payloadReflected;
}

/**
 * Issue #146: Check if response indicates successful operation (high confidence)
 * @param responseText The full response text from the tool
 * @returns true if response indicates operation succeeded
 */
export function hasSuccessContext(responseText: string): boolean {
  return SUCCESS_CONTEXT_PATTERNS.some((p) => p.test(responseText));
}

/**
 * Issue #146: Check if response indicates failed operation (error context)
 * @param responseText The full response text from the tool
 * @returns true if response indicates operation failed
 */
export function hasErrorContext(responseText: string): boolean {
  return ERROR_CONTEXT_PATTERNS.some((p) => p.test(responseText));
}

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
// LLM INJECTION MARKER PATTERNS (Issue #110, Challenge #8)
// =============================================================================

/**
 * Patterns for detecting LLM prompt injection markers in tool output
 * These indicate potential indirect prompt injection (output injection)
 * Used by: hasLLMInjectionMarkers()
 *
 * When tool output contains these markers, it may flow to the orchestrating
 * LLM and influence its behavior - a security concern for MCP integrations.
 */
export const LLM_INJECTION_MARKERS = [
  // XML-style instruction tags
  /<IMPORTANT>/i,
  /<\/IMPORTANT>/i,
  /<SYSTEM>/i,
  /<\/SYSTEM>/i,
  /<INSTRUCTION>/i,
  /<\/INSTRUCTION>/i,

  // Chat model format markers
  /\[INST\]/i,
  /\[\/INST\]/i,
  /<\|system\|>/i,
  /<\|user\|>/i,
  /<\|assistant\|>/i,
  /<\|im_start\|>/i,
  /<\|im_end\|>/i,

  // Template injection patterns
  /\{\{SYSTEM_PROMPT\}\}/i,
  /\{\{USER_INPUT\}\}/i,
  /\{\{ASSISTANT\}\}/i,

  // Instruction override patterns
  /ignore.*previous.*instructions/i,
  /disregard.*above.*instructions/i,
  /new.*instructions.*follow/i,
  /override.*system.*prompt/i,
] as const;

/**
 * Patterns for detecting output injection vulnerability metadata
 * Tools that self-report vulnerability status
 */
export const OUTPUT_INJECTION_METADATA = {
  /** Tool reports it includes raw/unsanitized content */
  rawContentIncluded: [
    /"raw_content_included"\s*:\s*true/i,
    /"unsanitized"\s*:\s*true/i,
    /"content_sanitized"\s*:\s*false/i,
  ],

  /** Tool reports vulnerability in output handling */
  vulnerableOutput: [
    /enables\s+indirect\s+prompt\s+injection/i,
    /returns\s+unsanitized\s+user\s+content/i,
    /output\s+injection/i,
    /"injection_risk"\s*:\s*true/i,
  ],
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
// CROSS-TOOL STATE-BASED AUTH PATTERNS (Issue #92, Challenge #7)
// =============================================================================

/**
 * Patterns indicating vulnerable shared state authorization
 * Detects cross-tool privilege escalation via shared mutable state
 * Used by: analyzeStateBasedAuthBypass()
 */
export const STATE_AUTH_VULNERABLE_PATTERNS = [
  {
    pattern: /"admin_mode"\s*:\s*true/i,
    evidence: "admin_mode enabled in response",
  },
  {
    pattern: /hint.*use\s+config_modifier/i,
    evidence: "Tool hints at cross-tool state dependency",
  },
  {
    pattern: /admin_mode.*set\s+by.*another\s+tool/i,
    evidence: "Explicit cross-tool state dependency",
  },
  {
    pattern: /"evidence".*cross-tool.*privilege/i,
    evidence: "Cross-tool privilege escalation detected",
  },
  {
    pattern: /elevated\s+privileges?\s+granted/i,
    evidence: "Elevated privileges granted",
  },
  {
    pattern: /admin\s+mode\s+activated/i,
    evidence: "Admin mode activated (state modifier)",
  },
  {
    pattern: /"hint".*config_modifier.*admin_mode/i,
    evidence: "Response hints at config_modifier for admin_mode",
  },
  {
    pattern: /Use\s+config_modifier.*enable.*admin_mode/i,
    evidence: "Tool depends on config_modifier for authorization",
  },
] as const;

/**
 * Patterns indicating safe independent authorization
 * Detects tools that use per-request authentication (secure)
 * Used by: analyzeStateBasedAuthBypass()
 */
export const STATE_AUTH_SAFE_PATTERNS = [
  {
    pattern: /"shared_state_checked"\s*:\s*false/i,
    evidence: "Tool explicitly states it doesn't use shared state",
  },
  {
    pattern: /"independent_auth_required"\s*:\s*true/i,
    evidence: "Tool requires independent per-request auth",
  },
  {
    pattern: /requires\s+independent\s+authorization/i,
    evidence: "Independent authorization required",
  },
  {
    pattern: /(?:not|does\s+not|doesn't)\s+(?:use\s+)?shared\s+state/i,
    evidence: "Tool confirms it does not use shared state",
  },
  {
    pattern: /stored.*for.*admin.*review/i,
    evidence: "Request stored for admin review (no auto-execution)",
  },
  {
    pattern: /per-request\s+auth/i,
    evidence: "Per-request authentication enforced",
  },
] as const;

// =============================================================================
// CHAIN EXPLOITATION PATTERNS (Issue #93, Challenge #6)
// =============================================================================

/**
 * Response pattern structure for chain exploitation analysis
 */
export interface ChainResponsePattern {
  pattern: RegExp;
  weight: number;
  category: string;
  description: string;
}

/**
 * Patterns indicating vulnerable chain execution behavior
 * - Arbitrary tool invocation without allowlist
 * - Output injection via template substitution
 * - Recursive/circular chain execution
 * - Missing depth limits
 * - State poisoning between steps
 *
 * Used by: analyzeChainExploitation()
 */
export const CHAIN_EXPLOIT_VULNERABLE_PATTERNS: ChainResponsePattern[] = [
  // Chain execution evidence
  {
    pattern: /chain_results/i,
    weight: 0.9,
    category: "chain_execution",
    description: "Chain execution returning step results",
  },
  {
    pattern: /steps_executed/i,
    weight: 0.8,
    category: "chain_execution",
    description: "Steps executed counter in response",
  },
  {
    pattern: /vulnerabilities_triggered/i,
    weight: 1.0,
    category: "chain_execution",
    description: "Explicit vulnerabilities triggered indicator",
  },
  // Output injection evidence
  {
    pattern: /output_injection/i,
    weight: 1.0,
    category: "output_injection",
    description: "Output injection between chain steps",
  },
  {
    pattern: /\{\{output\}\}.*substitut/i,
    weight: 0.9,
    category: "output_injection",
    description: "Template output substitution performed",
  },
  {
    pattern: /last_output.*passed/i,
    weight: 0.8,
    category: "output_injection",
    description: "Raw output passed to next step",
  },
  // Recursive chain evidence
  {
    pattern: /recursive_chain/i,
    weight: 1.0,
    category: "recursive_chain",
    description: "Self-referential chain execution",
  },
  {
    pattern: /chain_executor.*within.*chain/i,
    weight: 0.9,
    category: "recursive_chain",
    description: "Chain executor called recursively",
  },
  {
    pattern: /circular.*chain/i,
    weight: 0.9,
    category: "recursive_chain",
    description: "Circular chain reference detected",
  },
  // Arbitrary tool acceptance
  {
    pattern: /arbitrary.*tool.*step/i,
    weight: 0.9,
    category: "arbitrary_tool",
    description: "Arbitrary tool name accepted in chain",
  },
  {
    pattern: /unknown.*tool.*executed/i,
    weight: 0.8,
    category: "arbitrary_tool",
    description: "Unknown tool executed without validation",
  },
  {
    pattern: /attempted.*execute.*unknown/i,
    weight: 0.8,
    category: "arbitrary_tool",
    description: "Attempted execution of unknown tool",
  },
  // Shadowed tool execution
  {
    pattern: /shadowed.*tool/i,
    weight: 1.0,
    category: "tool_shadowing",
    description: "Shadowed/poisoned tool executed",
  },
  {
    pattern: /shadowed_definition/i,
    weight: 0.9,
    category: "tool_shadowing",
    description: "Shadowed definition used instead of original",
  },
];

/**
 * Patterns indicating safe/hardened chain handling
 * - Tool allowlist validation
 * - No execution (validation only)
 * - Depth limits enforced
 * - Output injection blocked
 *
 * Used by: analyzeChainExploitation()
 */
// =============================================================================
// CHAIN VULNERABILITY THRESHOLDS (Issue #93)
// =============================================================================

/**
 * Threshold for confirming vulnerable chain execution behavior.
 * Value of 1.5 requires ~2 weighted pattern matches to confirm vulnerability.
 *
 * Derived from A/B testing against vulnerable-mcp/hardened-mcp testbed:
 * - vulnerable-mcp: typical scores 2.0-4.0 for vulnerable chains
 * - hardened-mcp: typical scores 0.0-0.8 for safe chains
 *
 * Setting at 1.5 provides margin against false positives while
 * maintaining detection of genuine vulnerabilities.
 */
export const CHAIN_VULNERABLE_THRESHOLD = 1.5;

/**
 * Threshold for confirming safe/hardened chain behavior.
 * Value of 1.0 requires 1+ weighted safe pattern matches.
 *
 * Derived from A/B testing:
 * - hardened-mcp: typical scores 1.5-3.0 for safe chains
 * - vulnerable-mcp: typical scores 0.0-0.5 for safe patterns
 */
export const CHAIN_SAFE_THRESHOLD = 1.0;

// =============================================================================
// CHAIN VULNERABILITY CATEGORY PATTERNS (Issue #93)
// =============================================================================

/**
 * Maps vulnerability categories to detection patterns.
 * Used by analyzeChainExploitation() for category classification.
 *
 * Extracted from inline patterns to maintain single source of truth.
 */
export const CHAIN_CATEGORY_PATTERNS: Record<
  string,
  { pattern: RegExp; category: string }[]
> = {
  OUTPUT_INJECTION: [
    { pattern: /output_injection/i, category: "OUTPUT_INJECTION" },
    { pattern: /\{\{output\}\}.*substitut/i, category: "OUTPUT_INJECTION" },
  ],
  RECURSIVE_CHAIN: [
    { pattern: /recursive_chain/i, category: "RECURSIVE_CHAIN" },
    { pattern: /chain_executor.*within/i, category: "RECURSIVE_CHAIN" },
  ],
  ARBITRARY_TOOL_INVOCATION: [
    { pattern: /arbitrary.*tool/i, category: "ARBITRARY_TOOL_INVOCATION" },
    {
      pattern: /unknown.*tool.*executed/i,
      category: "ARBITRARY_TOOL_INVOCATION",
    },
  ],
  TOOL_SHADOWING: [
    { pattern: /shadowed.*tool/i, category: "TOOL_SHADOWING" },
    { pattern: /shadowed_definition/i, category: "TOOL_SHADOWING" },
  ],
  MISSING_DEPTH_LIMIT: [
    {
      pattern: /steps_executed.*[1-9][0-9]/i,
      category: "MISSING_DEPTH_LIMIT",
    },
    { pattern: /no.*depth.*limit/i, category: "MISSING_DEPTH_LIMIT" },
  ],
  STATE_POISONING: [
    { pattern: /state.*poison/i, category: "STATE_POISONING" },
    { pattern: /config.*modified.*chain/i, category: "STATE_POISONING" },
  ],
};

/**
 * Detect vulnerability categories from response text.
 * Returns array of detected category names.
 */
export function detectVulnerabilityCategories(responseText: string): string[] {
  const categories: string[] = [];

  for (const [categoryName, patterns] of Object.entries(
    CHAIN_CATEGORY_PATTERNS,
  )) {
    for (const { pattern } of patterns) {
      if (pattern.test(responseText)) {
        if (!categories.includes(categoryName)) {
          categories.push(categoryName);
        }
        break; // Found match for this category, move to next
      }
    }
  }

  return categories;
}

export const CHAIN_EXPLOIT_SAFE_PATTERNS: ChainResponsePattern[] = [
  // Validation-only behavior
  {
    pattern: /stored.*for.*review/i,
    weight: 0.8,
    category: "safe_storage",
    description: "Chain stored for review, not executed",
  },
  {
    pattern: /validation.*only/i,
    weight: 0.9,
    category: "safe_validation",
    description: "Chain validated but not executed",
  },
  {
    pattern: /chain.*validated/i,
    weight: 0.7,
    category: "safe_validation",
    description: "Chain validation response",
  },
  {
    pattern: /pending.*review/i,
    weight: 0.8,
    category: "safe_storage",
    description: "Request pending admin review",
  },
  // Allowlist enforcement
  {
    pattern: /tool.*not.*in.*allowlist/i,
    weight: 0.9,
    category: "allowlist",
    description: "Tool rejected - not in allowlist",
  },
  {
    pattern: /only.*safe.*tools.*permitted/i,
    weight: 0.9,
    category: "allowlist",
    description: "Allowlist enforcement message",
  },
  {
    pattern: /blocked.*tool.*chain/i,
    weight: 0.8,
    category: "allowlist",
    description: "Tool blocked from chain execution",
  },
  // Depth limit enforcement
  {
    pattern: /depth.*limit.*enforced/i,
    weight: 0.8,
    category: "depth_limit",
    description: "Depth limit properly enforced",
  },
  {
    pattern: /max.*depth.*exceeded/i,
    weight: 0.7,
    category: "depth_limit",
    description: "Chain rejected for exceeding depth",
  },
  // No execution indicators
  {
    pattern: /chain_executed.*false/i,
    weight: 0.9,
    category: "no_execution",
    description: "Chain execution disabled",
  },
  {
    pattern: /execution.*disabled/i,
    weight: 0.8,
    category: "no_execution",
    description: "Execution capability disabled",
  },
];

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
// SECRET LEAKAGE PATTERNS (Issue #103, Challenge #9)
// =============================================================================

/**
 * Patterns for detecting secret/credential leakage in tool responses
 * Used by: checkSecretLeakage()
 */
export const SECRET_LEAKAGE_PATTERNS = {
  /** Well-known API key formats */
  apiKeys: [
    /AKIA[A-Z0-9]{16}/, // AWS Access Key
    /sk-[a-zA-Z0-9]{20,}/, // OpenAI Key
    /ghp_[a-zA-Z0-9]{36}/, // GitHub PAT
    /glpat-[a-zA-Z0-9]{20}/, // GitLab PAT
    /xox[baprs]-[a-zA-Z0-9-]+/, // Slack tokens
  ],
  /** Database connection strings with credentials */
  connectionStrings: [
    /(postgresql|mysql|mongodb|redis|mssql):\/\/[^:]+:[^@]+@/i,
  ],
  /** Environment variable patterns with values */
  envVars: [
    /(SECRET_TOKEN|DATABASE_URL|API_KEY|PRIVATE_KEY|DB_PASSWORD)[^\s]*[:=]/i,
  ],
  /** Partial key exposure patterns */
  partialKeys: [/api_key_preview|key_fragment|partial_key/i],
  /** Generic credential assignment patterns */
  credentialAssignment: [
    /(api[_-]?key|secret|password)[^\s]*[:=]\s*["']?[a-zA-Z0-9_-]{10,}/i,
  ],
} as const;

// =============================================================================
// OUTPUT INJECTION PATTERNS (Issue #103, Challenge #8)
// =============================================================================

/**
 * Patterns for detecting tool output injection vulnerabilities
 * Detects when user content is echoed unsanitized in tool output
 * Used by: analyzeOutputInjection()
 */
export const OUTPUT_INJECTION_PATTERNS = {
  /** LLM control patterns that should be sanitized */
  llmControl: [
    /<IMPORTANT>.*<\/IMPORTANT>/is,
    /\[INST\].*\[\/INST\]/is,
    /<\|system\|>.*<\|end\|>/is,
    /\{\{.*\}\}/, // Template vars
  ],
  /** Canary markers for echo detection */
  canaryMarkers: [/SENTINEL_OUTPUT_MARKER_\d+/],
} as const;

// =============================================================================
// EXCESSIVE PERMISSIONS SCOPE PATTERNS (Issue #144, Challenge #22)
// =============================================================================

/**
 * Patterns indicating scope violation in tool response
 * Detects when tools exceed their declared annotations at runtime
 * CWE-250: Execution with Unnecessary Privileges
 * CWE-269: Improper Privilege Management
 */
export const SCOPE_VIOLATION_PATTERNS = [
  {
    pattern: /"scope_violation"\s*:\s*true/i,
    evidence: "scope_violation: true (tool exceeded declared scope)",
  },
  {
    pattern: /"scope_escalation"\s*:\s*true/i,
    evidence: "scope_escalation: true (privilege escalation via input)",
  },
  {
    pattern: /"actual_scope"\s*:\s*"(write|delete|execute|network)"/i,
    evidence: "actual_scope indicates privileged operation",
  },
  {
    pattern: /"privileged_data"\s*:/i,
    evidence: "privileged_data exposed in response",
  },
  {
    pattern: /"system_secrets"\s*:/i,
    evidence: "system_secrets leaked in response",
  },
  {
    pattern: /admin[\s_-]?mode[\s_-]?activated/i,
    evidence: "Admin mode activated via keyword trigger",
  },
] as const;

/**
 * Patterns indicating safe scope enforcement (hardened behavior)
 * Used to confirm tools properly reject privileged actions
 */
export const SCOPE_ENFORCED_PATTERNS = [
  {
    pattern: /"scope_enforced"\s*:\s*true/i,
    evidence: "scope_enforced: true (safe)",
  },
  {
    pattern: /"blocked"\s*:\s*true/i,
    evidence: "Action blocked by allowlist",
  },
  {
    pattern: /action.*not.*in.*allowlist/i,
    evidence: "Allowlist enforcement",
  },
  {
    pattern: /"rejection_reason"\s*:\s*"action_not_in_allowlist"/i,
    evidence: "Explicit rejection: action not in allowlist",
  },
  {
    pattern: /"escalation_attempted"\s*:\s*false/i,
    evidence: "No escalation attempted (safe)",
  },
  {
    pattern: /"allowed_actions"\s*:\s*\[/i,
    evidence: "Allowlist defined and enforced",
  },
] as const;

/**
 * Privileged actions that should be blocked by readOnlyHint=True tools
 */
export const PRIVILEGED_ACTIONS = [
  "write",
  "write_file",
  "delete",
  "delete_data",
  "execute",
  "execute_command",
  "network",
  "network_request",
  "modify",
  "modify_config",
  "admin",
  "environment_access",
] as const;

/**
 * Escalation keywords that may trigger hidden privilege escalation
 */
export const ESCALATION_KEYWORDS = [
  "admin",
  "sudo",
  "elevate",
  "root",
  "superuser",
  "privilege",
] as const;

/**
 * Check if response contains scope violation indicators (Issue #144)
 */
export function hasScopeViolation(text: string): boolean {
  return SCOPE_VIOLATION_PATTERNS.some(({ pattern }) => pattern.test(text));
}

/**
 * Check if response contains scope enforcement indicators (Issue #144)
 */
export function hasScopeEnforcement(text: string): boolean {
  return SCOPE_ENFORCED_PATTERNS.some(({ pattern }) => pattern.test(text));
}

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

/**
 * Check if text contains LLM injection markers (Issue #110, Challenge #8)
 * Detects XML-style tags, chat format markers, and instruction overrides
 */
export function hasLLMInjectionMarkers(text: string): boolean {
  return matchesAny(LLM_INJECTION_MARKERS, text);
}

/**
 * Check if response indicates output injection vulnerability (Issue #110, Challenge #8)
 * Detects tools that self-report including raw/unsanitized content
 */
export function hasOutputInjectionVulnerability(text: string): boolean {
  return (
    matchesAny(OUTPUT_INJECTION_METADATA.rawContentIncluded, text) ||
    matchesAny(OUTPUT_INJECTION_METADATA.vulnerableOutput, text)
  );
}

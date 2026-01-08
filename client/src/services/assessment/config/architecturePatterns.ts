/**
 * Architecture Pattern Configuration
 *
 * Pattern database for detecting server architecture characteristics including:
 * - Database backends (Neo4j, MongoDB, PostgreSQL, etc.)
 * - Transport modes (stdio, HTTP, SSE)
 * - Network access requirements
 *
 * Created as part of Issue #57: Architecture detection and behavior inference modules
 */

/**
 * Database backend types detected from patterns
 */
export type DatabaseBackend =
  | "neo4j"
  | "mongodb"
  | "sqlite"
  | "postgresql"
  | "mysql"
  | "redis"
  | "dynamodb"
  | "firestore"
  | "supabase"
  | "cassandra"
  | "elasticsearch"
  | "unknown";

/**
 * Transport mode capabilities
 */
export type TransportMode = "stdio" | "http" | "sse";

/**
 * Server architecture classification
 */
export type ServerArchitectureType = "local" | "hybrid" | "remote";

/**
 * Database detection patterns.
 * Each database has multiple patterns to catch various naming conventions.
 */
export const DATABASE_PATTERNS: Record<
  Exclude<DatabaseBackend, "unknown">,
  RegExp[]
> = {
  neo4j: [
    /\bneo4j\b/i,
    /\bcypher\b/i,
    /graph\s*database/i,
    /neo4j:\/\//i,
    /\bgraph\s*db\b/i,
  ],
  mongodb: [
    /\bmongodb\b/i,
    /\bmongoose\b/i,
    /\bmongo\b/i,
    /mongodb:\/\//i,
    /mongodb\+srv:\/\//i,
    /\bpymongo\b/i,
  ],
  sqlite: [/\bsqlite\b/i, /\bsqlite3\b/i, /\.sqlite\b/i, /\.db\b/i],
  postgresql: [
    /\bpostgres\b/i,
    /\bpostgresql\b/i,
    /\bpg\b/i,
    /postgres:\/\//i,
    /postgresql:\/\//i,
    /\bpsycopg\b/i,
  ],
  mysql: [/\bmysql\b/i, /\bmariadb\b/i, /mysql:\/\//i, /mariadb:\/\//i],
  redis: [/\bredis\b/i, /redis:\/\//i, /\bupstash\b/i],
  dynamodb: [/\bdynamodb\b/i, /\bdynamo\b/i, /aws.*dynamo/i],
  firestore: [/\bfirestore\b/i, /firebase.*firestore/i],
  supabase: [/\bsupabase\b/i, /supabase\.co/i],
  cassandra: [/\bcassandra\b/i, /\bscylla\b/i, /cql/i],
  elasticsearch: [/\belasticsearch\b/i, /\belastic\b/i, /\bopensearch\b/i],
};

/**
 * Transport detection patterns.
 * Used to identify which transport modes a server supports.
 */
export const TRANSPORT_PATTERNS: Record<TransportMode, RegExp[]> = {
  stdio: [
    /\bstdio\b/i,
    /\bstdin\b/i,
    /\bstdout\b/i,
    /transport.*stdio/i,
    /stdio.*transport/i,
    /process\.stdin/i,
    /process\.stdout/i,
  ],
  http: [
    /\bhttp\s*transport\b/i,
    /streamable-http/i,
    /rest\s*api/i,
    /\bhttp\s*server\b/i,
    /express|fastify|koa|hono/i,
    /app\.listen/i,
  ],
  sse: [
    /\bsse\b/i,
    /server-sent/i,
    /event\s*stream/i,
    /sse\s*transport/i,
    /text\/event-stream/i,
  ],
};

/**
 * Network access indicators.
 * Patterns that suggest the server requires network/internet access.
 */
export const NETWORK_INDICATORS: RegExp[] = [
  // URL patterns
  /https?:\/\//i,
  /wss?:\/\//i,

  // API domain patterns
  /api\.[a-z]+\./i,
  /\.api\./i,

  // HTTP client libraries
  /\bfetch\s*\(/i,
  /\baxios\b/i,
  /\brequest\b/i,
  /\bgot\b/i,
  /\bnode-fetch\b/i,
  /\bundici\b/i,
  /\bhttpx\b/i,
  /\brequests\b/i,
  /\baiohttp\b/i,

  // WebSocket patterns
  /\bwebsocket\b/i,
  /\bsocket\.io\b/i,
  /\bws\b/i,

  // Cloud service patterns
  /aws-sdk/i,
  /\bgoogle-cloud\b/i,
  /azure/i,
];

/**
 * Local-only indicators.
 * Patterns that suggest the server operates locally without network.
 */
export const LOCAL_ONLY_INDICATORS: RegExp[] = [
  // File system operations
  /\bfs\b/i,
  /file\s*system/i,
  /local\s*file/i,
  /\.readFile/i,
  /\.writeFile/i,

  // SQLite (local database)
  /\bsqlite\b/i,

  // Local path patterns
  /~\/|\/home\/|\/Users\//i,

  // Local process execution
  /child_process/i,
  /subprocess/i,
  /\bexec\b/i,
  /\bspawn\b/i,
];

/**
 * External service detection patterns.
 * Maps service names to URL/import patterns.
 */
export const EXTERNAL_SERVICE_PATTERNS: Record<string, RegExp[]> = {
  github: [/github\.com/i, /api\.github/i, /\b@octokit\b/i, /\bgithub\b/i],
  gitlab: [/gitlab\.com/i, /api\.gitlab/i, /\bgitlab\b/i],
  aws: [/aws-sdk/i, /amazonaws\.com/i, /\baws\b/i],
  gcp: [/google-cloud/i, /googleapis\.com/i, /\bgcp\b/i],
  azure: [/azure/i, /microsoft\.com/i],
  openai: [/openai\.com/i, /api\.openai/i, /\bopenai\b/i],
  anthropic: [/anthropic\.com/i, /api\.anthropic/i, /\banthropic\b/i],
  slack: [/slack\.com/i, /api\.slack/i, /\bslack\b/i],
  discord: [/discord\.com/i, /discord\.gg/i, /\bdiscord\b/i],
  stripe: [/stripe\.com/i, /api\.stripe/i, /\bstripe\b/i],
};

/**
 * Architecture pattern configuration interface.
 * Allows customization of all pattern categories.
 */
export interface ArchitecturePatternConfig {
  databases: Record<string, RegExp[]>;
  transports: Record<string, RegExp[]>;
  networkIndicators: RegExp[];
  localOnlyIndicators: RegExp[];
  externalServices: Record<string, RegExp[]>;
}

/**
 * Get default architecture patterns configuration.
 */
export function getDefaultArchitecturePatterns(): ArchitecturePatternConfig {
  return {
    databases: DATABASE_PATTERNS,
    transports: TRANSPORT_PATTERNS,
    networkIndicators: NETWORK_INDICATORS,
    localOnlyIndicators: LOCAL_ONLY_INDICATORS,
    externalServices: EXTERNAL_SERVICE_PATTERNS,
  };
}

/**
 * Detect database backends from text content.
 * Searches for patterns in tool descriptions, source code, or package.json.
 *
 * @param content - Text content to search (description, source code, etc.)
 * @returns Array of detected database backends with match evidence
 */
export function detectDatabasesFromContent(content: string): Array<{
  backend: DatabaseBackend;
  evidence: string;
  confidence: "high" | "medium" | "low";
}> {
  const results: Array<{
    backend: DatabaseBackend;
    evidence: string;
    confidence: "high" | "medium" | "low";
  }> = [];

  for (const [backend, patterns] of Object.entries(DATABASE_PATTERNS)) {
    for (const pattern of patterns) {
      const match = content.match(pattern);
      if (match) {
        // Determine confidence based on pattern specificity
        const confidence =
          pattern.source.includes("://") || pattern.source.includes("\\b")
            ? "high"
            : "medium";

        results.push({
          backend: backend as DatabaseBackend,
          evidence: match[0],
          confidence,
        });
        break; // Only one match per backend
      }
    }
  }

  return results;
}

/**
 * Detect transport modes from text content.
 *
 * @param content - Text content to search
 * @returns Array of detected transport modes
 */
export function detectTransportsFromContent(content: string): TransportMode[] {
  const transports: Set<TransportMode> = new Set();

  for (const [mode, patterns] of Object.entries(TRANSPORT_PATTERNS)) {
    for (const pattern of patterns) {
      if (pattern.test(content)) {
        transports.add(mode as TransportMode);
        break;
      }
    }
  }

  return Array.from(transports);
}

/**
 * Check if content indicates network access requirements.
 *
 * @param content - Text content to search
 * @returns Object with network access flag and matched indicators
 */
export function checkNetworkAccess(content: string): {
  requiresNetwork: boolean;
  indicators: string[];
  localOnly: boolean;
  localIndicators: string[];
} {
  const networkMatches: string[] = [];
  const localMatches: string[] = [];

  for (const pattern of NETWORK_INDICATORS) {
    const match = content.match(pattern);
    if (match) {
      networkMatches.push(match[0]);
    }
  }

  for (const pattern of LOCAL_ONLY_INDICATORS) {
    const match = content.match(pattern);
    if (match) {
      localMatches.push(match[0]);
    }
  }

  return {
    requiresNetwork: networkMatches.length > 0,
    indicators: networkMatches,
    localOnly: localMatches.length > 0 && networkMatches.length === 0,
    localIndicators: localMatches,
  };
}

/**
 * Detect external services from content.
 *
 * @param content - Text content to search
 * @returns Array of detected service names
 */
export function detectExternalServices(content: string): string[] {
  const services: Set<string> = new Set();

  for (const [service, patterns] of Object.entries(EXTERNAL_SERVICE_PATTERNS)) {
    for (const pattern of patterns) {
      if (pattern.test(content)) {
        services.add(service);
        break;
      }
    }
  }

  return Array.from(services);
}

/**
 * Tool Annotation Types
 *
 * Types for tool annotation validation (Policy #17), behavior inference,
 * and server architecture detection. Verifies readOnlyHint, destructiveHint
 * presence and validates annotation/behavior alignment.
 *
 * @module assessment/toolAnnotationTypes
 */

import type {
  AssessmentStatus,
  InferenceConfidence,
  AlignmentStatus,
} from "./coreTypes";

// ============================================================================
// Tool Annotation Types (Policy #17)
// Verifies readOnlyHint, destructiveHint presence
// ============================================================================

/**
 * Source of tool annotations
 */
export type AnnotationSource = "mcp" | "source-code" | "inferred" | "none";

export interface ToolAnnotationResult {
  toolName: string;
  hasAnnotations: boolean;
  annotations?: {
    readOnlyHint?: boolean;
    destructiveHint?: boolean;
    title?: string;
    description?: string;
    idempotentHint?: boolean;
    openWorldHint?: boolean;
  };
  /** Where the annotations were extracted from */
  annotationSource?: AnnotationSource;
  inferredBehavior?: {
    expectedReadOnly: boolean;
    expectedDestructive: boolean;
    reason: string;
    /** Confidence level of the inference */
    confidence: InferenceConfidence;
    /** True if the tool name matches an ambiguous pattern */
    isAmbiguous: boolean;
  };
  /** Alignment status between annotations and inferred behavior */
  alignmentStatus?: AlignmentStatus;
  issues: string[];
  recommendations: string[];
  /** Description poisoning detection (Issue #8) */
  descriptionPoisoning?: {
    detected: boolean;
    patterns: Array<{
      name: string;
      pattern: string;
      severity: "LOW" | "MEDIUM" | "HIGH";
      category: string;
      evidence: string;
    }>;
    riskLevel: "NONE" | "LOW" | "MEDIUM" | "HIGH";
  };
  /** Extended metadata extraction (Issue #54) */
  extendedMetadata?: {
    /** Rate limiting configuration */
    rateLimit?: {
      windowMs?: number;
      maxRequests?: number;
      requestsPerMinute?: number;
      requestsPerSecond?: number;
    };
    /** Permission/scope requirements */
    permissions?: {
      required?: string[];
      scopes?: string[];
    };
    /** Return schema presence */
    returnSchema?: {
      hasSchema: boolean;
      schema?: object;
    };
    /** Bulk operation support */
    bulkOperations?: {
      supported: boolean;
      maxBatchSize?: number;
    };
  };
}

export interface ToolAnnotationAssessment {
  toolResults: ToolAnnotationResult[];
  annotatedCount: number;
  missingAnnotationsCount: number;
  /** Count of high-confidence misalignments only (excludes REVIEW_RECOMMENDED) */
  misalignedAnnotationsCount: number;
  status: AssessmentStatus;
  explanation: string;
  recommendations: string[];
  /** Detailed metrics for annotation quality */
  metrics?: {
    /** Percentage of tools with any annotations (0-100) */
    coverage: number;
    /** Percentage of tools without contradictions (0-100) */
    consistency: number;
    /** Percentage of high-confidence alignments (0-100) */
    correctness: number;
    /** Count of tools needing manual review */
    reviewRequired: number;
  };
  /** Breakdown of tools by alignment status */
  alignmentBreakdown?: {
    aligned: number;
    misaligned: number;
    reviewRecommended: number;
    unknown: number;
  };
  /** Summary of where annotations were extracted from */
  annotationSources?: {
    /** Count from MCP protocol (tools/list response) */
    mcp: number;
    /** Count from source code analysis */
    sourceCode: number;
    /** Count where behavior was inferred from patterns */
    inferred: number;
    /** Count with no annotations found */
    none: number;
  };
  /** Count of tools with poisoned descriptions detected (Issue #8) */
  poisonedDescriptionsDetected?: number;
  /** Extended metadata coverage metrics (Issue #54) */
  extendedMetadataMetrics?: {
    toolsWithRateLimits: number;
    toolsWithPermissions: number;
    toolsWithReturnSchema: number;
    toolsWithBulkSupport: number;
  };
  /** Server architecture analysis (Issue #57) */
  architectureAnalysis?: ArchitectureAnalysis;
  /** Enhanced behavior inference metrics (Issue #57) */
  behaviorInferenceMetrics?: {
    /** Count of tools matched by name patterns */
    namePatternMatches: number;
    /** Count of tools matched by description analysis */
    descriptionMatches: number;
    /** Count of tools matched by schema analysis */
    schemaMatches: number;
    /** Average aggregated confidence across all tools (0-100) */
    aggregatedConfidenceAvg: number;
  };
}

// ============================================================================
// Architecture Detection Types (Issue #57)
// Detects database backends, server types, and transport capabilities
// ============================================================================

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
 * Result of architecture analysis
 * Provides insights into server infrastructure and dependencies
 */
export interface ArchitectureAnalysis {
  /** Classification of server architecture */
  serverType: ServerArchitectureType;
  /** Primary detected database backend (if any) */
  databaseBackend?: DatabaseBackend;
  /** All detected database backends (may include multiple) */
  databaseBackends: DatabaseBackend[];
  /** Detected transport modes the server supports */
  transportModes: TransportMode[];
  /** External services detected (e.g., GitHub, AWS, OpenAI) */
  externalDependencies: string[];
  /** Whether the server requires network/internet access */
  requiresNetworkAccess: boolean;
  /** Confidence level of the analysis */
  confidence: "high" | "medium" | "low";
  /** Evidence supporting the analysis */
  evidence: {
    /** Strings matched that indicate database usage */
    databaseIndicators: string[];
    /** Strings matched that indicate transport modes */
    transportIndicators: string[];
    /** Strings matched that indicate network requirements */
    networkIndicators: string[];
  };
}

// ============================================================================
// Enhanced Behavior Inference Types (Issue #57)
// Multi-signal behavior inference with aggregated confidence
// ============================================================================

/**
 * Signal from a single inference source (name, description, or schema)
 */
export interface InferenceSignal {
  /** Whether this signal indicates read-only behavior */
  expectedReadOnly: boolean;
  /** Whether this signal indicates destructive behavior */
  expectedDestructive: boolean;
  /** Confidence level (0-100) */
  confidence: number;
  /** Evidence explaining why this signal was detected */
  evidence: string[];
}

/**
 * Enhanced behavior inference result with multi-signal analysis
 * Aggregates signals from name patterns, descriptions, and schemas
 */
export interface EnhancedBehaviorInferenceResult {
  /** Final inferred behavior */
  expectedReadOnly: boolean;
  expectedDestructive: boolean;
  /** Primary reason for the inference */
  reason: string;
  /** Overall confidence level */
  confidence: "high" | "medium" | "low";
  /** Whether the inference is ambiguous */
  isAmbiguous: boolean;
  /** Individual signals from each source */
  signals: {
    /** Signal from tool name pattern matching */
    namePatternSignal?: InferenceSignal;
    /** Signal from description keyword analysis */
    descriptionSignal?: InferenceSignal;
    /** Signal from input schema analysis */
    inputSchemaSignal?: InferenceSignal;
    /** Signal from output schema analysis */
    outputSchemaSignal?: InferenceSignal;
  };
  /** Aggregated confidence from all signals (0-100) */
  aggregatedConfidence: number;
}

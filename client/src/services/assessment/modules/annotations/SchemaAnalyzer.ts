/**
 * Schema Analyzer
 *
 * Analyzes input and output schemas for behavioral hints.
 * Provides inference signals based on parameter patterns and return types.
 *
 * Part of Issue #57: Architecture detection and behavior inference modules
 */

import type { InferenceSignal } from "@/lib/assessment/extendedTypes";

/**
 * JSON Schema type definition for tool parameters.
 * Simplified version for analysis purposes.
 */
export interface JSONSchema {
  type?: string | string[];
  properties?: Record<string, JSONSchema>;
  items?: JSONSchema;
  required?: string[];
  description?: string;
  enum?: unknown[];
  additionalProperties?: boolean | JSONSchema;
  format?: string;
  pattern?: string;
  minimum?: number;
  maximum?: number;
  default?: unknown;
}

/**
 * Input schema patterns indicating read-only operations.
 */
export const INPUT_READONLY_PATTERNS = {
  /** ID-only parameters suggest retrieval (e.g., { id: string }) */
  idOnlyParams: /^(id|uuid|key|identifier|resource_id|item_id)$/i,
  /** Query/filter parameters suggest search */
  queryParams: /^(query|q|filter|search|where|criteria|condition)$/i,
  /** Pagination parameters suggest list retrieval */
  paginationParams:
    /^(limit|offset|page|page_size|pageSize|cursor|skip|take)$/i,
  /** Sort/order parameters suggest list retrieval */
  sortParams: /^(sort|order|orderBy|order_by|sortBy|sort_by|direction)$/i,
  /** Field selection suggests retrieval */
  fieldSelectionParams: /^(fields|select|include|exclude|projection)$/i,
};

/**
 * Input schema patterns indicating destructive operations.
 */
export const INPUT_DESTRUCTIVE_PATTERNS = {
  /** Force/confirm flags suggest potentially dangerous operations */
  forceFlags:
    /^(force|confirm|hard|permanent|cascade|recursive|skip_confirmation)$/i,
  /** Hard delete indicators */
  hardDeleteParams: /^(hard_delete|permanent_delete|force_delete|purge)$/i,
};

/**
 * Input schema patterns indicating write operations.
 */
export const INPUT_WRITE_PATTERNS = {
  /** Data payload suggests creation/update */
  dataPayloads:
    /^(data|payload|body|content|item|record|document|entity|object)$/i,
  /** Specific update parameters */
  updateParams: /^(update|changes|modifications|patch|diff)$/i,
  /** Creation parameters */
  createParams: /^(create|new|add|insert|name|title|description)$/i,
};

/**
 * Output schema patterns indicating read-only operations.
 */
/**
 * Recursively check if schema contains array type at any level.
 * Used to detect list/collection return patterns.
 */
function hasArrayTypeRecursive(
  schema: JSONSchema,
  maxDepth: number = 3,
): boolean {
  if (maxDepth <= 0) return false;

  // Direct array type
  if (
    schema.type === "array" ||
    (Array.isArray(schema.type) && schema.type.includes("array"))
  ) {
    return true;
  }

  // Check nested properties
  if (schema.properties) {
    for (const prop of Object.values(schema.properties)) {
      if (hasArrayTypeRecursive(prop, maxDepth - 1)) {
        return true;
      }
    }
  }

  // Check array items
  if (schema.items) {
    if (hasArrayTypeRecursive(schema.items, maxDepth - 1)) {
      return true;
    }
  }

  return false;
}

export const OUTPUT_READONLY_PATTERNS = {
  /** Array return type suggests list/search operation (checks nested schemas) */
  returnsArray: (schema: JSONSchema): boolean => {
    return hasArrayTypeRecursive(schema);
  },
  /** Object with common read-only fields */
  hasReadOnlyFields: (schema: JSONSchema): boolean => {
    if (schema.type !== "object" || !schema.properties) return false;
    const props = Object.keys(schema.properties);
    const readOnlyIndicators = [
      "items",
      "results",
      "data",
      "records",
      "total",
      "count",
      "page",
    ];
    return props.some((p) => readOnlyIndicators.includes(p.toLowerCase()));
  },
};

/**
 * Output schema patterns indicating destructive operations.
 */
export const OUTPUT_DESTRUCTIVE_PATTERNS = {
  /** Returns deleted flag/count */
  returnsDeletedFlag: (schema: JSONSchema): boolean => {
    if (schema.type !== "object" || !schema.properties) return false;
    const props = Object.keys(schema.properties).map((p) => p.toLowerCase());
    return (
      props.includes("deleted") ||
      props.includes("deletedcount") ||
      props.includes("deleted_count") ||
      props.includes("removed") ||
      props.includes("removedcount") ||
      props.includes("removed_count")
    );
  },
  /** Returns void/empty suggests side-effect only */
  returnsVoid: (schema: JSONSchema): boolean => {
    return (
      schema.type === "null" ||
      schema.type === "void" ||
      (schema.type === "object" &&
        (!schema.properties || Object.keys(schema.properties).length === 0))
    );
  },
};

/**
 * Output schema patterns indicating write operations.
 */
export const OUTPUT_WRITE_PATTERNS = {
  /** Returns created object with id and timestamp */
  returnsCreatedObject: (schema: JSONSchema): boolean => {
    if (schema.type !== "object" || !schema.properties) return false;
    const props = Object.keys(schema.properties).map((p) => p.toLowerCase());
    const hasId = props.includes("id") || props.includes("_id");
    const hasTimestamp =
      props.includes("createdat") ||
      props.includes("created_at") ||
      props.includes("timestamp");
    return hasId && hasTimestamp;
  },
  /** Returns single object with ID */
  returnsSingleWithId: (schema: JSONSchema): boolean => {
    if (schema.type !== "object" || !schema.properties) return false;
    const props = Object.keys(schema.properties).map((p) => p.toLowerCase());
    return props.includes("id") || props.includes("_id");
  },
};

/**
 * Analyze input schema for behavioral signals.
 *
 * @param schema - JSON Schema of tool input parameters
 * @returns InferenceSignal with read-only/destructive expectations
 */
export function analyzeInputSchema(schema: JSONSchema): InferenceSignal {
  if (!schema || !schema.properties) {
    return {
      expectedReadOnly: false,
      expectedDestructive: false,
      confidence: 0,
      evidence: ["No input schema or properties provided"],
    };
  }

  const paramNames = Object.keys(schema.properties);
  const evidence: string[] = [];
  let readOnlyScore = 0;
  let destructiveScore = 0;
  let writeScore = 0;

  for (const paramName of paramNames) {
    const lowerName = paramName.toLowerCase();
    const paramSchema = schema.properties[paramName];

    // Check for read-only patterns
    if (INPUT_READONLY_PATTERNS.idOnlyParams.test(paramName)) {
      // ID-only params are read-only only if few other params
      if (paramNames.length <= 2) {
        readOnlyScore += 70;
        evidence.push(`ID-only param pattern: ${paramName}`);
      }
    }
    if (INPUT_READONLY_PATTERNS.queryParams.test(paramName)) {
      readOnlyScore += 80;
      evidence.push(`Query param pattern: ${paramName}`);
    }
    if (INPUT_READONLY_PATTERNS.paginationParams.test(paramName)) {
      readOnlyScore += 90;
      evidence.push(`Pagination param pattern: ${paramName}`);
    }
    if (INPUT_READONLY_PATTERNS.sortParams.test(paramName)) {
      readOnlyScore += 70;
      evidence.push(`Sort param pattern: ${paramName}`);
    }
    if (INPUT_READONLY_PATTERNS.fieldSelectionParams.test(paramName)) {
      readOnlyScore += 70;
      evidence.push(`Field selection param pattern: ${paramName}`);
    }

    // Check for destructive patterns
    if (INPUT_DESTRUCTIVE_PATTERNS.forceFlags.test(paramName)) {
      destructiveScore += 90;
      evidence.push(`Force flag pattern: ${paramName}`);
    }
    if (INPUT_DESTRUCTIVE_PATTERNS.hardDeleteParams.test(paramName)) {
      destructiveScore += 95;
      evidence.push(`Hard delete param pattern: ${paramName}`);
    }

    // Check for write patterns
    if (INPUT_WRITE_PATTERNS.dataPayloads.test(paramName)) {
      writeScore += 80;
      evidence.push(`Data payload param pattern: ${paramName}`);
    }
    if (INPUT_WRITE_PATTERNS.updateParams.test(paramName)) {
      writeScore += 85;
      evidence.push(`Update param pattern: ${paramName}`);
    }

    // Check for array inputs indicating bulk operations
    if (
      paramSchema &&
      paramSchema.type === "array" &&
      paramSchema.items?.type === "string"
    ) {
      // Bulk ID array for deletion
      if (
        lowerName.includes("id") ||
        paramSchema.items.description?.toLowerCase().includes("id")
      ) {
        writeScore += 60;
        evidence.push(`Bulk ID array param: ${paramName}`);
      }
    }

    // Object payload suggests write operation
    if (
      paramSchema &&
      paramSchema.type === "object" &&
      paramSchema.properties
    ) {
      writeScore += 70;
      evidence.push(`Object payload param: ${paramName}`);
    }
  }

  // Determine dominant behavior
  let expectedReadOnly = false;
  let expectedDestructive = false;
  let confidence = 0;

  // Destructive takes priority
  if (destructiveScore > 0 && destructiveScore >= readOnlyScore) {
    expectedDestructive = true;
    confidence = Math.min(100, destructiveScore);
  } else if (readOnlyScore > writeScore && readOnlyScore > 0) {
    expectedReadOnly = true;
    confidence = Math.min(100, readOnlyScore);
  } else if (writeScore > 0) {
    confidence = Math.min(100, writeScore);
  }

  if (evidence.length === 0) {
    evidence.push("No recognizable schema patterns");
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
 * Analyze output schema for behavioral signals.
 *
 * @param schema - JSON Schema of tool output
 * @returns InferenceSignal with read-only/destructive expectations
 */
export function analyzeOutputSchema(schema: JSONSchema): InferenceSignal {
  if (!schema) {
    return {
      expectedReadOnly: false,
      expectedDestructive: false,
      confidence: 0,
      evidence: ["No output schema provided"],
    };
  }

  const evidence: string[] = [];
  let readOnlyScore = 0;
  let destructiveScore = 0;
  let writeScore = 0;

  // Check read-only output patterns
  if (OUTPUT_READONLY_PATTERNS.returnsArray(schema)) {
    readOnlyScore += 85;
    evidence.push("Returns array - suggests list/search operation");
  }
  if (OUTPUT_READONLY_PATTERNS.hasReadOnlyFields(schema)) {
    readOnlyScore += 75;
    evidence.push("Has read-only field patterns (items, results, data)");
  }

  // Check destructive output patterns
  if (OUTPUT_DESTRUCTIVE_PATTERNS.returnsDeletedFlag(schema)) {
    destructiveScore += 90;
    evidence.push("Returns deleted flag/count - suggests deletion");
  }
  if (OUTPUT_DESTRUCTIVE_PATTERNS.returnsVoid(schema)) {
    // Void return could be read-only (status check) or destructive
    // Only slight indicator without other context
    destructiveScore += 30;
    evidence.push("Returns void/empty - possible side-effect operation");
  }

  // Check write output patterns
  if (OUTPUT_WRITE_PATTERNS.returnsCreatedObject(schema)) {
    writeScore += 90;
    evidence.push(
      "Returns object with id and created timestamp - suggests creation",
    );
  } else if (OUTPUT_WRITE_PATTERNS.returnsSingleWithId(schema)) {
    // Single object with ID could be read (get by id) or write (create/update)
    // Weak signal without other context
    writeScore += 40;
    evidence.push("Returns single object with id");
  }

  // Determine dominant behavior
  let expectedReadOnly = false;
  let expectedDestructive = false;
  let confidence = 0;

  // Destructive takes priority if strong signal
  if (destructiveScore >= 80) {
    expectedDestructive = true;
    confidence = Math.min(100, destructiveScore);
  } else if (readOnlyScore > writeScore && readOnlyScore > destructiveScore) {
    expectedReadOnly = true;
    confidence = Math.min(100, readOnlyScore);
  } else if (writeScore >= destructiveScore) {
    confidence = Math.min(100, writeScore);
  }

  if (evidence.length === 0) {
    evidence.push("No recognizable output schema patterns");
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
 * Check if schema has bulk operation indicators.
 *
 * @param schema - Input schema to check
 * @returns True if schema suggests bulk operation support
 */
export function hasBulkOperationIndicators(schema: JSONSchema): boolean {
  if (!schema?.properties) return false;

  const paramNames = Object.keys(schema.properties);
  for (const paramName of paramNames) {
    const paramSchema = schema.properties[paramName];

    // Array parameters often indicate bulk operations
    if (paramSchema?.type === "array") {
      return true;
    }

    // Common bulk operation parameter names
    if (/^(ids|items|records|batch|bulk|list)$/i.test(paramName)) {
      return true;
    }
  }

  return false;
}

/**
 * Check if schema has pagination parameters.
 *
 * @param schema - Input schema to check
 * @returns True if schema has pagination parameters
 */
export function hasPaginationParameters(schema: JSONSchema): boolean {
  if (!schema?.properties) return false;

  const paramNames = Object.keys(schema.properties);
  for (const paramName of paramNames) {
    if (INPUT_READONLY_PATTERNS.paginationParams.test(paramName)) {
      return true;
    }
  }

  return false;
}

/**
 * Check if schema has force/confirm flags.
 *
 * @param schema - Input schema to check
 * @returns True if schema has force/confirm flags
 */
export function hasForceFlags(schema: JSONSchema): boolean {
  if (!schema?.properties) return false;

  const paramNames = Object.keys(schema.properties);
  for (const paramName of paramNames) {
    if (INPUT_DESTRUCTIVE_PATTERNS.forceFlags.test(paramName)) {
      return true;
    }
  }

  return false;
}

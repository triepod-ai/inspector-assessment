"use client";

import { useEffect, useState, useRef, Dispatch, SetStateAction } from "react";
import { Tool } from "@modelcontextprotocol/sdk/types.js";
import { DynamicJsonFormRef } from "@/components/DynamicJsonForm";
import type { JsonSchemaType } from "@/utils/jsonUtils";
import { generateDefaultValue, resolveRef } from "@/utils/schemaUtils";

/**
 * Metadata entry for tool-specific metadata key-value pairs
 */
export interface MetadataEntry {
  id: string;
  key: string;
  value: string;
}

/**
 * Options for useToolsTabState hook
 */
interface UseToolsTabStateOptions {
  selectedTool: Tool | null;
}

/**
 * Return type for useToolsTabState hook
 */
interface UseToolsTabStateReturn {
  // State values
  params: Record<string, unknown>;
  isToolRunning: boolean;
  isOutputSchemaExpanded: boolean;
  isMetadataExpanded: boolean;
  metadataEntries: MetadataEntry[];
  hasValidationErrors: boolean;

  // Refs
  formRefs: React.MutableRefObject<Record<string, DynamicJsonFormRef | null>>;

  // State setters
  setParams: Dispatch<SetStateAction<Record<string, unknown>>>;
  setIsToolRunning: Dispatch<SetStateAction<boolean>>;
  setIsOutputSchemaExpanded: Dispatch<SetStateAction<boolean>>;
  setIsMetadataExpanded: Dispatch<SetStateAction<boolean>>;
  setMetadataEntries: Dispatch<SetStateAction<MetadataEntry[]>>;

  // Helper functions
  checkValidationErrors: () => boolean;
}

/**
 * Custom hook for managing ToolsTab state
 *
 * Extracts all state management logic from ToolsTab component for better
 * testability and maintainability.
 *
 * @param options - Hook configuration options
 * @param options.selectedTool - Currently selected tool (triggers param reset on change)
 * @returns State values, setters, refs, and helper functions
 */
export function useToolsTabState({
  selectedTool,
}: UseToolsTabStateOptions): UseToolsTabStateReturn {
  // Tool input parameters
  const [params, setParams] = useState<Record<string, unknown>>({});

  // Loading state while tool is executing
  const [isToolRunning, setIsToolRunning] = useState(false);

  // UI toggle states
  const [isOutputSchemaExpanded, setIsOutputSchemaExpanded] = useState(false);
  const [isMetadataExpanded, setIsMetadataExpanded] = useState(false);

  // Metadata key-value pairs for tool-specific metadata
  const [metadataEntries, setMetadataEntries] = useState<MetadataEntry[]>([]);

  // Validation error tracking
  const [hasValidationErrors, setHasValidationErrors] = useState(false);

  // Refs to DynamicJsonForm components for validation
  const formRefs = useRef<Record<string, DynamicJsonFormRef | null>>({});

  /**
   * Check if any DynamicJsonForm has validation errors
   * Updates hasValidationErrors state and returns the error status
   */
  const checkValidationErrors = () => {
    const errors = Object.values(formRefs.current).some(
      (ref) => ref && !ref.validateJson().isValid,
    );
    setHasValidationErrors(errors);
    return errors;
  };

  // Reset params and validation state when selected tool changes
  useEffect(() => {
    const newParams = Object.entries(
      selectedTool?.inputSchema.properties ?? [],
    ).map(([key, value]) => {
      // First resolve any $ref references
      const resolvedValue = resolveRef(
        value as JsonSchemaType,
        selectedTool?.inputSchema as JsonSchemaType,
      );
      return [
        key,
        generateDefaultValue(
          resolvedValue,
          key,
          selectedTool?.inputSchema as JsonSchemaType,
        ),
      ];
    });
    setParams(Object.fromEntries(newParams));

    // Reset validation errors when switching tools
    setHasValidationErrors(false);

    // Clear form refs for the previous tool
    formRefs.current = {};
  }, [selectedTool]);

  return {
    // State values
    params,
    isToolRunning,
    isOutputSchemaExpanded,
    isMetadataExpanded,
    metadataEntries,
    hasValidationErrors,

    // Refs
    formRefs,

    // State setters
    setParams,
    setIsToolRunning,
    setIsOutputSchemaExpanded,
    setIsMetadataExpanded,
    setMetadataEntries,

    // Helper functions
    checkValidationErrors,
  };
}

export default useToolsTabState;

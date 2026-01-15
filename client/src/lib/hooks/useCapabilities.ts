import { useState, useCallback, useRef } from "react";
import {
  ClientRequest,
  Resource,
  ResourceTemplate,
  Tool,
  Root,
  ListResourcesResultSchema,
  ListResourceTemplatesResultSchema,
  ListPromptsResultSchema,
  ListToolsResultSchema,
  ReadResourceResultSchema,
  GetPromptResultSchema,
  EmptyResultSchema,
} from "@modelcontextprotocol/sdk/types.js";
import type {
  AnySchema,
  SchemaOutput,
} from "@modelcontextprotocol/sdk/server/zod-compat.js";
import { Prompt } from "@/components/PromptsTab";
import { cacheToolOutputSchemas } from "@/utils/schemaUtils";

/**
 * Options for the useCapabilities hook
 */
export interface UseCapabilitiesOptions {
  /** Function to make MCP requests with error handling */
  sendMCPRequest: <T extends AnySchema>(
    request: ClientRequest,
    schema: T,
    tabKey?: "resources" | "prompts" | "tools",
  ) => Promise<SchemaOutput<T>>;
  /** Ref tracking which tab initiated the tool call */
  lastToolCallOriginTabRef: React.MutableRefObject<string>;
  /** Ref tracking the current tab */
  currentTabRef: React.MutableRefObject<string>;
}

/**
 * Return type for the useCapabilities hook
 */
export interface UseCapabilitiesReturn {
  // Resources
  resources: Resource[];
  resourceTemplates: ResourceTemplate[];
  selectedResource: Resource | null;
  setSelectedResource: (resource: Resource | null) => void;
  resourceContent: string;
  resourceContentMap: Record<string, string>;
  resourceSubscriptions: Set<string>;
  nextResourceCursor: string | undefined;
  nextResourceTemplateCursor: string | undefined;
  listResources: () => Promise<void>;
  listResourceTemplates: () => Promise<void>;
  clearResources: () => void;
  clearResourceTemplates: () => void;
  readResource: (uri: string) => Promise<void>;
  subscribeToResource: (uri: string) => Promise<void>;
  unsubscribeFromResource: (uri: string) => Promise<void>;

  // Prompts
  prompts: Prompt[];
  selectedPrompt: Prompt | null;
  setSelectedPrompt: (prompt: Prompt | null) => void;
  promptContent: string;
  nextPromptCursor: string | undefined;
  listPrompts: () => Promise<void>;
  clearPrompts: () => void;
  getPrompt: (name: string, args?: Record<string, string>) => Promise<void>;

  // Tools
  tools: Tool[];
  selectedTool: Tool | null;
  setSelectedTool: (tool: Tool | null) => void;
  nextToolCursor: string | undefined;
  listTools: () => Promise<void>;
  clearTools: () => void;

  // Roots
  roots: Root[];
  setRoots: React.Dispatch<React.SetStateAction<Root[]>>;
  rootsRef: React.MutableRefObject<Root[]>;

  // Loading state
  isLoading: boolean;
}

/**
 * Custom hook for managing MCP server capabilities
 *
 * Handles resources, prompts, tools, and roots fetching, caching,
 * and selection state.
 *
 * @param options - Hook configuration options
 * @returns Capabilities state and actions
 */
export function useCapabilities({
  sendMCPRequest,
  lastToolCallOriginTabRef,
  currentTabRef,
}: UseCapabilitiesOptions): UseCapabilitiesReturn {
  // Resources state
  const [resources, setResources] = useState<Resource[]>([]);
  const [resourceTemplates, setResourceTemplates] = useState<
    ResourceTemplate[]
  >([]);
  const [selectedResource, setSelectedResource] = useState<Resource | null>(
    null,
  );
  const [resourceContent, setResourceContent] = useState<string>("");
  const [resourceContentMap, setResourceContentMap] = useState<
    Record<string, string>
  >({});
  const [resourceSubscriptions, setResourceSubscriptions] = useState<
    Set<string>
  >(new Set<string>());
  const [nextResourceCursor, setNextResourceCursor] = useState<
    string | undefined
  >();
  const [nextResourceTemplateCursor, setNextResourceTemplateCursor] = useState<
    string | undefined
  >();

  // Prompts state
  const [prompts, setPrompts] = useState<Prompt[]>([]);
  const [selectedPrompt, setSelectedPrompt] = useState<Prompt | null>(null);
  const [promptContent, setPromptContent] = useState<string>("");
  const [nextPromptCursor, setNextPromptCursor] = useState<
    string | undefined
  >();

  // Tools state
  const [tools, setTools] = useState<Tool[]>([]);
  const [selectedTool, setSelectedTool] = useState<Tool | null>(null);
  const [nextToolCursor, setNextToolCursor] = useState<string | undefined>();

  // Roots state
  const [roots, setRoots] = useState<Root[]>([]);
  const rootsRef = useRef<Root[]>([]);

  // Loading state
  const [isLoading, setIsLoading] = useState(false);

  // Resources actions
  const listResources = useCallback(async () => {
    setIsLoading(true);
    try {
      const response = await sendMCPRequest(
        {
          method: "resources/list" as const,
          params: nextResourceCursor ? { cursor: nextResourceCursor } : {},
        },
        ListResourcesResultSchema,
        "resources",
      );
      setResources((prev) => prev.concat(response.resources ?? []));
      setNextResourceCursor(response.nextCursor);
    } finally {
      setIsLoading(false);
    }
  }, [sendMCPRequest, nextResourceCursor]);

  const listResourceTemplates = useCallback(async () => {
    setIsLoading(true);
    try {
      const response = await sendMCPRequest(
        {
          method: "resources/templates/list" as const,
          params: nextResourceTemplateCursor
            ? { cursor: nextResourceTemplateCursor }
            : {},
        },
        ListResourceTemplatesResultSchema,
        "resources",
      );
      setResourceTemplates((prev) =>
        prev.concat(response.resourceTemplates ?? []),
      );
      setNextResourceTemplateCursor(response.nextCursor);
    } finally {
      setIsLoading(false);
    }
  }, [sendMCPRequest, nextResourceTemplateCursor]);

  const clearResources = useCallback(() => {
    setResources([]);
    setNextResourceCursor(undefined);
  }, []);

  const clearResourceTemplates = useCallback(() => {
    setResourceTemplates([]);
    setNextResourceTemplateCursor(undefined);
  }, []);

  const readResource = useCallback(
    async (uri: string) => {
      lastToolCallOriginTabRef.current = currentTabRef.current;

      const response = await sendMCPRequest(
        {
          method: "resources/read" as const,
          params: { uri },
        },
        ReadResourceResultSchema,
        "resources",
      );
      const content = JSON.stringify(response, null, 2);
      setResourceContent(content);
      setResourceContentMap((prev) => ({
        ...prev,
        [uri]: content,
      }));
    },
    [sendMCPRequest, lastToolCallOriginTabRef, currentTabRef],
  );

  const subscribeToResource = useCallback(
    async (uri: string) => {
      if (!resourceSubscriptions.has(uri)) {
        await sendMCPRequest(
          {
            method: "resources/subscribe" as const,
            params: { uri },
          },
          EmptyResultSchema,
          "resources",
        );
        setResourceSubscriptions((prev) => {
          const clone = new Set(prev);
          clone.add(uri);
          return clone;
        });
      }
    },
    [sendMCPRequest, resourceSubscriptions],
  );

  const unsubscribeFromResource = useCallback(
    async (uri: string) => {
      if (resourceSubscriptions.has(uri)) {
        await sendMCPRequest(
          {
            method: "resources/unsubscribe" as const,
            params: { uri },
          },
          EmptyResultSchema,
          "resources",
        );
        setResourceSubscriptions((prev) => {
          const clone = new Set(prev);
          clone.delete(uri);
          return clone;
        });
      }
    },
    [sendMCPRequest, resourceSubscriptions],
  );

  // Prompts actions
  const listPrompts = useCallback(async () => {
    setIsLoading(true);
    try {
      const response = await sendMCPRequest(
        {
          method: "prompts/list" as const,
          params: nextPromptCursor ? { cursor: nextPromptCursor } : {},
        },
        ListPromptsResultSchema,
        "prompts",
      );
      setPrompts(response.prompts as Prompt[]);
      setNextPromptCursor(response.nextCursor);
    } finally {
      setIsLoading(false);
    }
  }, [sendMCPRequest, nextPromptCursor]);

  const clearPrompts = useCallback(() => {
    setPrompts([]);
    setNextPromptCursor(undefined);
  }, []);

  const getPrompt = useCallback(
    async (name: string, args: Record<string, string> = {}) => {
      lastToolCallOriginTabRef.current = currentTabRef.current;

      const response = await sendMCPRequest(
        {
          method: "prompts/get" as const,
          params: { name, arguments: args },
        },
        GetPromptResultSchema,
        "prompts",
      );
      setPromptContent(JSON.stringify(response, null, 2));
    },
    [sendMCPRequest, lastToolCallOriginTabRef, currentTabRef],
  );

  // Tools actions
  const listTools = useCallback(async () => {
    setIsLoading(true);
    try {
      const response = await sendMCPRequest(
        {
          method: "tools/list" as const,
          params: nextToolCursor ? { cursor: nextToolCursor } : {},
        },
        ListToolsResultSchema,
        "tools",
      );
      setTools(response.tools);
      setNextToolCursor(response.nextCursor);
      cacheToolOutputSchemas(response.tools);
    } finally {
      setIsLoading(false);
    }
  }, [sendMCPRequest, nextToolCursor]);

  const clearTools = useCallback(() => {
    setTools([]);
    setNextToolCursor(undefined);
    cacheToolOutputSchemas([]);
  }, []);

  // Keep rootsRef in sync
  const handleSetRoots: React.Dispatch<React.SetStateAction<Root[]>> =
    useCallback((action) => {
      setRoots((prev) => {
        const newRoots = typeof action === "function" ? action(prev) : action;
        rootsRef.current = newRoots;
        return newRoots;
      });
    }, []);

  return {
    // Resources
    resources,
    resourceTemplates,
    selectedResource,
    setSelectedResource,
    resourceContent,
    resourceContentMap,
    resourceSubscriptions,
    nextResourceCursor,
    nextResourceTemplateCursor,
    listResources,
    listResourceTemplates,
    clearResources,
    clearResourceTemplates,
    readResource,
    subscribeToResource,
    unsubscribeFromResource,

    // Prompts
    prompts,
    selectedPrompt,
    setSelectedPrompt,
    promptContent,
    nextPromptCursor,
    listPrompts,
    clearPrompts,
    getPrompt,

    // Tools
    tools,
    selectedTool,
    setSelectedTool,
    nextToolCursor,
    listTools,
    clearTools,

    // Roots
    roots,
    setRoots: handleSetRoots,
    rootsRef,

    // Loading state
    isLoading,
  };
}

export default useCapabilities;

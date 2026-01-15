import { useState, useEffect, useRef, useCallback } from "react";
import { ServerCapabilities } from "@modelcontextprotocol/sdk/types.js";

/**
 * Options for the useTabState hook
 */
export interface UseTabStateOptions {
  /** Server capabilities to determine valid tabs */
  serverCapabilities: ServerCapabilities | null;
  /** Whether the MCP client is connected */
  isConnected: boolean;
}

/**
 * Return type for the useTabState hook
 */
export interface UseTabStateReturn {
  /** Currently active tab */
  activeTab: string;
  /** Set the active tab (also updates URL hash) */
  setActiveTab: (tab: string) => void;
  /** Ref tracking the current tab (for callbacks that need current value) */
  currentTabRef: React.MutableRefObject<string>;
  /** Ref tracking which tab initiated the last tool/resource call */
  lastToolCallOriginTabRef: React.MutableRefObject<string>;
}

/**
 * Get valid tabs based on server capabilities
 */
const getValidTabs = (
  serverCapabilities: ServerCapabilities | null,
): string[] => {
  return [
    ...(serverCapabilities?.resources ? ["resources"] : []),
    ...(serverCapabilities?.prompts ? ["prompts"] : []),
    ...(serverCapabilities?.tools ? ["tools"] : []),
    "ping",
    "sampling",
    "elicitations",
    "roots",
    "auth",
    "metadata",
  ];
};

/**
 * Get default tab based on server capabilities
 */
const getDefaultTab = (
  serverCapabilities: ServerCapabilities | null,
): string => {
  if (serverCapabilities?.resources) return "resources";
  if (serverCapabilities?.prompts) return "prompts";
  if (serverCapabilities?.tools) return "tools";
  return "ping";
};

/**
 * Custom hook for managing tab navigation state
 *
 * Handles tab state, URL hash synchronization, and tab validation
 * based on server capabilities.
 *
 * @param options - Hook configuration options
 * @returns Tab state, setter, and refs for tracking tab context
 */
export function useTabState({
  serverCapabilities,
  isConnected,
}: UseTabStateOptions): UseTabStateReturn {
  // Initialize from URL hash or default
  const [activeTab, setActiveTabState] = useState<string>(() => {
    const hash = window.location.hash.slice(1);
    return hash || "resources";
  });

  // Refs for tracking tab context in callbacks
  const currentTabRef = useRef<string>(activeTab);
  const lastToolCallOriginTabRef = useRef<string>(activeTab);

  // Keep currentTabRef in sync
  useEffect(() => {
    currentTabRef.current = activeTab;
  }, [activeTab]);

  // Wrapper to update both state and URL hash
  const setActiveTab = useCallback((tab: string) => {
    setActiveTabState(tab);
    window.location.hash = tab;
  }, []);

  // Validate tab against server capabilities
  useEffect(() => {
    if (serverCapabilities) {
      const hash = window.location.hash.slice(1);
      const validTabs = getValidTabs(serverCapabilities);
      const isValidTab = validTabs.includes(hash);

      if (!isValidTab) {
        const defaultTab = getDefaultTab(serverCapabilities);
        setActiveTabState(defaultTab);
        window.location.hash = defaultTab;
      }
    }
  }, [serverCapabilities]);

  // Set default hash when connected, clear when disconnected
  useEffect(() => {
    if (isConnected && !window.location.hash) {
      const defaultTab = getDefaultTab(serverCapabilities);
      window.location.hash = defaultTab;
    } else if (!isConnected && window.location.hash) {
      // Clear hash when disconnected
      window.history.replaceState(
        null,
        "",
        window.location.pathname + window.location.search,
      );
    }
  }, [isConnected, serverCapabilities]);

  // Listen for hash changes from browser navigation
  useEffect(() => {
    const handleHashChange = () => {
      const hash = window.location.hash.slice(1);
      if (hash && hash !== activeTab) {
        setActiveTabState(hash);
      }
    };

    window.addEventListener("hashchange", handleHashChange);
    return () => window.removeEventListener("hashchange", handleHashChange);
  }, [activeTab]);

  return {
    activeTab,
    setActiveTab,
    currentTabRef,
    lastToolCallOriginTabRef,
  };
}

export default useTabState;

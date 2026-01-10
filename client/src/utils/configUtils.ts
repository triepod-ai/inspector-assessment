import { InspectorConfig } from "@/lib/configurationTypes";
import {
  DEFAULT_MCP_PROXY_LISTEN_PORT,
  DEFAULT_INSPECTOR_CONFIG,
} from "@/lib/constants";
import { safeParseInspectorConfig } from "@/lib/configurationTypesSchemas";

const getSearchParam = (key: string): string | null => {
  try {
    const url = new URL(window.location.href);
    return url.searchParams.get(key);
  } catch {
    return null;
  }
};

export const getMCPProxyAddress = (config: InspectorConfig): string => {
  const rawValue = config.MCP_PROXY_FULL_ADDRESS?.value;
  let proxyFullAddress =
    typeof rawValue === "string"
      ? rawValue
      : String(
          rawValue ?? DEFAULT_INSPECTOR_CONFIG.MCP_PROXY_FULL_ADDRESS.value,
        );
  if (proxyFullAddress) {
    proxyFullAddress = proxyFullAddress.replace(/\/+$/, "");
    return proxyFullAddress;
  }

  // Check for proxy port from query params, fallback to default
  const proxyPort =
    getSearchParam("MCP_PROXY_PORT") || DEFAULT_MCP_PROXY_LISTEN_PORT;

  return `${window.location.protocol}//${window.location.hostname}:${proxyPort}`;
};

export const getMCPServerRequestTimeout = (config: InspectorConfig): number => {
  const rawValue = config.MCP_SERVER_REQUEST_TIMEOUT?.value;
  return typeof rawValue === "number"
    ? rawValue
    : Number(rawValue) ||
        (DEFAULT_INSPECTOR_CONFIG.MCP_SERVER_REQUEST_TIMEOUT.value as number);
};

export const resetRequestTimeoutOnProgress = (
  config: InspectorConfig,
): boolean => {
  const rawValue = config.MCP_REQUEST_TIMEOUT_RESET_ON_PROGRESS?.value;
  return typeof rawValue === "boolean"
    ? rawValue
    : (DEFAULT_INSPECTOR_CONFIG.MCP_REQUEST_TIMEOUT_RESET_ON_PROGRESS
        .value as boolean);
};

export const getMCPServerRequestMaxTotalTimeout = (
  config: InspectorConfig,
): number => {
  const rawValue = config.MCP_REQUEST_MAX_TOTAL_TIMEOUT?.value;
  return typeof rawValue === "number"
    ? rawValue
    : Number(rawValue) ||
        (DEFAULT_INSPECTOR_CONFIG.MCP_REQUEST_MAX_TOTAL_TIMEOUT
          .value as number);
};

export const getMCPProxyAuthToken = (
  config: InspectorConfig,
): {
  token: string;
  header: string;
} => {
  const rawValue = config.MCP_PROXY_AUTH_TOKEN?.value;
  const token =
    typeof rawValue === "string"
      ? rawValue
      : String(rawValue ?? DEFAULT_INSPECTOR_CONFIG.MCP_PROXY_AUTH_TOKEN.value);
  return {
    token,
    header: "X-MCP-Proxy-Auth",
  };
};

export const getInitialTransportType = ():
  | "stdio"
  | "sse"
  | "streamable-http" => {
  const param = getSearchParam("transport");
  if (param === "stdio" || param === "sse" || param === "streamable-http") {
    return param;
  }
  return (
    (localStorage.getItem("lastTransportType") as
      | "stdio"
      | "sse"
      | "streamable-http") || "stdio"
  );
};

export const getInitialSseUrl = (): string => {
  const param = getSearchParam("serverUrl");
  if (param) return param;
  return localStorage.getItem("lastSseUrl") || "http://localhost:3001/sse";
};

export const getInitialCommand = (): string => {
  const param = getSearchParam("serverCommand");
  if (param) return param;
  return localStorage.getItem("lastCommand") || "mcp-server-everything";
};

export const getInitialArgs = (): string => {
  const param = getSearchParam("serverArgs");
  if (param) return param;
  return localStorage.getItem("lastArgs") || "";
};

// Returns a map of config key -> value from query params if present
export const getConfigOverridesFromQueryParams = (
  defaultConfig: InspectorConfig,
): Partial<InspectorConfig> => {
  const url = new URL(window.location.href);
  const overrides: Partial<InspectorConfig> = {};
  for (const key of Object.keys(defaultConfig)) {
    const param = url.searchParams.get(key);
    if (param !== null) {
      // Try to coerce to correct type based on default value
      const defaultValue = defaultConfig[key as keyof InspectorConfig].value;
      let value: string | number | boolean = param;
      if (typeof defaultValue === "number") {
        value = Number(param);
      } else if (typeof defaultValue === "boolean") {
        value = param === "true";
      }
      overrides[key as keyof InspectorConfig] = {
        ...defaultConfig[key as keyof InspectorConfig],
        value,
      };
    }
  }
  return overrides;
};

export const initializeInspectorConfig = (
  localStorageKey: string,
): InspectorConfig => {
  // Read persistent config from localStorage
  const savedPersistentConfig = localStorage.getItem(localStorageKey);
  // Read ephemeral config from sessionStorage
  const savedEphemeralConfig = sessionStorage.getItem(
    `${localStorageKey}_ephemeral`,
  );

  // Start with default config
  let baseConfig = { ...DEFAULT_INSPECTOR_CONFIG };

  // Apply saved persistent config with validation
  if (savedPersistentConfig) {
    try {
      const parsedPersistentConfig = JSON.parse(savedPersistentConfig);
      // Merge with defaults first to ensure all keys exist
      const mergedConfig = { ...baseConfig, ...parsedPersistentConfig };
      const validationResult = safeParseInspectorConfig(mergedConfig);
      if (validationResult.success) {
        baseConfig = validationResult.data;
      } else {
        console.warn(
          "Invalid config in localStorage, using defaults:",
          validationResult.error.errors.map((e) => e.message),
        );
      }
    } catch (e) {
      console.warn("Failed to parse localStorage config:", e);
    }
  }

  // Apply saved ephemeral config with validation
  if (savedEphemeralConfig) {
    try {
      const parsedEphemeralConfig = JSON.parse(savedEphemeralConfig);
      // Merge with current config
      const mergedConfig = { ...baseConfig, ...parsedEphemeralConfig };
      const validationResult = safeParseInspectorConfig(mergedConfig);
      if (validationResult.success) {
        baseConfig = validationResult.data;
      } else {
        console.warn(
          "Invalid config in sessionStorage, using current config:",
          validationResult.error.errors.map((e) => e.message),
        );
      }
    } catch (e) {
      console.warn("Failed to parse sessionStorage config:", e);
    }
  }

  // Ensure all config items have the latest labels/descriptions from defaults
  for (const [key, value] of Object.entries(baseConfig)) {
    baseConfig[key as keyof InspectorConfig] = {
      ...value,
      label: DEFAULT_INSPECTOR_CONFIG[key as keyof InspectorConfig].label,
      description:
        DEFAULT_INSPECTOR_CONFIG[key as keyof InspectorConfig].description,
      is_session_item:
        DEFAULT_INSPECTOR_CONFIG[key as keyof InspectorConfig].is_session_item,
    };
  }

  // Apply query param overrides
  const overrides = getConfigOverridesFromQueryParams(DEFAULT_INSPECTOR_CONFIG);
  return { ...baseConfig, ...overrides };
};

export const saveInspectorConfig = (
  localStorageKey: string,
  config: InspectorConfig,
): void => {
  const persistentConfig: Partial<InspectorConfig> = {};
  const ephemeralConfig: Partial<InspectorConfig> = {};

  // Split config based on is_session_item flag
  for (const [key, value] of Object.entries(config)) {
    if (value.is_session_item) {
      ephemeralConfig[key as keyof InspectorConfig] = value;
    } else {
      persistentConfig[key as keyof InspectorConfig] = value;
    }
  }

  // Save persistent config to localStorage
  localStorage.setItem(localStorageKey, JSON.stringify(persistentConfig));

  // Save ephemeral config to sessionStorage
  sessionStorage.setItem(
    `${localStorageKey}_ephemeral`,
    JSON.stringify(ephemeralConfig),
  );
};

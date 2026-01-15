import {
  ClientRequest,
  EmptyResultSchema,
  ServerNotification,
  LoggingLevel,
} from "@modelcontextprotocol/sdk/types.js";
import { OAuthTokensSchema } from "@modelcontextprotocol/sdk/shared/auth.js";
import type {
  AnySchema,
  SchemaOutput,
} from "@modelcontextprotocol/sdk/server/zod-compat.js";
import { SESSION_KEYS, getServerSpecificKey } from "./lib/constants";
import {
  hasValidMetaName,
  hasValidMetaPrefix,
  isReservedMetaKey,
} from "@/utils/metaUtils";
import { AuthDebuggerState, EMPTY_DEBUGGER_STATE } from "./lib/auth-types";
import { OAuthStateMachine } from "./lib/oauth-state-machine";
import React, { Suspense, useCallback, useEffect, useState } from "react";

// Hooks
import { useConnection } from "./lib/hooks/useConnection";
import {
  useDraggablePane,
  useDraggableSidebar,
} from "./lib/hooks/useDraggablePane";
import { useNotifications } from "./lib/hooks/useNotifications";
import { useTabState } from "./lib/hooks/useTabState";
import { useSamplingHandler } from "./lib/hooks/useSamplingHandler";
import { useElicitationHandler } from "./lib/hooks/useElicitationHandler";
import { useToolExecution } from "./lib/hooks/useToolExecution";
import { useCapabilities } from "./lib/hooks/useCapabilities";

// UI Components
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import {
  Bell,
  Files,
  FolderTree,
  Hammer,
  Hash,
  Key,
  MessageSquare,
  Settings,
} from "lucide-react";

import "./App.css";
import AuthDebugger from "./components/AuthDebugger";
import ConsoleTab from "./components/ConsoleTab";
import HistoryAndNotifications from "./components/HistoryAndNotifications";
import PingTab from "./components/PingTab";
import PromptsTab from "./components/PromptsTab";
import ResourcesTab from "./components/ResourcesTab";
import RootsTab from "./components/RootsTab";
import SamplingTab from "./components/SamplingTab";
import Sidebar from "./components/Sidebar";
import ToolsTab from "./components/ToolsTab";
import { InspectorConfig } from "./lib/configurationTypes";
import {
  getMCPProxyAddress,
  getMCPProxyAuthToken,
  getInitialSseUrl,
  getInitialTransportType,
  getInitialCommand,
  getInitialArgs,
  initializeInspectorConfig,
  saveInspectorConfig,
} from "./utils/configUtils";
import ElicitationTab from "./components/ElicitationTab";
import {
  CustomHeaders,
  migrateFromLegacyAuth,
} from "./lib/types/customHeaders";
import MetadataTab from "./components/MetadataTab";

const CONFIG_LOCAL_STORAGE_KEY = "inspectorConfig_v1";

const filterReservedMetadata = (
  metadata: Record<string, string>,
): Record<string, string> => {
  return Object.entries(metadata).reduce<Record<string, string>>(
    (acc, [key, value]) => {
      if (
        !isReservedMetaKey(key) &&
        hasValidMetaPrefix(key) &&
        hasValidMetaName(key)
      ) {
        acc[key] = value;
      }
      return acc;
    },
    {},
  );
};

const App = () => {
  // ============================================
  // Connection Configuration State
  // ============================================
  const [command, setCommand] = useState<string>(getInitialCommand);
  const [args, setArgs] = useState<string>(getInitialArgs);
  const [sseUrl, setSseUrl] = useState<string>(getInitialSseUrl);
  const [transportType, setTransportType] = useState<
    "stdio" | "sse" | "streamable-http"
  >(getInitialTransportType);
  const [connectionType, setConnectionType] = useState<"direct" | "proxy">(
    () => {
      return (
        (localStorage.getItem("lastConnectionType") as "direct" | "proxy") ||
        "proxy"
      );
    },
  );
  const [logLevel, setLogLevel] = useState<LoggingLevel>("debug");
  const [env, setEnv] = useState<Record<string, string>>({});
  const [config, setConfig] = useState<InspectorConfig>(() =>
    initializeInspectorConfig(CONFIG_LOCAL_STORAGE_KEY),
  );

  // ============================================
  // Authentication State
  // ============================================
  const [bearerToken, setBearerToken] = useState<string>(() => {
    return localStorage.getItem("lastBearerToken") || "";
  });
  const [headerName, setHeaderName] = useState<string>(() => {
    return localStorage.getItem("lastHeaderName") || "";
  });
  const [oauthClientId, setOauthClientId] = useState<string>(() => {
    return localStorage.getItem("lastOauthClientId") || "";
  });
  const [oauthScope, setOauthScope] = useState<string>(() => {
    return localStorage.getItem("lastOauthScope") || "";
  });
  const [oauthClientSecret, setOauthClientSecret] = useState<string>(() => {
    return localStorage.getItem("lastOauthClientSecret") || "";
  });
  const [customHeaders, setCustomHeaders] = useState<CustomHeaders>(() => {
    const savedHeaders = localStorage.getItem("lastCustomHeaders");
    if (savedHeaders) {
      try {
        return JSON.parse(savedHeaders);
      } catch (error) {
        console.warn(
          `Failed to parse custom headers: "${savedHeaders}", will try legacy migration`,
          error,
        );
      }
    }
    const legacyToken = localStorage.getItem("lastBearerToken") || "";
    const legacyHeaderName = localStorage.getItem("lastHeaderName") || "";
    if (legacyToken) {
      return migrateFromLegacyAuth(legacyToken, legacyHeaderName);
    }
    return [{ name: "Authorization", value: "Bearer ", enabled: false }];
  });
  const [isAuthDebuggerVisible, setIsAuthDebuggerVisible] = useState(false);
  const [authState, setAuthState] =
    useState<AuthDebuggerState>(EMPTY_DEBUGGER_STATE);

  const updateAuthState = (updates: Partial<AuthDebuggerState>) => {
    setAuthState((prev) => ({ ...prev, ...updates }));
  };

  // ============================================
  // Metadata State
  // ============================================
  const [metadata, setMetadata] = useState<Record<string, string>>(() => {
    const savedMetadata = localStorage.getItem("lastMetadata");
    if (savedMetadata) {
      try {
        const parsed = JSON.parse(savedMetadata);
        if (parsed && typeof parsed === "object") {
          return filterReservedMetadata(parsed);
        }
      } catch (error) {
        console.warn("Failed to parse saved metadata:", error);
      }
    }
    return {};
  });

  const handleMetadataChange = (newMetadata: Record<string, string>) => {
    const sanitizedMetadata = filterReservedMetadata(newMetadata);
    setMetadata(sanitizedMetadata);
    localStorage.setItem("lastMetadata", JSON.stringify(sanitizedMetadata));
  };

  // ============================================
  // Error State
  // ============================================
  const [errors, setErrors] = useState<Record<string, string | null>>({
    resources: null,
    prompts: null,
    tools: null,
  });

  const clearError = useCallback((tabKey: keyof typeof errors) => {
    setErrors((prev) => ({ ...prev, [tabKey]: null }));
  }, []);

  const setError = useCallback((tabKey: keyof typeof errors, error: string) => {
    setErrors((prev) => ({ ...prev, [tabKey]: error }));
  }, []);

  // ============================================
  // Draggable Panes
  // ============================================
  const { height: historyPaneHeight, handleDragStart } = useDraggablePane(300);
  const {
    width: sidebarWidth,
    isDragging: isSidebarDragging,
    handleDragStart: handleSidebarDragStart,
  } = useDraggableSidebar(320);

  // ============================================
  // Notifications Hook
  // ============================================
  const {
    notifications,
    addNotification,
    clearNotifications: handleClearNotifications,
  } = useNotifications();

  // ============================================
  // Sampling Handler Hook
  // ============================================
  const {
    pendingRequests: pendingSampleRequests,
    handleSamplingRequest,
    approveRequest: handleApproveSampling,
    rejectRequest: handleRejectSampling,
  } = useSamplingHandler();

  // ============================================
  // Connection Hook
  // ============================================
  const {
    connectionStatus,
    serverCapabilities,
    serverImplementation,
    mcpClient,
    requestHistory,
    clearRequestHistory,
    makeRequest,
    sendNotification,
    handleCompletion,
    completionsSupported,
    connect: connectMcpServer,
    disconnect: disconnectMcpServer,
  } = useConnection({
    transportType,
    command,
    args,
    sseUrl,
    env,
    customHeaders,
    oauthClientId,
    oauthClientSecret,
    oauthScope,
    config,
    connectionType,
    onNotification: (notification) => {
      addNotification(notification as ServerNotification);
    },
    onPendingRequest: (request, resolve, reject) => {
      handleSamplingRequest(request, resolve, reject);
    },
    onElicitationRequest: (request, resolve) => {
      handleElicitationRequest(request, resolve);
    },
    getRoots: () => rootsRef.current,
    defaultLoggingLevel: logLevel,
    metadata,
  });

  // ============================================
  // Tab State Hook
  // ============================================
  const { activeTab, setActiveTab, currentTabRef, lastToolCallOriginTabRef } =
    useTabState({
      serverCapabilities,
      isConnected: !!mcpClient,
    });

  // ============================================
  // Elicitation Handler Hook
  // ============================================
  const {
    pendingRequests: pendingElicitationRequests,
    handleElicitationRequest,
    resolveRequest: handleResolveElicitation,
  } = useElicitationHandler({
    setActiveTab,
    lastToolCallOriginTabRef,
    serverCapabilities,
  });

  // ============================================
  // MCP Request Wrapper (with error handling)
  // ============================================
  const sendMCPRequest = useCallback(
    async <T extends AnySchema>(
      request: ClientRequest,
      schema: T,
      tabKey?: keyof typeof errors,
    ): Promise<SchemaOutput<T>> => {
      try {
        const response = await makeRequest(request, schema);
        if (tabKey !== undefined) {
          clearError(tabKey);
        }
        return response;
      } catch (e) {
        const errorString = (e as Error).message ?? String(e);
        if (tabKey !== undefined) {
          setErrors((prev) => ({ ...prev, [tabKey]: errorString }));
        }
        throw e;
      }
    },
    [makeRequest, clearError],
  );

  // ============================================
  // Capabilities Hook
  // ============================================
  const {
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
    prompts,
    selectedPrompt,
    setSelectedPrompt,
    promptContent,
    nextPromptCursor,
    listPrompts,
    clearPrompts,
    getPrompt,
    tools,
    selectedTool,
    setSelectedTool,
    nextToolCursor,
    listTools,
    clearTools,
    roots,
    setRoots,
    rootsRef,
  } = useCapabilities({
    sendMCPRequest,
    lastToolCallOriginTabRef,
    currentTabRef,
  });

  // ============================================
  // Tool Execution Hook
  // ============================================
  const { toolResult, clearToolResult, callTool } = useToolExecution({
    makeRequest,
    tools,
    metadata,
    lastToolCallOriginTabRef,
    currentTabRef,
    clearError: () => clearError("tools"),
    setError: (_, error) => setError("tools", error),
  });

  // ============================================
  // LocalStorage Persistence Effects
  // ============================================
  useEffect(() => {
    localStorage.setItem("lastCommand", command);
  }, [command]);

  useEffect(() => {
    localStorage.setItem("lastArgs", args);
  }, [args]);

  useEffect(() => {
    localStorage.setItem("lastSseUrl", sseUrl);
  }, [sseUrl]);

  useEffect(() => {
    localStorage.setItem("lastTransportType", transportType);
  }, [transportType]);

  useEffect(() => {
    localStorage.setItem("lastConnectionType", connectionType);
  }, [connectionType]);

  useEffect(() => {
    if (bearerToken) {
      localStorage.setItem("lastBearerToken", bearerToken);
    } else {
      localStorage.removeItem("lastBearerToken");
    }
  }, [bearerToken]);

  useEffect(() => {
    if (headerName) {
      localStorage.setItem("lastHeaderName", headerName);
    } else {
      localStorage.removeItem("lastHeaderName");
    }
  }, [headerName]);

  useEffect(() => {
    localStorage.setItem("lastCustomHeaders", JSON.stringify(customHeaders));
  }, [customHeaders]);

  useEffect(() => {
    if (customHeaders.length === 0 && (bearerToken || headerName)) {
      const migratedHeaders = migrateFromLegacyAuth(bearerToken, headerName);
      if (migratedHeaders.length > 0) {
        setCustomHeaders(migratedHeaders);
        setBearerToken("");
        setHeaderName("");
      }
    }
  }, [bearerToken, headerName, customHeaders]);

  useEffect(() => {
    localStorage.setItem("lastOauthClientId", oauthClientId);
  }, [oauthClientId]);

  useEffect(() => {
    localStorage.setItem("lastOauthScope", oauthScope);
  }, [oauthScope]);

  useEffect(() => {
    localStorage.setItem("lastOauthClientSecret", oauthClientSecret);
  }, [oauthClientSecret]);

  useEffect(() => {
    saveInspectorConfig(CONFIG_LOCAL_STORAGE_KEY, config);
  }, [config]);

  // ============================================
  // OAuth and Config Loading Effects
  // ============================================
  const onOAuthConnect = useCallback(
    (serverUrl: string) => {
      setSseUrl(serverUrl);
      setIsAuthDebuggerVisible(false);
      void connectMcpServer();
    },
    [connectMcpServer],
  );

  const onOAuthDebugConnect = useCallback(
    async ({
      authorizationCode,
      errorMsg,
      restoredState,
    }: {
      authorizationCode?: string;
      errorMsg?: string;
      restoredState?: AuthDebuggerState;
    }) => {
      setIsAuthDebuggerVisible(true);

      if (errorMsg) {
        updateAuthState({ latestError: new Error(errorMsg) });
        return;
      }

      if (restoredState && authorizationCode) {
        let currentState: AuthDebuggerState = {
          ...restoredState,
          authorizationCode,
          oauthStep: "token_request",
          isInitiatingAuth: true,
          statusMessage: null,
          latestError: null,
        };

        try {
          const stateMachine = new OAuthStateMachine(sseUrl, (updates) => {
            currentState = { ...currentState, ...updates };
          });

          while (
            currentState.oauthStep !== "complete" &&
            currentState.oauthStep !== "authorization_code"
          ) {
            await stateMachine.executeStep(currentState);
          }

          if (currentState.oauthStep === "complete") {
            updateAuthState({
              ...currentState,
              statusMessage: {
                type: "success",
                message: "Authentication completed successfully",
              },
              isInitiatingAuth: false,
            });
          }
        } catch (error) {
          console.error("OAuth continuation error:", error);
          updateAuthState({
            latestError:
              error instanceof Error ? error : new Error(String(error)),
            statusMessage: {
              type: "error",
              message: `Failed to complete OAuth flow: ${error instanceof Error ? error.message : String(error)}`,
            },
            isInitiatingAuth: false,
          });
        }
      } else if (authorizationCode) {
        updateAuthState({
          authorizationCode,
          oauthStep: "token_request",
        });
      }
    },
    [sseUrl],
  );

  useEffect(() => {
    const loadOAuthTokens = async () => {
      try {
        if (sseUrl) {
          const key = getServerSpecificKey(SESSION_KEYS.TOKENS, sseUrl);
          const tokens = sessionStorage.getItem(key);
          if (tokens) {
            const parsedTokens = await OAuthTokensSchema.parseAsync(
              JSON.parse(tokens),
            );
            updateAuthState({
              oauthTokens: parsedTokens,
              oauthStep: "complete",
            });
          }
        }
      } catch (error) {
        console.error("Error loading OAuth tokens:", error);
      }
    };
    loadOAuthTokens();
  }, [sseUrl]);

  useEffect(() => {
    const headers: HeadersInit = {};
    const { token: proxyAuthToken, header: proxyAuthTokenHeader } =
      getMCPProxyAuthToken(config);
    if (proxyAuthToken) {
      headers[proxyAuthTokenHeader] = `Bearer ${proxyAuthToken}`;
    }

    fetch(`${getMCPProxyAddress(config)}/config`, { headers })
      .then((response) => response.json())
      .then((data) => {
        setEnv(data.defaultEnvironment);
        if (data.defaultCommand) setCommand(data.defaultCommand);
        if (data.defaultArgs) setArgs(data.defaultArgs);
        if (data.defaultTransport) {
          setTransportType(
            data.defaultTransport as "stdio" | "sse" | "streamable-http",
          );
        }
        if (data.defaultServerUrl) setSseUrl(data.defaultServerUrl);
      })
      .catch((error) =>
        console.error("Error fetching default environment:", error),
      );
  }, [config]);

  // ============================================
  // Action Handlers
  // ============================================
  const handleRootsChange = async () => {
    await sendNotification({ method: "notifications/roots/list_changed" });
  };

  const sendLogLevelRequest = async (level: LoggingLevel) => {
    await sendMCPRequest(
      { method: "logging/setLevel" as const, params: { level } },
      EmptyResultSchema,
    );
    setLogLevel(level);
  };

  // ============================================
  // OAuth Callback Routes
  // ============================================
  if (window.location.pathname === "/oauth/callback") {
    const OAuthCallback = React.lazy(
      () => import("./components/OAuthCallback"),
    );
    return (
      <Suspense fallback={<div>Loading...</div>}>
        <OAuthCallback onConnect={onOAuthConnect} />
      </Suspense>
    );
  }

  if (window.location.pathname === "/oauth/callback/debug") {
    const OAuthDebugCallback = React.lazy(
      () => import("./components/OAuthDebugCallback"),
    );
    return (
      <Suspense fallback={<div>Loading...</div>}>
        <OAuthDebugCallback onConnect={onOAuthDebugConnect} />
      </Suspense>
    );
  }

  // ============================================
  // Component Wrappers
  // ============================================
  const AuthDebuggerWrapper = () => (
    <TabsContent value="auth">
      <AuthDebugger
        serverUrl={sseUrl}
        onBack={() => setIsAuthDebuggerVisible(false)}
        authState={authState}
        updateAuthState={updateAuthState}
      />
    </TabsContent>
  );

  // ============================================
  // Render
  // ============================================
  return (
    <div className="flex h-screen bg-background">
      <div
        style={{
          width: sidebarWidth,
          minWidth: 200,
          maxWidth: 600,
          transition: isSidebarDragging ? "none" : "width 0.15s",
        }}
        className="bg-card border-r border-border flex flex-col h-full relative"
      >
        <Sidebar
          connectionStatus={connectionStatus}
          transportType={transportType}
          setTransportType={setTransportType}
          command={command}
          setCommand={setCommand}
          args={args}
          setArgs={setArgs}
          sseUrl={sseUrl}
          setSseUrl={setSseUrl}
          env={env}
          setEnv={setEnv}
          config={config}
          setConfig={setConfig}
          customHeaders={customHeaders}
          setCustomHeaders={setCustomHeaders}
          oauthClientId={oauthClientId}
          setOauthClientId={setOauthClientId}
          oauthClientSecret={oauthClientSecret}
          setOauthClientSecret={setOauthClientSecret}
          oauthScope={oauthScope}
          setOauthScope={setOauthScope}
          onConnect={connectMcpServer}
          onDisconnect={disconnectMcpServer}
          logLevel={logLevel}
          sendLogLevelRequest={sendLogLevelRequest}
          loggingSupported={!!serverCapabilities?.logging || false}
          connectionType={connectionType}
          setConnectionType={setConnectionType}
          serverImplementation={serverImplementation}
        />
        <div
          onMouseDown={handleSidebarDragStart}
          style={{
            cursor: "col-resize",
            position: "absolute",
            top: 0,
            right: 0,
            width: 6,
            height: "100%",
            zIndex: 10,
            background: isSidebarDragging ? "rgba(0,0,0,0.08)" : "transparent",
          }}
          aria-label="Resize sidebar"
          data-testid="sidebar-drag-handle"
        />
      </div>
      <div className="flex-1 flex flex-col overflow-hidden">
        <div className="flex-1 overflow-auto">
          {mcpClient ? (
            <Tabs
              value={activeTab}
              className="w-full p-4"
              onValueChange={(value) => {
                setActiveTab(value);
                window.location.hash = value;
              }}
            >
              <TabsList className="mb-4 py-0">
                <TabsTrigger
                  value="resources"
                  disabled={!serverCapabilities?.resources}
                >
                  <Files className="w-4 h-4 mr-2" />
                  Resources
                </TabsTrigger>
                <TabsTrigger
                  value="prompts"
                  disabled={!serverCapabilities?.prompts}
                >
                  <MessageSquare className="w-4 h-4 mr-2" />
                  Prompts
                </TabsTrigger>
                <TabsTrigger
                  value="tools"
                  disabled={!serverCapabilities?.tools}
                >
                  <Hammer className="w-4 h-4 mr-2" />
                  Tools
                </TabsTrigger>
                <TabsTrigger value="ping">
                  <Bell className="w-4 h-4 mr-2" />
                  Ping
                </TabsTrigger>
                <TabsTrigger value="sampling" className="relative">
                  <Hash className="w-4 h-4 mr-2" />
                  Sampling
                  {pendingSampleRequests.length > 0 && (
                    <span className="absolute -top-1 -right-1 bg-red-500 text-white text-xs rounded-full h-4 w-4 flex items-center justify-center">
                      {pendingSampleRequests.length}
                    </span>
                  )}
                </TabsTrigger>
                <TabsTrigger value="elicitations" className="relative">
                  <MessageSquare className="w-4 h-4 mr-2" />
                  Elicitations
                  {pendingElicitationRequests.length > 0 && (
                    <span className="absolute -top-1 -right-1 bg-red-500 text-white text-xs rounded-full h-4 w-4 flex items-center justify-center">
                      {pendingElicitationRequests.length}
                    </span>
                  )}
                </TabsTrigger>
                <TabsTrigger value="roots">
                  <FolderTree className="w-4 h-4 mr-2" />
                  Roots
                </TabsTrigger>
                <TabsTrigger value="auth">
                  <Key className="w-4 h-4 mr-2" />
                  Auth
                </TabsTrigger>
                <TabsTrigger value="metadata">
                  <Settings className="w-4 h-4 mr-2" />
                  Metadata
                </TabsTrigger>
              </TabsList>

              <div className="w-full">
                {!serverCapabilities?.resources &&
                !serverCapabilities?.prompts &&
                !serverCapabilities?.tools ? (
                  <>
                    <div className="flex items-center justify-center p-4">
                      <p className="text-lg text-gray-500 dark:text-gray-400">
                        The connected server does not support any MCP
                        capabilities
                      </p>
                    </div>
                    <PingTab
                      onPingClick={() => {
                        void sendMCPRequest(
                          { method: "ping" as const },
                          EmptyResultSchema,
                        );
                      }}
                    />
                  </>
                ) : (
                  <>
                    <ResourcesTab
                      resources={resources}
                      resourceTemplates={resourceTemplates}
                      listResources={() => {
                        clearError("resources");
                        listResources();
                      }}
                      clearResources={clearResources}
                      listResourceTemplates={() => {
                        clearError("resources");
                        listResourceTemplates();
                      }}
                      clearResourceTemplates={clearResourceTemplates}
                      readResource={(uri) => {
                        clearError("resources");
                        readResource(uri);
                      }}
                      selectedResource={selectedResource}
                      setSelectedResource={(resource) => {
                        clearError("resources");
                        setSelectedResource(resource);
                      }}
                      resourceSubscriptionsSupported={
                        serverCapabilities?.resources?.subscribe || false
                      }
                      resourceSubscriptions={resourceSubscriptions}
                      subscribeToResource={(uri) => {
                        clearError("resources");
                        subscribeToResource(uri);
                      }}
                      unsubscribeFromResource={(uri) => {
                        clearError("resources");
                        unsubscribeFromResource(uri);
                      }}
                      handleCompletion={handleCompletion}
                      completionsSupported={completionsSupported}
                      resourceContent={resourceContent}
                      nextCursor={nextResourceCursor}
                      nextTemplateCursor={nextResourceTemplateCursor}
                      error={errors.resources}
                    />
                    <PromptsTab
                      prompts={prompts}
                      listPrompts={() => {
                        clearError("prompts");
                        listPrompts();
                      }}
                      clearPrompts={clearPrompts}
                      getPrompt={(name, args) => {
                        clearError("prompts");
                        getPrompt(name, args);
                      }}
                      selectedPrompt={selectedPrompt}
                      setSelectedPrompt={(prompt) => {
                        clearError("prompts");
                        setSelectedPrompt(prompt);
                      }}
                      handleCompletion={handleCompletion}
                      completionsSupported={completionsSupported}
                      promptContent={promptContent}
                      nextCursor={nextPromptCursor}
                      error={errors.prompts}
                    />
                    <ToolsTab
                      tools={tools}
                      listTools={() => {
                        clearError("tools");
                        listTools();
                      }}
                      clearTools={clearTools}
                      callTool={async (
                        name: string,
                        params: Record<string, unknown>,
                        metadata?: Record<string, unknown>,
                      ) => {
                        clearError("tools");
                        clearToolResult();
                        await callTool(name, params, metadata);
                      }}
                      selectedTool={selectedTool}
                      setSelectedTool={(tool) => {
                        clearError("tools");
                        setSelectedTool(tool);
                        clearToolResult();
                      }}
                      toolResult={toolResult}
                      nextCursor={nextToolCursor}
                      error={errors.tools}
                      resourceContent={resourceContentMap}
                      onReadResource={(uri: string) => {
                        clearError("resources");
                        readResource(uri);
                      }}
                    />
                    <ConsoleTab />
                    <PingTab
                      onPingClick={() => {
                        void sendMCPRequest(
                          { method: "ping" as const },
                          EmptyResultSchema,
                        );
                      }}
                    />
                    <SamplingTab
                      pendingRequests={pendingSampleRequests}
                      onApprove={handleApproveSampling}
                      onReject={handleRejectSampling}
                    />
                    <ElicitationTab
                      pendingRequests={pendingElicitationRequests}
                      onResolve={handleResolveElicitation}
                    />
                    <RootsTab
                      roots={roots}
                      setRoots={setRoots}
                      onRootsChange={handleRootsChange}
                    />
                    <AuthDebuggerWrapper />
                    <MetadataTab
                      metadata={metadata}
                      onMetadataChange={handleMetadataChange}
                    />
                  </>
                )}
              </div>
            </Tabs>
          ) : isAuthDebuggerVisible ? (
            <Tabs
              defaultValue={"auth"}
              className="w-full p-4"
              onValueChange={(value) => (window.location.hash = value)}
            >
              <AuthDebuggerWrapper />
            </Tabs>
          ) : (
            <div className="flex flex-col items-center justify-center h-full gap-4">
              <p className="text-lg text-gray-500 dark:text-gray-400">
                Connect to an MCP server to start inspecting
              </p>
              <div className="flex items-center gap-2">
                <p className="text-sm text-muted-foreground">
                  Need to configure authentication?
                </p>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setIsAuthDebuggerVisible(true)}
                >
                  Open Auth Settings
                </Button>
              </div>
            </div>
          )}
        </div>
        <div
          className="relative border-t border-border"
          style={{ height: `${historyPaneHeight}px` }}
        >
          <div
            className="absolute w-full h-4 -top-2 cursor-row-resize flex items-center justify-center hover:bg-accent/50 dark:hover:bg-input/40"
            onMouseDown={handleDragStart}
          >
            <div className="w-8 h-1 rounded-full bg-border" />
          </div>
          <div className="h-full overflow-auto">
            <HistoryAndNotifications
              requestHistory={requestHistory}
              serverNotifications={notifications}
              onClearHistory={clearRequestHistory}
              onClearNotifications={handleClearNotifications}
            />
          </div>
        </div>
      </div>
    </div>
  );
};

export default App;

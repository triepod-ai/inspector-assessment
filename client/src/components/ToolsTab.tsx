import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { TabsContent } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import DynamicJsonForm, { DynamicJsonFormRef } from "./DynamicJsonForm";
import type { JsonValue, JsonSchemaType } from "@/utils/jsonUtils";
import {
  generateDefaultValue,
  isPropertyRequired,
  normalizeUnionType,
} from "@/utils/schemaUtils";
import {
  CompatibilityCallToolResult,
  ListToolsResult,
  Tool,
} from "@modelcontextprotocol/sdk/types.js";
import {
  Loader2,
  Send,
  ChevronDown,
  ChevronUp,
  AlertCircle,
  Copy,
  CheckCheck,
} from "lucide-react";
import { useEffect, useState, useRef } from "react";
import ListPane from "./ListPane";
import JsonView from "./JsonView";
import ToolResults from "./ToolResults";
import { useToast } from "@/lib/hooks/useToast";
import useCopy from "@/lib/hooks/useCopy";

// Type guard to safely detect the optional _meta field without using `any`
const hasMeta = (tool: Tool): tool is Tool & { _meta: unknown } =>
  typeof (tool as { _meta?: unknown })._meta !== "undefined";

const ToolsTab = ({
  tools,
  listTools,
  clearTools,
  callTool,
  selectedTool,
  setSelectedTool,
  toolResult,
  nextCursor,
  error,
  resourceContent,
  onReadResource,
}: {
  tools: Tool[];
  listTools: () => void;
  clearTools: () => void;
  callTool: (name: string, params: Record<string, unknown>) => Promise<void>;
  selectedTool: Tool | null;
  setSelectedTool: (tool: Tool | null) => void;
  toolResult: CompatibilityCallToolResult | null;
  nextCursor: ListToolsResult["nextCursor"];
  error: string | null;
  resourceContent: Record<string, string>;
  onReadResource?: (uri: string) => void;
}) => {
  const [params, setParams] = useState<Record<string, unknown>>({});
  const [isToolRunning, setIsToolRunning] = useState(false);
  const [isOutputSchemaExpanded, setIsOutputSchemaExpanded] = useState(false);
  const [isMetaExpanded, setIsMetaExpanded] = useState(false);
  const [hasValidationErrors, setHasValidationErrors] = useState(false);
  const formRefs = useRef<Record<string, DynamicJsonFormRef | null>>({});
  const { toast } = useToast();
  const { copied, setCopied } = useCopy();

  // Function to check if any form has validation errors
  const checkValidationErrors = () => {
    const errors = Object.values(formRefs.current).some(
      (ref) => ref && !ref.validateJson().isValid,
    );
    setHasValidationErrors(errors);
    return errors;
  };

  useEffect(() => {
    const params = Object.entries(
      selectedTool?.inputSchema.properties ?? [],
    ).map(([key, value]) => [
      key,
      generateDefaultValue(
        value as JsonSchemaType,
        key,
        selectedTool?.inputSchema as JsonSchemaType,
      ),
    ]);
    setParams(Object.fromEntries(params));

    // Reset validation errors when switching tools
    setHasValidationErrors(false);

    // Clear form refs for the previous tool
    formRefs.current = {};
  }, [selectedTool]);

  return (
    <TabsContent value="tools">
      <div className="grid grid-cols-2 gap-4">
        <ListPane
          items={tools}
          listItems={listTools}
          clearItems={() => {
            clearTools();
            setSelectedTool(null);
          }}
          setSelectedItem={setSelectedTool}
          renderItem={(tool) => (
            <div className="flex flex-col items-start">
              <span className="flex-1">{tool.name}</span>
              <span className="text-sm text-gray-500 text-left">
                {tool.description}
              </span>
            </div>
          )}
          title="Tools"
          buttonText={nextCursor ? "List More Tools" : "List Tools"}
          isButtonDisabled={!nextCursor && tools.length > 0}
        />

        <div className="bg-card border border-border rounded-lg shadow">
          <div className="p-4 border-b border-gray-200 dark:border-border">
            <h3 className="font-semibold">
              {selectedTool ? selectedTool.name : "Select a tool"}
            </h3>
          </div>
          <div className="p-4">
            {selectedTool ? (
              <div className="space-y-4">
                {error && (
                  <Alert variant="destructive">
                    <AlertCircle className="h-4 w-4" />
                    <AlertTitle>Error</AlertTitle>
                    <AlertDescription>{error}</AlertDescription>
                  </Alert>
                )}
                <p className="text-sm text-gray-600 dark:text-gray-400">
                  {selectedTool.description}
                </p>
                {Object.entries(selectedTool.inputSchema.properties ?? []).map(
                  ([key, value]) => {
                    const prop = normalizeUnionType(value as JsonSchemaType);
                    const inputSchema =
                      selectedTool.inputSchema as JsonSchemaType;
                    const required = isPropertyRequired(key, inputSchema);
                    return (
                      <div key={key}>
                        <Label
                          htmlFor={key}
                          className="block text-sm font-medium text-gray-700 dark:text-gray-300"
                        >
                          {key}
                          {required && (
                            <span className="text-red-500 ml-1">*</span>
                          )}
                        </Label>
                        {prop.type === "boolean" ? (
                          <div className="flex items-center space-x-2 mt-2">
                            <Checkbox
                              id={key}
                              name={key}
                              checked={!!params[key]}
                              onCheckedChange={(checked: boolean) =>
                                setParams({
                                  ...params,
                                  [key]: checked,
                                })
                              }
                            />
                            <label
                              htmlFor={key}
                              className="text-sm font-medium text-gray-700 dark:text-gray-300"
                            >
                              {prop.description || "Toggle this option"}
                            </label>
                          </div>
                        ) : prop.type === "string" ? (
                          <Textarea
                            id={key}
                            name={key}
                            placeholder={prop.description}
                            value={
                              params[key] === undefined
                                ? ""
                                : String(params[key])
                            }
                            onChange={(e) => {
                              const value = e.target.value;
                              if (value === "") {
                                // Field cleared - set to undefined
                                setParams({
                                  ...params,
                                  [key]: undefined,
                                });
                              } else {
                                // Field has value - keep as string
                                setParams({
                                  ...params,
                                  [key]: value,
                                });
                              }
                            }}
                            className="mt-1"
                          />
                        ) : prop.type === "object" || prop.type === "array" ? (
                          <div className="mt-1">
                            <DynamicJsonForm
                              ref={(ref) => (formRefs.current[key] = ref)}
                              schema={{
                                type: prop.type,
                                properties: prop.properties,
                                description: prop.description,
                                items: prop.items,
                              }}
                              value={
                                (params[key] as JsonValue) ??
                                generateDefaultValue(prop)
                              }
                              onChange={(newValue: JsonValue) => {
                                setParams({
                                  ...params,
                                  [key]: newValue,
                                });
                                // Check validation after a short delay to allow form to update
                                setTimeout(checkValidationErrors, 100);
                              }}
                            />
                          </div>
                        ) : prop.type === "number" ||
                          prop.type === "integer" ? (
                          <Input
                            type="number"
                            id={key}
                            name={key}
                            placeholder={prop.description}
                            value={
                              params[key] === undefined
                                ? ""
                                : String(params[key])
                            }
                            onChange={(e) => {
                              const value = e.target.value;
                              if (value === "") {
                                // Field cleared - set to undefined
                                setParams({
                                  ...params,
                                  [key]: undefined,
                                });
                              } else {
                                // Field has value - try to convert to number, but store input either way
                                const num = Number(value);
                                if (!isNaN(num)) {
                                  setParams({
                                    ...params,
                                    [key]: num,
                                  });
                                } else {
                                  // Store invalid input as string - let server validate
                                  setParams({
                                    ...params,
                                    [key]: value,
                                  });
                                }
                              }
                            }}
                            className="mt-1"
                          />
                        ) : (
                          <div className="mt-1">
                            <DynamicJsonForm
                              ref={(ref) => (formRefs.current[key] = ref)}
                              schema={{
                                type: prop.type,
                                properties: prop.properties,
                                description: prop.description,
                                items: prop.items,
                              }}
                              value={params[key] as JsonValue}
                              onChange={(newValue: JsonValue) => {
                                setParams({
                                  ...params,
                                  [key]: newValue,
                                });
                                // Check validation after a short delay to allow form to update
                                setTimeout(checkValidationErrors, 100);
                              }}
                            />
                          </div>
                        )}
                      </div>
                    );
                  },
                )}
                {selectedTool.outputSchema && (
                  <div className="bg-gray-50 dark:bg-gray-900 p-3 rounded-lg">
                    <div className="flex items-center justify-between mb-2">
                      <h4 className="text-sm font-semibold">Output Schema:</h4>
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() =>
                          setIsOutputSchemaExpanded(!isOutputSchemaExpanded)
                        }
                        className="h-6 px-2"
                      >
                        {isOutputSchemaExpanded ? (
                          <>
                            <ChevronUp className="h-3 w-3 mr-1" />
                            Collapse
                          </>
                        ) : (
                          <>
                            <ChevronDown className="h-3 w-3 mr-1" />
                            Expand
                          </>
                        )}
                      </Button>
                    </div>
                    <div
                      className={`transition-all ${
                        isOutputSchemaExpanded
                          ? ""
                          : "max-h-[8rem] overflow-y-auto"
                      }`}
                    >
                      <JsonView data={selectedTool.outputSchema} />
                    </div>
                  </div>
                )}
                {selectedTool &&
                  hasMeta(selectedTool) &&
                  selectedTool._meta && (
                    <div className="bg-gray-50 dark:bg-gray-900 p-3 rounded-lg">
                      <div className="flex items-center justify-between mb-2">
                        <h4 className="text-sm font-semibold">Meta:</h4>
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() => setIsMetaExpanded(!isMetaExpanded)}
                          className="h-6 px-2"
                        >
                          {isMetaExpanded ? (
                            <>
                              <ChevronUp className="h-3 w-3 mr-1" />
                              Collapse
                            </>
                          ) : (
                            <>
                              <ChevronDown className="h-3 w-3 mr-1" />
                              Expand
                            </>
                          )}
                        </Button>
                      </div>
                      <div
                        className={`transition-all ${
                          isMetaExpanded ? "" : "max-h-[8rem] overflow-y-auto"
                        }`}
                      >
                        <JsonView data={selectedTool._meta} />
                      </div>
                    </div>
                  )}
                <div className="flex gap-2">
                  <Button
                    onClick={async () => {
                      // Validate JSON inputs before calling tool
                      if (checkValidationErrors()) return;

                      try {
                        setIsToolRunning(true);
                        await callTool(selectedTool.name, params);
                      } finally {
                        setIsToolRunning(false);
                      }
                    }}
                    disabled={isToolRunning || hasValidationErrors}
                  >
                    {isToolRunning ? (
                      <>
                        <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                        Running...
                      </>
                    ) : (
                      <>
                        <Send className="w-4 h-4 mr-2" />
                        Run Tool
                      </>
                    )}
                  </Button>
                  <Button
                    onClick={async () => {
                      try {
                        navigator.clipboard.writeText(
                          JSON.stringify(params, null, 2),
                        );
                        setCopied(true);
                      } catch (error) {
                        toast({
                          title: "Error",
                          description: `There was an error copying input to the clipboard: ${error instanceof Error ? error.message : String(error)}`,
                          variant: "destructive",
                        });
                      }
                    }}
                  >
                    {copied ? (
                      <CheckCheck className="h-4 w-4 mr-2 dark:text-green-700 text-green-600" />
                    ) : (
                      <Copy className="h-4 w-4 mr-2" />
                    )}
                    Copy Input
                  </Button>
                </div>
                <ToolResults
                  toolResult={toolResult}
                  selectedTool={selectedTool}
                  resourceContent={resourceContent}
                  onReadResource={onReadResource}
                />
              </div>
            ) : (
              <Alert>
                <AlertDescription>
                  Select a tool from the list to view its details and run it
                </AlertDescription>
              </Alert>
            )}
          </div>
        </div>
      </div>
    </TabsContent>
  );
};

export default ToolsTab;

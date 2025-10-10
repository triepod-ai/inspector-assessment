import React from "react";
import { ChevronsUpDown, Search } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";
import { Input } from "@/components/ui/input";

interface ToolSelectorProps {
  availableTools: string[];
  selectedTools: string[];
  onChange: (selectedTools: string[]) => void;
  disabled?: boolean;
  placeholder?: string;
}

export function ToolSelector({
  availableTools = [],
  selectedTools = [],
  onChange,
  disabled = false,
  placeholder = "Select tools...",
}: ToolSelectorProps) {
  const [open, setOpen] = React.useState(false);
  const [searchQuery, setSearchQuery] = React.useState("");

  // Filter tools based on search query
  const filteredTools = React.useMemo(() => {
    if (!searchQuery) return availableTools;
    return availableTools.filter((tool) =>
      tool.toLowerCase().includes(searchQuery.toLowerCase()),
    );
  }, [availableTools, searchQuery]);

  // Check if all tools are selected
  const allSelected = selectedTools.length === availableTools.length;

  // Handle individual tool toggle
  const handleToggle = React.useCallback(
    (toolName: string) => {
      const isSelected = selectedTools.includes(toolName);
      if (isSelected) {
        onChange(selectedTools.filter((t) => t !== toolName));
      } else {
        onChange([...selectedTools, toolName]);
      }
    },
    [selectedTools, onChange],
  );

  // Handle select all
  const handleSelectAll = React.useCallback(() => {
    onChange([...availableTools]);
  }, [availableTools, onChange]);

  // Handle deselect all
  const handleDeselectAll = React.useCallback(() => {
    onChange([]);
  }, [onChange]);

  // Display text for the trigger button
  const displayText = React.useMemo(() => {
    if (selectedTools.length === 0) {
      return "No tools selected";
    }
    if (selectedTools.length === availableTools.length) {
      return `All ${availableTools.length} tools`;
    }
    return `${selectedTools.length} of ${availableTools.length} tools`;
  }, [selectedTools.length, availableTools.length]);

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button
          variant="outline"
          role="combobox"
          aria-expanded={open}
          disabled={disabled}
          className="w-full justify-between"
        >
          {displayText}
          <ChevronsUpDown className="ml-2 h-4 w-4 shrink-0 opacity-50" />
        </Button>
      </PopoverTrigger>
      <PopoverContent className="w-[300px] p-0" align="start">
        <div className="flex flex-col">
          {/* Search Input */}
          <div className="flex items-center border-b px-3 py-2">
            <Search className="mr-2 h-4 w-4 shrink-0 opacity-50" />
            <Input
              placeholder={placeholder}
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="h-8 border-0 p-0 focus-visible:ring-0"
            />
          </div>

          {/* Select All / Deselect All Buttons */}
          <div className="flex items-center justify-between border-b px-3 py-2 text-xs">
            <Button
              variant="ghost"
              size="sm"
              onClick={handleSelectAll}
              disabled={allSelected}
              className="h-7 px-2"
            >
              Select All
            </Button>
            <Button
              variant="ghost"
              size="sm"
              onClick={handleDeselectAll}
              disabled={selectedTools.length === 0}
              className="h-7 px-2"
            >
              Deselect All
            </Button>
          </div>

          {/* Tool List */}
          <div className="max-h-[200px] overflow-y-auto p-2">
            {filteredTools.length === 0 ? (
              <div className="py-6 text-center text-sm text-muted-foreground">
                No tools found
              </div>
            ) : (
              filteredTools.map((tool) => {
                const isSelected = selectedTools.includes(tool);
                return (
                  <div
                    key={tool}
                    className="flex items-center space-x-2 rounded-sm px-2 py-1.5 hover:bg-accent cursor-pointer"
                    onClick={() => handleToggle(tool)}
                  >
                    <Checkbox
                      checked={isSelected}
                      onCheckedChange={() => handleToggle(tool)}
                      className="cursor-pointer"
                    />
                    <label className="flex-1 cursor-pointer text-sm">
                      {tool}
                    </label>
                  </div>
                );
              })
            )}
          </div>
        </div>
      </PopoverContent>
    </Popover>
  );
}

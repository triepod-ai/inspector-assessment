/**
 * Assessment Category Filter Component
 * Allows filtering which assessment categories are displayed
 */

import React from "react";
import { Checkbox } from "@/components/ui/checkbox";
import { Label } from "@/components/ui/label";
import { Button } from "@/components/ui/button";
import { ChevronDown, ChevronUp, Filter } from "lucide-react";

export interface CategoryFilterState {
  functionality: boolean;
  security: boolean;
  documentation: boolean;
  errorHandling: boolean;
  usability: boolean;
  mcpSpecCompliance: boolean;
  privacy: boolean;
  // Removed non-essential extended categories: supplyChain, dynamicSecurity, humanInLoop
}

interface AssessmentCategoryFilterProps {
  categories: CategoryFilterState;
  onCategoryChange: (
    category: keyof CategoryFilterState,
    enabled: boolean,
  ) => void;
  onSelectAll: () => void;
  onDeselectAll: () => void;
  isExtendedEnabled: boolean;
}

const categoryLabels: Record<keyof CategoryFilterState, string> = {
  functionality: "Functionality",
  security: "Security",
  documentation: "Documentation",
  errorHandling: "Error Handling",
  usability: "Usability",
  mcpSpecCompliance: "MCP Spec Compliance ⭐⭐⭐",
  privacy: "Privacy Compliance ⭐⭐",
};

const coreCategories: (keyof CategoryFilterState)[] = [
  "functionality",
  "security",
  "documentation",
  "errorHandling",
  "usability",
];

const essentialExtendedCategories: (keyof CategoryFilterState)[] = [
  "mcpSpecCompliance",
  "privacy",
];

export const AssessmentCategoryFilter: React.FC<
  AssessmentCategoryFilterProps
> = ({
  categories,
  onCategoryChange,
  onSelectAll,
  onDeselectAll,
  isExtendedEnabled,
}) => {
  const [isExpanded, setIsExpanded] = React.useState(false);

  const activeCount = Object.values(categories).filter(Boolean).length;
  const totalCount = isExtendedEnabled ? 8 : 5; // 5 core + 3 essential extended

  return (
    <div className="border rounded-lg p-4 mb-4">
      <div
        className="flex items-center justify-between cursor-pointer"
        onClick={() => setIsExpanded(!isExpanded)}
      >
        <div className="flex items-center gap-2">
          <Filter className="h-4 w-4" />
          <h4 className="font-semibold">Filter Categories</h4>
          <span className="text-sm text-muted-foreground">
            ({activeCount}/{totalCount} selected)
          </span>
        </div>
        {isExpanded ? (
          <ChevronUp className="h-4 w-4" />
        ) : (
          <ChevronDown className="h-4 w-4" />
        )}
      </div>

      {isExpanded && (
        <div className="mt-4 space-y-4">
          <div className="flex gap-2">
            <Button
              size="sm"
              variant="outline"
              onClick={onSelectAll}
              className="text-xs"
            >
              Select All
            </Button>
            <Button
              size="sm"
              variant="outline"
              onClick={onDeselectAll}
              className="text-xs"
            >
              Deselect All
            </Button>
          </div>

          <div>
            <h5 className="text-sm font-medium mb-2">Core Categories</h5>
            <div className="grid grid-cols-2 gap-2">
              {coreCategories.map((category) => (
                <div key={category} className="flex items-center space-x-2">
                  <Checkbox
                    id={category}
                    checked={categories[category]}
                    onCheckedChange={(checked) =>
                      onCategoryChange(category, !!checked)
                    }
                  />
                  <Label htmlFor={category} className="text-sm cursor-pointer">
                    {categoryLabels[category]}
                  </Label>
                </div>
              ))}
            </div>
          </div>

          {isExtendedEnabled && (
            <div>
              <div className="mb-3">
                <h5 className="text-sm font-medium mb-1">
                  Essential Extended Categories
                </h5>
                <p className="text-xs text-muted-foreground">
                  Critical for MCP Directory approval by Anthropic hiring
                  managers
                </p>
              </div>
              <div className="grid grid-cols-1 gap-3">
                {essentialExtendedCategories.map((category) => (
                  <div key={category} className="flex items-center space-x-2">
                    <Checkbox
                      id={category}
                      checked={categories[category]}
                      onCheckedChange={(checked) =>
                        onCategoryChange(category, !!checked)
                      }
                    />
                    <Label
                      htmlFor={category}
                      className="text-sm cursor-pointer font-medium"
                    >
                      {categoryLabels[category]}
                    </Label>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

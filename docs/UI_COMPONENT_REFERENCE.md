# UI Component Reference: MCP Inspector Assessment Interface

> **⚠️ DEPRECATION NOTICE (v1.23.0 - 2026-01-04)**
>
> The Assessment Tab UI has been deprecated and removed from the Inspector web interface.
> This document is preserved for historical reference only.
>
> **Assessment functionality is now CLI-only** via:
>
> - `mcp-assess-full` - Full 17-module assessment
> - `mcp-assess-security` - Security-focused assessment
>
> See [CLI_ASSESSMENT_GUIDE.md](CLI_ASSESSMENT_GUIDE.md) for current usage.

**Document Status**: ~~Reference documentation for assessment UI architecture and component patterns.~~ **DEPRECATED**

**Last Updated**: 2026-01-04

**Purpose**: ~~This document provides a comprehensive reference for developers working with the MCP Inspector's assessment UI components, covering architecture, patterns, and extension guidelines.~~ **Historical reference only - UI components have been removed.**

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Component Hierarchy](#component-hierarchy)
3. [Core Components](#core-components)
4. [State Management](#state-management)
5. [Styling Patterns](#styling-patterns)
6. [Adding New Visualizations](#adding-new-visualizations)
7. [Accessibility Guidelines](#accessibility-guidelines)
8. [Testing Patterns](#testing-patterns)

---

## Architecture Overview

The assessment UI follows a component-driven architecture with clear separation of concerns:

- **Presentation Components**: Display assessment results (ExtendedAssessmentCategories, ReviewerAssessmentView)
- **Container Components**: Manage state and orchestration (AssessmentTab)
- **Input Components**: User interaction and configuration (ToolSelector, configuration forms)
- **Service Layer**: Business logic for running assessments (MCPAssessmentService)

### Design Principles

1. **Single Responsibility**: Each component handles one clear concern
2. **Composition Over Inheritance**: Build complex UIs from simple, reusable components
3. **Accessibility First**: WCAG 2.1 AA compliance for all interactive elements
4. **Progressive Disclosure**: Show high-level summary with drill-down capability
5. **Mobile-First Responsive**: Tailwind utility classes for responsive layouts

### Technology Stack

- **React**: 18+ with Hooks and functional components
- **TypeScript**: Full type safety with strict mode
- **Tailwind CSS**: Utility-first styling with dark mode support
- **Lucide Icons**: Consistent icon system
- **shadcn/ui**: Base component library (button, dialog, input, etc.)

---

## Component Hierarchy

```
AssessmentTab (Container)
├── Configuration Section
│   ├── Textarea (README input)
│   ├── ToolSelector (multi-select tool picker)
│   ├── Input (rate limiting delay)
│   └── Checkbox (domain testing toggle)
│
├── Action Buttons
│   ├── Run Assessment Button
│   ├── View Mode Toggle
│   ├── Reset Button
│   ├── Show JSON/Report Toggle
│   └── Export Buttons (Copy, Download)
│
├── Status Display
│   ├── Current Test Alert (progress indicator)
│   └── Error Alert (error display)
│
└── Results Section
    ├── ReviewerAssessmentView (reviewer mode)
    │   └── Simplified, high-level view
    │
    └── Developer View
        ├── UnifiedAssessmentHeader
        │   ├── Overall Status Summary
        │   ├── MCP Directory Checklist
        │   └── Category Overview
        │
        ├── AssessmentCategoryFilter
        │   └── Toggle visibility of assessment categories
        │
        ├── Core Assessment Categories (5)
        │   ├── Functionality Display
        │   ├── Security Display
        │   ├── Documentation Display
        │   ├── Error Handling Display
        │   └── Usability Display
        │
        └── Extended Categories (1)
            └── MCPSpecComplianceDisplay
                ├── Protocol Checks (high confidence)
                └── Metadata Hints (low confidence)
```

---

## Core Components

### 1. AssessmentTab (Container Component)

**Location**: `client/src/components/AssessmentTab.tsx`

**Responsibilities**:

- Assessment orchestration and state management
- Configuration management (README content, tool selection, rate limiting)
- Running assessments via MCPAssessmentService
- Result display mode switching (reviewer vs developer)
- Export functionality (report, JSON)

**Key State Variables**:

```typescript
const [assessment, setAssessment] = useState<MCPDirectoryAssessment | null>(null);
const [isRunning, setIsRunning] = useState(false);
const [currentTest, setCurrentTest] = useState("");
const [readmeContent, setReadmeContent] = useState("");
const [config, setConfig] = useState<AssessmentConfiguration>(DEVELOPER_MODE_CONFIG);
const [error, setError] = useState<string | null>(null);
const [showJson, setShowJson] = useState(false);
const [viewMode, setViewMode] = useState<"reviewer" | "developer">("developer");
const [categoryFilter, setCategoryFilter] = useState<CategoryFilterState>({...});
```

**Key Methods**:

- `runAssessment()`: Initiates full assessment, updates progress, auto-saves results
- `copyReport()`: Copies filtered text report to clipboard
- `downloadReport()`: Downloads filtered text report as .txt file
- `downloadJson()`: Downloads complete assessment as .json file
- `resetAssessment()`: Clears current assessment results
- `calculateFilteredOverallStatus()`: Computes status based on enabled category filters

**Props Interface**:

```typescript
interface AssessmentTabProps {
  tools: Tool[];
  isLoadingTools?: boolean;
  listTools?: () => void;
  callTool: (
    name: string,
    params: Record<string, unknown>,
  ) => Promise<CompatibilityCallToolResult>;
  serverName?: string;
}
```

**Auto-Save Feature**: Assessments are automatically saved to `/tmp/inspector-assessment-{serverName}.json` for troubleshooting via `autoSaveAssessment()` callback.

---

### 2. ExtendedAssessmentCategories

**Location**: `client/src/components/ExtendedAssessmentCategories.tsx`

**Purpose**: Renders extended assessment categories (MCP Spec Compliance) with expandable sections and JSON view.

#### 2.1 ExtendedAssessmentCategory (Base Component)

**Responsibilities**:

- Collapsible category display with header
- Status badge rendering (PASS/FAIL/NEEDS INFO)
- Optional JSON view toggle
- Consistent styling for all extended categories

**Props Interface**:

```typescript
interface ExtendedCategoryProps {
  title: string;
  icon: React.ReactNode;
  status: AssessmentStatus;
  children: React.ReactNode;
  jsonData?: Record<string, unknown>;
  defaultExpanded?: boolean;
}
```

**Status Badge Logic**:

```typescript
const getStatusBadge = () => {
  switch (status) {
    case "PASS":
      return (
        <Badge className="bg-green-100 text-green-800">
          <CheckCircle className="h-3 w-3 mr-1" />
          PASS
        </Badge>
      );
    case "FAIL":
      return (
        <Badge className="bg-red-100 text-red-800">
          <XCircle className="h-3 w-3 mr-1" />
          FAIL
        </Badge>
      );
    case "NEED_MORE_INFO":
      return (
        <Badge className="bg-yellow-100 text-yellow-800">
          <AlertCircle className="h-3 w-3 mr-1" />
          NEEDS INFO
        </Badge>
      );
  }
};
```

#### 2.2 MCPSpecComplianceDisplay

**Responsibilities**:

- Display MCP protocol compliance checks (high confidence)
- Display server metadata hints (low confidence, informational)
- Expandable protocol check details with test methodology
- Manual verification steps for metadata hints

**Key Features**:

- **Two-Section Architecture**: Protocol checks (tested) vs metadata hints (untested)
- **Confidence Levels**: High/Medium/Low badges with explanatory warnings
- **Expandable Details**: Click to reveal test method, evidence, confidence, and raw response
- **Warning Display**: Protocol checks may include warnings for non-blocking issues

**Confidence Level Guidance**:

| Confidence | Source                  | Description                                         |
| ---------- | ----------------------- | --------------------------------------------------- |
| High       | Actual tool call test   | Verified via real MCP request/response cycle        |
| Medium     | Schema validation       | Validated structure but not full behavior           |
| Low        | Server metadata parsing | Indicated in metadata, NOT tested (may be outdated) |

**Example Check Display**:

```
✅ JSON-RPC Compliance (HIGH CONFIDENCE)
   Evidence: Made a test tool call and verified structured JSON-RPC 2.0 response format
   [Click to expand for test method, evidence, confidence, raw response]

⚠️ Structured Output Support (LOW CONFIDENCE)
   Evidence: Schema includes outputSchema property (untested)
   Warning: May have false positives (e.g., Zod/TypeBox schema conversion issues)
```

---

### 3. ToolSelector (Multi-Select Picker)

**Location**: `client/src/components/ui/tool-selector.tsx`

**Purpose**: Allows users to select which tools to include in error handling tests (the most intensive assessment category).

**Key Features**:

- **Multi-select**: Checkbox-based selection with Select All / Deselect All
- **Search**: Real-time filtering by tool name
- **Status Display**: "X of Y tools" summary in trigger button
- **Disabled State**: Prevents interaction during assessment runs

**Props Interface**:

```typescript
interface ToolSelectorProps {
  availableTools: string[];
  selectedTools: string[];
  onChange: (selectedTools: string[]) => void;
  disabled?: boolean;
  placeholder?: string;
}
```

**Implementation Details**:

- Uses shadcn/ui Popover for dropdown
- `useMemo` for filtered tools (performance optimization)
- `useCallback` for event handlers (prevent unnecessary re-renders)
- Search query state managed internally

**Example Usage**:

```tsx
<ToolSelector
  availableTools={tools.map((t) => t.name)}
  selectedTools={config.selectedToolsForTesting ?? tools.map((t) => t.name)}
  onChange={(selectedTools) => {
    setConfig({
      ...config,
      selectedToolsForTesting: selectedTools,
    });
  }}
  disabled={isRunning}
  placeholder="Search tools..."
/>
```

---

### 4. UnifiedAssessmentHeader

**Location**: `client/src/components/UnifiedAssessmentHeader.tsx`

**Purpose**: Provides a high-level summary of assessment results with overall status, checklist, and category overview.

**Key Sections**:

1. **Overall Status**: Large status badge with server name
2. **MCP Directory Checklist**: Pass/fail criteria for directory submission
3. **Category Overview**: Grid view of all assessment categories with status badges

**Used In**: Developer view mode in AssessmentTab.

---

### 5. ReviewerAssessmentView

**Location**: `client/src/components/ReviewerAssessmentView.tsx`

**Purpose**: Simplified view for MCP directory reviewers focusing on pass/fail decisions.

**Key Features**:

- Minimal detail, focus on actionable items
- Clear pass/fail indicators
- Export report button
- Reviewer-focused language

**Used In**: Reviewer view mode in AssessmentTab (currently disabled in UI).

---

### 6. AssessmentCategoryFilter

**Location**: `client/src/components/AssessmentCategoryFilter.tsx`

**Purpose**: Toggle visibility of assessment categories to focus on specific areas.

**Props Interface**:

```typescript
interface AssessmentCategoryFilterProps {
  categories: CategoryFilterState;
  onCategoryChange: (category: string, enabled: boolean) => void;
  onSelectAll: () => void;
  onDeselectAll: () => void;
}

interface CategoryFilterState {
  functionality: boolean;
  security: boolean;
  documentation: boolean;
  errorHandling: boolean;
  usability: boolean;
  mcpSpecCompliance: boolean;
}
```

**Behavior**:

- Filters displayed categories in results section
- Affects overall status calculation (only enabled categories count)
- Select All / Deselect All shortcuts

---

## State Management

### State Architecture

The assessment UI uses **local component state** with React Hooks (no global state management like Redux or Zustand). This is appropriate because:

1. State is UI-scoped (no cross-component sharing beyond parent-child)
2. Assessment results are ephemeral (not persisted between sessions)
3. Configuration is simple (no complex state transitions)

### Key State Patterns

#### 1. Assessment State

```typescript
const [assessment, setAssessment] = useState<MCPDirectoryAssessment | null>(
  null,
);
```

- Holds complete assessment results
- `null` when no assessment has been run
- Updated after successful assessment completion
- Used by all result display components

#### 2. Configuration State

```typescript
const [config, setConfig] = useState<AssessmentConfiguration>(
  DEVELOPER_MODE_CONFIG,
);
```

- Holds user configuration (README content, tool selection, rate limiting)
- Updated via configuration form inputs
- Passed to MCPAssessmentService on run
- Preset configurations: `REVIEWER_MODE_CONFIG`, `DEVELOPER_MODE_CONFIG`

#### 3. UI State

```typescript
const [isRunning, setIsRunning] = useState(false);
const [currentTest, setCurrentTest] = useState("");
const [showJson, setShowJson] = useState(false);
const [viewMode, setViewMode] = useState<"reviewer" | "developer">("developer");
```

- Controls loading states, progress indicators, and view modes
- Disables inputs during assessment runs
- Toggles between JSON and report views

#### 4. Filter State

```typescript
const [categoryFilter, setCategoryFilter] = useState<CategoryFilterState>({
  functionality: true,
  security: true,
  documentation: true,
  errorHandling: true,
  usability: true,
  mcpSpecCompliance: true,
});
```

- Controls which categories are visible and contribute to overall status
- Updated via AssessmentCategoryFilter component
- Affects `calculateFilteredOverallStatus()` logic

### State Update Patterns

#### Callback Optimization

Use `useCallback` for functions passed as props to prevent unnecessary re-renders:

```typescript
const handleToggle = useCallback(
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
```

#### Memoization

Use `useMemo` for expensive computations:

```typescript
const filteredTools = useMemo(() => {
  if (!searchQuery) return availableTools;
  return availableTools.filter((tool) =>
    tool.toLowerCase().includes(searchQuery.toLowerCase()),
  );
}, [availableTools, searchQuery]);
```

#### Service Instance Memoization

```typescript
const assessmentService = useMemo(
  () => new MCPAssessmentService(config),
  [config],
);
```

- Recreate service only when config changes
- Prevents unnecessary service instantiation on every render

---

## Styling Patterns

### Tailwind CSS Approach

The assessment UI uses **utility-first Tailwind CSS** for all styling. No custom CSS files are used.

### Common Patterns

#### 1. Layout and Spacing

```typescript
// Flexbox with gap spacing
<div className="flex items-center gap-2">
  <Icon className="h-4 w-4" />
  <span>Label</span>
</div>

// Grid layout
<div className="grid grid-cols-2 gap-4">
  <div>Column 1</div>
  <div>Column 2</div>
</div>

// Vertical spacing
<div className="space-y-4">
  <div>Item 1</div>
  <div>Item 2</div>
</div>
```

#### 2. Responsive Design

```typescript
// Mobile-first responsive classes
<div className="flex flex-col md:flex-row">
  {/* Stacks vertically on mobile, horizontal on medium+ screens */}
</div>
```

#### 3. Dark Mode Support

```typescript
// Light mode / dark mode variants
<div className="bg-blue-50 dark:bg-blue-950">
  <span className="text-blue-800 dark:text-blue-200">Content</span>
</div>
```

#### 4. Status-Based Styling

```typescript
// Conditional classes based on status
const statusClasses = {
  PASS: "bg-green-100 text-green-800",
  FAIL: "bg-red-100 text-red-800",
  NEED_MORE_INFO: "bg-yellow-100 text-yellow-800",
};

<Badge className={statusClasses[status]}>
  {status}
</Badge>
```

#### 5. Interactive States

```typescript
// Hover, focus, and disabled states
<button className="hover:bg-accent cursor-pointer focus:ring-2 disabled:opacity-50">
  Button
</button>
```

### Component-Specific Patterns

#### Badge Styling

```typescript
<Badge className="bg-green-600 text-white text-xs">HIGH CONFIDENCE</Badge>
<Badge variant="secondary" className="text-xs">
  MEDIUM
</Badge>
<Badge variant="outline" className="text-xs">
  LOW
</Badge>
```

#### Alert/Info Boxes

```typescript
// Informational alert
<div className="bg-blue-50 border border-blue-200 rounded-lg p-3">
  <p className="text-sm text-blue-800 font-medium">ℹ️ Information</p>
  <p className="text-xs text-blue-700">Details...</p>
</div>

// Success indicator
<div className="bg-green-50 border-l-4 border-green-500 rounded p-4">
  <h5 className="text-sm font-semibold text-green-900">Success</h5>
</div>
```

#### Expandable Sections

```typescript
// Clickable header with hover state
<div
  className="flex items-center justify-between p-2 cursor-pointer hover:bg-green-100 transition-colors rounded"
  onClick={() => setExpanded(!expanded)}
>
  <span>Title</span>
  {expanded ? <ChevronUp /> : <ChevronDown />}
</div>
```

---

## Adding New Visualizations

### Step-by-Step Guide

#### 1. Define New Assessment Type

Add interface to `client/src/lib/assessment/resultTypes.ts` (or `configTypes.ts` if configuration-related):

```typescript
// In client/src/lib/assessment/resultTypes.ts
export interface MyNewAssessment {
  status: AssessmentStatus;
  explanation: string;
  myMetric: number;
  myDetails: string[];
  recommendations: string[];
}

// Update main assessment interface (in same file)
export interface MCPDirectoryAssessment {
  // ... existing fields
  myNewAssessment?: MyNewAssessment;
}
```

**Note:** See [ASSESSMENT_TYPES_IMPORT_GUIDE.md](ASSESSMENT_TYPES_IMPORT_GUIDE.md) for detailed module organization. Core types are in `coreTypes.ts`, configuration in `configTypes.ts`, results in `resultTypes.ts`, etc.

#### 2. Implement Assessment Logic

Create assessor in `client/src/services/assessment/modules/`:

```typescript
// MyNewAssessor.ts
export class MyNewAssessor {
  async assess(
    tools: Tool[],
    callTool: CallToolFunction,
  ): Promise<MyNewAssessment> {
    // Assessment logic here
    return {
      status: "PASS",
      explanation: "Assessment explanation",
      myMetric: 95.0,
      myDetails: ["Detail 1", "Detail 2"],
      recommendations: ["Recommendation 1"],
    };
  }
}
```

#### 3. Integrate into Assessment Service

Update `client/src/services/assessmentService.ts`:

```typescript
import { MyNewAssessor } from "./assessment/modules/MyNewAssessor";

class MCPAssessmentService {
  async runFullAssessment(...) {
    const myNewAssessor = new MyNewAssessor();
    const myNewAssessment = await myNewAssessor.assess(tools, callTool);

    return {
      // ... existing assessments
      myNewAssessment,
    };
  }
}
```

#### 4. Create Display Component

Add display component to `ExtendedAssessmentCategories.tsx`:

```typescript
interface MyNewAssessmentProps {
  assessment: MyNewAssessment;
}

export const MyNewAssessmentDisplay: React.FC<MyNewAssessmentProps> = ({
  assessment,
}) => {
  return (
    <ExtendedAssessmentCategory
      title="My New Assessment"
      icon={<MyIcon className="h-5 w-5 text-purple-600" />}
      status={assessment.status}
      jsonData={assessment as unknown as Record<string, unknown>}
    >
      <div className="space-y-4">
        <p className="text-sm">{assessment.explanation}</p>

        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="text-xs text-muted-foreground">My Metric</label>
            <p className="text-sm font-medium">{assessment.myMetric.toFixed(1)}%</p>
          </div>
        </div>

        {assessment.myDetails.length > 0 && (
          <div>
            <h5 className="text-sm font-semibold mb-2">Details</h5>
            <ul className="list-disc list-inside text-sm space-y-1">
              {assessment.myDetails.map((detail, idx) => (
                <li key={idx}>{detail}</li>
              ))}
            </ul>
          </div>
        )}

        {assessment.recommendations && assessment.recommendations.length > 0 && (
          <div className="bg-gray-50 border border-gray-200 rounded-lg p-4">
            <h5 className="text-sm font-semibold mb-3 text-gray-900">
              Recommendations
            </h5>
            <div className="space-y-2">
              {assessment.recommendations.map((rec, idx) => (
                <div key={idx} className="text-sm text-gray-700 flex items-start gap-2">
                  <span className="text-gray-400 mt-0.5">•</span>
                  <span>{rec}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </ExtendedAssessmentCategory>
  );
};
```

#### 5. Add to AssessmentTab Rendering

Update `AssessmentTab.tsx` results section:

```typescript
import { MyNewAssessmentDisplay } from "./ExtendedAssessmentCategories";

// In the results section:
{
  assessment.myNewAssessment && (
    <MyNewAssessmentDisplay assessment={assessment.myNewAssessment} />
  );
}
```

#### 6. Add Category Filter (Optional)

Update `CategoryFilterState` in `client/src/lib/assessment/resultTypes.ts`:

```typescript
interface CategoryFilterState {
  // ... existing categories
  myNewAssessment: boolean;
}
```

Update `AssessmentCategoryFilter.tsx` to include the new category.

Update `calculateFilteredOverallStatus()` in `AssessmentTab.tsx`:

```typescript
if (categoryFilter.myNewAssessment && assessment.myNewAssessment) {
  statuses.push(assessment.myNewAssessment.status);
}
```

**Import Note:** Use the modular import path when working with these types:

```typescript
import type {
  CategoryFilterState,
  MCPDirectoryAssessment,
} from "@/lib/assessment/resultTypes";
// Or the barrel export:
import type {
  CategoryFilterState,
  MCPDirectoryAssessment,
} from "@/lib/assessment";
```

---

## Accessibility Guidelines

The assessment UI follows **WCAG 2.1 AA** accessibility standards. All new components must adhere to these guidelines.

### Core Accessibility Requirements

#### 1. Semantic HTML

Use semantic HTML elements for proper screen reader support:

```typescript
// ✅ Good: Semantic button
<button onClick={handleClick}>Submit</button>

// ❌ Bad: Non-semantic div
<div onClick={handleClick}>Submit</div>
```

#### 2. ARIA Attributes

Add ARIA attributes for custom interactive elements:

```typescript
<Button
  variant="outline"
  role="combobox"
  aria-expanded={open}
  aria-label="Select tools"
>
  Select Tools
</Button>

<div
  role="button"
  aria-expanded={expanded}
  aria-label={`${expanded ? "Collapse" : "Expand"} resource ${uri}`}
  onClick={toggleExpanded}
>
  {expanded ? <ChevronUp /> : <ChevronDown />}
</div>
```

#### 3. Keyboard Navigation

Ensure all interactive elements are keyboard accessible:

- **Tab**: Navigate between elements
- **Enter/Space**: Activate buttons and checkboxes
- **Escape**: Close dialogs and popovers
- **Arrow Keys**: Navigate within lists and dropdowns

```typescript
// shadcn/ui components handle keyboard navigation automatically
<Popover open={open} onOpenChange={setOpen}>
  <PopoverTrigger asChild>
    <Button>Open</Button>
  </PopoverTrigger>
  <PopoverContent>
    {/* Escape key closes automatically */}
  </PopoverContent>
</Popover>
```

#### 4. Focus Management

Maintain visible focus indicators:

```typescript
// Tailwind focus utilities
<button className="focus:ring-2 focus:ring-blue-500 focus:outline-none">
  Button
</button>
```

#### 5. Color Contrast

Ensure text meets WCAG AA contrast ratios (4.5:1 for normal text, 3:1 for large text):

```typescript
// ✅ Good: High contrast
<div className="bg-blue-50">
  <span className="text-blue-800">High contrast text</span>
</div>

// ❌ Bad: Low contrast
<div className="bg-gray-100">
  <span className="text-gray-200">Low contrast text</span>
</div>
```

#### 6. Alternative Text

Provide text alternatives for icons and images:

```typescript
// Use aria-label for icon-only buttons
<button aria-label="Delete item">
  <Trash className="h-4 w-4" />
</button>

// Use aria-hidden for decorative icons
<div>
  <span className="mr-2" aria-hidden="true">
    <CheckCircle className="h-4 w-4" />
  </span>
  <span>Success message</span>
</div>
```

#### 7. Form Validation

Associate labels with inputs and provide error messages:

```typescript
<div className="space-y-2">
  <Label htmlFor="readme">README Content</Label>
  <Textarea
    id="readme"
    value={readmeContent}
    onChange={(e) => setReadmeContent(e.target.value)}
    aria-invalid={hasError}
    aria-describedby={hasError ? "readme-error" : undefined}
  />
  {hasError && (
    <p id="readme-error" className="text-sm text-red-600">
      README content is required
    </p>
  )}
</div>
```

#### 8. Loading States

Announce loading states to screen readers:

```typescript
<Button disabled={isRunning}>
  {isRunning ? (
    <>
      <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
      <span className="sr-only">Running assessment, please wait...</span>
      Running Assessment...
    </>
  ) : (
    <>
      <Play className="h-4 w-4" />
      Run Assessment
    </>
  )}
</Button>
```

### Accessibility Checklist for New Components

- [ ] Use semantic HTML elements (button, nav, main, etc.)
- [ ] Add ARIA attributes for custom interactive elements
- [ ] Ensure keyboard navigation works (Tab, Enter, Escape, Arrow keys)
- [ ] Maintain visible focus indicators
- [ ] Test color contrast ratios (use browser DevTools)
- [ ] Provide alternative text for icons and images
- [ ] Associate labels with form inputs
- [ ] Announce loading and error states to screen readers
- [ ] Test with screen reader (NVDA, JAWS, or VoiceOver)

---

## Testing Patterns

### Component Testing Strategy

The assessment UI uses **Jest** and **React Testing Library** for component tests.

#### Test File Location

Component tests are located in `client/src/services/__tests__/` and `client/src/services/assessment/__tests__/`.

#### Testing Principles

1. **Test behavior, not implementation**: Focus on user interactions and outcomes
2. **Query by accessibility attributes**: Use `getByRole`, `getByLabelText`, not `getByClassName`
3. **Mock external dependencies**: Mock service layer, API calls, and MCP tool calls
4. **Test edge cases**: Empty states, error states, loading states

### Example Test Structure

```typescript
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AssessmentTab } from "../AssessmentTab";

describe("AssessmentTab", () => {
  const mockCallTool = jest.fn();
  const mockListTools = jest.fn();
  const mockTools = [
    {
      name: "test_tool_1",
      description: "Test tool 1",
      inputSchema: {
        type: "object",
        properties: {},
      },
    },
  ];

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it("renders configuration section", () => {
    render(
      <AssessmentTab
        tools={mockTools}
        callTool={mockCallTool}
        listTools={mockListTools}
        serverName="test-server"
      />
    );

    expect(screen.getByLabelText(/readme content/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /run assessment/i })).toBeInTheDocument();
  });

  it("disables run button when no tools are loaded", () => {
    render(
      <AssessmentTab tools={[]} callTool={mockCallTool} serverName="test-server" />
    );

    const runButton = screen.getByRole("button", { name: /run assessment/i });
    expect(runButton).toBeDisabled();
  });

  it("runs assessment when button is clicked", async () => {
    const user = userEvent.setup();
    mockCallTool.mockResolvedValue({
      content: [{ type: "text", text: "Success" }],
    });

    render(
      <AssessmentTab
        tools={mockTools}
        callTool={mockCallTool}
        serverName="test-server"
      />
    );

    const runButton = screen.getByRole("button", { name: /run assessment/i });
    await user.click(runButton);

    await waitFor(() => {
      expect(mockCallTool).toHaveBeenCalled();
    });
  });

  it("displays error when assessment fails", async () => {
    const user = userEvent.setup();
    mockCallTool.mockRejectedValue(new Error("Test error"));

    render(
      <AssessmentTab
        tools={mockTools}
        callTool={mockCallTool}
        serverName="test-server"
      />
    );

    const runButton = screen.getByRole("button", { name: /run assessment/i });
    await user.click(runButton);

    await waitFor(() => {
      expect(screen.getByText(/test error/i)).toBeInTheDocument();
    });
  });
});
```

### Testing ToolSelector

```typescript
import { render, screen, fireEvent } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ToolSelector } from "../ui/tool-selector";

describe("ToolSelector", () => {
  const mockOnChange = jest.fn();
  const availableTools = ["tool1", "tool2", "tool3"];

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it("renders with correct display text", () => {
    render(
      <ToolSelector
        availableTools={availableTools}
        selectedTools={["tool1", "tool2"]}
        onChange={mockOnChange}
      />
    );

    expect(screen.getByRole("combobox")).toHaveTextContent("2 of 3 tools");
  });

  it("filters tools based on search query", async () => {
    const user = userEvent.setup();
    render(
      <ToolSelector
        availableTools={availableTools}
        selectedTools={[]}
        onChange={mockOnChange}
      />
    );

    const combobox = screen.getByRole("combobox");
    await user.click(combobox);

    const searchInput = screen.getByPlaceholderText(/select tools/i);
    await user.type(searchInput, "tool1");

    expect(screen.getByLabelText("tool1")).toBeInTheDocument();
    expect(screen.queryByLabelText("tool2")).not.toBeInTheDocument();
  });

  it("calls onChange when tool is selected", async () => {
    const user = userEvent.setup();
    render(
      <ToolSelector
        availableTools={availableTools}
        selectedTools={[]}
        onChange={mockOnChange}
      />
    );

    const combobox = screen.getByRole("combobox");
    await user.click(combobox);

    const checkbox = screen.getByLabelText("tool1");
    await user.click(checkbox);

    expect(mockOnChange).toHaveBeenCalledWith(["tool1"]);
  });
});
```

### Running Tests

```bash
# Run all tests
npm test

# Run tests in watch mode
npm test -- --watch

# Run specific test file
npm test -- ToolSelector.test.tsx

# Run tests with coverage
npm test -- --coverage
```

---

## Common Patterns Reference

### Collapsible Section Pattern

```typescript
const [isExpanded, setIsExpanded] = useState(false);

<div>
  <div
    className="cursor-pointer hover:bg-muted/50 transition-colors p-4"
    onClick={() => setIsExpanded(!isExpanded)}
  >
    <div className="flex items-center justify-between">
      <h4 className="font-semibold">Section Title</h4>
      {isExpanded ? <ChevronUp /> : <ChevronDown />}
    </div>
  </div>

  {isExpanded && (
    <div className="border-t p-4 bg-muted/20">
      {/* Section content */}
    </div>
  )}
</div>
```

### Status Badge Pattern

```typescript
const getStatusBadge = (status: AssessmentStatus) => {
  const variants = {
    PASS: {
      className: "bg-green-100 text-green-800",
      icon: CheckCircle,
      label: "PASS",
    },
    FAIL: {
      className: "bg-red-100 text-red-800",
      icon: XCircle,
      label: "FAIL",
    },
    NEED_MORE_INFO: {
      className: "bg-yellow-100 text-yellow-800",
      icon: AlertCircle,
      label: "NEEDS INFO",
    },
  };

  const variant = variants[status];
  const Icon = variant.icon;

  return (
    <Badge className={variant.className}>
      <Icon className="h-3 w-3 mr-1" />
      {variant.label}
    </Badge>
  );
};
```

### Loading State Pattern

```typescript
const [isLoading, setIsLoading] = useState(false);

<Button disabled={isLoading}>
  {isLoading ? (
    <>
      <Loader2 className="h-4 w-4 animate-spin mr-2" />
      Loading...
    </>
  ) : (
    <>
      <Play className="h-4 w-4 mr-2" />
      Start
    </>
  )}
</Button>;
```

### Error Display Pattern

```typescript
const [error, setError] = useState<string | null>(null);

{
  error && (
    <Alert variant="destructive" className="mb-4">
      <AlertCircle className="h-4 w-4" />
      <AlertDescription>{error}</AlertDescription>
    </Alert>
  );
}
```

### Copy to Clipboard Pattern

```typescript
const copyToClipboard = (text: string) => {
  navigator.clipboard.writeText(text);
  // Optional: Show toast notification
};

<Button onClick={() => copyToClipboard(reportText)}>
  <Copy className="h-4 w-4 mr-2" />
  Copy Report
</Button>;
```

### Download File Pattern

```typescript
const downloadFile = (content: string, filename: string, type: string) => {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
};

<Button onClick={() => downloadFile(reportText, "report.txt", "text/plain")}>
  <Download className="h-4 w-4 mr-2" />
  Download Report
</Button>;
```

---

## Summary

### Key Takeaways

1. **Component Hierarchy**: AssessmentTab (container) → Display components (ExtendedAssessmentCategories, UnifiedAssessmentHeader) → UI primitives (ToolSelector, Buttons, Badges)
2. **State Management**: Local React state with Hooks, no global state library needed
3. **Styling**: Tailwind CSS utility-first with dark mode support
4. **Accessibility**: WCAG 2.1 AA compliance with semantic HTML, ARIA attributes, keyboard navigation
5. **Testing**: Jest + React Testing Library, focus on behavior and user interactions
6. **Extensibility**: Follow the 6-step guide to add new assessment visualizations

### Related Documentation

- **Assessment Logic**: See [ASSESSMENT_CATALOG.md](ASSESSMENT_CATALOG.md) for assessment module reference
- **Service Layer**: See `client/src/services/assessmentService.ts` for assessment orchestration
- **Type Definitions**: See `client/src/lib/assessmentTypes.ts` for all assessment interfaces
- **CLI Integration**: See [CLI_ASSESSMENT_GUIDE.md](CLI_ASSESSMENT_GUIDE.md) for CLI usage
- **Reviewer Guide**: See [REVIEWER_QUICK_START.md](REVIEWER_QUICK_START.md) for reviewer workflow

### Support

For questions or issues related to the assessment UI:

1. Check this document for common patterns and examples
2. Review existing component implementations in `client/src/components/`
3. See test examples in `client/src/services/__tests__/`
4. Refer to PROJECT_STATUS.md for recent changes and development history

---

**Document Version**: 1.0.0

**Last Updated**: 2026-01-03

**Maintainer**: Frontend Developer Agent

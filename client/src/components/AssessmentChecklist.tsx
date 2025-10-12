import React, { useState } from "react";
import {
  MCPDirectoryAssessment,
  AssessmentStatus,
} from "../lib/assessmentTypes";
import { Check, X, ChevronDown, ChevronUp, AlertCircle } from "lucide-react";
import { extractCategoryIssues } from "../utils/assessmentScoring";

interface AssessmentChecklistProps {
  assessment: MCPDirectoryAssessment | null;
}

interface ChecklistItem {
  name: string;
  status: AssessmentStatus;
  issues: string[];
  category:
    | "functionality"
    | "security"
    | "documentation"
    | "errorHandling"
    | "usability";
}

export const AssessmentChecklist: React.FC<AssessmentChecklistProps> = ({
  assessment,
}) => {
  const [expandedItems, setExpandedItems] = useState<Set<string>>(new Set());

  if (!assessment) {
    return null;
  }

  const toggleExpanded = (name: string) => {
    const newExpanded = new Set(expandedItems);
    if (newExpanded.has(name)) {
      newExpanded.delete(name);
    } else {
      newExpanded.add(name);
    }
    setExpandedItems(newExpanded);
  };

  const scrollToSection = (category: string) => {
    const sectionId = `${category}-section`;
    const element = document.getElementById(sectionId);
    if (element) {
      element.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  };

  // Build checklist items directly from assessment statuses
  const checklistItems: ChecklistItem[] = [
    {
      name: "Functionality",
      status: assessment.functionality.status,
      category: "functionality",
      issues: extractCategoryIssues(assessment.functionality),
    },
    {
      name: "Security",
      status: assessment.security.status,
      category: "security",
      issues: extractCategoryIssues(assessment.security),
    },
    {
      name: "Documentation",
      status: assessment.documentation.status,
      category: "documentation",
      issues: extractCategoryIssues(assessment.documentation),
    },
    {
      name: "Error Handling",
      status: assessment.errorHandling.status,
      category: "errorHandling",
      issues: extractCategoryIssues(assessment.errorHandling),
    },
    {
      name: "Usability",
      status: assessment.usability.status,
      category: "usability",
      issues: extractCategoryIssues(assessment.usability),
    },
  ];

  return (
    <div className="bg-white dark:bg-gray-800 rounded-lg shadow-sm border border-gray-200 dark:border-gray-700 mb-6">
      <div className="p-4 border-b border-gray-200 dark:border-gray-700">
        <h3 className="text-lg font-semibold text-gray-900 dark:text-gray-100">
          MCP Directory Requirements Checklist
        </h3>
        <p className="text-sm text-gray-600 dark:text-gray-400 mt-1">
          Anthropic's 5 core requirements for directory approval
        </p>
      </div>

      <div className="divide-y divide-gray-200 dark:divide-gray-700">
        {checklistItems.map((item) => {
          const isExpanded = expandedItems.has(item.name);
          const hasIssues = item.issues.length > 0;

          return (
            <div key={item.name} className="p-4">
              <div className="flex items-center justify-between">
                <div
                  className="flex items-center gap-3 cursor-pointer hover:opacity-80 transition-opacity"
                  onClick={() => scrollToSection(item.category)}
                >
                  <div className="flex-shrink-0">
                    {item.status === "PASS" ? (
                      <div className="w-6 h-6 bg-green-100 dark:bg-green-900/30 rounded flex items-center justify-center">
                        <Check className="w-4 h-4 text-green-600 dark:text-green-400" />
                      </div>
                    ) : item.status === "FAIL" ? (
                      <div className="w-6 h-6 bg-red-100 dark:bg-red-900/30 rounded flex items-center justify-center">
                        <X className="w-4 h-4 text-red-600 dark:text-red-400" />
                      </div>
                    ) : (
                      <div className="w-6 h-6 bg-yellow-100 dark:bg-yellow-900/30 rounded flex items-center justify-center">
                        <AlertCircle className="w-4 h-4 text-yellow-600 dark:text-yellow-400" />
                      </div>
                    )}
                  </div>

                  <div>
                    <span className="font-medium text-gray-900 dark:text-gray-100 hover:text-blue-600 dark:hover:text-blue-400 transition-colors">
                      {item.name}
                    </span>
                    {hasIssues && item.status !== "PASS" && (
                      <span
                        className={`ml-2 text-xs ${
                          item.status === "FAIL"
                            ? "text-red-600 dark:text-red-400"
                            : "text-yellow-600 dark:text-yellow-400"
                        }`}
                      >
                        ({item.issues.length} issue
                        {item.issues.length !== 1 ? "s" : ""})
                      </span>
                    )}
                  </div>
                </div>

                <div className="flex items-center gap-3">
                  <div className="text-right">
                    <span
                      className={`inline-block px-3 py-1 rounded-full text-sm font-semibold ${
                        item.status === "PASS"
                          ? "bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-200"
                          : item.status === "FAIL"
                            ? "bg-red-100 dark:bg-red-900/30 text-red-800 dark:text-red-200"
                            : "bg-yellow-100 dark:bg-yellow-900/30 text-yellow-800 dark:text-yellow-200"
                      }`}
                    >
                      {item.status === "NEED_MORE_INFO"
                        ? "NEEDS REVIEW"
                        : item.status}
                    </span>
                  </div>

                  {hasIssues && (
                    <div
                      className="text-gray-400 cursor-pointer hover:text-gray-600 dark:hover:text-gray-300"
                      onClick={(e) => {
                        e.stopPropagation();
                        toggleExpanded(item.name);
                      }}
                    >
                      {isExpanded ? (
                        <ChevronUp className="w-4 h-4" />
                      ) : (
                        <ChevronDown className="w-4 h-4" />
                      )}
                    </div>
                  )}
                </div>
              </div>

              {isExpanded && hasIssues && (
                <div className="mt-3 pl-9">
                  <div className="bg-gray-50 dark:bg-gray-900/50 rounded-lg p-3 space-y-2">
                    {item.issues.map((issue, idx) => (
                      <div key={idx} className="flex items-start gap-2">
                        <AlertCircle className="w-4 h-4 text-yellow-500 mt-0.5 flex-shrink-0" />
                        <p className="text-sm text-gray-700 dark:text-gray-300">
                          {issue}
                        </p>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};

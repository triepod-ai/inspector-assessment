// Review severity levels matching code-reviewer-pro
export type Severity = 'P0' | 'P1' | 'P2' | 'P3';

export interface ReviewFinding {
  severity: Severity;
  title: string;
  file: string;
  line?: number;
  problem: string;
  currentCode?: string;
  suggestedFix?: string;
  rationale: string;
}

export interface ReviewResult {
  summary: string;
  criticalCount: number;   // P0: Must fix before merge
  warningCount: number;    // P1: Should address
  suggestionCount: number; // P2/P3: Nice to have
  findings: ReviewFinding[];
  tokensUsed: {
    input: number;
    output: number;
    total: number;
  };
  modelUsed: string;
  reviewedAt: string;
}

export interface PRDiff {
  files: DiffFile[];
  totalAdditions: number;
  totalDeletions: number;
}

export interface DiffFile {
  filename: string;
  status: 'added' | 'modified' | 'deleted' | 'renamed' | 'copied' | 'changed' | 'unchanged';
  additions: number;
  deletions: number;
  patch?: string;  // Unified diff format
}

export interface ReviewConfig {
  model: string;
  maxTokens: number;
  maxDiffSize: number;  // Prevent huge diffs from blowing up costs
  excludePatterns: string[];  // Files to skip (lock files, etc.)
}

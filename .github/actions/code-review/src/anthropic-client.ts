import Anthropic from '@anthropic-ai/sdk';
import type { ReviewResult, PRDiff, ReviewConfig, ReviewFinding, Severity } from './types.js';
import { CODE_REVIEW_SYSTEM_PROMPT } from './review-prompt.js';

const DEFAULT_CONFIG: ReviewConfig = {
  model: 'claude-sonnet-4-20250514',  // Cost-efficient for code review
  maxTokens: 4096,
  maxDiffSize: 50000,  // ~50KB diff limit
  excludePatterns: [
    'package-lock.json',
    'yarn.lock',
    'pnpm-lock.yaml',
    '*.min.js',
    '*.min.css',
    'dist/**',
    'build/**',
    'node_modules/**',
    '*.map',
    'coverage/**'
  ]
};

interface ClaudeReviewResponse {
  summary: string;
  findings: Array<{
    severity: Severity;
    title: string;
    file: string;
    line?: number;
    problem: string;
    currentCode?: string;
    suggestedFix?: string;
    rationale: string;
  }>;
}

export class CodeReviewClient {
  private client: Anthropic;
  private config: ReviewConfig;

  constructor(apiKey: string, config: Partial<ReviewConfig> = {}) {
    this.client = new Anthropic({
      apiKey,
      maxRetries: 2  // Built-in retry for transient errors
    });
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  async reviewDiff(diff: PRDiff): Promise<ReviewResult> {
    // Filter out excluded files
    const relevantFiles = diff.files.filter(f =>
      !this.config.excludePatterns.some(pattern =>
        this.matchPattern(f.filename, pattern)
      )
    );

    if (relevantFiles.length === 0) {
      return this.createEmptyResult('No reviewable files in this PR (all files matched exclude patterns).');
    }

    // Build diff content
    let diffContent = relevantFiles
      .map(f => `### ${f.filename} (${f.status})\n\`\`\`diff\n${f.patch || 'Binary file or no changes'}\n\`\`\``)
      .join('\n\n');

    // Check size limit and truncate if needed
    if (diffContent.length > this.config.maxDiffSize) {
      console.warn(`Diff truncated from ${diffContent.length} to ${this.config.maxDiffSize} chars`);
      diffContent = diffContent.slice(0, this.config.maxDiffSize) + '\n\n[... diff truncated due to size ...]';
    }

    const userPrompt = `Review this pull request diff:

## Files Changed
${relevantFiles.map(f => `- ${f.filename}: +${f.additions}/-${f.deletions}`).join('\n')}

## Diff Content
${diffContent}`;

    try {
      const response = await this.client.messages.create({
        model: this.config.model,
        max_tokens: this.config.maxTokens,
        system: CODE_REVIEW_SYSTEM_PROMPT,
        messages: [{ role: 'user', content: userPrompt }]
      });

      // Parse JSON response
      const textContent = response.content.find(c => c.type === 'text');
      if (!textContent || textContent.type !== 'text') {
        throw new Error('No text response from Claude');
      }

      // Extract JSON from response (handle potential markdown code blocks)
      let jsonText = textContent.text.trim();
      if (jsonText.startsWith('```json')) {
        jsonText = jsonText.slice(7);
      }
      if (jsonText.startsWith('```')) {
        jsonText = jsonText.slice(3);
      }
      if (jsonText.endsWith('```')) {
        jsonText = jsonText.slice(0, -3);
      }
      jsonText = jsonText.trim();

      const review: ClaudeReviewResponse = JSON.parse(jsonText);

      const findings: ReviewFinding[] = review.findings.map(f => ({
        severity: f.severity,
        title: f.title,
        file: f.file,
        line: f.line,
        problem: f.problem,
        currentCode: f.currentCode,
        suggestedFix: f.suggestedFix,
        rationale: f.rationale
      }));

      return {
        summary: review.summary,
        criticalCount: findings.filter(f => f.severity === 'P0').length,
        warningCount: findings.filter(f => f.severity === 'P1').length,
        suggestionCount: findings.filter(f => f.severity === 'P2' || f.severity === 'P3').length,
        findings,
        tokensUsed: {
          input: response.usage.input_tokens,
          output: response.usage.output_tokens,
          total: response.usage.input_tokens + response.usage.output_tokens
        },
        modelUsed: this.config.model,
        reviewedAt: new Date().toISOString()
      };

    } catch (error: unknown) {
      // Handle rate limits gracefully
      if (error instanceof Anthropic.RateLimitError) {
        throw new Error('Rate limited by Anthropic API. Please try again later.');
      }

      // Handle auth errors
      if (error instanceof Anthropic.AuthenticationError) {
        throw new Error('Invalid Anthropic API key');
      }

      // Handle JSON parse errors
      if (error instanceof SyntaxError) {
        console.error('Failed to parse Claude response as JSON');
        throw new Error('Invalid JSON response from code review');
      }

      throw error;
    }
  }

  private matchPattern(filename: string, pattern: string): boolean {
    // Convert glob pattern to regex
    const regexPattern = pattern
      .replace(/\./g, '\\.')           // Escape dots
      .replace(/\*\*/g, '.*')          // ** matches anything
      .replace(/\*/g, '[^/]*')         // * matches anything except /
      .replace(/\?/g, '.');            // ? matches single char

    const regex = new RegExp(`^${regexPattern}$`);
    return regex.test(filename);
  }

  private createEmptyResult(message: string): ReviewResult {
    return {
      summary: message,
      criticalCount: 0,
      warningCount: 0,
      suggestionCount: 0,
      findings: [],
      tokensUsed: { input: 0, output: 0, total: 0 },
      modelUsed: this.config.model,
      reviewedAt: new Date().toISOString()
    };
  }
}

import { Octokit } from '@octokit/rest';
import type { PRDiff, DiffFile, ReviewResult, ReviewFinding } from './types.js';

export class GitHubClient {
  private octokit: Octokit;
  private owner: string;
  private repo: string;
  private prNumber: number;

  constructor(token: string, owner: string, repo: string, prNumber: number) {
    this.octokit = new Octokit({ auth: token });
    this.owner = owner;
    this.repo = repo;
    this.prNumber = prNumber;
  }

  async getPRDiff(): Promise<PRDiff> {
    const { data: files } = await this.octokit.pulls.listFiles({
      owner: this.owner,
      repo: this.repo,
      pull_number: this.prNumber,
      per_page: 100  // Max allowed
    });

    const diffFiles: DiffFile[] = files.map(f => ({
      filename: f.filename,
      status: f.status as DiffFile['status'],
      additions: f.additions,
      deletions: f.deletions,
      patch: f.patch  // Unified diff
    }));

    return {
      files: diffFiles,
      totalAdditions: diffFiles.reduce((sum, f) => sum + f.additions, 0),
      totalDeletions: diffFiles.reduce((sum, f) => sum + f.deletions, 0)
    };
  }

  async postReviewComment(result: ReviewResult): Promise<void> {
    const body = this.formatReviewComment(result);

    // Check for existing bot comment to update
    const { data: comments } = await this.octokit.issues.listComments({
      owner: this.owner,
      repo: this.repo,
      issue_number: this.prNumber
    });

    const existingComment = comments.find(c =>
      c.user?.login === 'github-actions[bot]' &&
      c.body?.startsWith('## AI Code Review')
    );

    if (existingComment) {
      // Update existing comment
      await this.octokit.issues.updateComment({
        owner: this.owner,
        repo: this.repo,
        comment_id: existingComment.id,
        body
      });
      console.log(`Updated existing comment #${existingComment.id}`);
    } else {
      // Create new comment
      const { data: newComment } = await this.octokit.issues.createComment({
        owner: this.owner,
        repo: this.repo,
        issue_number: this.prNumber,
        body
      });
      console.log(`Created new comment #${newComment.id}`);
    }
  }

  private formatReviewComment(result: ReviewResult): string {
    const severityEmoji: Record<string, string> = {
      P0: ':rotating_light:',
      P1: ':warning:',
      P2: ':bulb:',
      P3: ':memo:'
    };

    let body = `## AI Code Review

${result.summary}

### Summary
| Category | Count |
|----------|-------|
| ${severityEmoji.P0} Critical (P0) | ${result.criticalCount} |
| ${severityEmoji.P1} Warnings (P1) | ${result.warningCount} |
| ${severityEmoji.P2}${severityEmoji.P3} Suggestions (P2/P3) | ${result.suggestionCount} |

`;

    // Group findings by severity
    const groupedFindings: Record<string, ReviewFinding[]> = {
      P0: result.findings.filter(f => f.severity === 'P0'),
      P1: result.findings.filter(f => f.severity === 'P1'),
      P2: result.findings.filter(f => f.severity === 'P2'),
      P3: result.findings.filter(f => f.severity === 'P3')
    };

    // Critical Issues (P0)
    if (groupedFindings.P0.length > 0) {
      body += `### ${severityEmoji.P0} Critical Issues (Must Fix)\n\n`;
      groupedFindings.P0.forEach((f, i) => {
        body += this.formatFinding(f, i + 1);
      });
    }

    // Warnings (P1)
    if (groupedFindings.P1.length > 0) {
      body += `### ${severityEmoji.P1} Warnings (Should Address)\n\n`;
      groupedFindings.P1.forEach((f, i) => {
        body += this.formatFinding(f, i + 1);
      });
    }

    // Suggestions (P2/P3)
    const suggestions = [...groupedFindings.P2, ...groupedFindings.P3];
    if (suggestions.length > 0) {
      body += `### ${severityEmoji.P2} Suggestions (Nice to Have)\n\n`;
      suggestions.forEach((f, i) => {
        body += this.formatFinding(f, i + 1);
      });
    }

    // No findings case
    if (result.findings.length === 0) {
      body += `### :white_check_mark: No Issues Found\n\nThe code looks good! No issues were identified during the review.\n\n`;
    }

    // Footer with metadata
    body += `\n---\n`;
    body += `<sub>Reviewed by Claude (${result.modelUsed}) | `;
    body += `${result.tokensUsed.total.toLocaleString()} tokens | `;
    body += `${result.reviewedAt}</sub>`;

    return body;
  }

  private formatFinding(finding: ReviewFinding, index: number): string {
    let text = `**${index}. ${finding.title}**\n`;
    text += `- **Location:** \`${finding.file}`;
    if (finding.line) text += `:${finding.line}`;
    text += `\`\n`;
    text += `- **Problem:** ${finding.problem}\n`;

    if (finding.currentCode) {
      text += `- **Current Code:**\n\`\`\`\n${finding.currentCode}\n\`\`\`\n`;
    }

    if (finding.suggestedFix) {
      text += `- **Suggested Fix:**\n\`\`\`\n${finding.suggestedFix}\n\`\`\`\n`;
    }

    text += `- **Rationale:** ${finding.rationale}\n\n`;

    return text;
  }
}

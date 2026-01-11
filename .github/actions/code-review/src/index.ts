import { CodeReviewClient } from './anthropic-client.js';
import { GitHubClient } from './github-client.js';

async function main(): Promise<void> {
  // Validate environment variables
  const requiredEnvVars = [
    'ANTHROPIC_API_KEY',
    'GITHUB_TOKEN',
    'PR_NUMBER',
    'REPO_OWNER',
    'REPO_NAME'
  ];

  const missingVars = requiredEnvVars.filter(v => !process.env[v]);
  if (missingVars.length > 0) {
    throw new Error(`Missing required environment variables: ${missingVars.join(', ')}`);
  }

  const prNumber = parseInt(process.env.PR_NUMBER!, 10);
  if (isNaN(prNumber)) {
    throw new Error(`Invalid PR_NUMBER: ${process.env.PR_NUMBER}`);
  }

  console.log('='.repeat(60));
  console.log('AI Code Review');
  console.log('='.repeat(60));
  console.log(`Repository: ${process.env.REPO_OWNER}/${process.env.REPO_NAME}`);
  console.log(`PR Number: #${prNumber}`);
  console.log('='.repeat(60));

  // Initialize clients
  const anthropicClient = new CodeReviewClient(process.env.ANTHROPIC_API_KEY!);
  const githubClient = new GitHubClient(
    process.env.GITHUB_TOKEN!,
    process.env.REPO_OWNER!,
    process.env.REPO_NAME!,
    prNumber
  );

  try {
    // Get PR diff
    console.log('\n[1/3] Fetching PR diff...');
    const diff = await githubClient.getPRDiff();
    console.log(`      Found ${diff.files.length} files (+${diff.totalAdditions}/-${diff.totalDeletions})`);

    // Skip if no changes
    if (diff.files.length === 0) {
      console.log('      No files to review. Skipping.');
      return;
    }

    // List files
    console.log('\n      Files:');
    diff.files.slice(0, 10).forEach(f => {
      console.log(`        - ${f.filename} (${f.status})`);
    });
    if (diff.files.length > 10) {
      console.log(`        ... and ${diff.files.length - 10} more`);
    }

    // Run code review
    console.log('\n[2/3] Running AI code review...');
    const startTime = Date.now();
    const result = await anthropicClient.reviewDiff(diff);
    const duration = ((Date.now() - startTime) / 1000).toFixed(1);

    console.log(`      Completed in ${duration}s`);
    console.log(`      Tokens used: ${result.tokensUsed.total.toLocaleString()}`);
    console.log(`      Findings: ${result.criticalCount} critical, ${result.warningCount} warnings, ${result.suggestionCount} suggestions`);

    // Post results to PR
    console.log('\n[3/3] Posting review comment...');
    await githubClient.postReviewComment(result);

    // Summary
    console.log('\n' + '='.repeat(60));
    console.log('Review Summary');
    console.log('='.repeat(60));
    console.log(`Critical (P0): ${result.criticalCount}`);
    console.log(`Warnings (P1): ${result.warningCount}`);
    console.log(`Suggestions:   ${result.suggestionCount}`);
    console.log('='.repeat(60));

    // Log findings for workflow output
    if (result.criticalCount > 0) {
      console.log(`\n::warning::Found ${result.criticalCount} critical issue(s) that should be addressed`);
    }

    console.log('\nCode review completed successfully!');

  } catch (error: unknown) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    console.error('\nCode review failed:', errorMessage);

    // Try to post failure comment
    try {
      await githubClient.postReviewComment({
        summary: `Code review failed: ${errorMessage}`,
        criticalCount: 0,
        warningCount: 0,
        suggestionCount: 0,
        findings: [],
        tokensUsed: { input: 0, output: 0, total: 0 },
        modelUsed: 'N/A',
        reviewedAt: new Date().toISOString()
      });
    } catch {
      console.error('Failed to post error comment to PR');
    }

    throw error;
  }
}

main().catch(error => {
  console.error(error);
  process.exit(1);
});

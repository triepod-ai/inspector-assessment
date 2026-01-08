import js from "@eslint/js";
import globals from "globals";
import reactHooks from "eslint-plugin-react-hooks";
import reactRefresh from "eslint-plugin-react-refresh";
import tseslint from "typescript-eslint";

export default tseslint.config(
  { ignores: ["dist", "lib"] },
  {
    extends: [js.configs.recommended, ...tseslint.configs.recommended],
    files: ["**/*.{ts,tsx}"],
    languageOptions: {
      ecmaVersion: 2020,
      globals: globals.browser,
    },
    plugins: {
      "react-hooks": reactHooks,
      "react-refresh": reactRefresh,
    },
    rules: {
      ...reactHooks.configs.recommended.rules,
      "react-refresh/only-export-components": [
        "warn",
        { allowConstantExport: true },
      ],
      // Allow underscore-prefixed variables to be unused (common convention)
      "@typescript-eslint/no-unused-vars": [
        "error",
        {
          argsIgnorePattern: "^_",
          varsIgnorePattern: "^_",
          caughtErrorsIgnorePattern: "^_",
        },
      ],
      // Downgrade no-explicit-any to warning instead of error
      "@typescript-eslint/no-explicit-any": "warn",
      // Downgrade ban-ts-comment to warning
      "@typescript-eslint/ban-ts-comment": "warn",
      // Disallow console.* in production code - use structured Logger instead
      "no-console": "error",
    },
  },
  // Allow console in test files
  {
    files: ["**/*.test.ts", "**/*.test.tsx", "**/__tests__/**/*.ts"],
    rules: {
      "no-console": "off",
    },
  },
  // Allow intentional console.error for JSONL event emission (stderr)
  // Allow logger.ts to use console internally (it's the Logger implementation)
  {
    files: ["**/orchestratorHelpers.ts", "**/jsonl-events.ts", "**/logger.ts"],
    rules: {
      "no-console": "off",
    },
  },
  // Allow console in upstream UI components (browser debugging)
  // These are from the upstream inspector project and use browser console
  {
    files: [
      "src/App.tsx",
      "src/components/**/*.tsx",
      "src/lib/**/*.ts",
      "src/utils/**/*.ts",
      "src/services/assessmentService.ts",
    ],
    rules: {
      "no-console": "off",
    },
  },
);

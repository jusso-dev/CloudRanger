import js from "@eslint/js";
import globals from "globals";
import tseslint from "typescript-eslint";

export default tseslint.config(
  { ignores: ["**/dist/**", "**/node_modules/**", "**/.turbo/**", "**/drizzle/**"] },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    rules: {
      "@typescript-eslint/no-unused-vars": [
        "error",
        { argsIgnorePattern: "^_", varsIgnorePattern: "^_" },
      ],
      "@typescript-eslint/no-explicit-any": "off",
      "no-console": ["warn", { allow: ["error", "warn"] }],
    },
  },
  {
    files: ["apps/cli/**"],
    rules: { "no-console": "off" },
  },
  {
    // Standalone Node scripts (plain .mjs, not part of a tsconfig project).
    files: ["scripts/**/*.mjs"],
    languageOptions: { globals: globals.node },
    rules: { "no-console": "off" },
  },
  {
    // Workflow scripts run in the Workflow runtime with injected globals.
    files: ["scripts/wf-*.mjs"],
    languageOptions: {
      globals: { ...globals.node, args: "readonly", agent: "readonly", pipeline: "readonly", parallel: "readonly", phase: "readonly", log: "readonly", workflow: "readonly", budget: "readonly" },
    },
    rules: { "no-console": "off", "no-unused-vars": "off" },
  },
);

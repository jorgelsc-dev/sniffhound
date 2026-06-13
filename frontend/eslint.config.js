import js from "@eslint/js";
import globals from "globals";
import pluginVue from "eslint-plugin-vue";

export default [
  {
    ignores: [
      "dist/**",
      "dist_*/**",
      "dist_root_old/**",
      "node_modules/**",
      "node_modules_legacy_vuecli/**",
      "public/**",
    ],
  },
  {
    files: ["**/*.{js,mjs,cjs,vue}"],
    languageOptions: {
      ecmaVersion: "latest",
      sourceType: "module",
      globals: {
        ...globals.browser,
        ...globals.node,
      },
    },
  },
  js.configs.recommended,
  ...pluginVue.configs["flat/essential"],
];

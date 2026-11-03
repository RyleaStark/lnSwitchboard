# Native frontend lint toolchain

The frontend uses **Oxlint 1.90.0**, its supported native TypeScript/React rules, and a real-CLI contract test (`npm run lint`). There are no ESLint packages, JavaScript lint plugins, minimatch overrides, audit suppressions or forced peer resolution in the final graph. The complete development dependency graph must still pass `npm audit --audit-level=low` in CI.

This replaces the ESLint graph whose current parent releases require minimatch versions affected by GHSA-g3hv-75wg-m249. It is a toolchain migration, not a claim that an unsupported minimatch major override is safe.

## Preserved policy

`frontend/scripts/lint-rule-baseline.json` freezes the effective TSX rule policy from source `58ee51ed976bc9f7478c8a899fe6ee1392aa498a`, including severities/options and an explicit translation ledger. All **84 previously active checks** are accounted for:

- **81 map to native Oxlint rules**, at the same error/warning severities. This includes TypeScript recommended checks, hook order, exhaustive dependencies, compiler purity, refs, immutability, static components, manual memoization and render state checks.
- `no-octal` is enforced by the strict TS/ES module parser; its invalid fixture must fail.
- `react-hooks/config` and `react-hooks/gating` validated user-provided React Compiler plugin options. The native compiler lint rules expose no such options and always use valid fixed defaults: no invalid custom compiler/gating configuration is possible in this package. Do not introduce customizable compiler/gating options without restoring equivalent validation.

The existing deliberate exceptions remain: synchronous set-state-in-effect and only-export-components are **not enabled**. Existing warning-level checks stay warnings. Source selection remains `**/*.{ts,tsx}`, with browser globals and Vitest test globals; generated `dist`, `static` and `coverage` directories remain excluded. TypeScript compile/build is unchanged.

Effective options are retained where configurable. `no-unused-vars` uses an explicit options object with `reportVarsOnlyUsedAsTypes: true`: this also disables Oxlint's otherwise implicit underscore-ignore defaults, preserving the former TypeScript-ESLint checks for underscore-prefixed unused locals/arguments and values used only as types. All three have negative CLI fixtures. Oxlint's preserve-caught-error schema has no `errorClassNames` option; the old value was the empty list, so none were excluded from validation. Its existing `requireCatchParameter: false` is retained.

The automatic migration tool skips nested ESLint AND file patterns. The final config is built from the **effective baseline policy**, not accepted blindly from the generated config; in particular no-var, prefer-const, prefer-rest-params and prefer-spread are preserved explicitly.

## Regression gate

`frontend/scripts/verify-lint-contract.mjs` checks complete active-rule/severity coverage, absence of old vulnerable lint packages/overrides, and runs the actual installed Oxlint CLI on negative TypeScript/React fixtures. It covers hook order, render purity, props mutation, ref reads, render state, invalid useMemo, TypeScript safety, strict parsing and core correctness. A valid browser/Vitest/effect-state fixture must remain accepted. Run it as part of `npm run lint`, not as an optional manual check.

The migration's security and compatibility verdict requires a clean `npm ci`, `npm ls --all`, full npm audit, lint/contract suite, complete frontend tests and production build, plus exact-head hosted CI and independent review. Native linter rule names do not by themselves prove identical behavior on every possible input; the translation ledger, behavioral fixtures and independent review provide the bounded migration evidence.

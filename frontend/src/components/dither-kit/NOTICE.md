# Dither Kit source notice

These chart components were installed in source mode from the Dither Kit registry:

- Project: https://github.com/Boring-Software-Inc/dither-kit
- Registry: https://www.tripwire.sh
- Components: `core@0.1.0`, `area-chart@0.1.0`
- Installer: `@dither-kit/cli@0.1.1`
- Declared license: MIT
- License text: `LICENSE`
- Install record and upstream hashes: `frontend/dither-kit.json`

## Local adaptation

The source-mode installer normalized framework-only `"use client"` directives
and comment-only file headers when writing the registry components into this
Vite project. The hashes in `frontend/dither-kit.json` preserve the registry
inputs used for that installation.

Application-specific changes are intentionally limited to:

- `area.tsx` uses Vite's `import.meta.env.DEV` instead of the generated
  `process.env.NODE_ENV` expression because this browser-only Vite/TypeScript
  project does not expose Node's `process` global.
- `cartesian-root.tsx` accepts a caller-provided accessible chart name.
- `cartesian-canvas.tsx` marks its two visual-only canvas layers as hidden from
  assistive technology; the labeled SVG and dashboard data table provide the
  accessible representation.

// @vitest-environment node
import { createHash } from "node:crypto"
import { existsSync, readFileSync } from "node:fs"
import { fileURLToPath } from "node:url"
import { describe, expect, it } from "vitest"

const root = fileURLToPath(new URL("../", import.meta.url))

describe("CSS-only shadcn integration", () => {
  it("preserves the exact baseline stylesheet without installing the CLI", () => {
    const stylesheet = `${root}src/vendor/shadcn-tailwind.css`
    expect(existsSync(stylesheet)).toBe(true)
    const bytes = readFileSync(stylesheet)
    expect(createHash("sha256").update(bytes).digest("hex")).toBe(
      "bc7d83425702955b4cb67cb14ede9d603f9d912376d57a2d81d661094d2a782a",
    )
    expect(readFileSync(`${root}src/index.css`, "utf8")).toContain(
      '@import "./vendor/shadcn-tailwind.css";',
    )
    const manifest = JSON.parse(readFileSync(`${root}package.json`, "utf8"))
    expect(manifest.dependencies.shadcn).toBeUndefined()
    expect(manifest.devDependencies.shadcn).toBeUndefined()
    const lock = JSON.parse(readFileSync(`${root}package-lock.json`, "utf8"))
    expect(lock.packages["node_modules/shadcn"]).toBeUndefined()
    expect(readFileSync(`${root}src/vendor/shadcn-LICENSE.md`, "utf8")).toContain(
      "MIT License",
    )
  })
})

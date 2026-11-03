// Behavioral migration gate: test the installed CLI, not a mocked rule list.
import assert from 'node:assert/strict'
import { test } from 'node:test'
import { mkdtempSync, writeFileSync, rmSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { spawnSync } from 'node:child_process'

const root = resolve(import.meta.dirname, '..')
const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'))
const config = JSON.parse(readFileSync(join(root, '.oxlintrc.json'), 'utf8'))
const baseline = JSON.parse(readFileSync(join(root, 'scripts/lint-rule-baseline.json'), 'utf8'))

test('every previously active rule retains coverage and severity', () => {
  const actual = config.overrides[0].rules
  const severity = { off: 0, warn: 1, error: 2 }
  for (const [name, setting] of Object.entries(baseline.effective_rules)) {
    if (setting[0] === 0) continue
    const mapped = baseline.mapping[name]
    assert.ok(mapped, `missing migration coverage for ${name}`)
    if (mapped.rule) {
      const value = actual[mapped.rule]
      assert.ok(value, `missing configured rule ${mapped.rule}`)
      assert.equal(severity[Array.isArray(value) ? value[0] : value], setting[0], `severity changed: ${name}`)
    } else {
      assert.ok(['no-octal', 'react-hooks/config', 'react-hooks/gating'].includes(name), `unreviewed non-rule coverage for ${name}`)
      assert.ok(mapped.coverage)
    }
  }
  assert.equal(actual['react/set-state-in-effect'], undefined)
  assert.equal(actual['react/only-export-components'], undefined)
  assert.deepEqual(config.ignorePatterns, ['dist', 'static', 'coverage'])
  assert.deepEqual(config.overrides[0].files, ['**/*.{ts,tsx}'])
})

test('supported native lint toolchain replaces vulnerable ESLint graph', () => {
  assert.match(pkg.scripts.lint, /oxlint/)
  assert.ok(pkg.devDependencies.oxlint)
  for (const dependency of Object.keys(pkg.devDependencies)) {
    assert.ok(!dependency.includes('eslint'), `old lint dependency remains: ${dependency}`)
  }
  assert.equal(pkg.overrides, undefined, 'no unsupported dependency overrides')
})

const probes = [
  ['legacy octal', 'export const x = 010', 'ParsingError|parser|octal'],
  ['unused variable', 'export const x = 1; const unused = 2', 'no-unused-vars'],
  ['explicit any', 'export function f(x: any) { return x }', 'no-explicit-any'],
  ['empty object type', 'export type Empty = {}', 'no-empty-object-type'],
  ['ts ignore comment', '// @ts-ignore\nexport const x = 1', 'ban-ts-comment'],
  ['var declaration', 'export function f() { var x = 1; return x }', 'no-var'],
  ['prefer const', 'export function f() { let x = 1; return x }', 'prefer-const'],
  ['async promise executor', 'export const x = new Promise(async resolve => { resolve(1) })', 'no-async-promise-executor'],
  ['debugger', 'export function f() { debugger; return 1 }', 'no-debugger'],
  ['unsafe finally', 'export function f() { try { return 1 } finally { return 2 } }', 'no-unsafe-finally'],
  ['empty block', 'export function f() { try { throw Error() } catch {} }', 'no-empty'],
  ['preserve caught error', 'export function f() { try { throw Error() } catch (error) { throw new Error(String(error)) } }', 'preserve-caught-error'],
  ['hook order', "import { useState } from 'react'; export function Probe({ enabled }: { enabled: boolean }) { if (enabled) useState(0); return null }", 'rules-of-hooks'],
  ['render purity', 'export function Probe() { return <div>{Date.now()}</div> }', 'purity'],
  ['prop immutability', 'export function Probe(props: { value: number }) { props.value = 2; return <div>{props.value}</div> }', 'immutability'],
  ['render ref read', "import { useRef } from 'react'; export function Probe() { const ref = useRef(0); return <div>{ref.current}</div> }", 'refs'],
  ['unconditional render state', "import { useState } from 'react'; export function Probe() { const [value, setValue] = useState(0); setValue(value + 1); return <div>{value}</div> }", 'set-state-in-render'],
  ['invalid useMemo', "import { useMemo } from 'react'; export function Probe({ value }: { value: number }) { const result = useMemo(async () => { await value }, [value]); return <div>{String(result)}</div> }", 'use-memo'],
]

for (const [name, source, rule] of probes) {
  test(`retains ${name} rejection`, () => {
    const dir = mkdtempSync(join(tmpdir(), 'lns-lint-'))
    try {
      const file = join(dir, 'Probe.tsx')
      writeFileSync(file, source)
      const result = spawnSync(join(root, 'node_modules/.bin/oxlint'), ['-c', join(root, '.oxlintrc.json'), '--format', 'json', file], { cwd: root, encoding: 'utf8' })
      assert.notEqual(result.status, 0, `${name} was silently accepted: ${result.stdout} ${result.stderr}`)
      assert.match(result.stdout, new RegExp(rule), `${name} missing expected rule: ${result.stdout} ${result.stderr}`)
    } finally { rmSync(dir, { recursive: true, force: true }) }
  })
}

test('exhaustive dependency diagnostics retain warning severity', () => {
  const dir = mkdtempSync(join(tmpdir(), 'lns-lint-'))
  try {
    const file = join(dir, 'Probe.tsx')
    writeFileSync(file, "import { useEffect } from 'react'; export function Probe({ value }: { value: number }) { useEffect(() => { console.log(value) }, []); return null }")
    const result = spawnSync(join(root, 'node_modules/.bin/oxlint'), ['-c', join(root, '.oxlintrc.json'), '--format', 'json', file], { cwd: root, encoding: 'utf8' })
    assert.equal(result.status, 0, `${result.stdout} ${result.stderr}`)
    const diagnostics = JSON.parse(result.stdout).diagnostics
    assert.ok(diagnostics.some(item => item.code.includes('exhaustive-deps') && item.severity === 'warning'), result.stdout)
  } finally { rmSync(dir, { recursive: true, force: true }) }
})

test('browser globals, test globals and deliberate set-state-in-effect exception remain accepted', () => {
  const dir = mkdtempSync(join(tmpdir(), 'lns-lint-'))
  try {
    const file = join(dir, 'Probe.test.tsx')
    writeFileSync(file, "import { useEffect, useState } from 'react'; export function Probe() { const [value, setValue] = useState(0); useEffect(() => { setValue(window.innerWidth) }, []); return <div>{value}</div> } describe('probe', () => { it('works', () => { expect(true).toBe(true) }) })")
    const result = spawnSync(join(root, 'node_modules/.bin/oxlint'), ['-c', join(root, '.oxlintrc.json'), '--format', 'json', file], { cwd: root, encoding: 'utf8' })
    assert.equal(result.status, 0, `${result.stdout} ${result.stderr}`)
  } finally { rmSync(dir, { recursive: true, force: true }) }
})

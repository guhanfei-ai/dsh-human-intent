/**
 * Syntax-level lint: `node --check` every JS file in the project.
 * Zero dependencies; fails on any parse error.
 */
import { execFile } from 'node:child_process'
import { readdir } from 'node:fs/promises'
import { join } from 'node:path'
import { promisify } from 'node:util'

const run = promisify(execFile)
const ROOTS = ['bin', 'src', 'tests', 'scripts', 'public']

async function* walk(dir) {
  let entries
  try {
    entries = await readdir(dir, { withFileTypes: true })
  } catch {
    return
  }
  for (const entry of entries) {
    const path = join(dir, entry.name)
    if (entry.isDirectory()) yield* walk(path)
    else if (entry.isFile() && (entry.name.endsWith('.js') || entry.name.endsWith('.mjs'))) yield path
  }
}

const failures = []
let checked = 0

async function check(file) {
  try {
    await run(process.execPath, ['--check', file])
    checked += 1
  } catch (error) {
    failures.push(`${file}: ${(error.stderr || error.message || '').split('\n').filter(Boolean).slice(-3).join(' | ')}`)
  }
}

for (const root of ROOTS) {
  for await (const file of walk(root)) await check(file)
}
await check('index.js')

if (failures.length > 0) {
  console.error(`lint failed (${failures.length} file(s)):`)
  for (const failure of failures) console.error(`  ${failure}`)
  process.exit(1)
}
console.log(`lint ok: ${checked} files parsed cleanly`)

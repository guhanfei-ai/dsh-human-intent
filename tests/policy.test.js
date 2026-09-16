import test from 'node:test'
import assert from 'node:assert/strict'
import { compilePolicy } from '../src/policy/policy.js'

test('empty policy protects nothing', () => {
  const policy = compilePolicy({})
  assert.equal(policy.protects('shell.exec'), false)
  assert.equal(policy.protects('anything.else'), false)
})

test('exact tool names are protected', () => {
  const policy = compilePolicy({ protectedTools: ['shell.exec', 'kubectl.delete'] })
  assert.equal(policy.protects('shell.exec'), true)
  assert.equal(policy.protects('kubectl.delete'), true)
  assert.equal(policy.protects('shell.execx'), false)
  assert.equal(policy.protects('ssh.shell.exec'), false)
})

test('single-star globs match within one dot segment only', () => {
  const policy = compilePolicy({ protectedTools: ['shell.*'] })
  assert.equal(policy.protects('shell.exec'), true)
  assert.equal(policy.protects('shell.write'), true)
  assert.equal(policy.protects('shell'), false)
  assert.equal(policy.protects('shell.exec.deep'), false)
  assert.equal(policy.protects('bash.exec'), false)
})

test('double-star globs span segments', () => {
  const policy = compilePolicy({ protectedTools: ['shell.**'] })
  assert.equal(policy.protects('shell.exec'), true)
  assert.equal(policy.protects('shell.exec.deep'), true)
  assert.equal(policy.protects('bash.exec'), false)
})

test('rules expose risk levels', () => {
  const policy = compilePolicy({ rules: [{ tool: 'kubectl.*', risk: 'critical' }] })
  const rule = policy.match('kubectl.delete')
  assert.equal(rule.risk, 'critical')
  assert.equal(policy.match('kubectl.describe')?.risk, 'critical')
  assert.equal(policy.match('shell.exec'), null)
})

test('rules must require human intent', () => {
  assert.throws(() => compilePolicy({ rules: [{ tool: 'a.b', requireHumanIntent: false }] }))
})

test('invalid risk values are rejected', () => {
  assert.throws(() => compilePolicy({ rules: [{ tool: 'a.b', risk: 'extreme' }] }))
})

test('protectedTools and rules can be combined', () => {
  const policy = compilePolicy({
    protectedTools: ['grafana.push'],
    rules: [{ tool: 'shell.exec', risk: 'high' }],
  })
  assert.equal(policy.protects('grafana.push'), true)
  assert.equal(policy.match('shell.exec').risk, 'high')
})

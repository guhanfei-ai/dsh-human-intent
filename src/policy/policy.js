/**
 * Protected-tool policy: decides which agent tools require human intent
 * authorization before execution.
 *
 * v0.1 keeps this deliberately small: exact names, simple dot-globs
 * (`shell.*`), and optional risk-tagged rules. The structure leaves room
 * for a richer policy engine without breaking configuration format.
 */
export class PolicyError extends Error {
  constructor(message) {
    super(message)
    this.name = 'PolicyError'
  }
}

const MAX_RULES = 256
const MAX_PATTERN_LENGTH = 200

/** Escape regex characters, then translate tool globs to a regex source. */
function patternToRegExpSource(pattern) {
  let source = ''
  for (let i = 0; i < pattern.length; i += 1) {
    const char = pattern[i]
    if (char === '*') {
      if (pattern[i + 1] === '*') {
        source += '.*'
        i += 1
      } else {
        source += '[^.]*'
      }
    } else {
      source += char.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
    }
  }
  return source
}

function compilePattern(pattern, index) {
  const name = typeof pattern === 'string' ? pattern.trim() : ''
  if (!name) throw new PolicyError(`rules[${index}].tool must be a non-empty pattern`)
  if (name.length > MAX_PATTERN_LENGTH) throw new PolicyError(`rules[${index}].tool exceeds ${MAX_PATTERN_LENGTH} characters`)
  return { source: `^${patternToRegExpSource(name)}$`, pattern: name }
}

const RISK_LEVELS = ['low', 'medium', 'high', 'critical']

function normalizeRule(rule, index) {
  if (!rule || typeof rule !== 'object') throw new PolicyError(`rules[${index}] must be an object`)
  const compiled = compilePattern(rule.tool, index)
  const risk = rule.risk ?? null
  if (risk !== null && !RISK_LEVELS.includes(risk)) {
    throw new PolicyError(`rules[${index}].risk must be one of ${RISK_LEVELS.join(', ')}`)
  }
  return {
    tool: compiled.pattern,
    regex: new RegExp(compiled.source),
    ...(risk ? { risk } : {}),
    requireHumanIntent: rule.requireHumanIntent !== false,
  }
}

/**
 * Compile policy configuration.
 * @param {object} config - { protectedTools?: string[], rules?: object[] }
 */
export function compilePolicy(config = {}) {
  const protectedTools = Array.isArray(config.protectedTools) ? config.protectedTools : []
  const rules = Array.isArray(config.rules) ? config.rules : []
  if (protectedTools.length + rules.length > MAX_RULES) {
    throw new PolicyError(`policy exceeds ${MAX_RULES} rules`)
  }
  const compiled = []
  protectedTools.forEach((pattern, index) => {
    const normalized = normalizeRule({ tool: pattern }, index)
    compiled.push(normalized)
  })
  rules.forEach((rule, index) => {
    if (!rule || typeof rule !== 'object') throw new PolicyError(`rules[${index}] must be an object`)
    if (rule.requireHumanIntent === false) {
      throw new PolicyError(`rules[${index}]: requireHumanIntent=false is not a valid configuration; remove the rule instead`)
    }
    compiled.push(normalizeRule(rule, index))
  })
  return {
    rules: compiled,
    /** Returns the matching rule for a tool name, or null when unprotected. */
    match(toolName) {
      const name = String(toolName ?? '')
      for (const rule of compiled) {
        if (rule.regex.test(name)) return rule
      }
      return null
    },
    /** True when the tool requires human intent authorization. */
    protects(toolName) {
      return this.match(toolName) !== null
    },
    toJSON() {
      return compiled.map(({ tool, risk }) => ({ tool, ...(risk ? { risk } : {}) }))
    },
  }
}

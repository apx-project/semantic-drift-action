const fs = require('node:fs')
const path = require('node:path')
const core = require('@actions/core')
const github = require('@actions/github')

const LAW_NUMBER = 1

function readJson(filePath) {
  const resolved = path.resolve(filePath)
  try {
    const raw = fs.readFileSync(resolved, 'utf8')
    return JSON.parse(raw)
  } catch (error) {
    throw new Error(`Unable to read semantic diff from "${resolved}": ${error.message}`)
  }
}

function toArray(value) {
  if (!value) return []
  if (Array.isArray(value)) return value
  return [value]
}

function collectLabels(diff) {
  const labels = new Set()
  const add = (prefix, values) => {
    toArray(values).forEach((value) => {
      if (!value) return
      labels.add(`${prefix}${String(value).trim()}`.slice(0, 100))
    })
  }
  const packs = new Set([
    ...toArray(diff.packs),
    ...toArray(diff.packs?.touched),
    ...toArray(diff.packs?.changed),
  ])
  if (diff.summary?.packs) {
    Object.keys(diff.summary.packs).forEach((key) => packs.add(key))
  }
  add('apx:pack=', Array.from(packs))

  add('apx:impact=', toArray(diff.impacts))
  add('apx:impact=', toArray(diff.impacts?.domains))
  add('apx:trait=', toArray(diff.traits))
  add('apx:trait=', toArray(diff.labels))

  const constraintLabels = toArray(diff.extensions?.constraints).map((item) => item?.id || item?.name)
  add('apx:constraint=', constraintLabels.filter(Boolean))

  return Array.from(labels)
}

function hasBlockingSecurity(diff) {
  const alerts = toArray(diff.alerts)
  return alerts.some((alert) => {
    const kind = String(alert.kind || alert.type || '').toLowerCase()
    const severity = String(alert.severity || alert.level || '').toLowerCase()
    return kind.includes('security') && ['high', 'critical', 'block'].includes(severity)
  })
}

function formatMetricEntries(entries) {
  return entries
    .filter(([, value]) => Number.isFinite(Number(value)))
    .slice(0, 3)
    .map(([key, value]) => `${key}=${Number(value).toFixed(2)}`)
}

function summarizeExtensions(diff) {
  const extensionLines = []
  const extensions = diff.extensions || {}
  const constraintIds = toArray(extensions.constraints)
    .map((constraint) => constraint?.id || constraint?.name)
    .filter(Boolean)
  if (constraintIds.length) {
    extensionLines.push(`• Constraints touched: ${constraintIds.slice(0, 4).join(', ')}`)
  }

  const receiptRefs = toArray(extensions.lineage?.receipts).filter(Boolean)
  if (receiptRefs.length) {
    extensionLines.push(`• Lineage receipts: ${receiptRefs.slice(0, 3).join(', ')}`)
  }
  if (extensions.lineage?.amc_urn) {
    extensionLines.push(`• AMC URN: ${extensions.lineage.amc_urn}`)
  }

  const replayCommands = toArray(extensions.replay?.commands).filter(Boolean)
  if (extensions.replay?.bundle) {
    extensionLines.push(`• Replay bundle: ${extensions.replay.bundle}`)
  }
  if (replayCommands.length) {
    extensionLines.push(`• Replay commands: ${replayCommands.slice(0, 2).join(' | ')}`)
  }

  if (extensions.fitness?.runner && typeof extensions.fitness.runner === 'object') {
    const metrics = formatMetricEntries(Object.entries(extensions.fitness.runner))
    if (metrics.length) {
      extensionLines.push(`• Fitness metrics: ${metrics.join(', ')}`)
    }
  }
  if (extensions.fitness?.contexts && typeof extensions.fitness.contexts === 'object') {
    const contextMetrics = formatMetricEntries(Object.entries(extensions.fitness.contexts))
    if (contextMetrics.length) {
      extensionLines.push(`• Context metrics: ${contextMetrics.join(', ')}`)
    }
  }

  const proofRefs = toArray(extensions.proofs)
    .map((proof) => proof?.reference || proof?.id)
    .filter(Boolean)
  if (proofRefs.length) {
    extensionLines.push(`• Proof references: ${proofRefs.slice(0, 3).join(', ')}`)
  }

  return extensionLines
}

function summarizeConfigGuardLite() {
  const summaries = []
  const seen = new Set()
  for (const file of collectRegistryPacks(path.resolve('.apx/registry'))) {
    const summary = parseConfigGuardFile(file)
    if (!summary) continue
    const key = `${summary.id}@${summary.version}`
    if (seen.has(key)) continue
    seen.add(key)
    summaries.push(summary)
  }
  for (const file of collectLocalConfigGuardPacks(path.resolve('packs/config-guard'))) {
    const summary = parseConfigGuardFile(file)
    if (!summary) continue
    const key = `${summary.id}@${summary.version}`
    if (seen.has(key)) continue
    seen.add(key)
    summaries.push(summary)
  }
  if (!summaries.length) return null
  summaries.sort((a, b) => (b.missingEnv + b.staleSecrets) - (a.missingEnv + a.staleSecrets))
  const totals = summaries.reduce(
    (acc, pack) => {
      acc.missingEnv += pack.missingEnv
      acc.staleSecrets += pack.staleSecrets
      return acc
    },
    { missingEnv: 0, staleSecrets: 0 },
  )
  return {
    totalPacks: summaries.length,
    missingEnv: totals.missingEnv,
    staleSecrets: totals.staleSecrets,
    packs: summaries,
  }
}

function formatConfigGuardLines(summary) {
  if (!summary || !summary.totalPacks) return []
  const lines = [
    `• Config Guard Lite: ${summary.totalPacks} pack(s), ${summary.missingEnv} missing env vars, ${summary.staleSecrets} stale rotations`,
  ]
  const interesting = summary.packs.filter((pack) => pack.missingEnv || pack.staleSecrets).slice(0, 3)
  if (interesting.length === 0) {
    lines.push('•   All monitored packs satisfy baseline guardrails.')
  } else {
    for (const pack of interesting) {
      lines.push(
        `•   ${pack.namespace || pack.id} (${pack.environment || 'env'}) — env ${pack.missingEnv}/${pack.envCount}, secrets ${pack.staleSecrets}/${pack.secretsCount}`,
      )
    }
  }
  return lines
}

function collectRegistryPacks(root) {
  const files = []
  if (!fs.existsSync(root)) return files
  const stack = [root]
  while (stack.length) {
    const dir = stack.pop()
    let entries
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true })
    } catch {
      continue
    }
    for (const entry of entries) {
      const full = path.join(dir, entry.name)
      if (entry.isDirectory()) {
        stack.push(full)
      } else if (entry.isFile() && entry.name === 'pack.yaml') {
        files.push(full)
      }
    }
  }
  return files
}

function collectLocalConfigGuardPacks(root) {
  const files = []
  if (!fs.existsSync(root)) return files
  for (const entry of fs.readdirSync(root, { withFileTypes: true })) {
    if (entry.isFile() && entry.name.endsWith('.yaml')) {
      files.push(path.join(root, entry.name))
    }
  }
  return files
}

function parseConfigGuardFile(filePath) {
  let text
  try {
    text = fs.readFileSync(filePath, 'utf8')
  } catch {
    return null
  }
  if (!/\bconfig_guard_spec\b/.test(text)) return null
  const lines = text.split(/\r?\n/)
  const contexts = []
  const rotationEntries = []
  const state = {
    packId: null,
    packVersion: null,
    namespace: null,
    environment: null,
    missingEnv: 0,
  }
  let envCount = 0
  let secretsCount = 0

  for (const rawLine of lines) {
    const indent = rawLine.match(/^\s*/)[0].length
    let line = rawLine.trim()
    if (!line || line.startsWith('#')) continue
    while (contexts.length && indent <= contexts[contexts.length - 1].indent) contexts.pop()

    if (line.endsWith(':') && !line.startsWith('- ')) {
      const key = line.slice(0, -1).trim()
      contexts.push({ key, indent })
      continue
    }

    if (line.startsWith('- ')) {
      const parent = contexts[contexts.length - 1]?.key
      const content = line.slice(2).trim()
      const ctx = { key: parent ? `${parent}-item` : 'list-item', indent }
      if (parent === 'required_env') {
        ctx.type = 'env'
        envCount++
      } else if (parent === 'rotations') {
        ctx.type = 'rotation'
        const rotation = { last: null, max: null }
        ctx.rotation = rotation
        rotationEntries.push(rotation)
        secretsCount++
      }
      contexts.push(ctx)
      if (content) {
        const idx = content.indexOf(':')
        if (idx !== -1) {
          const key = content.slice(0, idx).trim()
          const value = content.slice(idx + 1).trim()
          handleConfigKey(state, key, value, contexts, ctx)
        }
      }
      continue
    }

    const idx = line.indexOf(':')
    if (idx === -1) continue
    const key = line.slice(0, idx).trim()
    const value = line.slice(idx + 1).trim()
    handleConfigKey(state, key, value, contexts)
  }

  const staleSecrets = rotationEntries.filter(
    (entry) => Number.isFinite(entry.last) && Number.isFinite(entry.max) && entry.last > entry.max,
  ).length

  return {
    id: state.packId || path.basename(filePath).replace(/\.(ya?ml)$/i, ''),
    version: state.packVersion || '0.0.0',
    namespace: state.namespace,
    environment: state.environment,
    envCount,
    missingEnv: state.missingEnv,
    secretsCount,
    staleSecrets,
  }
}

function handleConfigKey(state, key, value, contexts, forcedCtx) {
  const ctxStack = contexts
  const current = forcedCtx || ctxStack[ctxStack.length - 1]
  const keys = ctxStack.map((ctx) => ctx.key)
  if (key === 'id' && keys.includes('pack') && !state.packId) {
    state.packId = value
  }
  if (key === 'version' && keys.includes('pack') && !state.packVersion) {
    state.packVersion = value
  }
  if (key === 'namespace' && keys.includes('spec') && !state.namespace) {
    state.namespace = value
  }
  if (key === 'environment' && keys.includes('spec') && !state.environment) {
    state.environment = value
  }
  if ((current?.key === 'required_env-item' || current?.type === 'env') && key === 'present' && /false/i.test(value)) {
    state.missingEnv++
  }
  if ((current?.key === 'rotations-item' || current?.type === 'rotation') && key === 'last_rotated_days') {
    current.rotation = current.rotation || { last: null, max: null }
    current.rotation.last = Number(value)
  }
  if ((current?.key === 'rotations-item' || current?.type === 'rotation') && key === 'max_days') {
    current.rotation = current.rotation || { last: null, max: null }
    current.rotation.max = Number(value)
  }
}

function loadScanPayload(scanPath) {
  if (!scanPath) return null
  const resolved = path.resolve(scanPath)
  if (!fs.existsSync(resolved)) return null
  try {
    const raw = fs.readFileSync(resolved, 'utf8')
    return JSON.parse(raw)
  } catch (error) {
    core.info(`Unable to read semantic debt scan from "${resolved}": ${error?.message || error}`)
    return null
  }
}

function summarizeScanResult(scan) {
  if (!scan) return []
  const lines = []
  const rawScore = scan.debt_score ?? scan.debtScore ?? scan.debt
  const score = Number(rawScore)
  const rawCost = scan.expected_annual_cost ?? scan.expectedAnnualCost ?? scan.annualCost
  const cost = Number(rawCost)
  if (Number.isFinite(score)) {
    const headline = Number.isFinite(cost)
      ? `• Semantic Debt Score: ${score.toFixed(1)}% (est. $${Math.round(cost).toLocaleString()}/yr)`
      : `• Semantic Debt Score: ${score.toFixed(1)}%`
    lines.push(headline)
  }
  const conflicts = Array.isArray(scan.conflicts) ? scan.conflicts.slice(0, 3) : []
  if (conflicts.length) {
    const summaries = conflicts.map((conflict) => {
      const key = conflict.key || conflict.normalized_key || conflict.normalizedKey || '?'
      const severity = String(conflict.severity || '').toUpperCase() || '?'
      return `${key} (${severity})`
    })
    lines.push(`• Top conflicts: ${summaries.join(', ')}`)
  }
  return lines
}

function buildComment(diff, labels, securityAlert, lawNumber, lawScope, extensionLines, studioLink) {
  const packs = toArray(diff.packs).slice(0, 6)
  const impacts = toArray(diff.impacts).slice(0, 6)
  const lines = [
    `**APX Semantic SemanticDebt — Law #${lawNumber} (${lawScope.replace(/_/g, ' ')})**`,
    '',
  ]
  if (packs.length) {
    lines.push(`• Packs touched: ${packs.join(', ')}`)
  }
  if (impacts.length) {
    lines.push(`• Impacts: ${impacts.join(', ')}`)
  }
  if (securityAlert) {
    lines.push(`• ⚠️ Security semantic_debt detected (blocking)`)
  }
  if (extensionLines.length) {
    lines.push('', ...extensionLines)
  }
  lines.push(
    '',
    '_APX Laws #2‑#7 cover constraints, lineage, continuous evolution, context-aware fitness, replay, and mathematical safety._',
    `_View full PackSpec + Config Guard snapshot: ${studioLink}`,
  )
  return lines.join('\n')
}

async function emitTelemetry(url, payload) {
  if (!url) return
  const target = `${url.replace(/\/+$/, '')}/api/telemetry/semantic_debt-install`
  try {
    await fetch(target, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        recordedAt: new Date().toISOString(),
        provider: 'github-actions',
        ...payload,
      }),
    })
  } catch (error) {
    core.info(`Telemetry emit failed: ${error?.message || error}`)
  }
}

async function run() {
  try {
    const token = core.getInput('github-token', { required: true })
    const diffPath = core.getInput('diff-path') || '.apx/semantic_diff.json'
    const failOnSecurity = /^true$/i.test(core.getInput('fail-on-security') || 'false')
    const studioLink = core.getInput('studio-lite-url') || 'https://apx.run/lite'
    const telemetryUrl = core.getInput('telemetry-url') || process.env.APX_TELEMETRY_URL || ''
    const scanPath = core.getInput('scan-path') || '.apx/semantic_debt_scan.json'

    if (!github.context.payload.pull_request) {
      core.info('No pull_request payload detected. Nothing to do.')
      return
    }

    const diff = readJson(diffPath)
    const labels = collectLabels(diff)
    const securityAlert = hasBlockingSecurity(diff)
    const lawNumber = Number.isFinite(Number(diff.law)) ? Number(diff.law) : LAW_NUMBER
    const lawScope = diff.law_scope || 'drift_visibility'
    const extensionLines = summarizeExtensions(diff)
    const configSummary = summarizeConfigGuardLite()
    const configLines = formatConfigGuardLines(configSummary)
    const scanPayload = loadScanPayload(scanPath)
    const scanLines = summarizeScanResult(scanPayload)

    const octokit = github.getOctokit(token)
    const { owner, repo } = github.context.repo
    const issue_number = github.context.payload.pull_request.number

    if (labels.length) {
      core.info(`Applying labels: ${labels.join(', ')}`)
      await octokit.rest.issues.addLabels({ owner, repo, issue_number, labels })
    } else {
      core.info('No labels derived from semantic diff.')
    }

    const summaryLines = extensionLines.concat(configLines, scanLines)
    const body = buildComment(diff, labels, securityAlert, lawNumber, lawScope, summaryLines, studioLink)
    await octokit.rest.issues.createComment({ owner, repo, issue_number, body })

    core.setOutput('labels-applied', labels.join(','))
    core.setOutput('law', String(lawNumber))
    core.setOutput('security-alert', securityAlert ? 'true' : 'false')
    core.setOutput(
      'semantic-debt-score',
      scanPayload && Number.isFinite(Number(scanPayload.debt_score ?? scanPayload.debtScore))
        ? String(scanPayload.debt_score ?? scanPayload.debtScore)
        : '',
    )

    await emitTelemetry(telemetryUrl, {
      repo: github.context.payload.repository?.full_name || null,
      pipeline: github.context.runId ? String(github.context.runId) : null,
      source: github.context.eventName || null,
      metadata: {
        runAttempt: github.context.runAttempt || null,
        pullRequest: github.context.payload.pull_request?.number || null,
      },
    })

    if (securityAlert && failOnSecurity) {
      core.setFailed('High/critical security semantic_debt detected by APX Law #1.')
    }
  } catch (error) {
    core.setFailed(error.message)
  }
}

run()


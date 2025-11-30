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

function buildComment(diff, labels, securityAlert, lawNumber, lawScope, extensionLines) {
  const packs = toArray(diff.packs).slice(0, 6)
  const impacts = toArray(diff.impacts).slice(0, 6)
  const lines = [
    `**APX Semantic Drift — Law #${lawNumber} (${lawScope.replace(/_/g, ' ')})**`,
    '',
  ]
  if (packs.length) {
    lines.push(`• Packs touched: ${packs.join(', ')}`)
  }
  if (impacts.length) {
    lines.push(`• Impacts: ${impacts.join(', ')}`)
  }
  if (securityAlert) {
    lines.push(`• ⚠️ Security drift detected (blocking)`)
  }
  if (extensionLines.length) {
    lines.push('', ...extensionLines)
  }
  lines.push(
    '',
    '_APX Laws #2‑#7 cover constraints, lineage, continuous evolution, context-aware fitness, replay, and mathematical safety._',
    '_Learn more at https://apx.run/7-laws_',
  )
  return lines.join('\n')
}

async function run() {
  try {
    const token = core.getInput('github-token', { required: true })
    const diffPath = core.getInput('diff-path') || '.apx/semantic_diff.json'
    const failOnSecurity = /^true$/i.test(core.getInput('fail-on-security') || 'false')

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

    const octokit = github.getOctokit(token)
    const { owner, repo } = github.context.repo
    const issue_number = github.context.payload.pull_request.number

    if (labels.length) {
      core.info(`Applying labels: ${labels.join(', ')}`)
      await octokit.rest.issues.addLabels({ owner, repo, issue_number, labels })
    } else {
      core.info('No labels derived from semantic diff.')
    }

    const body = buildComment(diff, labels, securityAlert, lawNumber, lawScope, extensionLines)
    await octokit.rest.issues.createComment({ owner, repo, issue_number, body })

    core.setOutput('labels-applied', labels.join(','))
    core.setOutput('law', String(lawNumber))
    core.setOutput('security-alert', securityAlert ? 'true' : 'false')

    if (securityAlert && failOnSecurity) {
      core.setFailed('High/critical security drift detected by APX Law #1.')
    }
  } catch (error) {
    core.setFailed(error.message)
  }
}

run()


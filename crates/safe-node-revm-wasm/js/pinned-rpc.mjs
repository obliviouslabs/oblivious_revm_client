import { spawn } from 'node:child_process'

/** A curl SPKI mismatch that requires fresh Safe Node attestation. */
export class PinMismatchError extends Error {
  constructor() {
    super('attested TLS pin mismatch; stop and re-attest Safe Node')
    this.name = 'PinMismatchError'
  }
}

/**
 * Forward one JSON-RPC body while accepting only the configured TLS SPKI.
 *
 * Safe Node uses an attestation-bound, self-signed certificate, so WebPKI is
 * deliberately disabled with `-k`; curl's `--pinnedpubkey` remains mandatory.
 */
export async function forwardPinned(body, { rpcUrl, pin, expectedDomain, timeoutSeconds = '30' }) {
  if (typeof body !== 'string') throw new Error('body must be a string')
  if (!/^sha256\/\/[A-Za-z0-9+/]{43}=$/.test(pin ?? '')) {
    throw new Error('a valid sha256// SPKI pin is required')
  }
  const url = new URL(rpcUrl)
  if (url.protocol !== 'https:') throw new Error('rpcUrl must use https')
  if (url.username || url.password) throw new Error('rpcUrl must not contain userinfo')
  if (expectedDomain && url.hostname.toLowerCase() !== expectedDomain.toLowerCase()) {
    throw new Error(`RPC URL host ${url.hostname} does not match attested domain ${expectedDomain}`)
  }
  const timeout = Number(timeoutSeconds)
  if (!Number.isFinite(timeout) || timeout <= 0) {
    throw new Error('timeoutSeconds must be positive')
  }

  const args = [
    '-k',
    '--pinnedpubkey',
    pin,
    '--silent',
    '--show-error',
    '--connect-timeout',
    '10',
    '--max-time',
    String(timeout),
    '-X',
    'POST',
    url.href,
    '-H',
    'content-type: application/json',
    '--data-binary',
    '@-'
  ]

  const stdout = await new Promise((resolve, reject) => {
    const child = spawn('curl', args, { stdio: ['pipe', 'pipe', 'pipe'] })
    const out = []
    const err = []
    let size = 0
    let oversized = false

    child.stdout.on('data', (chunk) => {
      size += chunk.length
      if (size > 32 * 1024 * 1024) {
        oversized = true
        child.kill()
      } else {
        out.push(chunk)
      }
    })
    child.stderr.on('data', (chunk) => err.push(chunk))
    child.on('error', reject)
    child.on('close', (code) => {
      if (oversized) reject(new Error('Safe Node response exceeded 32 MiB'))
      else if (code === 0) resolve(Buffer.concat(out).toString('utf8'))
      else if (code === 90) reject(new PinMismatchError())
      else reject(new Error(Buffer.concat(err).toString('utf8').trim() || `curl exited ${code}`))
    })
    child.stdin.end(body)
  })

  return stdout.trim()
}

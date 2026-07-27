import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import { createHash, randomUUID, X509Certificate } from 'node:crypto'
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { createServer } from 'node:net'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'
import { forwardPinned } from './pinned-rpc.mjs'

const execFileAsync = promisify(execFile)
const here = dirname(fileURLToPath(import.meta.url))
const dockerContext = join(here, 'test-pinning')

async function command(program, args, options = {}) {
  const result = await execFileAsync(program, args, {
    maxBuffer: 16 * 1024 * 1024,
    ...options
  })
  return result.stdout.trim()
}

async function waitForMock(rpcUrl) {
  let lastError
  for (let attempt = 0; attempt < 50; attempt++) {
    try {
      await command('curl', ['-k', '--silent', '--fail', `${rpcUrl}/health`])
      return
    } catch (error) {
      lastError = error
      await new Promise((resolve) => setTimeout(resolve, 100))
    }
  }
  throw new Error(`mock TLS server did not become ready: ${lastError?.message}`)
}

function spkiPin(certificatePem) {
  const certificate = new X509Certificate(certificatePem)
  const spki = certificate.publicKey.export({ type: 'spki', format: 'der' })
  return `sha256//${createHash('sha256').update(spki).digest('base64')}`
}

async function unusedTcpPort() {
  const server = createServer()
  await new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', resolve)
  })
  const port = server.address().port
  await new Promise((resolve, reject) =>
    server.close((error) => (error ? reject(error) : resolve()))
  )
  return port
}

test('JavaScript forwarding client enforces the Docker mock server SPKI pin', {
  timeout: 120_000
}, async (t) => {
  await command('docker', ['info', '--format', '{{.ServerVersion}}'])
  await command('curl', ['--version'])
  await command('openssl', ['version'])

  const temporary = await mkdtemp(join(tmpdir(), 'safe-revm-pinning-'))
  const unique = randomUUID().toLowerCase()
  const image = `safe-revm-pinning-mock:${unique}`
  const container = `safe-revm-pinning-${unique}`
  let containerStarted = false

  t.after(async () => {
    if (containerStarted) {
      await command('docker', ['rm', '--force', container]).catch(() => {})
    }
    await command('docker', ['image', 'rm', '--force', image]).catch(() => {})
    await rm(temporary, { recursive: true, force: true })
  })

  const certificatePath = join(temporary, 'server-cert.pem')
  const keyPath = join(temporary, 'server-key.pem')
  await command('openssl', [
    'req',
    '-x509',
    '-newkey',
    'rsa:2048',
    '-sha256',
    '-nodes',
    '-days',
    '1',
    '-subj',
    '/CN=localhost',
    '-addext',
    'subjectAltName=DNS:localhost,IP:127.0.0.1',
    '-keyout',
    keyPath,
    '-out',
    certificatePath
  ])
  const pin = spkiPin(await readFile(certificatePath))

  await command('docker', ['build', '--quiet', '--tag', image, dockerContext])
  const hostPort = await unusedTcpPort()
  await command('docker', [
    'run',
    '--detach',
    '--rm',
    '--name',
    container,
    '--network',
    'host',
    '--env',
    `MOCK_PORT=${hostPort}`,
    '--mount',
    `type=bind,source=${temporary},target=/certs,readonly`,
    image
  ])
  containerStarted = true

  const rpcUrl = `https://127.0.0.1:${hostPort}`
  await waitForMock(rpcUrl)

  const request = { jsonrpc: '2.0', id: 'pin-test', method: 'eth_getProof', params: [] }

  // The certificate is intentionally self-signed: normal WebPKI must reject it.
  await assert.rejects(
    command('curl', [
      '--silent',
      '--show-error',
      '--fail',
      '-H',
      'content-type: application/json',
      '--data',
      JSON.stringify(request),
      rpcUrl
    ])
  )

  // Exercise the exact forwarding helper used by kps-safe-proxy.mjs.
  const direct = JSON.parse(
    await forwardPinned(JSON.stringify(request), {
      rpcUrl,
      pin,
      expectedDomain: '127.0.0.1',
      timeoutSeconds: '5'
    })
  )
  assert.deepEqual(direct.result, { mock: true, method: 'eth_getProof' })

  await assert.rejects(
    forwardPinned(JSON.stringify(request), {
      rpcUrl,
      pin,
      expectedDomain: 'rpc-gcp.safe-node.com',
      timeoutSeconds: '5'
    }),
    /does not match attested domain/
  )

  const wrongPin = `sha256//${Buffer.alloc(32, 0xa5).toString('base64')}`
  await assert.rejects(
    forwardPinned(JSON.stringify(request), {
      rpcUrl,
      pin: wrongPin,
      expectedDomain: '127.0.0.1',
      timeoutSeconds: '5'
    }),
    /attested TLS pin mismatch/i
  )
})

#!/usr/bin/env node
import { listen } from '@kpstreams/server'
import { forwardPinned, PinMismatchError } from './pinned-rpc.mjs'

const encoder = new TextEncoder()
const decoder = new TextDecoder()
let fatalPinError

const rpcUrl = process.env.SAFE_NODE_RPC_URL
const pin = process.env.SAFE_NODE_TLS_PIN
const expectedDomain = process.env.SAFE_NODE_TLS_DOMAIN ?? 'rpc-gcp.safe-node.com'
if (!rpcUrl || !pin) {
  console.error('Run `safe-revm attest`, then set SAFE_NODE_RPC_URL and SAFE_NODE_TLS_PIN.')
  process.exit(2)
}

const port = Number(process.env.KPS_PORT ?? 41108)
if (!Number.isInteger(port) || port < 1 || port > 65_535) {
  console.error('KPS_PORT must be an integer from 1 through 65535.')
  process.exit(2)
}
const bind = process.env.KPS_BIND ?? '127.0.0.1'
const advertise = process.env.KPS_ADVERTISE ?? '127.0.0.1'
const listener = await listen({
  port,
  address: bind,
  certPath: process.env.KPS_CERT_PATH ?? 'kps-cert.pem',
  keyPath: process.env.KPS_KEY_PATH ?? 'kps-key.pem'
})

console.log(listener.address(advertise))
console.error('KPS authenticates this proxy, not Safe Node. The proxy can read every request.')

for (;;) {
  const conn = await listener.accept()
  void handleConnection(conn)
}

async function handleConnection(conn) {
  try {
    for (;;) {
      const stream = await conn.acceptStream()
      void handleStream(stream)
    }
  } catch {}
}

async function handleStream(stream) {
  const writer = stream.writable.getWriter()
  let writeTail = Promise.resolve()
  try {
    for await (const line of lines(stream.readable)) {
      if (line.length > 1024 * 1024) throw new Error('request line too large')
      // Launch immediately; do not serialize responses across cadence ticks.
      const forwarding = fatalPinError
        ? Promise.reject(fatalPinError)
        : forwardPinned(line, {
            rpcUrl,
            pin,
            expectedDomain,
            timeoutSeconds: process.env.SAFE_NODE_REQUEST_TIMEOUT ?? '30'
          })
      void forwarding
        .then((response) => {
          writeTail = writeTail.then(() => writer.write(encoder.encode(`${response}\n`)))
          return writeTail
        })
        .catch((error) => {
          if (error instanceof PinMismatchError) fatalPinError = error
          let id = null
          try {
            id = JSON.parse(line).id
          } catch {}
          const response = JSON.stringify({
            jsonrpc: '2.0',
            id,
            error: {
              code: error instanceof PinMismatchError ? -32097 : -32098,
              message: `KPS proxy: ${error.message}`
            }
          })
          writeTail = writeTail.then(() => writer.write(encoder.encode(`${response}\n`)))
        })
    }
    await writeTail
    await writer.close()
  } catch {
    try {
      await writer.abort()
    } catch {}
  }
}

async function* lines(readable) {
  const reader = readable.getReader()
  let buffered = ''
  try {
    for (;;) {
      const { value, done } = await reader.read()
      if (done) break
      buffered += decoder.decode(value, { stream: true })
      if (buffered.length > 1024 * 1024 && !buffered.includes('\n')) {
        throw new Error('request line too large')
      }
      for (;;) {
        const newline = buffered.indexOf('\n')
        if (newline < 0) break
        const line = buffered.slice(0, newline)
        buffered = buffered.slice(newline + 1)
        if (line.trim()) yield line
      }
    }
    buffered += decoder.decode()
    if (buffered.trim()) yield buffered
  } finally {
    reader.releaseLock()
  }
}

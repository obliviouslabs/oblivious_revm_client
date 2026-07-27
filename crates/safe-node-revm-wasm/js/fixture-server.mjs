#!/usr/bin/env node
import { readFile } from 'node:fs/promises'
import { createServer } from 'node:http'
import { dirname, extname, isAbsolute, join, normalize, relative, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { listen } from '@kpstreams/server'

const here = dirname(fileURLToPath(import.meta.url))
const repo = normalize(join(here, '../../..'))
const fixturePath = join(repo, 'crates/safe-node-revm/fixtures/sepolia-weth9-11344323.json')
const fixture = JSON.parse(await readFile(fixturePath, 'utf8'))
const encoder = new TextEncoder()
const decoder = new TextDecoder()

const kps = await listen({
  port: 41109,
  address: '127.0.0.1',
  certPath: join(here, 'kps-cert.pem'),
  keyPath: join(here, 'kps-key.pem')
})
const kpsAddress = kps.address('127.0.0.1')
void acceptKps()

const mime = {
  '.html': 'text/html',
  '.js': 'text/javascript',
  '.json': 'application/json',
  '.wasm': 'application/wasm'
}
const http = createServer(async (req, res) => {
  if (req.url === '/health') return end(res, 200, 'text/plain', 'ok')
  if (req.url === '/kps-address') {
    return end(res, 200, 'application/json', JSON.stringify(kpsAddress))
  }
  const urlPath =
    req.url === '/' ? '/crates/safe-node-revm-wasm/js/smoke.html' : req.url.split('?')[0]
  const path = resolve(repo, `.${urlPath}`)
  const relativePath = relative(repo, path)
  if (relativePath.startsWith('..') || isAbsolute(relativePath)) {
    return end(res, 403, 'text/plain', 'forbidden')
  }
  try {
    end(res, 200, mime[extname(path)] ?? 'application/octet-stream', await readFile(path))
  } catch {
    end(res, 404, 'text/plain', 'not found')
  }
})
http.listen(4173, '127.0.0.1', () =>
  console.log(`smoke server http://127.0.0.1:4173 KPS ${kpsAddress}`)
)

async function acceptKps() {
  for (;;) {
    const conn = await kps.accept()
    void (async () => {
      try {
        for (;;) void handleStream(await conn.acceptStream())
      } catch {}
    })()
  }
}

async function handleStream(stream) {
  const writer = stream.writable.getWriter()
  try {
    for await (const line of lines(stream.readable)) {
      const request = JSON.parse(line)
      const [address, keys] = request.params
      let response
      if (address.toLowerCase() !== fixture.address.toLowerCase()) {
        response = {
          jsonrpc: '2.0',
          id: request.id,
          error: { code: -32001, message: 'fixture account unavailable' }
        }
      } else {
        const proof = structuredClone(fixture.proof)
        if (keys.length === 0) proof.storageProof = []
        else {
          proof.storageProof = keys.map((key) => {
            if (BigInt(key) !== BigInt(fixture.slot)) throw new Error('fixture slot unavailable')
            return { ...structuredClone(fixture.proof.storageProof[0]), key }
          })
        }
        response = { jsonrpc: '2.0', id: request.id, result: proof }
      }
      await writer.write(encoder.encode(`${JSON.stringify(response)}\n`))
    }
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
      for (;;) {
        const newline = buffered.indexOf('\n')
        if (newline < 0) break
        const line = buffered.slice(0, newline)
        buffered = buffered.slice(newline + 1)
        if (line.trim()) yield line
      }
    }
  } finally {
    reader.releaseLock()
  }
}

function end(res, status, type, body) {
  res.writeHead(status, {
    'content-type': type,
    'cross-origin-opener-policy': 'same-origin',
    'cross-origin-embedder-policy': 'require-corp'
  })
  res.end(body)
}

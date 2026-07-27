import { dial } from '@kpstreams/webrtc-client'

const encoder = new TextEncoder()
const decoder = new TextDecoder()

/**
 * Input-independent account/storage tick scheduler.
 *
 * `executor` is the wasm `WasmExecutor`; `sendRpc` sends one JSON line and
 * resolves with one JSON-RPC response. Calls are launched without awaiting
 * prior responses so slow requests do not intentionally stall the ticker.
 */
export class ConstantRateClient {
  constructor({ executor, sendRpc, requestsPerSecond = 4, maxAttempts = 10 }) {
    if (!Number.isInteger(requestsPerSecond) || requestsPerSecond <= 0) {
      throw new Error('requestsPerSecond must be a positive integer')
    }
    if (!Number.isInteger(maxAttempts) || maxAttempts < 1 || maxAttempts > 10) {
      throw new Error('maxAttempts must be between 1 and 10')
    }
    this.executor = executor
    this.sendRpc = sendRpc
    this.periodMs = 1000 / requestsPerSecond
    this.maxAttempts = maxAttempts
    this.accountQueue = []
    this.storageQueue = []
    this.nextStorage = false
    this.nextId = 0n
    this.timer = undefined
    this.sentCount = 0
    this.fatalError = undefined
  }

  start() {
    if (this.timer !== undefined) return
    this.timer = setInterval(() => {
      void this.tick()
    }, this.periodMs)
  }

  stop() {
    if (this.timer !== undefined) clearInterval(this.timer)
    this.timer = undefined
  }

  request(query) {
    if (this.fatalError) return Promise.reject(this.fatalError)
    if (!query || (query.kind !== 'account' && query.kind !== 'storage')) {
      return Promise.reject(new Error('query kind must be account or storage'))
    }
    const queue = query.kind === 'storage' ? this.storageQueue : this.accountQueue
    return new Promise((resolve, reject) => queue.push({ query, resolve, reject, attempts: 0 }))
  }

  /** One deterministic tick, public for fake-time tests. */
  async tick() {
    if (this.fatalError) throw this.fatalError
    const storage = this.nextStorage
    this.nextStorage = !this.nextStorage
    const queue = storage ? this.storageQueue : this.accountQueue
    const job = queue.shift()
    const id = (++this.nextId).toString(16).padStart(16, '0').slice(-16)
    const request = job
      ? this.executor.requestFor(JSON.stringify(job.query), id)
      : this.executor.coverRequest(storage, id)
    this.sentCount++

    // Do not await this from the interval callback: cadence is independent of
    // response latency, subject to browser/transport scheduling limits.
    const completion = Promise.resolve(this.sendRpc(request))
      .then((response) => {
        if (!job) return
        if (this.fatalError) {
          job.reject(this.fatalError)
          return
        }
        this.executor.applyProof(JSON.stringify(job.query), response)
        job.resolve()
      })
      .catch((error) => {
        if (error?.code === -32097) {
          this.fatalError = error
          this.stop()
          if (job) job.reject(error)
          this.#rejectQueued(error)
          return
        }
        if (!job) return
        job.attempts++
        if (job.attempts < this.maxAttempts) {
          // Retry only by replacing cover work on a later matching tick.
          queue.push(job)
        } else {
          job.reject(
            new Error(
              `proof request failed after ${job.attempts} attempts: ${error.message ?? error}`
            )
          )
        }
      })
    return completion
  }

  /** Execute with cache-miss replay, capped by the wasm executor at 10 attempts. */
  async execute() {
    for (;;) {
      const result = JSON.parse(this.executor.executeAttempt())
      if (result.status === 'need') {
        await this.request(result.query)
        continue
      }
      if (result.status === 'success') return result
      throw new Error(result.message ?? `EVM ${result.status}: ${result.output ?? ''}`)
    }
  }

  #rejectQueued(error) {
    for (const queue of [this.accountQueue, this.storageQueue]) {
      for (const job of queue.splice(0)) job.reject(error)
    }
  }
}

/** A newline-delimited JSON-RPC channel over one certificate-pinned KPS stream. */
export class KpsRpcChannel {
  static async connect(address, { signal } = {}) {
    const conn = await dial(address, { signal })
    const stream = await conn.openStream({ signal })
    return new KpsRpcChannel(conn, stream)
  }

  constructor(conn, stream) {
    this.conn = conn
    this.stream = stream
    this.writer = stream.writable.getWriter()
    this.pending = new Map()
    this.writeTail = Promise.resolve()
    this.closed = false
    void this.#readLoop()
  }

  sendRpc(requestText) {
    if (this.closed) return Promise.reject(new Error('KPS RPC channel is closed'))
    const id = String(JSON.parse(requestText).id)
    if (this.pending.has(id)) return Promise.reject(new Error(`duplicate JSON-RPC id ${id}`))
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject })
      this.writeTail = this.writeTail
        .then(() => this.writer.write(encoder.encode(`${requestText}\n`)))
        .catch((error) => {
          this.pending.delete(String(id))
          reject(error)
        })
    })
  }

  async close() {
    this.closed = true
    try {
      await this.writer.close()
    } catch {}
    try {
      await this.stream.close()
    } catch {}
    try {
      await this.conn.close()
    } catch {}
    this.#rejectAll(new Error('KPS RPC channel closed'))
  }

  async #readLoop() {
    const reader = this.stream.readable.getReader()
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
          if (!line.trim()) continue
          const response = JSON.parse(line)
          const id = String(response.id)
          const pending = this.pending.get(id)
          if (pending) {
            this.pending.delete(id)
            if (response.error?.code === -32097 || response.error?.code === -32098) {
              const error = new Error(response.error.message)
              error.code = response.error.code
              pending.reject(error)
            } else {
              pending.resolve(line)
            }
          }
        }
      }
      this.#rejectAll(new Error('KPS peer closed the response stream'))
    } catch (error) {
      this.#rejectAll(error)
    } finally {
      reader.releaseLock()
    }
  }

  #rejectAll(error) {
    for (const { reject } of this.pending.values()) reject(error)
    this.pending.clear()
  }
}

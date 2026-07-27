import assert from 'node:assert/strict'
import test from 'node:test'
import { ConstantRateClient } from './index.js'

class FakeExecutor {
  constructor() {
    this.applied = 0
    this.executeCalls = 0
  }

  requestFor(queryText, id) {
    return JSON.stringify({ jsonrpc: '2.0', id, real: true, query: JSON.parse(queryText) })
  }

  coverRequest(storage, id) {
    return JSON.stringify({ jsonrpc: '2.0', id, real: false, storage })
  }

  applyProof() {
    this.applied++
  }

  executeAttempt() {
    this.executeCalls++
    if (this.applied === 0) {
      return JSON.stringify({
        status: 'need',
        query: { kind: 'account', address: `0x${'11'.repeat(20)}` }
      })
    }
    return JSON.stringify({ status: 'success', output: '0x01', attempt: this.executeCalls })
  }
}

const responseFor = (request) =>
  JSON.stringify({ jsonrpc: '2.0', id: JSON.parse(request).id, result: {} })

test('real work replaces cover without changing one request per tick', async () => {
  const executor = new FakeExecutor()
  const sent = []
  const client = new ConstantRateClient({
    executor,
    sendRpc: async (request) => {
      sent.push(JSON.parse(request))
      return responseFor(request)
    },
    requestsPerSecond: 4
  })

  const real = client.request({ kind: 'account', address: `0x${'22'.repeat(20)}` })
  for (let i = 0; i < 6; i++) await client.tick()
  await real

  assert.equal(sent.length, 6)
  assert.equal(sent.filter((request) => request.real).length, 1)
  assert.deepEqual(
    sent.map((request) => request.storage ?? false),
    [false, true, false, true, false, true]
  )
})

test('failed real work retries only on later matching ticks, capped at ten', async () => {
  const executor = new FakeExecutor()
  let realAttempts = 0
  const client = new ConstantRateClient({
    executor,
    sendRpc: async (request) => {
      const parsed = JSON.parse(request)
      if (parsed.real && ++realAttempts < 3) throw new Error('transient')
      return responseFor(request)
    },
    requestsPerSecond: 4,
    maxAttempts: 10
  })

  const completion = client.request({ kind: 'account', address: `0x${'33'.repeat(20)}` })
  // Account ticks are 1, 3 and 5; intervening storage ticks stay cover traffic.
  for (let i = 0; i < 5; i++) await client.tick()
  await completion
  assert.equal(realAttempts, 3)
  assert.equal(client.sentCount, 5)
})

test('pin mismatch on cover traffic stops scheduling and fails queued work', async () => {
  const error = Object.assign(new Error('attested TLS pin mismatch'), { code: -32097 })
  const client = new ConstantRateClient({
    executor: new FakeExecutor(),
    sendRpc: async () => {
      throw error
    },
    requestsPerSecond: 4
  })

  await client.tick()
  await assert.rejects(
    client.request({ kind: 'account', address: `0x${'44'.repeat(20)}` }),
    /pin mismatch/
  )
  await assert.rejects(client.tick(), /pin mismatch/)
})

test('execution replays after a scheduled cache miss', async () => {
  const executor = new FakeExecutor()
  const client = new ConstantRateClient({
    executor,
    sendRpc: async (request) => responseFor(request),
    requestsPerSecond: 4
  })
  const execution = client.execute()
  await Promise.resolve()
  await client.tick()
  const result = await execution
  assert.equal(result.status, 'success')
  assert.equal(executor.executeCalls, 2)
})

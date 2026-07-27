import init, { WasmExecutor } from '../pkg/safe_node_revm_wasm.js'
import { ConstantRateClient, KpsRpcChannel } from './index.js'

window.smokePromise = (async () => {
  await init()
  const [fixture, address] = await Promise.all([
    fetch('/crates/safe-node-revm/fixtures/sepolia-weth9-11344323.json').then((response) =>
      response.json()
    ),
    fetch('/kps-address').then((response) => response.json())
  ])
  const executor = new WasmExecutor(
    JSON.stringify({
      stateRoot: fixture.stateRoot,
      block: fixture.block,
      contract: fixture.address,
      bytecode: fixture.code,
      calldata: fixture.calldata,
      dummyAddress: fixture.address,
      dummySlot: fixture.slot,
      storageKeysPerRequest: 1,
      maxAttempts: 10
    })
  )
  const channel = await KpsRpcChannel.connect(address, { signal: AbortSignal.timeout(15_000) })
  const client = new ConstantRateClient({
    executor,
    sendRpc: (request) => channel.sendRpc(request),
    requestsPerSecond: 20,
    maxAttempts: 10
  })
  client.start()
  try {
    const result = await client.execute()
    document.body.dataset.status = 'ok'
    document.body.textContent = `${result.status} after ${result.attempt} attempts`
    return result
  } finally {
    // A production caller should use an execution-independent cover window.
    await new Promise((resolve) => setTimeout(resolve, 100))
    client.stop()
    await channel.close()
  }
})().catch((error) => {
  document.body.dataset.status = 'error'
  document.body.textContent = error.stack ?? String(error)
  throw error
})

import {
  getAddress,
  isAddress,
  isAddressEqual,
  type Address,
  type Hex,
} from 'viem'

import type {
  ChainHistoryProvider,
  FinalizedBlockProvider,
  GetOutboundTransactionsInput,
  NormalizedOutboundTransaction,
  OutboundTransactionHistory,
} from '../types.js'

const ETHERSCAN_V2_ENDPOINT = 'https://api.etherscan.io/v2/api'
const DEFAULT_PAGE_SIZE = 1_000
const MAX_PAGE_SIZE = 1_000
const DEFAULT_MAX_PAGES = 10_000
const DEFAULT_REQUEST_INTERVAL_MS = 350

export class EtherscanHistoryProviderError extends Error {
  override readonly name = 'EtherscanHistoryProviderError'
}

export type JsonHttpGet = (url: URL) => Promise<unknown>
export type Sleep = (milliseconds: number) => Promise<void>
export type Clock = () => Date

export type EtherscanV2HistoryProviderOptions = Readonly<{
  apiKey: string
  finalizedBlockProvider: FinalizedBlockProvider
  httpGet?: JsonHttpGet
  sleep?: Sleep
  clock?: Clock
  pageSize?: number
  maxPages?: number
  requestIntervalMs?: number
}>

export class EtherscanV2HistoryProvider implements ChainHistoryProvider {
  readonly id = 'etherscan-v2'

  readonly #apiKey: string
  readonly #finalizedBlockProvider: FinalizedBlockProvider
  readonly #httpGet: JsonHttpGet
  readonly #sleep: Sleep
  readonly #clock: Clock
  readonly #pageSize: number
  readonly #maxPages: number
  readonly #requestIntervalMs: number

  constructor(options: EtherscanV2HistoryProviderOptions) {
    const apiKey = options.apiKey.trim()
    if (apiKey.length === 0) {
      throw new Error('Etherscan apiKey must not be empty')
    }

    const pageSize = options.pageSize ?? DEFAULT_PAGE_SIZE
    if (
      !Number.isInteger(pageSize) ||
      pageSize <= 0 ||
      pageSize > MAX_PAGE_SIZE
    ) {
      throw new Error(`pageSize must be an integer between 1 and ${MAX_PAGE_SIZE}`)
    }

    const maxPages = options.maxPages ?? DEFAULT_MAX_PAGES
    if (!Number.isInteger(maxPages) || maxPages <= 0) {
      throw new Error('maxPages must be a positive integer')
    }

    const requestIntervalMs =
      options.requestIntervalMs ?? DEFAULT_REQUEST_INTERVAL_MS
    if (!Number.isInteger(requestIntervalMs) || requestIntervalMs < 0) {
      throw new Error('requestIntervalMs must be a non-negative integer')
    }

    this.#apiKey = apiKey
    this.#finalizedBlockProvider = options.finalizedBlockProvider
    this.#httpGet = options.httpGet ?? defaultJsonHttpGet
    this.#sleep = options.sleep ?? defaultSleep
    this.#clock = options.clock ?? (() => new Date())
    this.#pageSize = pageSize
    this.#maxPages = maxPages
    this.#requestIntervalMs = requestIntervalMs
  }

  async getOutboundTransactions(
    input: GetOutboundTransactionsInput,
  ): Promise<OutboundTransactionHistory> {
    assertValidRequest(input)

    const address = getAddress(input.address)
    const finalizedBlock = await this.#finalizedBlockProvider.getFinalizedBlockNumber({
      chainId: input.chainId,
    })

    if (finalizedBlock < 0n) {
      throw new EtherscanHistoryProviderError(
        'Finalized block provider returned an invalid block number',
      )
    }

    const fetchedAt = new Date(this.#clock())
    if (Number.isNaN(fetchedAt.getTime())) {
      throw new EtherscanHistoryProviderError('Clock returned an invalid Date')
    }

    const transactions: NormalizedOutboundTransaction[] = []
    let exhausted = false

    for (let page = 1; page <= this.#maxPages; page += 1) {
      if (page > 1 && this.#requestIntervalMs > 0) {
        await this.#sleep(this.#requestIntervalMs)
      }

      const rows = await this.#requestPage({
        address,
        chainId: input.chainId,
        finalizedBlock,
        page,
      })

      for (const row of rows) {
        const normalized = normalizeEtherscanRow({
          row,
          queriedAddress: address,
          chainId: input.chainId,
          finalizedBlock,
        })

        if (normalized) transactions.push(normalized)
      }

      if (rows.length < this.#pageSize) {
        exhausted = true
        break
      }
    }

    if (!exhausted) {
      throw new EtherscanHistoryProviderError(
        'History pagination reached the configured safety limit before exhaustion',
      )
    }

    return {
      coverage: {
        providerId: this.id,
        chainId: input.chainId,
        fromBlock: 0n,
        throughBlock: finalizedBlock,
        fetchedAt,
        complete: true,
      },
      transactions,
    }
  }

  async #requestPage(input: {
    address: Address
    chainId: number
    finalizedBlock: bigint
    page: number
  }): Promise<readonly unknown[]> {
    const url = new URL(ETHERSCAN_V2_ENDPOINT)
    url.searchParams.set('chainid', String(input.chainId))
    url.searchParams.set('module', 'account')
    url.searchParams.set('action', 'txlist')
    url.searchParams.set('address', input.address)
    url.searchParams.set('startblock', '0')
    url.searchParams.set('endblock', input.finalizedBlock.toString())
    url.searchParams.set('page', String(input.page))
    url.searchParams.set('offset', String(this.#pageSize))
    url.searchParams.set('sort', 'asc')
    url.searchParams.set('apikey', this.#apiKey)

    let payload: unknown
    try {
      payload = await this.#httpGet(url)
    } catch {
      // Do not propagate a fetch error that may include the URL/API key.
      throw new EtherscanHistoryProviderError('Etherscan HTTP request failed')
    }

    return parseEtherscanEnvelope(payload)
  }
}

async function defaultJsonHttpGet(url: URL): Promise<unknown> {
  const response = await fetch(url, {
    method: 'GET',
    headers: { accept: 'application/json' },
  })

  if (!response.ok) {
    throw new Error(`HTTP ${response.status}`)
  }

  return response.json()
}

async function defaultSleep(milliseconds: number): Promise<void> {
  await new Promise<void>((resolve) => setTimeout(resolve, milliseconds))
}

function assertValidRequest(input: GetOutboundTransactionsInput): void {
  if (!Number.isInteger(input.chainId) || input.chainId <= 0) {
    throw new Error('chainId must be a positive integer')
  }

  if (!isAddress(input.address)) {
    throw new Error('address must be a valid EVM address')
  }
}

function parseEtherscanEnvelope(payload: unknown): readonly unknown[] {
  if (!isRecord(payload)) {
    throw new EtherscanHistoryProviderError('Malformed Etherscan response envelope')
  }

  const status = payload.status
  const message = payload.message
  const result = payload.result

  if (
    status === '0' &&
    typeof message === 'string' &&
    message.toLowerCase().includes('no transactions found') &&
    Array.isArray(result) &&
    result.length === 0
  ) {
    return []
  }

  if (status !== '1' || !Array.isArray(result)) {
    const detail = providerErrorDetail(message, result)
    throw new EtherscanHistoryProviderError(
      detail ? `Etherscan rejected the request: ${detail}` : 'Etherscan rejected the request',
    )
  }

  return result
}

function normalizeEtherscanRow(input: {
  row: unknown
  queriedAddress: Address
  chainId: number
  finalizedBlock: bigint
}): NormalizedOutboundTransaction | undefined {
  if (!isRecord(input.row)) {
    throw new EtherscanHistoryProviderError('Malformed Etherscan transaction row')
  }

  const blockNumber = parseUnsignedBigInt(input.row.blockNumber, 'blockNumber')
  if (blockNumber > input.finalizedBlock) {
    throw new EtherscanHistoryProviderError(
      'Etherscan returned a transaction beyond the captured finalized block',
    )
  }

  const fromRaw = requireString(input.row.from, 'from')
  if (!isAddress(fromRaw)) {
    throw new EtherscanHistoryProviderError('Etherscan returned an invalid from address')
  }
  const from = getAddress(fromRaw)

  // txlist includes transactions involving the queried address. This provider
  // contract intentionally exposes outbound history only.
  if (!isAddressEqual(from, input.queriedAddress)) {
    return undefined
  }

  const toRaw = requireString(input.row.to, 'to')
  let to: Address | null
  if (toRaw === '') {
    to = null
  } else if (isAddress(toRaw)) {
    to = getAddress(toRaw)
  } else {
    throw new EtherscanHistoryProviderError('Etherscan returned an invalid to address')
  }

  const hash = parseTransactionHash(input.row.hash)
  const transactionIndex = parseSafeUnsignedInteger(
    input.row.transactionIndex,
    'transactionIndex',
  )
  const timestamp = parseUnixTimestamp(input.row.timeStamp)
  const valueWei = parseUnsignedBigInt(input.row.value, 'value')
  const calldata = parseCalldata(input.row.input)

  const isError = requireString(input.row.isError, 'isError')
  if (isError !== '0' && isError !== '1') {
    throw new EtherscanHistoryProviderError('Etherscan returned an invalid isError value')
  }

  const receiptStatus = requireString(
    input.row.txreceipt_status,
    'txreceipt_status',
  )
  if (receiptStatus !== '' && receiptStatus !== '0' && receiptStatus !== '1') {
    throw new EtherscanHistoryProviderError(
      'Etherscan returned an invalid txreceipt_status value',
    )
  }

  const failed = isError === '1' || receiptStatus === '0'

  return {
    chainId: input.chainId,
    hash,
    from,
    to,
    blockNumber,
    transactionIndex,
    timestamp,
    status: failed ? 'failed' : 'success',
    finalized: true,
    valueWei,
    input: calldata,
  }
}

function parseTransactionHash(value: unknown): Hex {
  const text = requireString(value, 'hash')
  if (!/^0x[0-9a-fA-F]{64}$/.test(text)) {
    throw new EtherscanHistoryProviderError('Etherscan returned an invalid transaction hash')
  }
  return text as Hex
}

function parseCalldata(value: unknown): Hex {
  const text = requireString(value, 'input')
  if (!/^0x(?:[0-9a-fA-F]{2})*$/.test(text)) {
    throw new EtherscanHistoryProviderError('Etherscan returned invalid calldata')
  }
  return text as Hex
}

function parseUnixTimestamp(value: unknown): Date {
  const seconds = parseSafeUnsignedInteger(value, 'timeStamp')
  const milliseconds = seconds * 1_000
  const date = new Date(milliseconds)
  if (Number.isNaN(date.getTime())) {
    throw new EtherscanHistoryProviderError('Etherscan returned an invalid timestamp')
  }
  return date
}

function parseSafeUnsignedInteger(value: unknown, field: string): number {
  const parsed = parseUnsignedBigInt(value, field)
  if (parsed > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new EtherscanHistoryProviderError(
      `Etherscan returned ${field} outside the safe integer range`,
    )
  }
  return Number(parsed)
}

function parseUnsignedBigInt(value: unknown, field: string): bigint {
  const text = requireString(value, field)
  if (!/^(?:0|[1-9][0-9]*)$/.test(text)) {
    throw new EtherscanHistoryProviderError(`Etherscan returned invalid ${field}`)
  }
  return BigInt(text)
}

function requireString(value: unknown, field: string): string {
  if (typeof value !== 'string') {
    throw new EtherscanHistoryProviderError(`Etherscan returned non-string ${field}`)
  }
  return value
}

function providerErrorDetail(message: unknown, result: unknown): string | undefined {
  // `message` is often only "NOTOK" while `result` contains the actionable
  // provider reason (rate limit, invalid key, timeout, etc.). Prefer result.
  const candidates = [result, message]
  for (const candidate of candidates) {
    if (typeof candidate === 'string' && candidate.length > 0) {
      return candidate.slice(0, 200)
    }
  }
  return undefined
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

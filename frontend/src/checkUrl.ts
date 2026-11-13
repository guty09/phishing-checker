export const MAX_URL_LENGTH = 4096

export type LookupStatus =
  | 'found'
  | 'disabled'
  | 'not_found'
  | 'rate_limited'
  | 'authentication_failure'
  | 'unavailable'

export type AnalysisCounts = Record<string, number>

export type CheckResult = {
  provider: string
  status: LookupStatus
  checkedAt: string
  lastAnalysisDate?: string | null
  analysis?: AnalysisCounts | null
}

const STATUSES: readonly LookupStatus[] = [
  'found',
  'disabled',
  'not_found',
  'rate_limited',
  'authentication_failure',
  'unavailable',
]

export function validateUrl(value: string): string | null {
  const url = value.trim()
  if (url.length === 0) {
    return 'Enter an absolute http or https URL.'
  }
  if (url.length > MAX_URL_LENGTH) {
    return 'The URL must be at most 4096 characters.'
  }
  let parsed: URL
  try {
    parsed = new URL(url)
  } catch {
    return 'Enter an absolute http or https URL.'
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return 'Only absolute http and https URLs can be checked.'
  }
  if (parsed.hostname.length === 0) {
    return 'Enter an absolute http or https URL.'
  }
  return null
}

export async function checkUrl(url: string): Promise<CheckResult> {
  let response: Response
  try {
    response = await fetch('/api/check/url', {
      method: 'POST',
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ url }),
    })
  } catch {
    throw new Error('The checker could not be reached. Try again in a moment.')
  }

  if (response.status === 400) {
    throw new Error('The URL was rejected. Use an absolute http or https URL of at most 4096 characters.')
  }

  if (!response.ok) {
    throw new Error('The checker could not complete the lookup.')
  }

  const body: unknown = await response.json()
  if (!isCheckResult(body)) {
    throw new Error('The checker returned an unexpected response.')
  }
  return body
}

function isCheckResult(value: unknown): value is CheckResult {
  if (typeof value !== 'object' || value === null) {
    return false
  }
  const record = value as Record<string, unknown>
  return (
    typeof record.provider === 'string' &&
    typeof record.status === 'string' &&
    isLookupStatus(record.status) &&
    typeof record.checkedAt === 'string'
  )
}

function isLookupStatus(value: string): value is LookupStatus {
  return STATUSES.some((status) => status === value)
}

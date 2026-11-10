export const MAX_EMAIL_TEXT_LENGTH = 50_000

export type EmailExtractResult = {
  urls: string[]
  warnings: string[]
  truncated: boolean
}

export function validateEmailText(value: string): string | null {
  if (value.trim().length === 0) {
    return 'Enter the email text to extract links.'
  }
  if (value.length > MAX_EMAIL_TEXT_LENGTH) {
    return 'The email text must be at most 50,000 characters.'
  }
  return null
}

export async function extractEmailLinks(text: string): Promise<EmailExtractResult> {
  let response: Response
  try {
    response = await fetch('/api/email/extract', {
      method: 'POST',
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ text }),
    })
  } catch {
    throw new Error('The checker could not be reached. Start the backend on port 8081.')
  }

  if (response.status === 400) {
    throw new Error('The email text was rejected. Use nonblank text of at most 50,000 characters.')
  }

  if (!response.ok) {
    throw new Error('The checker could not extract links.')
  }

  const body: unknown = await response.json()
  if (!isEmailExtractResult(body)) {
    throw new Error('The checker returned an unexpected response.')
  }
  return body
}

function isEmailExtractResult(value: unknown): value is EmailExtractResult {
  if (typeof value !== 'object' || value === null) {
    return false
  }
  const record = value as Record<string, unknown>
  return Array.isArray(record.urls) && record.urls.every(isString) && Array.isArray(record.warnings) && record.warnings.every(isString) && typeof record.truncated === 'boolean'
}

function isString(value: unknown): value is string {
  return typeof value === 'string'
}

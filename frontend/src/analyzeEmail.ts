import { MAX_EMAIL_TEXT_LENGTH } from './extractEmail'

export type EmailAssessment = 'suspicious' | 'no_obvious_warning_signs' | 'inconclusive'

export type EmailFinding = {
  ruleId: string
  explanation: string
}

export type EmailAnalysis = {
  assessment: EmailAssessment
  findings: EmailFinding[]
  limitations: string[]
}

const ASSESSMENTS: readonly EmailAssessment[] = ['suspicious', 'no_obvious_warning_signs', 'inconclusive']

export function validateEmailTextForAnalysis(value: string): string | null {
  if (value.trim().length === 0) {
    return 'Enter the message text to analyze.'
  }
  if (value.length > MAX_EMAIL_TEXT_LENGTH) {
    return 'The email text must be at most 50,000 characters.'
  }
  return null
}

export async function analyzeEmail(text: string): Promise<EmailAnalysis> {
  let response: Response
  try {
    response = await fetch('/api/email/analyze', {
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
    throw new Error('The checker could not analyze the message.')
  }

  const body: unknown = await response.json()
  if (!isEmailAnalysis(body)) {
    throw new Error('The checker returned an unexpected response.')
  }
  return body
}

function isEmailAnalysis(value: unknown): value is EmailAnalysis {
  if (typeof value !== 'object' || value === null) {
    return false
  }
  const record = value as Record<string, unknown>
  return (
    typeof record.assessment === 'string' &&
    ASSESSMENTS.some((assessment) => assessment === record.assessment) &&
    Array.isArray(record.findings) &&
    record.findings.every(isFinding) &&
    Array.isArray(record.limitations) &&
    record.limitations.every(isString)
  )
}

function isFinding(value: unknown): value is EmailFinding {
  if (typeof value !== 'object' || value === null) {
    return false
  }
  const record = value as Record<string, unknown>
  return typeof record.ruleId === 'string' && typeof record.explanation === 'string'
}

function isString(value: unknown): value is string {
  return typeof value === 'string'
}

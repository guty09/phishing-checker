import { useState, type FormEvent } from 'react'
import { checkUrl, validateUrl, type AnalysisCounts, type CheckResult, type LookupStatus } from './checkUrl'
import { EmailPaste } from './EmailPaste'
import './App.css'

const STATUS_EXPLANATION: Record<LookupStatus, string> = {
  found: 'An existing report was retrieved. This does not mean the URL is safe.',
  disabled: 'VirusTotal is disabled because the backend has no API key.',
  not_found: 'No existing report was found. This does not mean the URL is safe.',
  rate_limited: 'The lookup was rate limited. Wait a minute and try again.',
  authentication_failure: 'VirusTotal rejected the backend API key.',
  unavailable: 'The lookup is unavailable right now.',
}

function App() {
  const [url, setUrl] = useState('')
  const [submittedUrl, setSubmittedUrl] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const [inputError, setInputError] = useState<string | null>(null)
  const [requestError, setRequestError] = useState<string | null>(null)
  const [result, setResult] = useState<CheckResult | null>(null)

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const candidate = url.trim()
    const validationError = validateUrl(candidate)
    setSubmittedUrl(candidate.length > 0 ? candidate : null)
    setResult(null)
    setRequestError(null)
    if (validationError) {
      setInputError(validationError)
      return
    }
    setInputError(null)
    setLoading(true)
    try {
      const next = await checkUrl(candidate)
      setResult(next)
    } catch (error) {
      setRequestError(error instanceof Error ? error.message : 'The checker could not complete the lookup.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <main className="page">
      <p className="prototype">
        Prototype. The URL section checks reputation only. Pasted email text is used to extract links, not to decide whether the email is phishing.
      </p>
      <h1>Phishing checker</h1>
      <p className="lead">
        Look up an existing VirusTotal report. A result of <strong>found</strong> means a report was retrieved, not that the URL is safe.
      </p>
      <form onSubmit={onSubmit}>
        <label htmlFor="url">URL</label>
        <input
          id="url"
          name="url"
          type="text"
          inputMode="url"
          autoComplete="off"
          spellCheck={false}
          value={url}
          onChange={(event) => setUrl(event.target.value)}
          placeholder="https://example.com"
        />
        <button type="submit" disabled={loading}>
          {loading ? 'Checking…' : 'Check URL'}
        </button>
      </form>
      <section className="result" aria-live="polite">
        {loading ? <p>Checking the URL…</p> : null}
        {submittedUrl ? (
          <p>
            Submitted URL: <span className="plain-url">{submittedUrl}</span>
          </p>
        ) : null}
        {inputError ? <p className="message">{inputError}</p> : null}
        {requestError ? <p className="message">{requestError}</p> : null}
        {result ? <ResultView result={result} /> : null}
      </section>
      <EmailPaste />
    </main>
  )
}

function ResultView({ result }: { result: CheckResult }) {
  return (
    <dl>
      <dt>Provider</dt>
      <dd>{result.provider}</dd>
      <dt>Lookup status</dt>
      <dd>{result.status}</dd>
      <dt>What this status means</dt>
      <dd>{STATUS_EXPLANATION[result.status]}</dd>
      <dt>checkedAt</dt>
      <dd>{formatTimestamp(result.checkedAt)}</dd>
      <dt>lastAnalysisDate</dt>
      <dd>{result.lastAnalysisDate ? formatTimestamp(result.lastAnalysisDate) : 'Not included'}</dd>
      <dt>Analysis counts</dt>
      <dd>
        <AnalysisList analysis={result.analysis} />
      </dd>
    </dl>
  )
}

function AnalysisList({ analysis }: { analysis?: AnalysisCounts | null }) {
  if (!analysis || Object.keys(analysis).length === 0) {
    return <span>No counts were returned.</span>
  }
  const entries = Object.entries(analysis).sort(([left], [right]) => left.localeCompare(right))
  return (
    <ul>
      {entries.map(([name, count]) => (
        <li key={name}>
          {name}: {count}
        </li>
      ))}
    </ul>
  )
}

function formatTimestamp(value: string): string {
  const parsed = new Date(value)
  if (Number.isNaN(parsed.getTime())) {
    return value
  }
  return parsed.toISOString()
}

export default App

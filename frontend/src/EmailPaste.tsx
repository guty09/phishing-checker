import { useRef, useState, type FormEvent } from 'react'
import type { CheckResult } from './checkUrl'
import { extractEmailLinks, MAX_EMAIL_TEXT_LENGTH, validateEmailText, type EmailExtractResult } from './extractEmail'
import { ResultView } from './reputationResult'

type ExtractedReputationCheck = {
  url: string
  loading: boolean
  requestError: string | null
  result: CheckResult | null
}

type EmailPasteProps = {
  reputationBusy: boolean
  extractedCheck: ExtractedReputationCheck | null
  onEmailTextChange: () => void
  onCheckReputation: (url: string) => void
}

export function EmailPaste({ reputationBusy, extractedCheck, onEmailTextChange, onCheckReputation }: EmailPasteProps) {
  const [text, setText] = useState('')
  const [loading, setLoading] = useState(false)
  const [inputError, setInputError] = useState<string | null>(null)
  const [requestError, setRequestError] = useState<string | null>(null)
  const [result, setResult] = useState<EmailExtractResult | null>(null)
  const requestGeneration = useRef(0)

  function onTextChange(value: string) {
    requestGeneration.current += 1
    setText(value)
    setLoading(false)
    setInputError(null)
    setRequestError(null)
    setResult(null)
    onEmailTextChange()
  }

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const generation = requestGeneration.current + 1
    requestGeneration.current = generation
    setResult(null)
    setRequestError(null)
    const validationError = validateEmailText(text)
    if (validationError) {
      setInputError(validationError)
      setLoading(false)
      return
    }
    setInputError(null)
    setLoading(true)
    try {
      const next = await extractEmailLinks(text)
      if (requestGeneration.current !== generation) {
        return
      }
      setResult(next)
    } catch (error) {
      if (requestGeneration.current !== generation) {
        return
      }
      setRequestError(error instanceof Error ? error.message : 'The checker could not extract links.')
    } finally {
      if (requestGeneration.current === generation) {
        setLoading(false)
      }
    }
  }

  return (
    <section className="email-paste">
      <h2>Paste email text</h2>
      <p id="email-note">
        This extracts links only. It does not yet assess whether the email is phishing.
      </p>
      <form onSubmit={onSubmit}>
        <label htmlFor="email-text">Email text</label>
        <textarea
          id="email-text"
          name="email-text"
          rows={8}
          maxLength={MAX_EMAIL_TEXT_LENGTH}
          autoComplete="off"
          spellCheck={false}
          value={text}
          aria-describedby="email-note email-count"
          onChange={(event) => onTextChange(event.target.value)}
        />
        <p id="email-count" className="counter">
          {text.length.toLocaleString()} / {MAX_EMAIL_TEXT_LENGTH.toLocaleString()}
        </p>
        <button type="submit" disabled={loading}>
          {loading ? 'Extracting…' : 'Extract links'}
        </button>
      </form>
      <div className="result" aria-live="polite">
        {loading ? <p>Extracting links…</p> : null}
        {inputError ? <p className="message">{inputError}</p> : null}
        {requestError ? <p className="message">{requestError}</p> : null}
        {result ? (
          <ExtractResultView
            result={result}
            reputationBusy={reputationBusy}
            extractedCheck={extractedCheck}
            onCheckReputation={onCheckReputation}
          />
        ) : null}
      </div>
    </section>
  )
}

function ExtractResultView({
  result,
  reputationBusy,
  extractedCheck,
  onCheckReputation,
}: {
  result: EmailExtractResult
  reputationBusy: boolean
  extractedCheck: ExtractedReputationCheck | null
  onCheckReputation: (url: string) => void
}) {
  return (
    <div>
      <p>{result.truncated ? 'Truncation: only the first 20 unique URLs are shown.' : 'Truncation: no.'}</p>
      {result.urls.length === 0 ? <p>No explicit http or https links were found.</p> : null}
      {result.urls.length > 0 ? (
        <>
          <p>Check reputation sends the selected URL to VirusTotal through our backend. Nothing is checked until you click its button.</p>
          <ul className="url-list">
            {result.urls.map((url) => (
              <li key={url}>
                <span className="plain-url">{url}</span>
                <button type="button" disabled={reputationBusy} onClick={() => onCheckReputation(url)}>
                  {extractedCheck?.loading && extractedCheck.url === url ? 'Checking…' : 'Check reputation'}
                </button>
              </li>
            ))}
          </ul>
        </>
      ) : null}
      <ul className="warning-list">
        {result.warnings.map((warning) => (
          <li key={warning}>{warning}</li>
        ))}
      </ul>
      {extractedCheck ? (
        <div className="extracted-check">
          <p>
            Reputation result for extracted URL: <span className="plain-url">{extractedCheck.url}</span>
          </p>
          {extractedCheck.loading ? <p>Checking the URL…</p> : null}
          {extractedCheck.requestError ? <p className="message">{extractedCheck.requestError}</p> : null}
          {extractedCheck.result ? <ResultView result={extractedCheck.result} /> : null}
        </div>
      ) : null}
    </div>
  )
}

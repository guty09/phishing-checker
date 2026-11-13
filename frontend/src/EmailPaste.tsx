import { useRef, useState, type FormEvent } from 'react'
import { analyzeEmail, validateEmailTextForAnalysis, type EmailAnalysis, type EmailAssessment } from './analyzeEmail'
import type { CheckResult } from './checkUrl'
import { extractEmailLinks, MAX_EMAIL_TEXT_LENGTH, validateEmailText, type EmailExtractResult } from './extractEmail'
import { ResultView } from './reputationResult'

const ASSESSMENT_LABEL: Record<EmailAssessment, string> = {
  suspicious: 'Suspicious warning signs',
  no_obvious_warning_signs: 'No obvious warning signs',
  inconclusive: 'Inconclusive',
}

const MESSAGE_SOURCES = [
  { id: 'email', label: 'Email', inputLabel: 'Email text', placeholder: 'Paste the email message text' },
  { id: 'whatsapp', label: 'WhatsApp', inputLabel: 'WhatsApp text', placeholder: 'Paste the WhatsApp message text' },
  { id: 'telegram', label: 'Telegram', inputLabel: 'Telegram text', placeholder: 'Paste the Telegram message text' },
  { id: 'sms', label: 'SMS', inputLabel: 'SMS text', placeholder: 'Paste the SMS message text' },
] as const

type MessageSourceId = (typeof MESSAGE_SOURCES)[number]['id']

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
  const [source, setSource] = useState<MessageSourceId>('email')
  const [text, setText] = useState('')
  const [loading, setLoading] = useState(false)
  const [inputError, setInputError] = useState<string | null>(null)
  const [requestError, setRequestError] = useState<string | null>(null)
  const [result, setResult] = useState<EmailExtractResult | null>(null)
  const [analysisLoading, setAnalysisLoading] = useState(false)
  const [analysisInputError, setAnalysisInputError] = useState<string | null>(null)
  const [analysisError, setAnalysisError] = useState<string | null>(null)
  const [analysis, setAnalysis] = useState<EmailAnalysis | null>(null)
  const requestGeneration = useRef(0)
  const analysisGeneration = useRef(0)

  function invalidatePendingResults() {
    requestGeneration.current += 1
    analysisGeneration.current += 1
    setLoading(false)
    setInputError(null)
    setRequestError(null)
    setResult(null)
    setAnalysisLoading(false)
    setAnalysisInputError(null)
    setAnalysisError(null)
    setAnalysis(null)
    onEmailTextChange()
  }

  function onTextChange(value: string) {
    invalidatePendingResults()
    setText(value)
  }

  function onSourceChange(next: MessageSourceId) {
    if (next === source) {
      return
    }
    invalidatePendingResults()
    setSource(next)
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

  async function onAnalyze() {
    const generation = analysisGeneration.current + 1
    analysisGeneration.current = generation
    setAnalysis(null)
    setAnalysisError(null)
    const validationError = validateEmailTextForAnalysis(text)
    if (validationError) {
      setAnalysisInputError(validationError)
      setAnalysisLoading(false)
      return
    }
    setAnalysisInputError(null)
    setAnalysisLoading(true)
    try {
      const next = await analyzeEmail(text)
      if (analysisGeneration.current !== generation) {
        return
      }
      setAnalysis(next)
    } catch (error) {
      if (analysisGeneration.current !== generation) {
        return
      }
      setAnalysisError(error instanceof Error ? error.message : 'The checker could not analyze the message.')
    } finally {
      if (analysisGeneration.current === generation) {
        setAnalysisLoading(false)
      }
    }
  }

  const selectedSource = MESSAGE_SOURCES.find((item) => item.id === source) ?? MESSAGE_SOURCES[0]

  return (
    <section className="email-paste">
      <h2>Paste message text</h2>
      <p id="email-note">
        Only the pasted text is checked. The source label does not change the checks. Sender identity, platform metadata, headers, and attachments are not verified. Extract links lists explicit http and https URLs. Analyze message applies the same text rules for every source. Message analysis does not confirm phishing and does not contact VirusTotal.
      </p>
      <form onSubmit={onSubmit}>
        <label htmlFor="message-source">Message source</label>
        <select
          id="message-source"
          name="message-source"
          value={source}
          onChange={(event) => onSourceChange(event.target.value as MessageSourceId)}
        >
          {MESSAGE_SOURCES.map((item) => (
            <option key={item.id} value={item.id}>
              {item.label}
            </option>
          ))}
        </select>
        <label htmlFor="message-text">{selectedSource.inputLabel}</label>
        <textarea
          id="message-text"
          name="message-text"
          rows={8}
          maxLength={MAX_EMAIL_TEXT_LENGTH}
          autoComplete="off"
          spellCheck={false}
          placeholder={selectedSource.placeholder}
          value={text}
          aria-describedby="email-note email-count"
          onChange={(event) => onTextChange(event.target.value)}
        />
        <p id="email-count" className="counter">
          {text.length.toLocaleString()} / {MAX_EMAIL_TEXT_LENGTH.toLocaleString()}
        </p>
        <div className="button-row">
          <button type="submit" disabled={loading}>
            {loading ? 'Extracting…' : 'Extract links'}
          </button>
          <button type="button" disabled={analysisLoading} onClick={() => void onAnalyze()}>
            {analysisLoading ? 'Analyzing…' : 'Analyze message'}
          </button>
        </div>
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
        <AnalysisView
          loading={analysisLoading}
          inputError={analysisInputError}
          requestError={analysisError}
          analysis={analysis}
        />
      </div>
    </section>
  )
}

function AnalysisView({
  loading,
  inputError,
  requestError,
  analysis,
}: {
  loading: boolean
  inputError: string | null
  requestError: string | null
  analysis: EmailAnalysis | null
}) {
  return (
    <section className="message-analysis" aria-live="polite">
      <h3>Message analysis</h3>
      {loading ? <p>Analyzing the message…</p> : null}
      {inputError ? <p className="message">{inputError}</p> : null}
      {requestError ? <p className="message">{requestError}</p> : null}
      {analysis ? (
        <>
          <p>
            Assessment: <strong>{ASSESSMENT_LABEL[analysis.assessment]}</strong>
          </p>
          <p>This assessment does not confirm phishing and is not a verdict that the message is harmless.</p>
          <h4>Rule explanations</h4>
          {analysis.findings.length === 0 ? <p>No rules matched.</p> : null}
          {analysis.findings.length > 0 ? (
            <ul>
              {analysis.findings.map((finding) => (
                <li key={finding.ruleId}>{finding.explanation}</li>
              ))}
            </ul>
          ) : null}
          <h4>Limitations</h4>
          <ul>
            {analysis.limitations.map((limitation) => (
              <li key={limitation}>{limitation}</li>
            ))}
          </ul>
        </>
      ) : null}
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

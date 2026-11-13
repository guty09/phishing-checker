import { useRef, useState, type FormEvent } from 'react'
import { checkUrl, validateUrl, type CheckResult } from './checkUrl'
import { EmailPaste } from './EmailPaste'
import { ResultView } from './reputationResult'
import './App.css'

type ReputationSource = 'standalone' | 'extracted'

type ReputationCheck = {
  url: string
  source: ReputationSource
  loading: boolean
  requestError: string | null
  result: CheckResult | null
}

function App() {
  const [url, setUrl] = useState('')
  const [submittedUrl, setSubmittedUrl] = useState<string | null>(null)
  const [inputError, setInputError] = useState<string | null>(null)
  const [check, setCheck] = useState<ReputationCheck | null>(null)
  const reputationGeneration = useRef(0)
  const reputationSource = useRef<ReputationSource | null>(null)

  const reputationBusy = check?.loading === true

  async function requestReputation(target: string, source: ReputationSource) {
    const generation = reputationGeneration.current + 1
    reputationGeneration.current = generation
    reputationSource.current = source
    setCheck({ url: target, source, loading: true, requestError: null, result: null })
    try {
      const next = await checkUrl(target)
      if (reputationGeneration.current !== generation) {
        return
      }
      setCheck({ url: target, source, loading: false, requestError: null, result: next })
    } catch (error) {
      if (reputationGeneration.current !== generation) {
        return
      }
      setCheck({
        url: target,
        source,
        loading: false,
        requestError: error instanceof Error ? error.message : 'The checker could not complete the lookup.',
        result: null,
      })
    }
  }

  function onEmailTextChange() {
    if (reputationSource.current !== 'extracted') {
      return
    }
    reputationGeneration.current += 1
    reputationSource.current = null
    setCheck(null)
  }

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const candidate = url.trim()
    const validationError = validateUrl(candidate)
    setSubmittedUrl(candidate.length > 0 ? candidate : null)
    if (validationError) {
      setInputError(validationError)
      if (reputationSource.current === 'standalone') {
        reputationGeneration.current += 1
        reputationSource.current = null
        setCheck(null)
      }
      return
    }
    setInputError(null)
    await requestReputation(candidate, 'standalone')
  }

  const standaloneCheck = check?.source === 'standalone' ? check : null
  const extractedCheck = check?.source === 'extracted' ? check : null

  return (
    <main className="page">
      <p className="prototype">
        Prototype. The URL section checks reputation only after you click Check URL or Check reputation. Pasted text can extract links or run text-only message analysis. The message source is a label for that text and does not change the checks. Message analysis does not confirm phishing and does not contact VirusTotal.
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
        <button type="submit" disabled={reputationBusy}>
          {standaloneCheck?.loading ? 'Checking…' : 'Check URL'}
        </button>
      </form>
      <section className="result" aria-live="polite">
        {standaloneCheck?.loading ? <p>Checking the URL…</p> : null}
        {submittedUrl ? (
          <p>
            Submitted URL: <span className="plain-url">{submittedUrl}</span>
          </p>
        ) : null}
        {inputError ? <p className="message">{inputError}</p> : null}
        {standaloneCheck?.requestError ? <p className="message">{standaloneCheck.requestError}</p> : null}
        {standaloneCheck?.result ? <ResultView result={standaloneCheck.result} /> : null}
      </section>
      <EmailPaste
        reputationBusy={reputationBusy}
        extractedCheck={extractedCheck}
        onEmailTextChange={onEmailTextChange}
        onCheckReputation={(target) => {
          void requestReputation(target, 'extracted')
        }}
      />
    </main>
  )
}

export default App

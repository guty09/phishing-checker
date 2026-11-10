import type { AnalysisCounts, CheckResult, LookupStatus } from './checkUrl'

const STATUS_EXPLANATION: Record<LookupStatus, string> = {
  found: 'An existing report was retrieved. This does not mean the URL is safe.',
  disabled: 'VirusTotal is disabled because the backend has no API key.',
  not_found: 'No existing report was found. This does not mean the URL is safe.',
  rate_limited: 'The lookup was rate limited. Wait a minute and try again.',
  authentication_failure: 'VirusTotal rejected the backend API key.',
  unavailable: 'The lookup is unavailable right now.',
}

export function ResultView({ result }: { result: CheckResult }) {
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

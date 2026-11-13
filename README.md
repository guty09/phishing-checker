# Phishing Checker

## Backend

The Spring Boot application is in `backend/`. It listens on port 8081. `GET /api/health` returns `{"status":"ok"}`.

`POST /api/email/extract` with `{"text":"..."}` extracts explicit `http` and `https` URLs from pasted plain text. Text must be nonblank and at most 50,000 characters. The response lists up to 20 unique URLs in first-seen order, plus warnings that pasted text omits full email headers and can hide an HTML link’s original destination. When more than 20 unique URLs are present, `truncated` is true and only the first 20 are returned. A trailing `?`, `!`, `;`, or `:` stays on the URL, because plain text does not show whether it belongs to the path or query. A trailing period or comma, and an unmatched closing bracket, are still removed and can shorten a URL that really ends with that character. This endpoint does not open the URLs, resolve DNS, render HTML, or call VirusTotal.

`POST /api/email/analyze` with `{"text":"..."}` uses the same nonblank and 50,000-character limits. It applies deterministic text rules and returns `suspicious`, `no_obvious_warning_signs`, or `inconclusive`, plus rule IDs and explanations. It does not confirm phishing or assign a probability.

- `credential_request`: the text directly asks for a password, passcode, or verification code. A nearby verb and the word “password” are not enough.
- `gift_card_payment`: the text asks someone to buy or pay with a gift card, or to send a gift-card code. Mentioning a gift card, its number, or a receipt code is not enough.
- `urgency_or_threat`: the text uses urgency or threat language. This rule alone is `inconclusive`, not `suspicious`.
- `negated_secret_request`: that individual instruction is explicitly negated, such as “never share your password,” so that instruction is not a request. Negation does not suppress a separate request later in the sentence.

Either an active credential request or an active gift-card request produces `suspicious`. No matching request and no urgency produces `no_obvious_warning_signs`. Text-only rules can miss threats and can flag legitimate messages. This endpoint does not analyze email headers, attachments, or link reputation, and it does not contact another service.

Start it from PowerShell:

```powershell
cd D:\Cyber\Projects\phishing-checker\backend
.\mvnw.cmd spring-boot:run
```

## VirusTotal

`POST /api/check/url` with `{"url":"https://example.com"}` reads an existing VirusTotal report. It does not open the submitted URL or request a new scan. A missing report is `not_found`, which is not a safety verdict.

During a live development check, `POST /api/check/url` for `https://example.com` returned status `found`. VirusTotal’s analysis counts change over time, so a later lookup can show different numbers. Neither `found` nor those counts means the URL is safe.

The API key comes only from the `VIRUSTOTAL_API_KEY` environment variable. When that variable is missing or blank, the integration is disabled and the application still starts.

Set it in the current PowerShell session, then start the backend from that same session. Use your own key in place of the placeholder. Do not commit the key, paste it into the repository, or store it in a `.env` file here.

```powershell
$env:VIRUSTOTAL_API_KEY = "<your-virustotal-api-key>"
```

## PhishTank

`POST /api/check/url/phishtank` uses the same URL validation as `POST /api/check/url`. It does not change the VirusTotal endpoint or its response. The lookup is a single `POST` to `https://checkurl.phishtank.com/checkurl/` with a form body of `url`, `format=json`, and `app_key` only when an application key is configured. Redirects are not followed. The submitted URL is not opened, and it is not sent to PhishTank as a phishing report.

The integration is disabled unless `PHISHTANK_ENABLED` is `true`. `PHISHTANK_APP_KEY` is optional. `PHISHTANK_USER_AGENT` overrides the descriptive User-Agent; a blank User-Agent does not call PhishTank. The application key is not written into code, logs, errors, or `toString()`. This application does not store the submitted URL. Sending a lookup gives that URL to PhishTank, which then handles it under PhishTank's own terms.

This application allows one PhishTank request per rolling minute and does not retry. HTTP 509 is `rate_limited`. `X-Request-Limit-Interval`, `X-Request-Limit`, and `X-Request-Count` are returned when PhishTank sends them. They are not turned into another quota.

`verified` and `valid` accept a JSON boolean or the strings `y` and `n`. `verified_phishing` requires both flags to parse as true. Any missing, malformed, or contradictory required field is `unavailable`. `not_listed` and `verified_not_phishing` do not mean the URL is safe. `checkedAt` is the time of this lookup. `verifiedAt` is included only when PhishTank provided a parseable timestamp.

An `unavailable` result from the provider call includes `diagnostic`: `connection_failure`, `timeout`, `provider_http_status`, `oversized_response`, `invalid_json`, or `unsupported_response`. `providerStatus` is present only for `provider_http_status` and is the HTTP status code. Neither field includes the submitted URL, response body, application key, or exception text.

PhishTank is not operational. The integration remains disabled by default and is paused pending provider access. Leave `PHISHTANK_ENABLED` unset or `false`.

- Mocked backend suite passed: 73 tests.
- The disabled endpoint was verified locally.
- An enabled live lookup returned HTTP 403.
- New-user registration displayed "temporarily disabled."
- A successful live PhishTank lookup remains unverified.

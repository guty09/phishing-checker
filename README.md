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

Inspecting an uploaded `.eml` file is future work. The current email endpoints accept pasted text only.

Future local backend builds, tests, and application starts on this Windows machine must use `backend/mvn.ps1`. That launcher creates `D:\Cyber\Maven\home` and `D:\Cyber\Temp` when they are missing, then sets these variables for the Maven process only:

- `MAVEN_USER_HOME` is `D:\Cyber\Maven\home`, which is where the Maven Wrapper stores its downloaded distribution.
- `TEMP` and `TMP` are `D:\Cyber\Temp`.
- Existing `MAVEN_OPTS` values are kept, and `java.io.tmpdir` is set to `D:\Cyber\Temp` for that run.
- `maven.repo.local` is `D:\Cyber\Maven\repository`. The launcher appends that property after the forwarded Maven arguments.

`backend/.mvn/maven.config` does not set a repository path. A hosted build uses `./mvnw` and the builder's own repository. The launcher forwards every Maven argument and returns Maven's exit code, then restores the previous values of those environment variables. It does not change Windows user or system settings and does not remove an existing Maven installation on `C:`.

Pasted message text is sent to this server for extraction and text analysis. Those requests do not send the text to VirusTotal. Check URL and Check reputation send the selected URL to VirusTotal. The server listens on `PORT` when that variable is set, and on 8081 otherwise.

JSON bodies are limited to 512 KiB, including a request that omits Content-Length. Each read from the underlying stream asks for at most the remaining allowance plus one byte. A decoded string is limited to 50,000 characters, which is the message-text limit. That byte budget accepts 50,000 characters written as `\uXXXX` escapes and ordinary multibyte UTF-8. A larger body is `invalid_text` or `invalid_url` and is not echoed. The full mocked backend suite passed offline through `backend/mvn.ps1`: 82 tests, 0 failures, 0 errors. Dependencies came from `D:\Cyber\Maven\repository`.

```powershell
cd D:\Cyber\Projects\phishing-checker\backend
.\mvn.ps1 spring-boot:run
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

## Deployment

The public site is one service. The Docker image builds the React app, copies `frontend/dist` into the Spring Boot jar, and runs that jar on Java 21. The page and `/api` share one origin, so the existing relative `/api` calls work without the Vite dev proxy. Nothing has been provisioned or deployed.

Hosted build, when deployment is approved:

1. Point the host at this Git repository and its root `Dockerfile`. The host builds the image. This machine does not need to download Maven or npm for that build.
2. Use a plan with enough memory for Java 21. The earlier recommendation is Render's $25/month instance with 1 CPU and 2 GB RAM. The free 512 MB instance can sleep and can run out of memory.
3. Let the host set `PORT`. Leave `PHISHTANK_ENABLED` unset. Set `VIRUSTOTAL_API_KEY` only as a host secret, and only after the permission question below is resolved. Do not put the key in the image, the repository, or the frontend.
4. Use `GET /api/health` as the health check.

VirusTotal permission is unresolved. The public API docs describe a free consumer website and also prohibit commercial products, business workflows that do not contribute new files, and sharing the personal API key. The Terms page fetched from VirusTotal's docs is labeled historic while its body says the current terms were last updated January 27, 2021. Those terms restrict redistributing service information and say the service is for non-commercial malware detection. This app only reads an existing URL report and shows category counts. Do not treat that as permission to offer reputation checks to the public. Text extraction and text analysis do not call VirusTotal.

Public visitor limits are not implemented. The proposal, once the trusted proxy ranges are known:

- Keep the existing global VirusTotal limit of 4 lookups per rolling minute. Add a global cap of 500 lookups per day so the deployment stays inside the published public quota.
- Limit message extraction and analysis to 10 requests per rolling minute per visitor, separate from the VirusTotal limit.
- Keep PhishTank disabled. Its existing one-request-per-minute limiter stays in place for a later, explicit enablement.
- Identify a visitor from the connection address. On a host that sits behind its own proxy, trust `X-Forwarded-For` only through Tomcat's remote-ip support and only for that host's published proxy ranges. Ignore forwarded headers from any other client. Until those ranges are confirmed, do not implement the per-visitor limit, because every visitor would otherwise share the proxy's address.

Before calling the deployed site ready, check each current behavior in a browser on that URL:

- `GET /api/health` returns `{"status":"ok"}`.
- Invalid URLs are rejected, and a valid Check URL calls `POST /api/check/url` only after the click. `found` and `not_found` are not safety verdicts. With no API key, the status is `disabled` and VirusTotal is not called.
- Extract and analyze send only `{"text":"..."}`. Source labels change the field label and placeholder. Changing the text or source clears visible results and drops a late response. A standalone reputation result remains when the message changes. An extracted reputation result clears.
- Analyze can show suspicious, no obvious warning signs, and inconclusive, with explanations and limitations. It does not say the message is safe or that phishing is confirmed, and it does not call `/api/check/url`.
- `POST /api/check/url/phishtank` returns `disabled` and does not call PhishTank.
- The built JavaScript contains no API key. The page does not store the submission in browser storage. Server logs for these requests contain neither the message text nor the URL.
- A 50,000-character message is accepted, including multibyte text and `\u` escapes. A body larger than 512 KiB is rejected and is not echoed, including when Content-Length is absent. Single-byte and bulk reads both stop after one byte past the limit.

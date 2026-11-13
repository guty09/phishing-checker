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

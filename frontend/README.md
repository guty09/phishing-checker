# Frontend

Prototype page. It checks URL reputation, extracts links from pasted message text, and can analyze that text with backend rules. The message source can be Email, WhatsApp, Telegram, or SMS, and it defaults to Email. That choice is a label only: it is not sent to the API and does not change link extraction or message analysis. Pasted text is sent to this server for link extraction and text-only analysis. It is not sent to VirusTotal. Sender identity, platform metadata, headers, and attachments are not verified. Check URL and Check reputation each send one selected URL to VirusTotal through the backend, and only after that button is clicked. Message analysis does not confirm phishing. A connection failure says to try again. It does not ask the visitor to start a local server.

The dev server proxies `/api` to `http://127.0.0.1:8081`. API keys stay in the backend. Submitted text and URLs are not stored in browser storage.

```powershell
cd D:\Cyber\Projects\phishing-checker\frontend
npm run dev
```

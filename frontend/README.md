# Frontend

Prototype page. It checks URL reputation, extracts links from pasted message text, and can analyze that text with backend rules. The message source can be Email, WhatsApp, Telegram, or SMS, and it defaults to Email. That choice is a label only: it is not sent to the API and does not change link extraction or message analysis. Only the pasted text is checked. Sender identity, platform metadata, headers, and attachments are not verified. Link extraction and message analysis do not send the text or its links to VirusTotal. Check URL and Check reputation each send one selected URL to VirusTotal through the backend, and only after that button is clicked. Message analysis does not confirm phishing.

The dev server proxies `/api` to `http://127.0.0.1:8081`. API keys stay in the backend. Submitted text and URLs are not stored in browser storage.

```powershell
cd D:\Cyber\Projects\phishing-checker\frontend
npm run dev
```

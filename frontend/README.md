# Frontend

Prototype page. It checks URL reputation and extracts links from pasted email text. Link extraction does not assess whether the email is phishing, and it does not send those links to VirusTotal.

The dev server proxies `/api` to `http://127.0.0.1:8081`. API keys stay in the backend. Submitted text and URLs are not stored in browser storage.

```powershell
cd D:\Cyber\Projects\phishing-checker\frontend
npm run dev
```

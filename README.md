# Phishing Checker

## Backend

The Spring Boot application is in `backend/`. It listens on port 8081. `GET /api/health` returns `{"status":"ok"}`.

Start it from PowerShell:

```powershell
cd D:\Cyber\Projects\phishing-checker\backend
.\mvnw.cmd spring-boot:run
```

## VirusTotal

VirusTotal lookups are not implemented yet. The backend only reads the API key from the `VIRUSTOTAL_API_KEY` environment variable. When that variable is missing or blank, the integration is disabled and the application still starts.

Set it in the current PowerShell session, then start the backend from that same session. Use your own key in place of the placeholder. Do not commit the key, paste it into the repository, or store it in a `.env` file here.

```powershell
$env:VIRUSTOTAL_API_KEY = "<your-virustotal-api-key>"
```

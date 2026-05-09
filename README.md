# Malicious Email Scorer

Small home-assignment project: Gmail Add-on + Node.js backend.

The add-on reads the opened email, sends relevant data to the backend, and shows:
- risk score (`0-100`)
- verdict (`Safe`, `Suspicious`, `Malicious`)
- short explanation of triggered signals

## Project Structure

- `backend/` - Express API and scoring logic
- `extension/` - Google Apps Script code for Gmail add-on UI

## Quick Start (Backend)

```bash
cd backend
npm install
```

Create `backend/.env` from `backend/.env.example`:

```env
PORT=8080
NODE_ENV=development
CORS_ORIGIN=*
```

Run:

```bash
npm run dev
```

Check:

`http://localhost:8080/health`

## API

Endpoint: `POST /analyze`

Expected input:
- `headers` object (`subject`, `from`, `replyTo`, `returnPath`, `authenticationResults`)
- `bodyText` string
- `attachments` array

Main output:
- `score`
- `verdict`
- `reasoning`
- `topSignals`

## What is Checked

- SPF / DKIM / DMARC hints from headers
- sender mismatch / spoofing patterns
- suspicious or aggressive language (English + Hebrew)
- threat / terror phrases
- suspicious links (typosquatting, punycode, IP links, obfuscation, risky params)

Verdict ranges:
- `0-29` -> Safe
- `30-69` -> Suspicious (orange)
- `70-100` -> Malicious (red)

## Gmail Add-on Setup

1. Open [script.google.com](https://script.google.com)
2. Paste:
   - `extension/code.js` into `Code.gs`
   - `extension/appsscript.json` into manifest
3. In Script Properties set:
   - `BACKEND_URL=https://<your-public-backend-url>`
4. Deploy test deployment and open Gmail to test

## Notes

- This project uses deterministic rules (not ML) so each result is explainable.
- Rule-based detection can still produce false positives/false negatives.

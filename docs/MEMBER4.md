# Member 4: Approval, Dashboard, and Demo

This module adds exact-action human approval and a local dashboard using synthetic fixtures. It does not connect to real tools or use real student data.

## Run the approval demonstration

```powershell
python -m approval.test_flow
```

The demo prints a mock code in the terminal as its out-of-band adapter, then demonstrates successful one-time approval, reuse rejection, and modified-argument rejection.

## Run the dashboard

```powershell
python -m ui.dashboard
```

Open `http://127.0.0.1:8765`. Run the Safe summary and Malicious PDF fixtures, then run Approval transfer. In mock mode, the code is printed only in the server terminal. The dashboard endpoint never returns it. Use Verify log and Replay decisions to inspect the hash-chained evidence.

## Configure out-of-band delivery

The application reads configuration from process environment variables; it does not load `.env` automatically. Set values in PowerShell before starting the dashboard. Never commit real credentials.

- Email: set `APPROVAL_CHANNEL=email`, `APPROVAL_DESTINATION`, `SMTP_HOST`, and `SMTP_FROM`; configure SMTP credentials as needed.
- Telegram: set `APPROVAL_CHANNEL=telegram`, `TELEGRAM_BOT_TOKEN`, and `TELEGRAM_CHAT_ID` (or `APPROVAL_DESTINATION`).
- `APPROVAL_CHANNEL=mock` uses the test/demo adapter.

For example, configure email for the current PowerShell session, then launch the dashboard:

```powershell
$env:APPROVAL_CHANNEL = "email"
$env:APPROVAL_DESTINATION = "reviewer@example.com"
$env:SMTP_HOST = "smtp.example.com"
$env:SMTP_FROM = "sender@example.com"
$env:SMTP_USERNAME = "sender@example.com"
$env:SMTP_PASSWORD = "your-app-password"
$env:APPROVAL_CODE_TTL_SECONDS = "180"
python -m ui.dashboard
```

The dashboard displays only a masked destination. The approval service stores a SHA-256 code hash, binds approval to canonical request ID, tool, and arguments, checks expiry and reuse, then consumes the code under a lock before resuming the held request. Approval events are append-only and contain no code. Dashboard scenario and release events share a hash-chained JSONL evidence log.

## Tests

```powershell
python -m pytest tests/test_approval.py tests/test_dashboard.py -q
```

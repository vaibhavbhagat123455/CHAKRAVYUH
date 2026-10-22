# Local Windows Setup and Demo

Run PowerShell from the repository root:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\scripts\setup.ps1
.\scripts\run_demo.ps1
```

Open `http://127.0.0.1:8765` in a browser.

## Demo order

1. Run `Safe summary` and show `ALLOW`.
2. Run `Malicious PDF` and show `DENY`, evidence ID and seven-layer results.
3. Run `Approval transfer` and show `HOLD`.
4. Read the one-time mock code from the dashboard terminal, enter it once and show release.
5. Press `Verify log` and show the valid hash chain.
6. Press `Replay decisions` and show the deterministic replay digest and final approved outcome.

The dashboard talks to the proxy using a real JSON-RPC-over-stdio subprocess.
The included PDFs are synthetic and safe for demonstration. The default tool
executor is a local sandbox: it performs PDF summarisation and writes transfer
intents locally, so no email, upload or external export occurs.
For a real out-of-band approval channel, configure `APPROVAL_CHANNEL=email` or
`telegram` in `.env` and provide its credentials; never use real personal data
in the fixture scenarios.

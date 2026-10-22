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
6. Press `Replay decisions` and show the deterministic replay digest.

The code uses synthetic fixtures and simulated tools only. Do not configure a
real destination or real personal data during the hackathon demo.

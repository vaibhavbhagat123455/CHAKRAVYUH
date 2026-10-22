"""Local evidence dashboard backed by synthetic scenario fixtures."""

from __future__ import annotations

import json
import os
import secrets
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from approval.approval_codes import ApprovalService
from approval.notification import ConfiguredNotificationAdapter, MockNotificationAdapter
from proxy.checkpoint import Checkpoint
from proxy.mcp_server import McpToolProxy
from proxy.tool_executor import SimulatedToolExecutor
from ui.evidence import EvidenceLog

ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = ROOT / "scenarios"
HTML = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>AI Chakravyuh | Evidence Console</title>
<style>
:root{color-scheme:dark;--bg:#0b1020;--panel:#121a2c;--line:#263550;--muted:#9aa9c1;--text:#edf3ff;--cyan:#64d9e9;--green:#39d98a;--yellow:#ffc857;--red:#ff647c}*{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at 10% 0%,#152542,var(--bg) 55%);color:var(--text);font:15px/1.5 Inter,Segoe UI,system-ui,sans-serif}.wrap{max-width:1200px;margin:auto;padding:32px 22px 60px}.top{display:flex;justify-content:space-between;align-items:center;gap:18px;margin-bottom:28px}.brand{display:flex;align-items:center;gap:14px}.mark{width:44px;height:44px;border-radius:14px;background:linear-gradient(135deg,#37d6dc,#6f82ff);display:grid;place-items:center;color:#08111d;font-weight:900;font-size:22px}.eyebrow{color:var(--cyan);font-size:11px;text-transform:uppercase;letter-spacing:.18em;font-weight:700}.sub{color:var(--muted);font-size:13px}.topright{display:flex;gap:10px;align-items:center}.pill,.tag{border:1px solid var(--line);border-radius:999px;padding:6px 11px;color:var(--muted);font-size:12px}.dot{display:inline-block;width:7px;height:7px;border-radius:50%;background:var(--green);margin-right:7px}.hero{display:flex;justify-content:space-between;align-items:end;gap:20px;margin:28px 0 18px}.hero h1{font-size:32px;line-height:1.1;letter-spacing:-.04em;margin:7px 0}.hero p{color:var(--muted);margin:0}.controls{display:flex;gap:9px;align-items:center}select,input,button{font:inherit;border-radius:9px;border:1px solid var(--line);padding:10px 13px;background:#0e1728;color:var(--text)}button{cursor:pointer;font-weight:650;transition:.15s}button:hover{transform:translateY(-1px);border-color:var(--cyan)}button.primary{background:var(--cyan);color:#08111d;border-color:var(--cyan)}button.ghost{background:transparent}.grid{display:grid;grid-template-columns:1.15fr .85fr;gap:14px}.card{background:linear-gradient(145deg,#151f33,#101827);border:1px solid var(--line);border-radius:15px;padding:19px;box-shadow:0 12px 30px #0002}.wide{grid-column:1/-1}.cardhead{display:flex;justify-content:space-between;align-items:center;margin-bottom:15px}.card h2{font-size:14px;margin:0;letter-spacing:.01em}.label{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.12em}.goal{font-size:17px;margin:5px 0 13px}.summary{padding:12px;border-radius:10px;background:#0c1423;border:1px solid #1f2c42;color:#becbe0}.decision{display:flex;align-items:center;gap:12px}.decision-badge{font-size:12px;font-weight:800;letter-spacing:.1em;padding:7px 12px;border-radius:8px;background:#263245}.ALLOW{color:var(--green);border:1px solid #287f5d}.HOLD{color:var(--yellow);border:1px solid #937339}.DENY{color:var(--red);border:1px solid #974252}.layers{display:grid;grid-template-columns:repeat(4,1fr);gap:9px}.layer{padding:12px;border:1px solid var(--line);border-radius:11px;background:#0e1728;min-height:111px}.layer strong{display:flex;justify-content:space-between;font-size:12px}.layer p{color:var(--muted);font-size:12px;margin:9px 0 0}.status{font-size:10px;font-weight:750;letter-spacing:.08em}.PASS{color:var(--green)}.REVIEW{color:var(--yellow)}.layer .DENY{background:none;border:0}.timeline{display:grid;grid-template-columns:140px 1fr;gap:8px 14px;font-size:13px}.timeline .label{padding-top:2px}.timeline div:nth-child(2n){color:#dce7f8;overflow-wrap:anywhere}.mono{font:12px/1.5 ui-monospace,Consolas,monospace;color:#a9c3e7}.actions{display:flex;gap:9px;flex-wrap:wrap}.statusline{color:var(--muted);font-size:12px;margin-top:12px}.approvalform{display:flex;gap:8px;flex-wrap:wrap;margin-top:12px}.approvalform input{min-width:140px}.hidden{display:none}.result{margin-top:11px;color:var(--muted)}.log{max-height:230px;overflow:auto;border-top:1px solid var(--line);margin-top:14px;padding-top:10px}.logrow{padding:8px 2px;border-bottom:1px solid #1d2a40;display:grid;grid-template-columns:70px 1fr auto;gap:9px;font-size:12px}.logrow a{color:var(--cyan);text-decoration:none}.foot{color:#73829b;text-align:center;font-size:11px;margin-top:22px}@media(max-width:760px){.grid{grid-template-columns:1fr}.wide{grid-column:auto}.layers{grid-template-columns:repeat(2,1fr)}.hero,.top{align-items:start;flex-direction:column}.controls{width:100%;flex-wrap:wrap}.controls select{flex:1}}
</style></head><body><main class="wrap">
<header class="top"><div class="brand"><div class="mark">A</div><div><div class="eyebrow">AI Chakravyuh · Team GOAT Coders</div><div class="sub">Tool-call security evidence console</div></div></div><div class="topright"><span class="pill"><span class="dot"></span>LOCAL SIMULATION</span><span class="pill">POLICY v1</span></div></header>
<section class="hero"><div><div class="eyebrow">Scenario lab</div><h1>See every decision.</h1><p>Trace a synthetic request through seven layers, approval and replay.</p></div><div class="controls"><select id="scenario"><option value="safe_summary">Safe summary</option><option value="malicious_pdf">Malicious PDF</option><option value="approval_transfer">Approval transfer</option></select><button id="run" class="primary">Run scenario ↗</button></div></section>
<section class="grid"><article class="card"><div class="cardhead"><h2>Scenario context</h2><span id="scenarioTag" class="tag">READY</span></div><div class="label">Original goal</div><div id="goal" class="goal">Select a scenario to begin.</div><div class="label">Synthetic input</div><div id="summary" class="summary">All demo content is fictional. No real tools or student data are used.</div></article>
<article class="card"><div class="cardhead"><h2>Checkpoint decision</h2><span class="label">Deterministic policy</span></div><div class="decision"><span id="decision" class="decision-badge">—</span><span id="reason">Run a scenario to see the reason.</span></div><div class="label" style="margin-top:20px">Tool call</div><div id="tool" class="mono" style="margin-top:7px">No request yet</div><div id="approvalArea" class="hidden"><div class="statusline" id="approvalStatus"></div><form class="approvalform" id="approvalForm"><input id="code" autocomplete="one-time-code" placeholder="One-time code" aria-label="One-time approval code"><button class="primary">Verify approval</button></form><div class="result" id="approvalResult"></div></div></article>
<article class="card wide"><div class="cardhead"><h2>Seven-layer review</h2><span class="label">Every layer leaves a reason</span></div><div id="layers" class="layers"></div></article>
<article class="card"><div class="cardhead"><h2>Request timeline</h2><span class="label">Synthetic tool</span></div><div class="timeline"><div class="label">Request ID</div><div id="requestId" class="mono">—</div><div class="label">Tool</div><div id="toolName" class="mono">—</div><div class="label">Arguments</div><div id="arguments" class="mono">—</div><div class="label">Evidence ID</div><div id="evidence" class="mono">Pending scenario run</div><div class="label">Log sequence</div><div id="sequence" class="mono">—</div></div></article>
<article class="card"><div class="cardhead"><h2>Evidence controls</h2><span class="label">Append-only events</span></div><div class="actions"><button class="ghost" id="verify">Verify log</button><button class="ghost" id="replay">Replay decisions</button><button class="ghost" id="showLog">Refresh log</button></div><div id="controlsResult" class="statusline">Run a scenario to create evidence.</div><div id="log" class="log"></div></article></section>
<div class="foot">Fictional fixtures · simulated tools only · approval codes are delivered out of band and never shown here</div></main>
<script>
let current=null;const $=id=>document.getElementById(id);async function api(path,body){const r=await fetch(path,body?{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}:{});const x=await r.json();if(!r.ok)throw Error(x.error||'Request failed');return x}
function showScenario(s){current=s;$('scenarioTag').textContent=s.scenario_id;$('goal').textContent=s.original_goal;$('summary').textContent=s.input_summary;$('decision').textContent=s.decision;$('decision').className='decision-badge '+s.decision;$('reason').textContent=s.reason;$('tool').textContent=s.request.tool+' · '+s.request.request_id;$('requestId').textContent=s.request.request_id;$('toolName').textContent=s.request.tool;$('arguments').textContent=JSON.stringify(s.request.arguments);$('layers').innerHTML=s.layers.map(l=>`<div class="layer"><strong><span>${l.layer_id}</span><span class="status ${l.status}">${l.status}</span></strong><p>${l.reason}</p></div>`).join('');$('approvalArea').classList.toggle('hidden',s.decision!=='HOLD');$('approvalResult').textContent='';$('code').value='';$('evidence').textContent=s.evidence_id||'—';$('sequence').textContent=s.log_sequence||'—';refreshLog()}
async function refreshLog(){try{const x=await api('/api/log');$('log').innerHTML=x.events.slice().reverse().map(e=>`<div class="logrow"><span class="label">#${e.sequence}</span><span><a href="#${e.evidence_id||e.event_id}">${e.event_type}</a> · ${e.decision||e.status||''}</span><span class="mono">${e.evidence_id||e.event_id}</span></div>`).join('')||'<div class="statusline">No events yet.</div>'}catch(e){$('log').textContent=e.message}}
$('run').onclick=async()=>{try{const x=await api('/api/run',{scenario_id:$('scenario').value});showScenario(x);$('controlsResult').textContent='Scenario recorded in the append-only evidence log.'}catch(e){$('controlsResult').textContent=e.message}};
$('approvalForm').onsubmit=async ev=>{ev.preventDefault();try{const x=await api('/api/approval/verify',{approval_id:current.approval_id,code:$('code').value,request:current.request});$('approvalResult').textContent=x.approved?'Approved once. Exact request released. Evidence '+x.evidence_id:'Denied: '+x.reason+' · evidence '+x.evidence_id;$('approvalStatus').textContent=x.approved?'Approval status: APPROVED':'Approval status: DENIED';$('evidence').textContent=x.evidence_id;await refreshLog()}catch(e){$('approvalResult').textContent=e.message}};
$('verify').onclick=async()=>{try{const x=await api('/api/log/verify');$('controlsResult').textContent=x.valid?'✓ Log valid · '+x.entries+' events':'✕ '+x.reason+' · line '+x.line_number;$('controlsResult').style.color=x.valid?'var(--green)':'var(--red)'}catch(e){$('controlsResult').textContent=e.message}};
$('replay').onclick=async()=>{try{const x=await api('/api/log/replay');$('controlsResult').textContent='Replay complete · '+x.decisions.length+' decisions · digest '+x.decision_digest.slice(0,20)+'…'}catch(e){$('controlsResult').textContent=e.message}};
$('showLog').onclick=refreshLog;
</script></body></html>'''


class DashboardState:
    def __init__(self, service: ApprovalService | None = None, *, evidence_path: str | Path | None = None,
                 approval_log_path: str | Path | None = None) -> None:
        self.notifier = MockNotificationAdapter()
        self.scenarios: dict[str, dict] = {}
        self.evidence = EvidenceLog(evidence_path or ROOT / "data" / "security-log.jsonl")
        self.executor = SimulatedToolExecutor()
        self.proxy = McpToolProxy(Checkpoint(self.evidence.path), self.executor)
        ttl_seconds = int(os.getenv("APPROVAL_CODE_TTL_SECONDS", "180"))
        self.service = service or ApprovalService(self.notifier, ttl_seconds=ttl_seconds,
                                                 log_path=approval_log_path or ROOT / "data" / "approval-events.jsonl",
                                                 resume_callback=self._resume_held_request,
                                                 event_sink=self.evidence.append)

    def _resume_held_request(self, request: dict) -> str:
        scenario = self.scenarios.get(request.get("request_id"))
        if scenario is None or scenario.get("decision") != "HOLD":
            return "held request unavailable"
        self.proxy.release_held(request["request_id"], approval_verified=True)
        scenario["approval_status"] = "APPROVED"
        scenario["decision"] = "ALLOW"
        event = self.evidence.append({"event_id": f"evt-{secrets.token_hex(8)}", "event_type": "APPROVED_RELEASE",
                                      "timestamp": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
                                      "request_id": request["request_id"], "decision": "ALLOW",
                                      "evidence_id": f"ev-{secrets.token_hex(8)}", "reason": "Exact request approved once"})
        scenario["evidence_id"], scenario["log_sequence"] = event["evidence_id"], event["sequence"]
        return "released"

    def run(self, scenario_id: str) -> dict:
        path = SCENARIOS / f"{scenario_id}.json"
        if not path.is_file():
            raise ValueError("Unknown scenario. Choose one of the listed synthetic fixtures.")
        scenario = json.loads(path.read_text(encoding="utf-8"))
        scenario["scenario_id"] = scenario_id
        rpc_payload = {
            "jsonrpc": "2.0", "id": f"dashboard-{scenario_id}", "method": "tools/call",
            "params": {"request": scenario["request"], "content": scenario.get("content", "")},
        }
        response = self.proxy.handle(rpc_payload)
        decision = self.proxy.checkpoint.decisions[scenario["request"]["request_id"]]
        scenario["decision"] = decision.decision
        scenario["reason"] = decision.reason
        scenario["evidence_id"] = decision.evidence_id
        scenario["layers"] = [
            {"layer_id": item.layer_id, "status": {"BLOCK": "DENY", "REVIEW": "REVIEW"}.get(item.status, item.status), "reason": item.reason}
            for item in decision.layer_results
        ]
        if decision.decision == "HOLD":
            if os.getenv("APPROVAL_CHANNEL") in {"email", "telegram"}:
                channel = os.environ["APPROVAL_CHANNEL"]
                notifier = ConfiguredNotificationAdapter(channel)
                self.service.notifier = notifier
                destination = os.getenv("APPROVAL_DESTINATION") or os.getenv("TELEGRAM_CHAT_ID", "")
                if not destination:
                    raise ValueError("Set APPROVAL_DESTINATION for the configured approval channel")
            else:
                destination = "demo-reviewer@example.test"
            approval = self.service.create_approval(scenario["request"], destination)
            scenario["approval_id"] = approval["approval_id"]
            scenario["approval_status"] = approval["status"]
            scenario["masked_destination"] = approval["destination"]
        if "error" in response:
            scenario["error"] = response["error"]
        entries = self.evidence.read_entries()
        decision_events = [e for e in entries if e.get("event_type") == "CHECKPOINT_DECISION" and e.get("request_id") == scenario["request"]["request_id"]]
        scenario["log_sequence"] = decision_events[-1]["sequence"] if decision_events else None
        self.scenarios[scenario["request"]["request_id"]] = scenario
        return scenario

    def log_events(self) -> list[dict]:
        return self.evidence.read_entries()


class DashboardHandler(BaseHTTPRequestHandler):
    state = DashboardState()

    def log_message(self, fmt: str, *args: object) -> None:
        print("[dashboard] " + fmt % args)

    def send_json(self, payload: dict, status: int = 200) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/":
            body = HTML.encode()
            self.send_response(200); self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body))); self.send_header("Cache-Control", "no-store")
            self.end_headers(); self.wfile.write(body)
        elif path == "/api/log":
            self.send_json({"events": self.state.log_events()})
        elif path == "/api/scenarios":
            self.send_json({"scenarios": [p.stem for p in SCENARIOS.glob("*.json")]})
        else:
            self.send_json({"error": "Not found"}, 404)

    def do_POST(self) -> None:
        try:
            length = min(int(self.headers.get("Content-Length", "0")), 100_000)
            data = json.loads(self.rfile.read(length) or b"{}")
            path = urlparse(self.path).path
            if path == "/api/run":
                result = self.state.run(str(data.get("scenario_id", "")))
                # The demo code reaches only the out-of-band adapter/terminal, never the browser.
                result.pop("demo_delivery", None)
                self.send_json(result)
            elif path == "/api/approval/verify":
                result = self.state.service.verify_approval(data.get("code", ""), data.get("request", {}), data.get("approval_id"))
                result.pop("resumed", None)
                self.send_json(result)
            elif path == "/api/log/verify":
                self.send_json(self.state.evidence.verify())
            elif path == "/api/log/replay":
                self.send_json(self.state.evidence.replay())
            else:
                self.send_json({"error": "Not found"}, 404)
        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            self.send_json({"error": str(exc)}, 400)
        except Exception as exc:
            self.send_json({"error": f"Operation failed: {exc}"}, 500)


def main() -> None:
    port = int(os.getenv("DASHBOARD_PORT", "8765"))
    server = ThreadingHTTPServer(("127.0.0.1", port), DashboardHandler)
    print(f"AI Chakravyuh dashboard: http://127.0.0.1:{port}")
    print("Demo codes are delivered to the configured channel; mock mode writes them only to this terminal.")
    if isinstance(DashboardHandler.state.notifier, MockNotificationAdapter):
        original_run = DashboardHandler.state.run
        def run_and_print(scenario_id: str) -> dict:
            result = original_run(scenario_id)
            delivery = DashboardHandler.state.notifier.deliveries[-1] if result.get("decision") == "HOLD" and DashboardHandler.state.notifier.deliveries else None
            if delivery and delivery["approval_id"] == result.get("approval_id"):
                print(f"[mock out-of-band delivery] {delivery['destination']}: {delivery['code']}")
            return result
        DashboardHandler.state.run = run_and_print  # type: ignore[method-assign]
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nDashboard stopped.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()

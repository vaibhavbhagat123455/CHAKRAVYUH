"""Runnable end-to-end Member 4 approval demo using synthetic data."""

from __future__ import annotations

import json
from pathlib import Path

from approval.approval_codes import ApprovalService
from approval.notification import MockNotificationAdapter

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    request = {"request_id": "req-demo-approval", "tool": "send_report",
               "arguments": {"recipient": "reviewer@example.test", "file": "synthetic_report.txt"},
               "purpose": "Approve one synthetic report transfer", "scenario_id": "approval-transfer-001"}
    safe_request = {"request_id": "req-demo-safe", "tool": "summarize_document",
                    "arguments": {"document": "synthetic_public_notice.txt"}, "purpose": "Summarise synthetic public text",
                    "scenario_id": "safe-summary-001"}
    notifier = MockNotificationAdapter()
    resumed = []
    service = ApprovalService(notifier, log_path=ROOT / "data" / "demo-approval.jsonl",
                              resume_callback=lambda held: resumed.append(held["request_id"]) or "released")
    approval = service.create_approval(request, "demo-reviewer@example.test")
    delivery = notifier.deliveries[-1]
    print("Held request:", json.dumps({"request_id": request["request_id"], "decision": "HOLD"}))
    print("Independent safe request continues:", json.dumps({"request_id": safe_request["request_id"], "decision": "ALLOW"}))
    print("Mock out-of-band delivery:", delivery["destination"], "code", delivery["code"])
    print("Exact action approval:", json.dumps(service.verify_approval(delivery["code"], request, approval["approval_id"])))
    print("Code reuse attempt:", json.dumps(service.verify_approval(delivery["code"], request, approval["approval_id"])))
    altered = {**request, "arguments": {**request["arguments"], "recipient": "attacker@example.test"}}
    approval2 = service.create_approval(request, "demo-reviewer@example.test")
    code2 = notifier.deliveries[-1]["code"]
    print("Modified action attempt:", json.dumps(service.verify_approval(code2, altered, approval2["approval_id"])))
    print("Resumed held request:", resumed)
    print("Approval trail:", Path(ROOT / "data" / "demo-approval.jsonl").read_text(encoding="utf-8"))


if __name__ == "__main__":
    main()

"""
Assignment 11 — Audit Log starter (TODO).

Records every interaction for forensics. Never blocks by itself —
other layers catch attacks; this layer makes them reviewable.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path


def default_audit_log_path() -> str:
    """Always resolve to <repo>/outputs/… (safe when cwd is src/)."""
    repo_root = Path(__file__).resolve().parents[2]
    return str(repo_root / "outputs" / "audit_log.json")


class AuditLogPlugin:
    """Framework-agnostic audit logger (wire into ADK callbacks or your pipeline)."""

    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        self._open: dict[str, dict] = {}

    def record_input(self, *, user_id: str, text: str, request_id: str | None = None):
        """Store input + start timestamp keyed by request_id/user_id."""
        req_id = request_id or f"{user_id}_{len(self.logs)}_{len(self._open)}"
        self._open[req_id] = {
            "user_id": user_id,
            "text": text,
            "start_time": datetime.now(timezone.utc).timestamp(),
            "timestamp": utc_now_iso(),
        }
        return req_id

    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
    ):
        """Store output, layer decision, latency; append to self.logs."""
        req_id = request_id
        if not req_id:
            # Match latest open record for this user
            matching = [k for k, v in self._open.items() if v["user_id"] == user_id]
            req_id = matching[-1] if matching else None

        open_data = self._open.pop(req_id, {}) if req_id else {}
        start_time = open_data.get("start_time")
        latency = (
            datetime.now(timezone.utc).timestamp() - start_time
            if start_time
            else 0.0
        )

        entry = {
            "request_id": req_id or f"req_{len(self.logs) + 1}",
            "user_id": user_id,
            "input_text": open_data.get("text", ""),
            "output_text": text,
            "blocked": blocked,
            "layer": layer,
            "latency_seconds": round(latency, 4),
            "timestamp": utc_now_iso(),
        }
        self.logs.append(entry)
        return entry

    def export_json(self, filepath: str | None = None):
        """Write logs to disk (JSON array) under repo-root ``outputs/`` by default."""
        target_path = Path(filepath or default_audit_log_path())
        target_path.parent.mkdir(parents=True, exist_ok=True)
        target_path.write_text(
            json.dumps(self.logs, indent=2, ensure_ascii=False), encoding="utf-8"
        )


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

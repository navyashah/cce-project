from __future__ import annotations
import pathlib
from datetime import datetime, timezone
from typing import Any
from sqlalchemy import desc, select
from sqlalchemy.orm import Session
from collectors.github import collect_github_evidence
from collectors.iam import collect_iam_evidence
from collectors.logging import collect_logging_evidence
from controls.loader import upsert_controls
from db.models import Alert, Control, EvalStatus, Evidence, Evaluation
from evaluator.evaluate import evaluate_control

def run_checks_service(db: Session, run_at: datetime | None = None, simulate_drift: bool | None = None) -> dict[str, Any]:
    if run_at is None:
        run_at = datetime.now(timezone.utc)
    # Allow caller to override drift setting; fall back to env/settings
    if simulate_drift is None:
        from db.config import settings
        simulate_drift = settings.simulate_drift
    controls_dir = pathlib.Path(__file__).parent.parent / "controls"
    controls = upsert_controls(db, controls_dir)
    summary = {"run_at": run_at.isoformat(), "controls_processed": 0, "controls_passed": 0, "controls_failed": 0, "evidence_collected": 0, "evaluations_created": 0, "alerts_created": 0, "failed_controls": []}

    for control in controls:
        summary["controls_processed"] += 1
        evidence_by_source: dict[str, dict[str, Any]] = {}
        evidence_rows: list[Evidence] = []
        for source_info in control.evidence_sources:
            source_system = source_info["system"]
            evidence_data = _collect_evidence_for_source(control.control_id, source_system, run_at, simulate_drift)
            evidence_row = Evidence(control_id=control.control_id, source_system=source_system, collected_at=run_at, raw_snapshot=evidence_data["raw_snapshot"])
            db.add(evidence_row)
            db.flush()
            evidence_rows.append(evidence_row)
            evidence_by_source[source_system] = evidence_data
            summary["evidence_collected"] += 1

        eval_result = evaluate_control(control, evidence_by_source)
        prev_eval = db.execute(select(Evaluation).where(Evaluation.control_id == control.control_id).order_by(desc(Evaluation.evaluated_at)).limit(1)).scalars().first()
        primary_evidence_id = evidence_rows[0].id if evidence_rows else None
        if primary_evidence_id is None:
            continue
        evaluation = Evaluation(control_id=control.control_id, evidence_id=primary_evidence_id, evaluated_at=run_at, status=eval_result["status"], severity=eval_result["severity"], remediation=eval_result["remediation"], details=eval_result["details"])
        db.add(evaluation)
        db.flush()
        summary["evaluations_created"] += 1

        if eval_result["status"] == EvalStatus.pass_:
            summary["controls_passed"] += 1
        else:
            summary["controls_failed"] += 1
            summary["failed_controls"].append({"control_id": control.control_id, "name": control.name, "severity": eval_result["severity"].value, "remediation": eval_result["remediation"]})

        drifted = prev_eval is not None and prev_eval.status == EvalStatus.pass_ and eval_result["status"] == EvalStatus.fail
        if eval_result["severity"].value == "high" and drifted:
            alert = Alert(control_id=control.control_id, severity=eval_result["severity"], message=f"Control {control.control_id} ({control.name}) failed after previously passing", remediation=eval_result["remediation"])
            db.add(alert)
            summary["alerts_created"] += 1

    db.commit()
    return summary

def _collect_evidence_for_source(control_id: str, source_system: str, collected_at: datetime, simulate_drift: bool = False) -> dict[str, Any]:
    if source_system == "fincore_db":
        from collectors.fincore import collect_fincore_evidence
        from db.config import settings
        # For drift simulation on PCI-7.1, temporarily disable RLS
        if simulate_drift and control_id == "PCI-7.1":
            _set_fincore_rls(settings.database_url, enabled=False)
        elif control_id == "PCI-7.1":
            _set_fincore_rls(settings.database_url, enabled=True)
        return collect_fincore_evidence(control_id, settings.database_url, collected_at)
    elif control_id.startswith("PCI") and source_system == "cloud_iam":
        from collectors.pci import collect_pci_iam_evidence
        return collect_pci_iam_evidence(control_id, collected_at, simulate_drift)
    elif control_id.startswith("PCI") and source_system == "cicd":
        from collectors.pci import collect_pci_logging_evidence
        return collect_pci_logging_evidence(control_id, collected_at)
    elif source_system == "github":
        return collect_github_evidence(control_id, collected_at)
    elif source_system == "cloud_iam":
        return collect_iam_evidence(control_id, collected_at, simulate_drift)
    elif source_system == "cicd":
        return collect_logging_evidence(control_id, collected_at)
    else:
        return {"collected_at": collected_at.isoformat(), "source_system": source_system, "raw_snapshot": {"error": f"Unknown source system: {source_system}"}}


def _set_fincore_rls(database_url: str, enabled: bool):
    """Toggle row-level security on fincore.card_data to simulate drift."""
    from sqlalchemy import create_engine, text
    try:
        engine = create_engine(database_url)
        with engine.connect() as conn:
            if enabled:
                conn.execute(text("ALTER TABLE fincore.card_data ENABLE ROW LEVEL SECURITY;"))
            else:
                conn.execute(text("ALTER TABLE fincore.card_data DISABLE ROW LEVEL SECURITY;"))
            conn.commit()
    except Exception:
        pass  # fincore may not be seeded yet

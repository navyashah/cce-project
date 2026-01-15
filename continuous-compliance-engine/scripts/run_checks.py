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


def run_checks_service(db: Session, run_at: datetime | None = None) -> dict[str, Any]:
    """
    Main orchestration function for running compliance checks.

    Flow:
    1. Load/upsert controls from YAML
    2. For each control:
       a. Collect evidence from each source system (one Evidence row per source)
       b. Evaluate control against evidence
       c. Write Evaluation row
       d. If severity=high AND drifted from PASS->FAIL, create Alert
    3. Return summary

    Evidence and Evaluations are append-only (immutable).
    """
    if run_at is None:
        run_at = datetime.now(timezone.utc)

    # Step 1: Load and upsert controls from YAML
    controls_dir = pathlib.Path(__file__).parent.parent / "controls"
    controls = upsert_controls(db, controls_dir)

    # Step 2: Process each control
    summary = {
        "run_at": run_at.isoformat(),
        "controls_processed": 0,
        "controls_passed": 0,
        "controls_failed": 0,
        "evidence_collected": 0,
        "evaluations_created": 0,
        "alerts_created": 0,
        "failed_controls": [],
    }

    for control in controls:
        summary["controls_processed"] += 1

        # Collect evidence from each source system
        evidence_by_source: dict[str, dict[str, Any]] = {}
        evidence_rows: list[Evidence] = []

        for source_info in control.evidence_sources:
            source_system = source_info["system"]
            evidence_data = _collect_evidence_for_source(control.control_id, source_system, run_at)

            # Create immutable Evidence row
            evidence_row = Evidence(
                control_id=control.control_id,
                source_system=source_system,
                collected_at=run_at,
                raw_snapshot=evidence_data["raw_snapshot"],
            )
            db.add(evidence_row)
            db.flush()  # Flush to get evidence_row.id

            evidence_rows.append(evidence_row)
            evidence_by_source[source_system] = evidence_data
            summary["evidence_collected"] += 1

        # Evaluate control
        eval_result = evaluate_control(control, evidence_by_source)

        # Get latest previous evaluation for drift detection
        prev_eval = (
            db.execute(
                select(Evaluation)
                .where(Evaluation.control_id == control.control_id)
                .order_by(desc(Evaluation.evaluated_at))
                .limit(1)
            )
            .scalars()
            .first()
        )

        # Create Evaluation row (append-only)
        # Use the first evidence row's ID as the primary evidence reference
        primary_evidence_id = evidence_rows[0].id if evidence_rows else None
        if primary_evidence_id is None:
            # Should not happen, but handle gracefully
            continue

        evaluation = Evaluation(
            control_id=control.control_id,
            evidence_id=primary_evidence_id,
            evaluated_at=run_at,
            status=eval_result["status"],
            severity=eval_result["severity"],
            remediation=eval_result["remediation"],
            details=eval_result["details"],
        )
        db.add(evaluation)
        db.flush()
        summary["evaluations_created"] += 1

        # Track pass/fail
        if eval_result["status"] == EvalStatus.pass_:
            summary["controls_passed"] += 1
        else:
            summary["controls_failed"] += 1
            summary["failed_controls"].append(
                {
                    "control_id": control.control_id,
                    "name": control.name,
                    "severity": eval_result["severity"].value,
                    "remediation": eval_result["remediation"],
                }
            )

        # Alert creation: severity=high AND drifted from PASS->FAIL
        drifted = prev_eval is not None and prev_eval.status == EvalStatus.pass_ and eval_result["status"] == EvalStatus.fail
        if eval_result["severity"].value == "high" and drifted:
            alert = Alert(
                control_id=control.control_id,
                severity=eval_result["severity"],
                message=f"Control {control.control_id} ({control.name}) failed after previously passing",
                remediation=eval_result["remediation"],
            )
            db.add(alert)
            summary["alerts_created"] += 1

    db.commit()
    return summary


def _collect_evidence_for_source(control_id: str, source_system: str, collected_at: datetime) -> dict[str, Any]:
    """
    Route evidence collection to the appropriate collector based on source_system.
    """
    if source_system == "github":
        return collect_github_evidence(control_id, collected_at)
    elif source_system == "cloud_iam":
        return collect_iam_evidence(control_id, collected_at)
    elif source_system == "cicd":
        return collect_logging_evidence(control_id, collected_at)
    else:
        # Fallback: return empty evidence
        return {
            "collected_at": collected_at.isoformat(),
            "source_system": source_system,
            "raw_snapshot": {"error": f"Unknown source system: {source_system}"},
        }

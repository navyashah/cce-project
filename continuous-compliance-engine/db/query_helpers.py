from __future__ import annotations

from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from db.models import Control, Evidence, Evaluation


def get_controls_with_latest_status(db: Session) -> list[dict[str, Any]]:
    """
    Efficiently fetch all controls with their latest evaluation status and evidence freshness.

    Returns a list of dicts with:
    - All control fields
    - latest_status: PASS/FAIL or None
    - latest_evaluated_at: timestamp or None
    - latest_evidence_freshness: dict mapping source_system -> latest collected_at
    """
    # Get latest evaluation per control_id using subquery approach
    eval_subq = (
        select(
            Evaluation.control_id.label("control_id"),
            func.max(Evaluation.evaluated_at).label("max_evaluated_at"),
        )
        .group_by(Evaluation.control_id)
        .subquery()
    )
    latest_evals_query = (
        select(Evaluation)
        .join(eval_subq, (Evaluation.control_id == eval_subq.c.control_id) & (Evaluation.evaluated_at == eval_subq.c.max_evaluated_at))
    )
    latest_evals = db.execute(latest_evals_query).scalars().all()
    eval_map = {e.control_id: {"status": e.status, "evaluated_at": e.evaluated_at} for e in latest_evals}

    # Get latest evidence timestamp per control_id and source_system
    ev_subq = (
        select(
            Evidence.control_id,
            Evidence.source_system,
            func.max(Evidence.collected_at).label("max_collected_at"),
        )
        .group_by(Evidence.control_id, Evidence.source_system)
        .subquery()
    )
    freshness_rows = db.execute(select(ev_subq)).mappings().all()
    freshness_map: dict[str, dict[str, str]] = {}
    for row in freshness_rows:
        cid = row["control_id"]
        if cid not in freshness_map:
            freshness_map[cid] = {}
        freshness_map[cid][row["source_system"]] = row["max_collected_at"].isoformat()

    # Fetch all controls
    controls = db.execute(select(Control).order_by(Control.control_id.asc())).scalars().all()

    result = []
    for ctrl in controls:
        eval_data = eval_map.get(ctrl.control_id)
        result.append(
            {
                "control_id": ctrl.control_id,
                "name": ctrl.name,
                "risk": ctrl.risk,
                "expected_state": ctrl.expected_state,
                "evidence_sources": ctrl.evidence_sources,
                "severity": ctrl.severity.value,
                "check_frequency": ctrl.check_frequency,
                "created_at": ctrl.created_at.isoformat(),
                "latest_status": eval_data["status"].value if eval_data else None,
                "latest_evaluated_at": eval_data["evaluated_at"].isoformat() if eval_data else None,
                "latest_evidence_freshness": freshness_map.get(ctrl.control_id, {}),
            }
        )
    return result

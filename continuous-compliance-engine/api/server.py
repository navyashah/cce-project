from __future__ import annotations

import pathlib
from datetime import datetime, timezone
from urllib.parse import quote

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session

from db.config import settings
from db.models import Alert, Base, Control, Evidence, Evaluation, EvalStatus, Severity
from db.query_helpers import get_controls_with_latest_status
from db.session import engine, get_db

# Setup templates and static files
BASE_DIR = pathlib.Path(__file__).parent.parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

app = FastAPI(title=settings.app_name)

# Mount static files
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


@app.on_event("startup")
def _init_db() -> None:
    """
    Simple schema management:
    - create_all is enough for this internal demo (no migrations).
    - Tradeoff: schema changes require manual coordination.
    """

    Base.metadata.create_all(bind=engine)


@app.get("/controls")
def list_controls(db: Session = Depends(get_db)):
    rows = db.execute(select(Control).order_by(Control.control_id.asc())).scalars().all()
    return [
        {
            "control_id": c.control_id,
            "name": c.name,
            "risk": c.risk,
            "expected_state": c.expected_state,
            "evidence_sources": c.evidence_sources,
            "severity": c.severity.value,
            "check_frequency": c.check_frequency,
            "created_at": c.created_at.isoformat(),
        }
        for c in rows
    ]


@app.get("/controls/{control_id}")
def get_control(control_id: str, db: Session = Depends(get_db)):
    c = db.execute(select(Control).where(Control.control_id == control_id)).scalar_one_or_none()
    if not c:
        raise HTTPException(status_code=404, detail="control not found")

    latest_eval = (
        db.execute(
            select(Evaluation).where(Evaluation.control_id == control_id).order_by(desc(Evaluation.evaluated_at)).limit(1)
        )
        .scalars()
        .first()
    )
    latest_evidence = None
    if latest_eval:
        latest_evidence = db.execute(select(Evidence).where(Evidence.id == latest_eval.evidence_id)).scalar_one_or_none()

    return {
        "control": {
            "control_id": c.control_id,
            "name": c.name,
            "risk": c.risk,
            "expected_state": c.expected_state,
            "evidence_sources": c.evidence_sources,
            "severity": c.severity.value,
            "check_frequency": c.check_frequency,
            "created_at": c.created_at.isoformat(),
        },
        "latest_evaluation": (
            None
            if not latest_eval
            else {
                "evaluated_at": latest_eval.evaluated_at.isoformat(),
                "status": latest_eval.status.value,
                "severity": latest_eval.severity.value,
                "remediation": latest_eval.remediation,
                "details": latest_eval.details,
            }
        ),
        "latest_evidence": (
            None
            if not latest_evidence
            else {
                "collected_at": latest_evidence.collected_at.isoformat(),
                "source_system": latest_evidence.source_system,
                "raw_snapshot": latest_evidence.raw_snapshot,
            }
        ),
    }


@app.post("/run-checks")
def run_checks(db: Session = Depends(get_db)):
    """
    Implemented in `scripts/run_checks.py` (service-style function).
    Imported lazily to keep API startup fast and side-effect-free.
    """

    from scripts.run_checks import run_checks_service

    return run_checks_service(db=db, run_at=utcnow())


def _dashboard_metrics(db: Session) -> dict:
    # Latest evaluation per control_id
    subq = (
        select(
            Evaluation.control_id.label("control_id"),
            func.max(Evaluation.evaluated_at).label("max_evaluated_at"),
        )
        .group_by(Evaluation.control_id)
        .subquery()
    )
    latest = (
        db.execute(
            select(Evaluation)
            .join(subq, (Evaluation.control_id == subq.c.control_id) & (Evaluation.evaluated_at == subq.c.max_evaluated_at))
        )
        .scalars()
        .all()
    )

    total = len(latest)
    passing = sum(1 for e in latest if e.status == EvalStatus.pass_)
    pass_rate = 0.0 if total == 0 else (passing / total)

    failed_by_sev: dict[str, int] = {"high": 0, "medium": 0, "low": 0}
    for e in latest:
        if e.status == EvalStatus.fail:
            failed_by_sev[e.severity.value] += 1

    # Evidence freshness: latest evidence timestamp per control_id
    ev_subq = (
        select(Evidence.control_id.label("control_id"), func.max(Evidence.collected_at).label("max_collected_at"))
        .group_by(Evidence.control_id)
        .subquery()
    )
    freshness_rows = db.execute(select(ev_subq.c.control_id, ev_subq.c.max_collected_at)).all()
    evidence_freshness = {cid: ts.isoformat() for cid, ts in freshness_rows if ts is not None}

    # Active (unacknowledged) alerts count
    active_alerts_count = db.execute(select(func.count(Alert.id)).where(Alert.acknowledged == False)).scalar() or 0

    return {
        "controls_total": total,
        "controls_passing": passing,
        "pass_rate": pass_rate,
        "audit_readiness_score": pass_rate,  # same as pass rate for this demo
        "failed_controls_by_severity": failed_by_sev,
        "evidence_freshness": evidence_freshness,
        "active_alerts_count": active_alerts_count,
        "mttr_days": None,  # placeholder: requires remediation workflow + ticket timestamps
    }


@app.get("/dashboard")
def dashboard_json(db: Session = Depends(get_db)):
    return _dashboard_metrics(db)


@app.get("/alerts")
def list_alerts(db: Session = Depends(get_db), limit: int = 50):
    """
    List recent alerts ordered by created_at descending.
    """
    alerts = (
        db.execute(select(Alert).order_by(desc(Alert.created_at)).limit(limit))
        .scalars()
        .all()
    )
    return [
        {
            "id": a.id,
            "control_id": a.control_id,
            "created_at": a.created_at.isoformat(),
            "severity": a.severity.value,
            "message": a.message,
            "remediation": a.remediation,
            "acknowledged": a.acknowledged,
        }
        for a in alerts
    ]


@app.get("/dashboard/ui", response_class=HTMLResponse)
def dashboard_ui(db: Session = Depends(get_db)):
    m = _dashboard_metrics(db)
    html = f"""
    <html>
      <head><title>Continuous Compliance Engine</title></head>
      <body style="font-family: ui-sans-serif, system-ui; max-width: 900px; margin: 24px auto;">
        <h2>Continuous Compliance Engine — Dashboard</h2>
        <p><b>Pass rate:</b> {m["pass_rate"]:.0%} ({m["controls_passing"]}/{m["controls_total"]})</p>
        <p><b>Audit readiness score:</b> {m["audit_readiness_score"]:.0%}</p>
        <p><b>Active alerts:</b> {m["active_alerts_count"]}</p>
        <h3>Failed controls by severity</h3>
        <pre>{m["failed_controls_by_severity"]}</pre>
        <h3>Evidence freshness (latest per control)</h3>
        <pre>{m["evidence_freshness"]}</pre>
        <h3>MTTR</h3>
        <p>{m["mttr_days"]}</p>
        <hr />
        <p>JSON endpoints: <code>/dashboard</code> | <code>/alerts</code></p>
      </body>
    </html>
    """
    return HTMLResponse(content=html)


# ============================================================================
# UI Routes (Jinja2 templates)
# ============================================================================

@app.get("/ui")
def ui_root():
    """Redirect to controls page."""
    return RedirectResponse(url="/ui/controls", status_code=302)


@app.get("/ui/controls", response_class=HTMLResponse)
def ui_controls(request: Request, db: Session = Depends(get_db), message: str | None = None):
    """Controls table view."""
    controls = get_controls_with_latest_status(db)
    return templates.TemplateResponse(
        "controls.html",
        {
            "request": request,
            "controls": controls,
            "message": message,
            "message_type": "success" if message else None,
        },
    )


@app.get("/ui/controls/{control_id}", response_class=HTMLResponse)
def ui_control_detail(control_id: str, request: Request, db: Session = Depends(get_db)):
    """Control detail view."""
    ctrl = db.execute(select(Control).where(Control.control_id == control_id)).scalar_one_or_none()
    if not ctrl:
        raise HTTPException(status_code=404, detail="Control not found")

    # Latest evaluation
    latest_eval = (
        db.execute(
            select(Evaluation).where(Evaluation.control_id == control_id).order_by(desc(Evaluation.evaluated_at)).limit(1)
        )
        .scalars()
        .first()
    )

    # Latest evidence grouped by source_system
    latest_evidence_by_source: dict[str, list[dict]] = {}
    if latest_eval:
        # Get all evidence for the latest evaluation timestamp
        evidence_rows = (
            db.execute(
                select(Evidence)
                .where(Evidence.control_id == control_id)
                .where(Evidence.collected_at == latest_eval.evaluated_at)
                .order_by(Evidence.source_system.asc())
            )
            .scalars()
            .all()
        )
        for ev in evidence_rows:
            source = ev.source_system
            if source not in latest_evidence_by_source:
                latest_evidence_by_source[source] = []
            latest_evidence_by_source[source].append(
                {
                    "collected_at": ev.collected_at.isoformat(),
                    "raw_snapshot": ev.raw_snapshot,
                }
            )

    # Evaluation history (last 10)
    eval_history = (
        db.execute(
            select(Evaluation)
            .where(Evaluation.control_id == control_id)
            .order_by(desc(Evaluation.evaluated_at))
            .limit(10)
        )
        .scalars()
        .all()
    )

    # Evidence history (last 10)
    evidence_history = (
        db.execute(
            select(Evidence)
            .where(Evidence.control_id == control_id)
            .order_by(desc(Evidence.collected_at))
            .limit(10)
        )
        .scalars()
        .all()
    )

    control_dict = {
        "control_id": ctrl.control_id,
        "name": ctrl.name,
        "risk": ctrl.risk,
        "expected_state": ctrl.expected_state,
        "evidence_sources": ctrl.evidence_sources,
        "severity": ctrl.severity.value,
        "check_frequency": ctrl.check_frequency,
        "created_at": ctrl.created_at.isoformat(),
    }

    latest_eval_dict = None
    if latest_eval:
        latest_eval_dict = {
            "status": latest_eval.status.value,
            "evaluated_at": latest_eval.evaluated_at.isoformat(),
            "severity": latest_eval.severity.value,
            "remediation": latest_eval.remediation,
            "details": latest_eval.details,
        }

    eval_history_list = [
        {
            "status": e.status.value,
            "evaluated_at": e.evaluated_at.isoformat(),
        }
        for e in eval_history
    ]

    evidence_history_list = [
        {
            "source_system": e.source_system,
            "collected_at": e.collected_at.isoformat(),
        }
        for e in evidence_history
    ]

    return templates.TemplateResponse(
        "control_detail.html",
        {
            "request": request,
            "control": control_dict,
            "latest_evaluation": latest_eval_dict,
            "latest_evidence_by_source": latest_evidence_by_source,
            "evaluation_history": eval_history_list,
            "evidence_history": evidence_history_list,
        },
    )


@app.post("/ui/run-checks")
def ui_run_checks(db: Session = Depends(get_db)):
    """Run checks and redirect back to controls page."""
    from scripts.run_checks import run_checks_service

    try:
        result = run_checks_service(db=db, run_at=utcnow())
        message = (
            f"Checks completed: {result['controls_passed']}/{result['controls_processed']} passed. "
            f"{result['alerts_created']} alert(s) created."
        )
    except Exception as e:
        message = f"Error running checks: {str(e)}"

    return RedirectResponse(url=f"/ui/controls?message={quote(message)}", status_code=302)


@app.get("/ui/alerts", response_class=HTMLResponse)
def ui_alerts(request: Request, db: Session = Depends(get_db), limit: int = 50):
    """Alerts view."""
    alerts = (
        db.execute(select(Alert).order_by(desc(Alert.created_at)).limit(limit))
        .scalars()
        .all()
    )

    alerts_list = [
        {
            "control_id": a.control_id,
            "created_at": a.created_at.isoformat(),
            "severity": a.severity.value,
            "message": a.message,
            "remediation": a.remediation,
            "acknowledged": a.acknowledged,
        }
        for a in alerts
    ]

    return templates.TemplateResponse(
        "alerts.html",
        {
            "request": request,
            "alerts": alerts_list,
        },
    )


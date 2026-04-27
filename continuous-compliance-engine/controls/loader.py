from __future__ import annotations
import pathlib
from typing import Any
import yaml
from sqlalchemy import select
from sqlalchemy.orm import Session
from db.models import Control, Severity

def load_controls_from_yaml(controls_dir: pathlib.Path) -> list[dict[str, Any]]:
    controls = []
    for yaml_file in sorted(controls_dir.glob("*.yml")):
        with open(yaml_file, "r") as f:
            data = yaml.safe_load(f)
            controls.append(_normalize_control(data))
    return controls

def _normalize_control(data: dict[str, Any]) -> dict[str, Any]:
    control_id = data["control_id"]
    severity_str = data["severity"].lower()
    try:
        severity = Severity(severity_str)
    except ValueError:
        raise ValueError(f"Invalid severity '{severity_str}' for control {control_id}")
    normalized_sources = []
    for src in data.get("evidence_sources", []):
        if isinstance(src, dict):
            normalized_sources.append(src)
        elif isinstance(src, str):
            normalized_sources.append({"system": src})
    return {"control_id": control_id, "name": data["name"], "risk": data["risk"], "expected_state": data["expected_state"], "evidence_sources": normalized_sources, "severity": severity, "check_frequency": data.get("check_frequency", "daily")}

def upsert_controls(db: Session, controls_dir: pathlib.Path) -> list[Control]:
    control_dicts = load_controls_from_yaml(controls_dir)
    controls = []
    for ctrl_dict in control_dicts:
        control_id = ctrl_dict["control_id"]
        existing = db.execute(select(Control).where(Control.control_id == control_id)).scalar_one_or_none()
        if existing:
            for key, value in ctrl_dict.items():
                if key != "control_id":
                    setattr(existing, key, value)
            controls.append(existing)
        else:
            new_control = Control(**ctrl_dict)
            db.add(new_control)
            controls.append(new_control)
    db.commit()
    return controls

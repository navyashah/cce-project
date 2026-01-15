from __future__ import annotations

import pathlib
from typing import Any

import yaml
from sqlalchemy import select
from sqlalchemy.orm import Session

from db.models import Control, Severity


def load_controls_from_yaml(controls_dir: pathlib.Path) -> list[dict[str, Any]]:
    """
    Load all YAML control definitions from the controls directory.

    Returns a list of normalized control dicts ready for upsert.
    """
    controls = []
    for yaml_file in sorted(controls_dir.glob("*.yml")):
        with open(yaml_file, "r") as f:
            data = yaml.safe_load(f)
            controls.append(_normalize_control(data))
    return controls


def _normalize_control(data: dict[str, Any]) -> dict[str, Any]:
    """
    Normalize YAML control definition to match Control model schema.

    Ensures:
    - control_id is present
    - severity is a valid Severity enum value
    - evidence_sources is a list of dicts with 'system' key
    - All required fields are present
    """
    control_id = data["control_id"]
    name = data["name"]
    risk = data["risk"]
    expected_state = data["expected_state"]
    evidence_sources = data.get("evidence_sources", [])
    severity_str = data["severity"].lower()
    check_frequency = data.get("check_frequency", "daily")

    # Validate severity
    try:
        severity = Severity(severity_str)
    except ValueError:
        raise ValueError(f"Invalid severity '{severity_str}' for control {control_id}. Must be: low, medium, high")

    # Normalize evidence_sources: ensure each has 'system' key
    normalized_sources = []
    for src in evidence_sources:
        if isinstance(src, dict):
            if "system" not in src:
                raise ValueError(f"evidence_sources entry missing 'system' key for control {control_id}")
            normalized_sources.append(src)
        elif isinstance(src, str):
            normalized_sources.append({"system": src})
        else:
            raise ValueError(f"Invalid evidence_sources format for control {control_id}")

    return {
        "control_id": control_id,
        "name": name,
        "risk": risk,
        "expected_state": expected_state,
        "evidence_sources": normalized_sources,
        "severity": severity,
        "check_frequency": check_frequency,
    }


def upsert_controls(db: Session, controls_dir: pathlib.Path) -> list[Control]:
    """
    Load controls from YAML and upsert into the database by control_id.

    Returns list of Control objects (existing or newly created).
    """
    control_dicts = load_controls_from_yaml(controls_dir)
    controls = []

    for ctrl_dict in control_dicts:
        control_id = ctrl_dict["control_id"]
        existing = db.execute(select(Control).where(Control.control_id == control_id)).scalar_one_or_none()

        if existing:
            # Update existing control (upsert semantics)
            for key, value in ctrl_dict.items():
                if key != "control_id":
                    setattr(existing, key, value)
            controls.append(existing)
        else:
            # Create new control
            new_control = Control(**ctrl_dict)
            db.add(new_control)
            controls.append(new_control)

    db.commit()
    return controls

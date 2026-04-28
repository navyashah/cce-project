from __future__ import annotations
from datetime import datetime, timezone
from typing import Any

def collect_pci_iam_evidence(control_id: str, collected_at: datetime | None = None, simulate_drift: bool = False) -> dict[str, Any]:
    if collected_at is None:
        collected_at = datetime.now(timezone.utc)

    if control_id == "PCI-2.1":
        return {
            "collected_at": collected_at.isoformat(),
            "source_system": "cloud_iam",
            "raw_snapshot": {
                "default_credentials_removed": True,
                "vendor_supplied_defaults_changed": True,
                "scanned_accounts": 12,
                "accounts_with_default_creds": 0,
            },
        }

    if control_id == "PCI-7.1":
        return {
            "collected_at": collected_at.isoformat(),
            "source_system": "cloud_iam",
            "raw_snapshot": {
                "access_restricted_to_need_to_know": not simulate_drift,
                "api_layer_enforcement": not simulate_drift,
                "ui_layer_enforcement": True,
                "roles_with_cardholder_access": 2 if not simulate_drift else 8,
                "note": "Separation enforced at API layer" if not simulate_drift else "Separation only at UI layer — API layer unprotected",
            },
        }

    return {"collected_at": collected_at.isoformat(), "source_system": "cloud_iam", "raw_snapshot": {}}

def collect_pci_logging_evidence(control_id: str, collected_at: datetime | None = None) -> dict[str, Any]:
    if collected_at is None:
        collected_at = datetime.now(timezone.utc)
    return {
        "collected_at": collected_at.isoformat(),
        "source_system": "cicd",
        "raw_snapshot": {
            "audit_logging_enabled": True,
            "log_retention_days": 365,
            "card_data_access_events_logged": True,
            "log_integrity_protected": True,
        },
    }

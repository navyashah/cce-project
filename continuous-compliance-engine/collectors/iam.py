from __future__ import annotations
from datetime import datetime, timezone
from typing import Any

def collect_iam_evidence(control_id: str, collected_at: datetime | None = None, simulate_drift: bool = False) -> dict[str, Any]:
    if collected_at is None:
        collected_at = datetime.now(timezone.utc)

    if simulate_drift and control_id == "CC6.1":
        return {
            "collected_at": collected_at.isoformat(),
            "source_system": "cloud_iam",
            "raw_snapshot": {
                "privileged_users": [
                    {"username": "admin1", "roles": ["admin"], "mfa_enabled": False, "mfa_devices": []},
                    {"username": "admin2", "roles": ["admin"], "mfa_enabled": False, "mfa_devices": []},
                ],
                "mfa_required_for_privileged_users": False,
                "admin_access_restricted": True,
                "total_admin_users": 2,
                "admin_users_without_mfa": 2,
                "policy_enforcement": {"mfa_required_policy": "disabled", "admin_restriction_policy": "enforced"},
            },
        }

    return {
        "collected_at": collected_at.isoformat(),
        "source_system": "cloud_iam",
        "raw_snapshot": {
            "privileged_users": [
                {"username": "admin1", "roles": ["admin"], "mfa_enabled": True, "mfa_devices": ["totp"]},
                {"username": "admin2", "roles": ["admin"], "mfa_enabled": True, "mfa_devices": ["totp"]},
            ],
            "mfa_required_for_privileged_users": True,
            "admin_access_restricted": True,
            "total_admin_users": 2,
            "admin_users_without_mfa": 0,
            "policy_enforcement": {"mfa_required_policy": "enforced", "admin_restriction_policy": "enforced"},
        },
    }

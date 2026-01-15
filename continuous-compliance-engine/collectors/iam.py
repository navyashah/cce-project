from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any


def collect_iam_evidence(control_id: str, collected_at: datetime | None = None) -> dict[str, Any]:
    """
    Mock Cloud IAM evidence collector for CC6.1 (Logical Access Controls).

    Deterministic mock data:
    - MFA enabled for privileged users: True (or False if SIMULATE_DRIFT=1)
    - Admin access restricted: True (or False if SIMULATE_DRIFT=1)

    In production, this would call cloud provider APIs:
    - AWS: IAM list_users, get_user_mfa_devices, list_attached_user_policies
    - GCP: projects.getIamPolicy, serviceAccounts.list
    - Azure: Microsoft Graph API for users and role assignments
    """
    if collected_at is None:
        collected_at = datetime.now(timezone.utc)

    # Drift simulation: when SIMULATE_DRIFT=1, force CC6.1 to fail
    simulate_drift = os.getenv("SIMULATE_DRIFT", "0") == "1"
    if simulate_drift and control_id == "CC6.1":
        # Simulate MFA policy being disabled
        return {
            "collected_at": collected_at.isoformat(),
            "source_system": "cloud_iam",
            "raw_snapshot": {
                "privileged_users": [
                    {
                        "username": "admin1",
                        "roles": ["admin"],
                        "mfa_enabled": False,
                        "mfa_devices": [],
                    },
                    {
                        "username": "admin2",
                        "roles": ["admin"],
                        "mfa_enabled": False,
                        "mfa_devices": [],
                    },
                ],
                "mfa_required_for_privileged_users": False,
                "admin_access_restricted": True,
                "total_admin_users": 2,
                "admin_users_without_mfa": 2,
                "policy_enforcement": {
                    "mfa_required_policy": "disabled",
                    "admin_restriction_policy": "enforced",
                },
            },
        }

    # Deterministic mock: CC6.1 expects mfa_required_for_privileged_users=True and admin_access_restricted=True
    # For demo purposes, we simulate a passing state
    return {
        "collected_at": collected_at.isoformat(),
        "source_system": "cloud_iam",
        "raw_snapshot": {
            "privileged_users": [
                {
                    "username": "admin1",
                    "roles": ["admin"],
                    "mfa_enabled": True,
                    "mfa_devices": ["totp"],
                },
                {
                    "username": "admin2",
                    "roles": ["admin"],
                    "mfa_enabled": True,
                    "mfa_devices": ["totp"],
                },
            ],
            "mfa_required_for_privileged_users": True,
            "admin_access_restricted": True,
            "total_admin_users": 2,
            "admin_users_without_mfa": 0,
            "policy_enforcement": {
                "mfa_required_policy": "enforced",
                "admin_restriction_policy": "enforced",
            },
        },
    }

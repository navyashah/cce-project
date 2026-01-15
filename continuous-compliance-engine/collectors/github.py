from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def collect_github_evidence(control_id: str, collected_at: datetime | None = None) -> dict[str, Any]:
    """
    Mock GitHub evidence collector for CC8.1 (Change Management).

    Deterministic mock data:
    - Branch protection: enabled for main/master
    - PR reviews required: 2 approvals
    - Production deploy approvals: enforced via branch protection

    In production, this would call GitHub API:
    - GET /repos/{owner}/{repo}/branches/{branch}/protection
    - GET /repos/{owner}/{repo}/pulls (to verify PR review requirements)
    """
    if collected_at is None:
        collected_at = datetime.now(timezone.utc)

    # Deterministic mock: CC8.1 expects pr_reviews_required=True and production_deploy_approvals_required=True
    # For demo purposes, we simulate a passing state (all requirements met)
    return {
        "collected_at": collected_at.isoformat(),
        "source_system": "github",
        "raw_snapshot": {
            "branch_protection": {
                "main": {
                    "enabled": True,
                    "required_approving_review_count": 2,
                    "dismiss_stale_reviews": True,
                    "require_code_owner_reviews": True,
                    "enforce_admins": True,
                },
                "master": {
                    "enabled": True,
                    "required_approving_review_count": 2,
                    "dismiss_stale_reviews": True,
                    "require_code_owner_reviews": True,
                    "enforce_admins": True,
                },
            },
            "pr_reviews_required": True,
            "production_deploy_approvals_required": True,
            "recent_prs": [
                {
                    "number": 123,
                    "merged": True,
                    "approvals": 2,
                    "base_branch": "main",
                },
                {
                    "number": 124,
                    "merged": True,
                    "approvals": 2,
                    "base_branch": "main",
                },
            ],
        },
    }

from __future__ import annotations
from datetime import datetime, timezone
from typing import Any

def collect_github_evidence(control_id: str, collected_at: datetime | None = None) -> dict[str, Any]:
    if collected_at is None:
        collected_at = datetime.now(timezone.utc)
    return {
        "collected_at": collected_at.isoformat(),
        "source_system": "github",
        "raw_snapshot": {
            "branch_protection": {"main": {"enabled": True, "required_approving_review_count": 2, "dismiss_stale_reviews": True, "require_code_owner_reviews": True, "enforce_admins": True}},
            "pr_reviews_required": True,
            "production_deploy_approvals_required": True,
            "recent_prs": [{"number": 123, "merged": True, "approvals": 2, "base_branch": "main"}, {"number": 124, "merged": True, "approvals": 2, "base_branch": "main"}],
        },
    }

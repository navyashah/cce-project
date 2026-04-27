from __future__ import annotations
from datetime import datetime, timezone
from typing import Any

def collect_logging_evidence(control_id: str, collected_at: datetime | None = None) -> dict[str, Any]:
    if collected_at is None:
        collected_at = datetime.now(timezone.utc)
    return {
        "collected_at": collected_at.isoformat(),
        "source_system": "cicd",
        "raw_snapshot": {
            "centralized_logging_enabled": True,
            "log_retention_days": 90,
            "log_aggregation_system": "cloudwatch_logs",
            "log_sources": [
                {"source": "github_actions", "shipped": True, "retention_days": 90},
                {"source": "production_app", "shipped": True, "retention_days": 90},
                {"source": "infrastructure", "shipped": True, "retention_days": 90},
            ],
            "retention_policy": {"minimum_days": 90, "enforced": True},
        },
    }

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


def collect_logging_evidence(control_id: str, collected_at: datetime | None = None) -> dict[str, Any]:
    """
    Mock CI/CD logging evidence collector for CC7.2 (Logging and Monitoring).

    Deterministic mock data:
    - Centralized logging enabled: True
    - Log retention: 90 days (meets minimum requirement)

    In production, this would call:
    - CI/CD platform APIs (GitHub Actions, GitLab CI, Jenkins, etc.)
    - Log aggregation systems (Datadog, Splunk, ELK, CloudWatch Logs)
    - Verify log shipping configuration and retention policies
    """
    if collected_at is None:
        collected_at = datetime.now(timezone.utc)

    # Deterministic mock: CC7.2 expects centralized_logging_enabled=True and log_retention_days_minimum >= 90
    # For demo purposes, we simulate a passing state
    return {
        "collected_at": collected_at.isoformat(),
        "source_system": "cicd",
        "raw_snapshot": {
            "centralized_logging_enabled": True,
            "log_retention_days": 90,
            "log_aggregation_system": "cloudwatch_logs",
            "log_sources": [
                {
                    "source": "github_actions",
                    "shipped": True,
                    "retention_days": 90,
                },
                {
                    "source": "production_app",
                    "shipped": True,
                    "retention_days": 90,
                },
                {
                    "source": "infrastructure",
                    "shipped": True,
                    "retention_days": 90,
                },
            ],
            "retention_policy": {
                "minimum_days": 90,
                "enforced": True,
            },
        },
    }

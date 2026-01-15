from __future__ import annotations

from typing import Any

from db.models import Control, EvalStatus, Severity


def evaluate_control(control: Control, evidence_by_source: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """
    Evaluate a control against collected evidence.

    Returns:
        {
            "status": EvalStatus (PASS/FAIL),
            "severity": Severity (from control),
            "remediation": str (actionable guidance),
            "details": dict (evaluation context)
        }
    """
    expected = control.expected_state
    control_id = control.control_id

    if control_id == "CC6.1":
        return _evaluate_cc6_1(control, evidence_by_source, expected)
    elif control_id == "CC7.2":
        return _evaluate_cc7_2(control, evidence_by_source, expected)
    elif control_id == "CC8.1":
        return _evaluate_cc8_1(control, evidence_by_source, expected)
    else:
        return {
            "status": EvalStatus.fail,
            "severity": control.severity,
            "remediation": f"Unknown control {control_id}. Implement evaluator logic.",
            "details": {"error": "unknown_control"},
        }


def _evaluate_cc6_1(control: Control, evidence_by_source: dict[str, dict[str, Any]], expected: dict[str, Any]) -> dict[str, Any]:
    """
    CC6.1: Logical Access Controls
    Expected: mfa_required_for_privileged_users=True, admin_access_restricted=True
    """
    iam_evidence = evidence_by_source.get("cloud_iam", {})
    snapshot = iam_evidence.get("raw_snapshot", {})

    mfa_required = expected.get("mfa_required_for_privileged_users", False)
    admin_restricted = expected.get("admin_access_restricted", False)

    actual_mfa = snapshot.get("mfa_required_for_privileged_users", False)
    actual_admin_restricted = snapshot.get("admin_access_restricted", False)
    admin_without_mfa = snapshot.get("admin_users_without_mfa", 999)

    issues = []
    if mfa_required and not actual_mfa:
        issues.append("MFA not required for privileged users")
    if admin_restricted and not actual_admin_restricted:
        issues.append("Admin access not properly restricted")
    if admin_without_mfa > 0:
        issues.append(f"{admin_without_mfa} admin user(s) without MFA")

    if issues:
        return {
            "status": EvalStatus.fail,
            "severity": control.severity,
            "remediation": (
                "1. Enable MFA enforcement policy for all privileged roles.\n"
                "2. Review and restrict admin role assignments to minimum necessary users.\n"
                "3. Verify all admin users have MFA devices enrolled."
            ),
            "details": {
                "issues": issues,
                "expected": expected,
                "actual": {
                    "mfa_required_for_privileged_users": actual_mfa,
                    "admin_access_restricted": actual_admin_restricted,
                    "admin_users_without_mfa": admin_without_mfa,
                },
            },
        }
    else:
        return {
            "status": EvalStatus.pass_,
            "severity": control.severity,
            "remediation": "No action required.",
            "details": {
                "expected": expected,
                "actual": {
                    "mfa_required_for_privileged_users": actual_mfa,
                    "admin_access_restricted": actual_admin_restricted,
                },
            },
        }


def _evaluate_cc7_2(control: Control, evidence_by_source: dict[str, dict[str, Any]], expected: dict[str, Any]) -> dict[str, Any]:
    """
    CC7.2: Logging and Monitoring
    Expected: centralized_logging_enabled=True, log_retention_days_minimum >= 90
    """
    cicd_evidence = evidence_by_source.get("cicd", {})
    snapshot = cicd_evidence.get("raw_snapshot", {})

    expected_enabled = expected.get("centralized_logging_enabled", False)
    expected_retention_min = expected.get("log_retention_days_minimum", 0)

    actual_enabled = snapshot.get("centralized_logging_enabled", False)
    actual_retention = snapshot.get("log_retention_days", 0)

    issues = []
    if expected_enabled and not actual_enabled:
        issues.append("Centralized logging not enabled")
    if actual_retention < expected_retention_min:
        issues.append(f"Log retention {actual_retention} days is below minimum {expected_retention_min} days")

    if issues:
        return {
            "status": EvalStatus.fail,
            "severity": control.severity,
            "remediation": (
                "1. Enable centralized log shipping from all production systems.\n"
                f"2. Configure log retention policy to retain logs for at least {expected_retention_min} days.\n"
                "3. Verify log aggregation system is receiving logs from all critical sources."
            ),
            "details": {
                "issues": issues,
                "expected": expected,
                "actual": {
                    "centralized_logging_enabled": actual_enabled,
                    "log_retention_days": actual_retention,
                },
            },
        }
    else:
        return {
            "status": EvalStatus.pass_,
            "severity": control.severity,
            "remediation": "No action required.",
            "details": {
                "expected": expected,
                "actual": {
                    "centralized_logging_enabled": actual_enabled,
                    "log_retention_days": actual_retention,
                },
            },
        }


def _evaluate_cc8_1(control: Control, evidence_by_source: dict[str, dict[str, Any]], expected: dict[str, Any]) -> dict[str, Any]:
    """
    CC8.1: Change Management
    Expected: pr_reviews_required=True, production_deploy_approvals_required=True
    """
    github_evidence = evidence_by_source.get("github", {})
    cicd_evidence = evidence_by_source.get("cicd", {})

    github_snapshot = github_evidence.get("raw_snapshot", {})
    cicd_snapshot = cicd_evidence.get("raw_snapshot", {})

    expected_pr_reviews = expected.get("pr_reviews_required", False)
    expected_deploy_approvals = expected.get("production_deploy_approvals_required", False)

    # Check GitHub branch protection
    branch_protection = github_snapshot.get("branch_protection", {})
    main_protection = branch_protection.get("main") or branch_protection.get("master", {})
    actual_pr_reviews = (
        github_snapshot.get("pr_reviews_required", False)
        or main_protection.get("required_approving_review_count", 0) >= 2
    )

    # Check CI/CD deploy approvals
    actual_deploy_approvals = (
        github_snapshot.get("production_deploy_approvals_required", False)
        or cicd_snapshot.get("production_deploy_approvals_required", False)
        or main_protection.get("enforce_admins", False)
    )

    issues = []
    if expected_pr_reviews and not actual_pr_reviews:
        issues.append("PR reviews not required for production branches")
    if expected_deploy_approvals and not actual_deploy_approvals:
        issues.append("Production deploy approvals not enforced")

    if issues:
        return {
            "status": EvalStatus.fail,
            "severity": control.severity,
            "remediation": (
                "1. Enable branch protection rules for main/master branch.\n"
                "2. Require at least 2 PR approvals before merge.\n"
                "3. Enforce admin approval requirements for production deployments.\n"
                "4. Verify CI/CD pipeline blocks deployments without approvals."
            ),
            "details": {
                "issues": issues,
                "expected": expected,
                "actual": {
                    "pr_reviews_required": actual_pr_reviews,
                    "production_deploy_approvals_required": actual_deploy_approvals,
                    "branch_protection": main_protection,
                },
            },
        }
    else:
        return {
            "status": EvalStatus.pass_,
            "severity": control.severity,
            "remediation": "No action required.",
            "details": {
                "expected": expected,
                "actual": {
                    "pr_reviews_required": actual_pr_reviews,
                    "production_deploy_approvals_required": actual_deploy_approvals,
                },
            },
        }

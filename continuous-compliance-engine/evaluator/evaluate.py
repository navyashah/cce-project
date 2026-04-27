from __future__ import annotations
from typing import Any
from db.models import Control, EvalStatus, Severity

def evaluate_control(control: Control, evidence_by_source: dict[str, dict[str, Any]]) -> dict[str, Any]:
    expected = control.expected_state
    control_id = control.control_id
    if control_id == "CC6.1":
        return _evaluate_cc6_1(control, evidence_by_source, expected)
    elif control_id == "CC7.2":
        return _evaluate_cc7_2(control, evidence_by_source, expected)
    elif control_id == "CC8.1":
        return _evaluate_cc8_1(control, evidence_by_source, expected)
    elif control_id == "PCI-2.1":
        return _evaluate_pci_2_1(control, evidence_by_source, expected)
    elif control_id == "PCI-7.1":
        return _evaluate_pci_7_1(control, evidence_by_source, expected)
    elif control_id == "PCI-10.1":
        return _evaluate_pci_10_1(control, evidence_by_source, expected)
    else:
        return {"status": EvalStatus.fail, "severity": control.severity, "remediation": f"Unknown control {control_id}.", "details": {"error": "unknown_control"}}

def _evaluate_pci_2_1(control, evidence_by_source, expected):
    snapshot = evidence_by_source.get("cloud_iam", {}).get("raw_snapshot", {})
    issues = []
    if not snapshot.get("default_credentials_removed", False):
        issues.append("Default credentials detected on system components")
    if not snapshot.get("vendor_supplied_defaults_changed", False):
        issues.append("Vendor-supplied default passwords have not been changed")
    if issues:
        return {"status": EvalStatus.fail, "severity": control.severity, "remediation": "1. Audit all components for default credentials.\n2. Change all vendor-supplied default passwords before deployment.\n3. Enforce via pre-deployment checklist or automated scanner.", "details": {"issues": issues, "actual": snapshot}}
    return {"status": EvalStatus.pass_, "severity": control.severity, "remediation": "No action required.", "details": {"actual": snapshot}}

def _evaluate_pci_7_1(control, evidence_by_source, expected):
    snapshot = evidence_by_source.get("cloud_iam", {}).get("raw_snapshot", {})
    issues = []
    if not snapshot.get("access_restricted_to_need_to_know", False):
        issues.append("Cardholder data access not restricted to need-to-know")
    if not snapshot.get("api_layer_enforcement", False):
        issues.append("Access restriction only enforced at UI layer — API layer unprotected")
    if issues:
        return {"status": EvalStatus.fail, "severity": control.severity, "remediation": "1. Implement access controls at the API layer, not just the UI.\n2. Apply least-privilege role bindings to cardholder data routes.\n3. Audit and remove unnecessary permissions.", "details": {"issues": issues, "actual": snapshot}}
    return {"status": EvalStatus.pass_, "severity": control.severity, "remediation": "No action required.", "details": {"actual": snapshot}}

def _evaluate_pci_10_1(control, evidence_by_source, expected):
    snapshot = evidence_by_source.get("cicd", {}).get("raw_snapshot", {})
    retention = snapshot.get("log_retention_days", 0)
    min_ret = expected.get("log_retention_days_minimum", 90)
    issues = []
    if not snapshot.get("audit_logging_enabled", False):
        issues.append("Audit logging for card data access is not enabled")
    if retention < min_ret:
        issues.append(f"Log retention {retention} days is below PCI DSS minimum of {min_ret} days")
    if issues:
        return {"status": EvalStatus.fail, "severity": control.severity, "remediation": f"1. Enable audit logging for all cardholder data access events.\n2. Configure retention to at least {min_ret} days.\n3. Protect log integrity to prevent tampering.", "details": {"issues": issues, "actual": snapshot}}
    return {"status": EvalStatus.pass_, "severity": control.severity, "remediation": "No action required.", "details": {"actual": snapshot}}

def _evaluate_cc6_1(control, evidence_by_source, expected):
    snapshot = evidence_by_source.get("cloud_iam", {}).get("raw_snapshot", {})
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
        return {"status": EvalStatus.fail, "severity": control.severity, "remediation": "1. Enable MFA enforcement policy for all privileged roles.\n2. Review and restrict admin role assignments.\n3. Verify all admin users have MFA devices enrolled.", "details": {"issues": issues, "expected": expected, "actual": {"mfa_required_for_privileged_users": actual_mfa, "admin_access_restricted": actual_admin_restricted, "admin_users_without_mfa": admin_without_mfa}}}
    return {"status": EvalStatus.pass_, "severity": control.severity, "remediation": "No action required.", "details": {"expected": expected, "actual": {"mfa_required_for_privileged_users": actual_mfa, "admin_access_restricted": actual_admin_restricted}}}

def _evaluate_cc7_2(control, evidence_by_source, expected):
    snapshot = evidence_by_source.get("cicd", {}).get("raw_snapshot", {})
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
        return {"status": EvalStatus.fail, "severity": control.severity, "remediation": f"1. Enable centralized log shipping.\n2. Configure retention to at least {expected_retention_min} days.", "details": {"issues": issues, "expected": expected, "actual": {"centralized_logging_enabled": actual_enabled, "log_retention_days": actual_retention}}}
    return {"status": EvalStatus.pass_, "severity": control.severity, "remediation": "No action required.", "details": {"expected": expected, "actual": {"centralized_logging_enabled": actual_enabled, "log_retention_days": actual_retention}}}

def _evaluate_cc8_1(control, evidence_by_source, expected):
    github_snapshot = evidence_by_source.get("github", {}).get("raw_snapshot", {})
    cicd_snapshot = evidence_by_source.get("cicd", {}).get("raw_snapshot", {})
    expected_pr_reviews = expected.get("pr_reviews_required", False)
    expected_deploy_approvals = expected.get("production_deploy_approvals_required", False)
    branch_protection = github_snapshot.get("branch_protection", {})
    main_protection = branch_protection.get("main") or branch_protection.get("master", {})
    actual_pr_reviews = github_snapshot.get("pr_reviews_required", False) or main_protection.get("required_approving_review_count", 0) >= 2
    actual_deploy_approvals = github_snapshot.get("production_deploy_approvals_required", False) or cicd_snapshot.get("production_deploy_approvals_required", False) or main_protection.get("enforce_admins", False)
    issues = []
    if expected_pr_reviews and not actual_pr_reviews:
        issues.append("PR reviews not required for production branches")
    if expected_deploy_approvals and not actual_deploy_approvals:
        issues.append("Production deploy approvals not enforced")
    if issues:
        return {"status": EvalStatus.fail, "severity": control.severity, "remediation": "1. Enable branch protection rules.\n2. Require at least 2 PR approvals before merge.\n3. Enforce admin approval for production deployments.", "details": {"issues": issues, "expected": expected, "actual": {"pr_reviews_required": actual_pr_reviews, "production_deploy_approvals_required": actual_deploy_approvals}}}
    return {"status": EvalStatus.pass_, "severity": control.severity, "remediation": "No action required.", "details": {"expected": expected, "actual": {"pr_reviews_required": actual_pr_reviews, "production_deploy_approvals_required": actual_deploy_approvals}}}

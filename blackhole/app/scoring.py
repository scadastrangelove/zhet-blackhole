from __future__ import annotations

from typing import Any, Dict, List

from .models import ReplayProfile, ScannerFinding, ScoreResult


def _candidate_path(finding: ScannerFinding) -> str | None:
    return finding.path or finding.endpoint


def _path_matches(profile: ReplayProfile, path: str | None) -> bool:
    if path is None:
        return True
    matcher = profile.matcher
    if matcher.path and matcher.path == path:
        return True
    if matcher.path_template and matcher.path_template == path:
        return True
    if matcher.path_regex:
        import re
        return re.search(matcher.path_regex, path) is not None
    return matcher.path is None and matcher.path_template is None and matcher.path_regex is None


def score_findings(profiles: List[ReplayProfile], findings: List[ScannerFinding]) -> ScoreResult:
    by_case_id = {profile.case_id: profile for profile in profiles}
    matched_case_ids: List[str] = []
    false_positive_findings: List[Dict[str, Any]] = []
    false_negative_case_ids: List[str] = []
    class_mismatches: List[Dict[str, Any]] = []

    for finding in findings:
        matched_profile = None
        if finding.case_id and finding.case_id in by_case_id:
            matched_profile = by_case_id[finding.case_id]
            if finding.vuln_class != matched_profile.truth.vuln_class:
                class_mismatches.append(
                    {
                        "case_id": finding.case_id,
                        "expected": matched_profile.truth.vuln_class,
                        "observed": finding.vuln_class,
                    }
                )
            else:
                matched_case_ids.append(finding.case_id)
            continue

        for profile in profiles:
            if finding.vuln_class == profile.truth.vuln_class and _path_matches(profile, _candidate_path(finding)):
                matched_profile = profile
                matched_case_ids.append(profile.case_id)
                break

        if matched_profile is None:
            false_positive_findings.append(finding.model_dump(mode="json"))

    expected_case_ids = {profile.case_id for profile in profiles}
    false_negative_case_ids = sorted(expected_case_ids - set(matched_case_ids))
    matched_case_ids = sorted(set(matched_case_ids))

    return ScoreResult(
        matched_case_ids=matched_case_ids,
        false_positive_findings=false_positive_findings,
        false_negative_case_ids=false_negative_case_ids,
        class_mismatches=class_mismatches,
        summary={
            "expected_total": len(expected_case_ids),
            "matched_total": len(matched_case_ids),
            "false_negative_total": len(false_negative_case_ids),
            "false_positive_total": len(false_positive_findings),
            "class_mismatch_total": len(class_mismatches),
            "precision_proxy": round(
                len(matched_case_ids) / max(1, len(matched_case_ids) + len(false_positive_findings)), 4
            ),
            "recall_proxy": round(len(matched_case_ids) / max(1, len(expected_case_ids)), 4),
        },
    )

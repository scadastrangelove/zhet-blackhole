from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field, model_validator


class FieldMatcher(BaseModel):
    exact: Optional[str] = None
    regex: Optional[str] = None
    contains: Optional[str] = None
    one_of: Optional[List[str]] = None
    present: Optional[bool] = None
    absent: Optional[bool] = None
    any_value: bool = False

    @model_validator(mode="after")
    def ensure_sane(self) -> "FieldMatcher":
        if self.present and self.absent:
            raise ValueError("present and absent cannot both be true")
        return self


class JsonMatcher(BaseModel):
    path: str
    exact: Optional[Any] = None
    contains: Optional[str] = None
    regex: Optional[str] = None
    present: Optional[bool] = None


class RequestMatcher(BaseModel):
    method: str = "ANY"
    path: Optional[str] = None
    path_regex: Optional[str] = None
    path_template: Optional[str] = None
    query: Dict[str, FieldMatcher | str] = Field(default_factory=dict)
    headers: Dict[str, FieldMatcher | str] = Field(default_factory=dict)
    cookies: Dict[str, FieldMatcher | str] = Field(default_factory=dict)
    body_contains: Optional[str] = None
    body_regex: Optional[str] = None
    json_fields: List[JsonMatcher] = Field(default_factory=list)


class ResponseSpec(BaseModel):
    status: int = 200
    headers: Dict[str, str] = Field(default_factory=dict)
    body_template: str = ""
    body_json: Optional[Dict[str, Any]] = None
    media_type: Optional[str] = None
    delay_ms: int = 0
    set_client_cookie: bool = True


class TruthSpec(BaseModel):
    vuln_class: str
    positive_evidence: List[str] = Field(default_factory=list)
    guardrails: List[str] = Field(default_factory=list)
    must_not_claim: List[str] = Field(default_factory=list)
    manual_followup: List[str] = Field(default_factory=list)
    confidence_cap: Literal["low", "medium", "high", "critical"] = "medium"
    emulation_grade: str = "replayable"
    automation_grade: str = "signature"
    north_star_section: Optional[str] = None
    delayed_effect: bool = False
    second_order: bool = False
    second_order_sink: Optional[str] = None
    requires_repeat: bool = False
    race_window_ms: Optional[int] = None
    cache_ttl_s: Optional[int] = None


class ScenarioSpec(BaseModel):
    name: str
    required_state: str = "STARTED"
    next_state: Optional[str] = None


class ReplayProfile(BaseModel):
    id: str
    case_id: str
    title: str
    enabled: bool = True
    tags: List[str] = Field(default_factory=list)
    source_name: Optional[str] = None
    source_url: Optional[str] = None
    matcher: RequestMatcher
    response: ResponseSpec
    truth: TruthSpec
    scenario: Optional[ScenarioSpec] = None
    notes: List[str] = Field(default_factory=list)


class ReplayPack(BaseModel):
    name: str
    version: str = "0.1.0"
    profiles: List[ReplayProfile]


class RequestLogEntry(BaseModel):
    request_id: str
    method: str
    path: str
    query: Dict[str, Any]
    headers: Dict[str, str]
    matched_profile_id: Optional[str] = None
    matched_case_id: Optional[str] = None
    status_code: int
    body_excerpt: Optional[str] = None
    scenario_state: Dict[str, str] = Field(default_factory=dict)
    timestamp: str


class ScannerFinding(BaseModel):
    case_id: Optional[str] = None
    vuln_class: str
    path: Optional[str] = None
    endpoint: Optional[str] = None
    evidence: List[str] = Field(default_factory=list)
    confidence: Optional[float] = None
    severity: Optional[str] = None


class ScoreRequest(BaseModel):
    findings: List[ScannerFinding]


class ScoreResult(BaseModel):
    matched_case_ids: List[str]
    false_positive_findings: List[Dict[str, Any]]
    false_negative_case_ids: List[str]
    class_mismatches: List[Dict[str, Any]]
    summary: Dict[str, Any]

from __future__ import annotations

import secrets
import uuid
from collections import deque
from datetime import datetime, timezone
from typing import Deque, List, Optional

from jinja2 import Environment
from starlette.requests import Request
from starlette.responses import PlainTextResponse, Response

from .matcher import match_request
from .models import ReplayPack, ReplayProfile, RequestLogEntry, ScoreRequest
from .pack_loader import load_pack
from .renderer import build_environment, render_profile_response
from .scoring import score_findings
from .state import ScenarioStateStore
from .truth import truth_entries


class BlackholeRuntime:
    def __init__(self, pack: ReplayPack) -> None:
        self.pack = pack
        self.state = ScenarioStateStore()
        self.request_logs: Deque[RequestLogEntry] = deque(maxlen=5000)
        self.env: Environment = build_environment()

    @classmethod
    def from_pack_path(cls, pack_path: str) -> "BlackholeRuntime":
        return cls(load_pack(pack_path))

    @property
    def profiles(self) -> List[ReplayProfile]:
        return self.pack.profiles

    def reset(self) -> None:
        self.state.reset()
        self.request_logs.clear()

    def get_client_id(self, request: Request) -> str:
        if request.headers.get("x-blackhole-client"):
            return request.headers["x-blackhole-client"]
        if request.cookies.get("bh_client_id"):
            return request.cookies["bh_client_id"]
        if request.client and request.client.host:
            return request.client.host
        return f"anon-{secrets.token_hex(8)}"

    def _scenario_allowed(self, client_id: str, profile: ReplayProfile) -> bool:
        if not profile.scenario:
            return True
        current = self.state.get_state(client_id, profile.scenario.name)
        return current == profile.scenario.required_state

    async def resolve(self, request: Request) -> tuple[Optional[ReplayProfile], Response, str]:
        client_id = self.get_client_id(request)
        for profile in self.profiles:
            if not self._scenario_allowed(client_id, profile):
                continue
            if await match_request(request, profile):
                if profile.id == "builtin-store-comment":
                    body = await request.json()
                    comment = body.get("comment", "")
                    comments = self.state.recall(client_id, "comments", []) or []
                    comments.append(comment)
                    self.state.remember(client_id, "comments", comments)
                response = await render_profile_response(
                    request=request,
                    profile=profile,
                    env=self.env,
                    state_snapshot=self.state.snapshot(client_id),
                    memory_snapshot=self.state.memory_snapshot(client_id),
                )
                if profile.scenario and profile.scenario.next_state:
                    self.state.set_state(client_id, profile.scenario.name, profile.scenario.next_state)
                if profile.response.set_client_cookie:
                    response.set_cookie("bh_client_id", client_id, httponly=False)
                await self.log_request(request, response.status_code, profile, client_id)
                return profile, response, client_id

        response = PlainTextResponse("No replay profile matched this request.", status_code=404)
        response.set_cookie("bh_client_id", client_id, httponly=False)
        await self.log_request(request, response.status_code, None, client_id)
        return None, response, client_id

    async def log_request(
        self,
        request: Request,
        status_code: int,
        profile: Optional[ReplayProfile],
        client_id: str,
    ) -> None:
        body = await request.body()
        entry = RequestLogEntry(
            request_id=str(uuid.uuid4()),
            method=request.method,
            path=request.url.path,
            query=dict(request.query_params),
            headers=dict(request.headers),
            matched_profile_id=profile.id if profile else None,
            matched_case_id=profile.case_id if profile else None,
            status_code=status_code,
            body_excerpt=body.decode("utf-8", errors="replace")[:500] if body else None,
            scenario_state=self.state.snapshot(client_id),
            timestamp=datetime.now(timezone.utc).isoformat(),
        )
        self.request_logs.appendleft(entry)

    def admin_status(self) -> dict:
        return {
            "pack": self.pack.name,
            "version": self.pack.version,
            "profiles_total": len(self.profiles),
            "logs_total": len(self.request_logs),
        }

    def profile_by_id(self, profile_id: str):
        for p in self.profiles:
            if p.id == profile_id:
                return p
        return None

    def list_profiles(self) -> list[dict]:
        return [
            {
                "id": p.id,
                "case_id": p.case_id,
                "title": p.title,
                "path": p.matcher.path,
                "path_regex": p.matcher.path_regex,
                "method": p.matcher.method,
                "vuln_class": p.truth.vuln_class,
                "tags": p.tags,
                "enabled": p.enabled,
            }
            for p in self.profiles
        ]

    def list_truth(self) -> list[dict]:
        return truth_entries(self.profiles)

    def score(self, payload: ScoreRequest):
        return score_findings(self.profiles, payload.findings)

    def request_log_dump(self) -> list[dict]:
        return [entry.model_dump(mode="json") for entry in self.request_logs]

from __future__ import annotations

from typing import Dict, List

from .models import ReplayProfile


def truth_entries(profiles: List[ReplayProfile]) -> List[Dict]:
    entries = []
    for profile in profiles:
        entries.append(
            {
                "profile_id": profile.id,
                "case_id": profile.case_id,
                "title": profile.title,
                "matcher": profile.matcher.model_dump(mode="json"),
                "truth": profile.truth.model_dump(mode="json"),
                "tags": profile.tags,
                "source_name": profile.source_name,
                "source_url": profile.source_url,
            }
        )
    return entries

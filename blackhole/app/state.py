from __future__ import annotations

from collections import defaultdict
from typing import Dict, List


class ScenarioStateStore:
    def __init__(self) -> None:
        self._state: Dict[str, Dict[str, str]] = defaultdict(dict)
        self._memory: Dict[str, Dict[str, List[str] | str | int | dict]] = defaultdict(dict)

    def get_state(self, client_id: str, scenario_name: str) -> str:
        return self._state[client_id].get(scenario_name, "STARTED")

    def set_state(self, client_id: str, scenario_name: str, new_state: str) -> None:
        self._state[client_id][scenario_name] = new_state

    def snapshot(self, client_id: str) -> Dict[str, str]:
        return dict(self._state.get(client_id, {}))

    def reset(self) -> None:
        self._state.clear()
        self._memory.clear()

    def remember(self, client_id: str, key: str, value) -> None:
        self._memory[client_id][key] = value

    def recall(self, client_id: str, key: str, default=None):
        return self._memory.get(client_id, {}).get(key, default)

    def memory_snapshot(self, client_id: str) -> Dict:
        return dict(self._memory.get(client_id, {}))

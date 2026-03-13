from typing import Dict, List, Optional


class InMemoryScanRepository:
    def __init__(self):
        self._storage: Dict[str, dict] = {}

    def save(self, scan_data: dict) -> dict:
        self._storage[scan_data["scan_id"]] = scan_data
        return scan_data

    def update(self, scan_id: str, updates: dict) -> Optional[dict]:
        if scan_id not in self._storage:
            return None

        self._storage[scan_id].update(updates)
        return self._storage[scan_id]

    def list_all(self) -> List[dict]:
        return list(self._storage.values())

    def get_by_id(self, scan_id: str) -> Optional[dict]:
        return self._storage.get(scan_id)

    def exists(self, scan_id: str) -> bool:
        return scan_id in self._storage
import os
import tempfile
import requests
import uuid
from datetime import datetime, timezone
from typing import List, Optional

from core.engine import APIScanEngine
from core.models import ScanConfig, ScanTarget
from repositories.in_memory_scan_repository import InMemoryScanRepository


class ScanService:
    def __init__(self, repository: Optional[InMemoryScanRepository] = None):
        self.engine = APIScanEngine(
            ScanConfig(
                timeout=2,
                rate_limit_attempts=2,
                verbose=False,
                enable_bruteforce=True
            )
        )
        self.repository = repository or InMemoryScanRepository()

    def _download_spec(self, spec_url: str) -> str:
        response = requests.get(spec_url, timeout=10)
        response.raise_for_status()

        suffix = ".json"
        if spec_url.endswith(".yaml") or spec_url.endswith(".yml"):
            suffix = ".yaml"

        temp_file = tempfile.NamedTemporaryFile(
            delete=False,
            suffix=suffix,
            mode="w",
            encoding="utf-8"
        )
        temp_file.write(response.text)
        temp_file.close()

        return temp_file.name

    def create_scan_job(self, target: ScanTarget) -> dict:
        scan_id = str(uuid.uuid4())

        scan_job = {
            "scan_id": scan_id,
            "target_url": target.base_url,
            "status": "pending",
            "findings": [],
            "final_score": 0.0,
            "grade": "Pending",
            "category_scores": {},
            "started_at": None,
            "finished_at": None,
            "duration_ms": 0,
            "spec_url": target.spec_url,
            "error_message": None,
            "discovered_endpoints_count": 0
        }

        self.repository.save(scan_job)
        return scan_job

    def execute_scan_job(self, scan_id: str, target: ScanTarget) -> None:
        temp_spec_path = None
        started_dt = datetime.now(timezone.utc)

        self.repository.update(
            scan_id,
            {
                "status": "running",
                "started_at": started_dt.isoformat(),
                "error_message": None
            }
        )

        try:
            if target.spec_url:
                temp_spec_path = self._download_spec(target.spec_url)
                target.spec_path = temp_spec_path

            result = self.engine.run(target)

            self.repository.update(
                scan_id,
                {
                    "status": "completed",
                    "findings": [f.to_dict() for f in result.findings],
                    "final_score": result.final_score,
                    "grade": result.grade,
                    "category_scores": result.category_scores,
                    "started_at": result.started_at,
                    "finished_at": result.finished_at,
                    "duration_ms": result.duration_ms,
                    "spec_url": result.spec_url,
                    "error_message": None,
                    "discovered_endpoints_count": result.discovered_endpoints_count
                }
            )

        except Exception as e:
            finished_dt = datetime.now(timezone.utc)
            duration_ms = int((finished_dt - started_dt).total_seconds() * 1000)

            self.repository.update(
                scan_id,
                {
                    "status": "failed",
                    "finished_at": finished_dt.isoformat(),
                    "duration_ms": duration_ms,
                    "error_message": str(e)
                }
            )

        finally:
            if temp_spec_path and os.path.exists(temp_spec_path):
                os.remove(temp_spec_path)

    def list_scans(self) -> List[dict]:
        return self.repository.list_all()

    def get_scan_by_id(self, scan_id: str) -> Optional[dict]:
        return self.repository.get_by_id(scan_id)

    def get_scan_status(self, scan_id: str) -> Optional[dict]:
        scan = self.repository.get_by_id(scan_id)
        if not scan:
            return None

        return {
            "scan_id": scan["scan_id"],
            "status": scan["status"],
            "started_at": scan["started_at"],
            "finished_at": scan["finished_at"],
            "duration_ms": scan["duration_ms"],
            "error_message": scan.get("error_message"),
            "discovered_endpoints_count": scan.get("discovered_endpoints_count", 0)
        }
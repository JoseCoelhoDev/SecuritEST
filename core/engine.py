import uuid
from datetime import datetime, timezone
from typing import Callable, List, Optional

from core.discovery import OpenAPIDiscovery
from core.endpoint_discovery import BruteForceEndpointDiscovery
from core.http_client import HTTPClient
from core.models import Finding, ScanConfig, ScanResult, ScanTarget
from core.scorer import RiskScorer

from checks.auth_check import BrokenAuthCheck
from checks.bola_check import BOLACheck
from checks.function_auth_check import FunctionLevelAuthCheck
from checks.misconfig_check import MisconfigurationCheck
from checks.rate_limit_check import RateLimitCheck


ProgressCallback = Optional[Callable[[int, int, str], None]]


class APIScanEngine:
    def __init__(self, config: ScanConfig):
        self.config = config

    def _build_checks(self, http_client: HTTPClient):
        return [
            BrokenAuthCheck(http_client),
            BOLACheck(http_client),
            FunctionLevelAuthCheck(http_client),
            MisconfigurationCheck(http_client),
            RateLimitCheck(http_client, attempts=self.config.rate_limit_attempts),
        ]

    def _discover_endpoints(self, target: ScanTarget, http_client: HTTPClient):
        if target.spec_path:
            discovery = OpenAPIDiscovery(target.spec_path, target.base_url)
            return discovery.discover_endpoints()

        if self.config.enable_bruteforce:
            discovery = BruteForceEndpointDiscovery(target.base_url, http_client)
            return discovery.discover()

        return []

    def run(self, target: ScanTarget, progress_callback: ProgressCallback = None) -> ScanResult:
        started_dt = datetime.now(timezone.utc)

        http_client = HTTPClient(timeout=self.config.timeout, verbose=self.config.verbose)
        endpoints = self._discover_endpoints(target, http_client)

        checks = self._build_checks(http_client)
        findings: List[Finding] = []

        total = len(endpoints)

        for index, endpoint in enumerate(endpoints, start=1):
            if progress_callback:
                progress_callback(index, total, f"{endpoint.method} {endpoint.path}")

            for check in checks:
                try:
                    results = check.run(endpoint, target.identities())
                    if results:
                        findings.extend(results)
                except Exception:
                    continue

        score_data = RiskScorer.calculate(findings)

        finished_dt = datetime.now(timezone.utc)
        duration_ms = int((finished_dt - started_dt).total_seconds() * 1000)

        return ScanResult(
            scan_id=str(uuid.uuid4()),
            target_url=target.base_url,
            status="completed",
            findings=findings,
            final_score=score_data["final_score"],
            grade=score_data["grade"],
            category_scores=score_data["category_scores"],
            started_at=started_dt.isoformat(),
            finished_at=finished_dt.isoformat(),
            duration_ms=duration_ms,
            spec_url=target.spec_url,
            discovered_endpoints_count=len(endpoints)
        )
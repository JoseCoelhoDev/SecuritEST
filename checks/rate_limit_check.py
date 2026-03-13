from typing import List, Dict
from core.models import Endpoint, Finding
from core.http_client import HTTPClient


class RateLimitCheck:
    def __init__(self, http_client: HTTPClient, attempts: int = 10):
        self.http_client = http_client
        self.attempts = attempts

    def run(self, endpoint: Endpoint, identities: Dict) -> List[Finding]:
        findings = []

        statuses = []

        for _ in range(self.attempts):
            response = self.http_client.send_request(
                method=endpoint.method,
                url=endpoint.full_url
            )
            if response is not None:
                statuses.append(response.status_code)

        if len(statuses) == self.attempts and all(code == 200 for code in statuses):
            findings.append(
                Finding(
                    id="RATE-001",
                    name="No visible rate limiting detected",
                    owasp="API4:2023",
                    endpoint=f"{endpoint.method} {endpoint.path}",
                    severity=6.0,
                    confidence=0.75,
                    weight=1.00,
                    evidence=f"{self.attempts} pedidos consecutivos devolveram HTTP 200 sem throttling visível.",
                    recommendation="Aplicar rate limiting, quotas e proteção contra abuso."
                )
            )

        return findings
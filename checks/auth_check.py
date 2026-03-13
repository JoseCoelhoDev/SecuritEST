from typing import List, Dict
from core.models import Endpoint, Finding
from core.http_client import HTTPClient


class BrokenAuthCheck:
    def __init__(self, http_client: HTTPClient):
        self.http_client = http_client

    def run(self, endpoint: Endpoint, identities: Dict) -> List[Finding]:
        findings = []

        if not endpoint.requires_auth:
            return findings

        # Sem token
        response_no_auth = self.http_client.send_request(
            method=endpoint.method,
            url=endpoint.full_url
        )

        if response_no_auth is not None and response_no_auth.status_code == 200:
            findings.append(
                Finding(
                    id="AUTH-001",
                    name="Protected endpoint accessible without authentication",
                    owasp="API2:2023",
                    endpoint=f"{endpoint.method} {endpoint.path}",
                    severity=8.5,
                    confidence=0.95,
                    weight=1.25,
                    evidence=f"Endpoint protegido respondeu HTTP 200 sem token.",
                    recommendation="Exigir autenticação em todos os endpoints protegidos."
                )
            )

        # Token inválido
        invalid_headers = {"Authorization": "Bearer invalid-token-for-testing"}
        response_invalid = self.http_client.send_request(
            method=endpoint.method,
            url=endpoint.full_url,
            headers=invalid_headers
        )

        if response_invalid is not None and response_invalid.status_code == 200:
            findings.append(
                Finding(
                    id="AUTH-002",
                    name="Protected endpoint accepts invalid token",
                    owasp="API2:2023",
                    endpoint=f"{endpoint.method} {endpoint.path}",
                    severity=9.0,
                    confidence=0.90,
                    weight=1.25,
                    evidence="Endpoint protegido respondeu HTTP 200 com token inválido.",
                    recommendation="Validar assinatura, expiração e integridade dos tokens."
                )
            )

        return findings
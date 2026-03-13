from typing import List, Dict
from core.models import Endpoint, Finding
from core.http_client import HTTPClient


class FunctionLevelAuthCheck:
    def __init__(self, http_client: HTTPClient):
        self.http_client = http_client

    def _looks_sensitive(self, endpoint: Endpoint) -> bool:
        sensitive_keywords = ["admin", "manage", "delete", "create", "update"]
        text = (endpoint.path + " " + " ".join(endpoint.tags)).lower()

        if endpoint.method in ["POST", "PUT", "PATCH", "DELETE"]:
            return True

        return any(keyword in text for keyword in sensitive_keywords)

    def run(self, endpoint: Endpoint, identities: Dict) -> List[Finding]:
        findings = []

        if not self._looks_sensitive(endpoint):
            return findings

        user_token = identities.get("user_token")
        if not user_token:
            return findings

        headers = {"Authorization": f"Bearer {user_token}"}

        response = self.http_client.send_request(
            method=endpoint.method,
            url=endpoint.full_url,
            headers=headers
        )

        if response is not None and response.status_code == 200:
            findings.append(
                Finding(
                    id="BFLA-001",
                    name="Possible Broken Function Level Authorization",
                    owasp="API5:2023",
                    endpoint=f"{endpoint.method} {endpoint.path}",
                    severity=8.8,
                    confidence=0.80,
                    weight=1.20,
                    evidence="Utilizador normal conseguiu aceder a função potencialmente privilegiada com HTTP 200.",
                    recommendation="Aplicar RBAC/ABAC consistente por função e operação."
                )
            )

        return findings
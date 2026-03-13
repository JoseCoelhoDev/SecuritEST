from typing import List, Dict
from core.models import Endpoint, Finding
from core.http_client import HTTPClient


class MisconfigurationCheck:
    def __init__(self, http_client: HTTPClient):
        self.http_client = http_client

    def run(self, endpoint: Endpoint, identities: Dict) -> List[Finding]:
        findings = []

        response = self.http_client.send_request(
            method="GET",
            url=endpoint.full_url
        )

        if response is None:
            return findings

        cors = response.headers.get("Access-Control-Allow-Origin")
        server = response.headers.get("Server", "")
        powered_by = response.headers.get("X-Powered-By", "")

        if cors == "*":
            findings.append(
                Finding(
                    id="MISCONF-001",
                    name="Overly permissive CORS",
                    owasp="API8:2023",
                    endpoint=f"{endpoint.method} {endpoint.path}",
                    severity=5.5,
                    confidence=0.90,
                    weight=0.90,
                    evidence="Header Access-Control-Allow-Origin configurado como '*'.",
                    recommendation="Restringir CORS a origens confiáveis."
                )
            )

        if server or powered_by:
            findings.append(
                Finding(
                    id="MISCONF-002",
                    name="Technology disclosure in headers",
                    owasp="API8:2023",
                    endpoint=f"{endpoint.method} {endpoint.path}",
                    severity=4.0,
                    confidence=0.85,
                    weight=0.90,
                    evidence=f"Headers revelam tecnologia: Server='{server}' X-Powered-By='{powered_by}'.",
                    recommendation="Reduzir fingerprinting removendo headers desnecessários."
                )
            )

        return findings
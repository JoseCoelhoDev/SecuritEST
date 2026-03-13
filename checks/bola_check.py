import re
from typing import List, Dict
from core.models import Endpoint, Finding
from core.http_client import HTTPClient


class BOLACheck:
    def __init__(self, http_client: HTTPClient):
        self.http_client = http_client

    def _looks_like_object_endpoint(self, path: str) -> bool:
        return bool(re.search(r"\{[^}]+\}", path))

    def run(self, endpoint: Endpoint, identities: Dict) -> List[Finding]:
        findings = []

        if not self._looks_like_object_endpoint(endpoint.path):
            return findings

        user_token = identities.get("user_token")
        foreign_id = identities.get("foreign_object_id")
        own_id = identities.get("own_object_id")

        if not user_token or own_id is None or foreign_id is None:
            return findings

        own_url = endpoint.full_url
        foreign_url = endpoint.full_url

        placeholder_match = re.search(r"\{[^}]+\}", endpoint.path)
        if not placeholder_match:
            return findings

        placeholder = placeholder_match.group(0)
        own_url = own_url.replace(placeholder, str(own_id))
        foreign_url = foreign_url.replace(placeholder, str(foreign_id))

        headers = {"Authorization": f"Bearer {user_token}"}

        own_response = self.http_client.send_request(
            method=endpoint.method,
            url=own_url,
            headers=headers
        )

        foreign_response = self.http_client.send_request(
            method=endpoint.method,
            url=foreign_url,
            headers=headers
        )

        if (
            own_response is not None
            and foreign_response is not None
            and own_response.status_code == 200
            and foreign_response.status_code == 200
        ):
            findings.append(
                Finding(
                    id="BOLA-001",
                    name="Possible Broken Object Level Authorization",
                    owasp="API1:2023",
                    endpoint=f"{endpoint.method} {endpoint.path}",
                    severity=9.5,
                    confidence=0.85,
                    weight=1.30,
                    evidence=(
                        f"Utilizador autenticado acedeu ao próprio objeto e também a objeto alheio "
                        f"({own_id} -> {foreign_id}) com HTTP 200."
                    ),
                    recommendation="Validar ownership/autorização ao nível de cada objeto."
                )
            )

        return findings
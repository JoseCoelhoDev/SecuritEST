from typing import List

from core.http_client import HTTPClient
from core.models import Endpoint


class BruteForceEndpointDiscovery:
    COMMON_PATHS = [
        "/",
        "/health",
        "/metrics",
        "/status",
        "/version",
        "/docs",
        "/swagger",
        "/swagger.json",
        "/openapi.json",
        "/api",
        "/api/v1",
        "/api/v2",
        "/users",
        "/users/1",
        "/admin",
        "/admin/reports",
        "/admin/users",
        "/internal",
        "/internal/debug",
        "/debug",
        "/config",
        "/test",
        "/login",
        "/auth",
        "/auth/login",
        "/files",
        "/files/1",
        "/orders",
        "/orders/1",
        "/products",
        "/products/1"
    ]

    METHODS = ["GET"]

    def __init__(self, base_url: str, http_client: HTTPClient):
        self.base_url = base_url.rstrip("/")
        self.http_client = http_client

    def discover(self) -> List[Endpoint]:
        discovered = []

        for path in self.COMMON_PATHS:
            full_url = f"{self.base_url}{path}"

            for method in self.METHODS:
                response = self.http_client.send_request(method=method, url=full_url)

                if response is None:
                    continue

                if response.status_code in [200, 201, 202, 401, 403]:
                    discovered.append(
                        Endpoint(
                            path=path,
                            method=method,
                            full_url=full_url,
                            parameters=[],
                            request_body=None,
                            tags=["bruteforce-discovered"],
                            requires_auth=(response.status_code in [401, 403])
                        )
                    )

        unique = {}
        for endpoint in discovered:
            key = f"{endpoint.method}:{endpoint.path}"
            unique[key] = endpoint

        return list(unique.values())
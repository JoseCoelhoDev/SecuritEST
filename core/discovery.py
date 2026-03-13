import json
import yaml
from typing import List, Dict, Any
from core.models import Endpoint


class OpenAPIDiscovery:
    def __init__(self, spec_path: str, base_url_override: str = None):
        self.spec_path = spec_path
        self.base_url_override = base_url_override
        self.spec = self._load_spec()

    def _load_spec(self) -> Dict[str, Any]:
        with open(self.spec_path, "r", encoding="utf-8") as f:
            content = f.read()

        try:
            return json.loads(content)
        except json.JSONDecodeError:
            return yaml.safe_load(content)

    def _extract_base_url(self) -> str:
        if self.base_url_override:
            return self.base_url_override.rstrip("/")

        servers = self.spec.get("servers", [])
        if servers:
            return servers[0]["url"].rstrip("/")

        host = self.spec.get("host")
        base_path = self.spec.get("basePath", "")
        schemes = self.spec.get("schemes", ["https"])

        if host:
            return f"{schemes[0]}://{host}{base_path}".rstrip("/")

        raise ValueError("Não foi possível determinar a base URL.")

    def discover_endpoints(self) -> List[Endpoint]:
        base_url = self._extract_base_url()
        endpoints = []

        paths = self.spec.get("paths", {})

        for path, path_item in paths.items():
            common_parameters = path_item.get("parameters", [])

            for method in ["get", "post", "put", "delete", "patch", "options", "head"]:
                if method not in path_item:
                    continue

                operation = path_item[method]
                params = common_parameters + operation.get("parameters", [])
                request_body = operation.get("requestBody")
                tags = operation.get("tags", [])
                security = operation.get("security", self.spec.get("security", []))
                requires_auth = len(security) > 0

                endpoints.append(
                    Endpoint(
                        path=path,
                        method=method.upper(),
                        full_url=f"{base_url}{path}",
                        parameters=params,
                        request_body=request_body,
                        tags=tags,
                        requires_auth=requires_auth
                    )
                )

        return endpoints
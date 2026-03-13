import requests
from typing import Dict, Optional


class HTTPClient:
    def __init__(self, timeout: int = 2, verbose: bool = False):
        self.timeout = timeout
        self.verbose = verbose

    def send_request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict] = None,
        params: Optional[Dict] = None,
        json_data: Optional[Dict] = None
    ):
        try:
            if self.verbose:
                print(f"[HTTP] {method} {url}")

            response = requests.request(
                method=method,
                url=url,
                headers=headers or {},
                params=params,
                json=json_data,
                timeout=self.timeout
            )
            return response
        except requests.RequestException as e:
            if self.verbose:
                print(f"[HTTP ERROR] {method} {url} -> {e}")
            return None
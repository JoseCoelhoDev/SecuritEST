from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any


@dataclass
class Endpoint:
    path: str
    method: str
    full_url: str
    parameters: List[Dict[str, Any]] = field(default_factory=list)
    request_body: Optional[Dict[str, Any]] = None
    tags: List[str] = field(default_factory=list)
    requires_auth: bool = False


@dataclass
class Finding:
    id: str
    name: str
    owasp: str
    endpoint: str
    severity: float
    confidence: float
    weight: float
    evidence: str
    recommendation: str

    def to_dict(self):
        return asdict(self)


@dataclass
class ScanConfig:
    timeout: int = 2
    rate_limit_attempts: int = 2
    verbose: bool = False
    enable_bruteforce: bool = True


@dataclass
class ScanTarget:
    base_url: str
    spec_path: str = ""
    spec_url: Optional[str] = None
    user_token: str = "user-test-token"
    admin_token: str = "admin-test-token"
    own_object_id: int = 1
    foreign_object_id: int = 2

    def identities(self) -> Dict[str, Any]:
        return {
            "user_token": self.user_token,
            "admin_token": self.admin_token,
            "own_object_id": self.own_object_id,
            "foreign_object_id": self.foreign_object_id,
        }


@dataclass
class ScanResult:
    scan_id: str
    target_url: str
    status: str
    findings: List[Finding]
    final_score: float
    grade: str
    category_scores: Dict[str, float]
    started_at: Optional[str]
    finished_at: Optional[str]
    duration_ms: int
    spec_url: Optional[str] = None
    error_message: Optional[str] = None
    discovered_endpoints_count: int = 0

    def to_dict(self):
        return {
            "scan_id": self.scan_id,
            "target_url": self.target_url,
            "status": self.status,
            "findings": [f.to_dict() for f in self.findings],
            "final_score": self.final_score,
            "grade": self.grade,
            "category_scores": self.category_scores,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_ms": self.duration_ms,
            "spec_url": self.spec_url,
            "error_message": self.error_message,
            "discovered_endpoints_count": self.discovered_endpoints_count,
        }
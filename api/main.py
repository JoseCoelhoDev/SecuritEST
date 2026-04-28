from typing import Optional

from fastapi import BackgroundTasks, FastAPI, HTTPException
from pydantic import BaseModel, Field

from core.models import ScanTarget
from repositories.cosmos_scan_repository import CosmosScanRepository
from repositories.blob_report_repository import BlobReportRepository

from services.scan_service import ScanService

from dotenv import load_dotenv
load_dotenv()


app = FastAPI(
    title="API Security Scanner Backend",
    version="1.3.0",
    description="Backend para correr scans assíncronos com OpenAPI ou brute-force básico"
)

repository = CosmosScanRepository()
blob_repository = BlobReportRepository()
scan_service = ScanService(
    repository=repository,
    blob_repository=blob_repository
)


class ScanRequest(BaseModel):
    base_url: str = Field(..., example="http://localhost:8000")
    spec_url: Optional[str] = Field(default=None, example="http://localhost:8000/openapi.json")
    user_token: str = Field(default="user-test-token")
    admin_token: str = Field(default="admin-test-token")
    own_object_id: int = Field(default=1)
    foreign_object_id: int = Field(default=2)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/scans", status_code=202)
def create_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    target = ScanTarget(
        base_url=request.base_url,
        spec_path="",
        spec_url=request.spec_url,
        user_token=request.user_token,
        admin_token=request.admin_token,
        own_object_id=request.own_object_id,
        foreign_object_id=request.foreign_object_id
    )

    scan_job = scan_service.create_scan_job(target)

    background_tasks.add_task(
        scan_service.execute_scan_job,
        scan_job["scan_id"],
        target
    )

    return {
        "message": "Scan job created",
        "scan_id": scan_job["scan_id"],
        "status": scan_job["status"],
        "mode": "openapi" if request.spec_url else "bruteforce"
    }


@app.get("/scans")
def list_scans():
    items = scan_service.list_scans()
    return {
        "count": len(items),
        "items": items
    }


@app.get("/scans/{scan_id}")
def get_scan(scan_id: str):
    scan = scan_service.get_scan_by_id(scan_id)

    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    return scan


@app.get("/scans/{scan_id}/status")
def get_scan_status(scan_id: str):
    status = scan_service.get_scan_status(scan_id)

    if not status:
        raise HTTPException(status_code=404, detail="Scan not found")

    return status
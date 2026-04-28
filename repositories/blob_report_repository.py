"""
BlobReportRepository
--------------------
Guarda relatórios JSON completos e logs no Azure Blob Storage.
Chamado pelo ScanService após cada scan concluído (ou falhado).

Variáveis de ambiente necessárias:
    BLOB_CONNECTION_STRING = DefaultEndpointsProtocol=https;AccountName=...
    BLOB_CONTAINER         = scan-reports    (default)

Estrutura dos blobs criados:
    scan-reports/
        {scan_id}/report.json        ← relatório completo (findings, score, grade…)
        {scan_id}/scan.log           ← log de execução (opcional)
"""

import os
import json
import logging
from datetime import datetime, timezone
from typing import Optional

from azure.storage.blob import BlobServiceClient, ContentSettings


class BlobReportRepository:
    def __init__(self):
        conn_str = os.environ["BLOB_CONNECTION_STRING"]
        self._container_name = os.environ.get("BLOB_CONTAINER", "scan-reports")

        self._service = BlobServiceClient.from_connection_string(conn_str)

        # Cria o container automaticamente se não existir
        container = self._service.get_container_client(self._container_name)
        if not container.exists():
            container.create_container()
            logging.info(f"Blob container '{self._container_name}' criado")

    # ------------------------------------------------------------------
    # Guarda o relatório completo do scan em JSON
    # Recebe exactamente o dict que o ScanService guarda no CosmosDB
    # ------------------------------------------------------------------
    def save_report(self, scan_id: str, scan_data: dict) -> str:
        """
        Guarda scan_data como JSON e devolve a URL do blob.
        """
        blob_name = f"{scan_id}/report.json"

        payload = {
            **scan_data,
            "exported_at": datetime.now(timezone.utc).isoformat()
        }
        content = json.dumps(payload, indent=2, ensure_ascii=False).encode("utf-8")

        blob_client = self._service.get_blob_client(
            container=self._container_name,
            blob=blob_name
        )
        blob_client.upload_blob(
            content,
            overwrite=True,
            content_settings=ContentSettings(content_type="application/json")
        )
        logging.info(f"Relatório guardado: {blob_client.url}")
        return blob_client.url

    # ------------------------------------------------------------------
    # Guarda um log de texto simples (útil para debug/auditoria)
    # ------------------------------------------------------------------
    def save_log(self, scan_id: str, log_text: str) -> str:
        blob_name = f"{scan_id}/scan.log"
        content = log_text.encode("utf-8")

        blob_client = self._service.get_blob_client(
            container=self._container_name,
            blob=blob_name
        )
        blob_client.upload_blob(
            content,
            overwrite=True,
            content_settings=ContentSettings(content_type="text/plain")
        )
        logging.info(f"Log guardado: {blob_client.url}")
        return blob_client.url

    # ------------------------------------------------------------------
    # Lê o relatório de um scan
    # ------------------------------------------------------------------
    def get_report(self, scan_id: str) -> Optional[dict]:
        blob_client = self._service.get_blob_client(
            container=self._container_name,
            blob=f"{scan_id}/report.json"
        )
        try:
            stream = blob_client.download_blob()
            return json.loads(stream.readall().decode("utf-8"))
        except Exception as e:
            logging.warning(f"Relatório não encontrado para {scan_id}: {e}")
            return None
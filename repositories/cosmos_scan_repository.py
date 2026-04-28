"""
CosmosScanRepository
--------------------
Substitui o InMemoryScanRepository mantendo exactamente a mesma interface:
    .save(scan_data)         → dict
    .update(scan_id, updates) → dict | None
    .get_by_id(scan_id)      → dict | None
    .list_all()              → list[dict]
    .exists(scan_id)         → bool
 
Variáveis de ambiente necessárias (Azure Function App → Configuration):
    COSMOS_ENDPOINT    = https://securitest-cosmos.documents.azure.com:443/
    COSMOS_KEY         = <chave primária>
    COSMOS_DATABASE    = securitest          (default)
    COSMOS_CONTAINER   = scans               (default)
"""
 
import os
import logging
from typing import Dict, List, Optional
 
from azure.cosmos import CosmosClient, PartitionKey, exceptions
 
 
class CosmosScanRepository:
    def __init__(self):
        endpoint = os.environ["COSMOS_ENDPOINT"]
        key = os.environ["COSMOS_KEY"]
        db_name = os.environ.get("COSMOS_DATABASE", "securitest")
        container_name = os.environ.get("COSMOS_CONTAINER", "scans")
 
        client = CosmosClient(endpoint, credential=key)
        database = client.create_database_if_not_exists(id=db_name)
        self._container = database.create_container_if_not_exists(
            id=container_name,
            partition_key=PartitionKey(path="/scan_id"),
            offer_throughput=400  # 400 RU/s → tier gratuito
        )
        logging.info(f"CosmosDB ligado: {db_name}/{container_name}")
 
    # ------------------------------------------------------------------
    # Igual ao InMemory: recebe o dict completo do scan_job e guarda
    # ------------------------------------------------------------------
    def save(self, scan_data: dict) -> dict:
        document = {
            "id": scan_data["scan_id"],  # campo obrigatório do Cosmos
            **scan_data
        }
        self._container.create_item(body=document)
        logging.info(f"Scan guardado no CosmosDB: {scan_data['scan_id']}")
        return scan_data
 
    # ------------------------------------------------------------------
    # Aplica só os campos alterados (igual ao InMemory .update())
    # ------------------------------------------------------------------
    def update(self, scan_id: str, updates: dict) -> Optional[dict]:
        try:
            existing = self._container.read_item(
                item=scan_id, partition_key=scan_id
            )
            existing.update(updates)
            self._container.upsert_item(body=existing)
            logging.info(f"Scan atualizado no CosmosDB: {scan_id}")
            # Devolve sem o campo interno "id" do Cosmos para manter
            # a mesma forma que o InMemory devolvia
            return {k: v for k, v in existing.items() if k != "id"}
        except exceptions.CosmosResourceNotFoundError:
            logging.warning(f"Scan não encontrado para update: {scan_id}")
            return None
 
    # ------------------------------------------------------------------
    # Leitura por ID
    # ------------------------------------------------------------------
    def get_by_id(self, scan_id: str) -> Optional[dict]:
        try:
            item = self._container.read_item(
                item=scan_id, partition_key=scan_id
            )
            return {k: v for k, v in item.items() if k != "id"}
        except exceptions.CosmosResourceNotFoundError:
            return None
 
    # ------------------------------------------------------------------
    # Lista todos (os 100 mais recentes por finished_at)
    # ------------------------------------------------------------------
    def list_all(self) -> List[dict]:
        query = """
            SELECT * FROM c
            ORDER BY c.started_at DESC
            OFFSET 0 LIMIT 100
        """
        items = list(self._container.query_items(
            query=query,
            enable_cross_partition_query=True
        ))
        return [{k: v for k, v in i.items() if k != "id"} for i in items]
 
    # ------------------------------------------------------------------
    # Verifica existência (evita leitura completa do documento)
    # ------------------------------------------------------------------
    def exists(self, scan_id: str) -> bool:
        query = "SELECT c.scan_id FROM c WHERE c.scan_id = @scan_id"
        params = [{"name": "@scan_id", "value": scan_id}]
        items = list(self._container.query_items(
            query=query,
            parameters=params,
            partition_key=scan_id
        ))
        return len(items) > 0
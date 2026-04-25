from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Optional

from api.schemas import EnrichedAuditReport


@dataclass
class ScanRecord:
    scan_id: str
    status: str
    findings_total: int = 0
    elapsed_ms: int = 0
    report: Optional[EnrichedAuditReport] = None
    error: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.utcnow)


class ScanStore:
    def __init__(self) -> None:
        self._store: Dict[str, ScanRecord] = {}
        self._lock = threading.Lock()

    def create(self, scan_id: str) -> ScanRecord:
        with self._lock:
            record = ScanRecord(scan_id=scan_id, status="running")
            self._store[scan_id] = record
            return record

    def update(self, scan_id: str, **kwargs) -> None:
        with self._lock:
            record = self._store.get(scan_id)
            if not record:
                return

            for key, value in kwargs.items():
                if hasattr(record, key):
                    setattr(record, key, value)

    def get(self, scan_id: str) -> Optional[ScanRecord]:
        with self._lock:
            return self._store.get(scan_id)

    def exists(self, scan_id: str) -> bool:
        with self._lock:
            return scan_id in self._store


scan_store = ScanStore()
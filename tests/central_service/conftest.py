"""Prevent TestClient(app) from connecting to PostgreSQL.

Patches AuditDB.connect and PartitionManager.connect at import time so
the lifespan context manager becomes a no-op before any test module
imports api_server.
"""

import sys
from pathlib import Path

# Ensure central-service/ and shared/ are on sys.path (mirror root conftest.py)
PROJECT_ROOT = Path(__file__).parent.parent.resolve()
sys.path.insert(0, str(PROJECT_ROOT / "central-service"))
sys.path.insert(0, str(PROJECT_ROOT / "shared"))

# Patch AuditDB.connect before any api_server import
from audit_db import AuditDB


async def _noop_connect(self, *args, **kwargs):
    pass


AuditDB.connect = _noop_connect

# Patch PartitionManager.connect before any api_server import
from partition_manager import PartitionManager

PartitionManager.connect = _noop_connect
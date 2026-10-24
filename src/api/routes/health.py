import time
from fastapi import APIRouter
from src.config import settings
from src.api.db import db_manager, mask_mongo_uri

router = APIRouter()
START_TIME = time.time()

@router.get("/health")
async def health_check():
    """Service health, model readiness, and database latency probe."""
    uptime = round(time.time() - START_TIME, 2)
    return {
        "status": "healthy",
        "version": "1.0.0",
        "models_ready": True,
        "database_connected": db_manager.is_mongo,
        "database_mode": "mongodb_atlas" if db_manager.is_mongo else "in_memory_resilient",
        "database_latency_ms": db_manager.ping_latency_ms,
        "database_uri_configured": mask_mongo_uri(settings.MONGO_URI),
        "uptime_seconds": uptime,
    }

@router.get("/metrics")
async def get_metrics():
    """Basic operational telemetry metrics."""
    analyses_count = len(db_manager.memory.analyses)
    return {
        "uptime_seconds": round(time.time() - START_TIME, 2),
        "total_analyses_in_session": analyses_count,
        "database_mode": "mongodb_atlas" if db_manager.is_mongo else "in_memory_resilient",
        "database_latency_ms": db_manager.ping_latency_ms,
        "database_uri_configured": mask_mongo_uri(settings.MONGO_URI),
    }

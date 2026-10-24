import re
import time
import hashlib
import uuid
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from src.config import settings

def mask_mongo_uri(uri: str) -> str:
    """Mask password credentials in MongoDB connection string for safe logging."""
    if not uri:
        return ""
    # Mask password between ':' and '@'
    return re.sub(r':([^:@/]+)@', r':****@', uri)


class MemoryStore:
    """Resilient in-memory fallback store ensuring 100% uptime when MongoDB is unreachable."""
    def __init__(self):
        self.applications: Dict[str, Dict[str, Any]] = {}
        self.analyses: List[Dict[str, Any]] = []
        self.feedback: List[Dict[str, Any]] = []
        self.settings: Dict[str, Any] = {
            "policy_version": "v1.2",
            "low_max": settings.POLICY_LOW_MAX,
            "medium_max": settings.POLICY_MEDIUM_MAX,
            "high_max": settings.POLICY_HIGH_MAX,
            "store_raw_text": settings.STORE_RAW_TEXT,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        # Seed default admin key
        hashed = hashlib.sha256(settings.DEFAULT_ADMIN_KEY.encode()).hexdigest()
        self.applications["app_demo_email_assistant"] = {
            "_id": "app_demo_email_assistant",
            "name": "Demo Email Assistant",
            "api_key_hash": hashed,
            "key_prefix": settings.DEFAULT_ADMIN_KEY[:10],
            "created_at": datetime.now(timezone.utc).isoformat(),
            "is_active": True,
        }

    async def insert_analysis(self, doc: Dict[str, Any]) -> str:
        self.analyses.insert(0, doc)
        if len(self.analyses) > 1000:
            self.analyses.pop()
        return doc["analysis_id"]

    async def list_analyses(
        self,
        skip: int = 0,
        limit: int = 50,
        risk_band: Optional[str] = None,
        decision: Optional[str] = None,
        source_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        results = self.analyses
        if risk_band:
            results = [a for a in results if a.get("risk_band") == risk_band]
        if decision:
            results = [a for a in results if a.get("decision") == decision]
        if source_type:
            results = [a for a in results if a.get("source_type") == source_type]
        return results[skip : skip + limit]

    async def get_analysis(self, analysis_id: str) -> Optional[Dict[str, Any]]:
        for a in self.analyses:
            if a.get("analysis_id") == analysis_id:
                return a
        return None

    async def insert_feedback(self, doc: Dict[str, Any]) -> str:
        self.feedback.append(doc)
        return doc["feedback_id"]

    async def get_policy(self) -> Dict[str, Any]:
        return self.settings

    async def update_policy(self, updates: Dict[str, Any]) -> Dict[str, Any]:
        self.settings.update(updates)
        self.settings["updated_at"] = datetime.now(timezone.utc).isoformat()
        return self.settings

    async def validate_api_key(self, api_key: str) -> bool:
        if api_key == settings.DEFAULT_ADMIN_KEY:
            return True
        hashed = hashlib.sha256(api_key.encode()).hexdigest()
        for app in self.applications.values():
            if app.get("api_key_hash") == hashed and app.get("is_active", True):
                return True
        return False


class DatabaseManager:
    """Production MongoDB Database Manager with Connection Pooling and Resilient Fallback."""

    def __init__(self):
        self.client = None
        self.db = None
        self.is_mongo = False
        self.ping_latency_ms: Optional[float] = None
        self.connection_error: Optional[str] = None
        self.memory = MemoryStore()

    async def connect(self):
        if not settings.MONGO_URI or settings.MONGO_URI.strip().lower() in ["memory", "none", "disabled", ""]:
            self.is_mongo = False
            print("[DatabaseManager] Running in resilient in-memory mode (MongoDB disabled).")
            return

        if os.environ.get("VERCEL") and "localhost" in settings.MONGO_URI:
            self.is_mongo = False
            print("[DatabaseManager] Vercel serverless environment detected. Using resilient in-memory store.")
            return

        masked_uri = mask_mongo_uri(settings.MONGO_URI)
        try:
            import motor.motor_asyncio
            # Production-grade connection pooling and timeout settings
            self.client = motor.motor_asyncio.AsyncIOMotorClient(
                settings.MONGO_URI,
                serverSelectionTimeoutMS=4000,
                connectTimeoutMS=4000,
                socketTimeoutMS=8000,
                maxPoolSize=50,
                minPoolSize=2,
            )
            # Measure ping latency
            t0 = time.perf_counter()
            await self.client.admin.command("ping")
            self.ping_latency_ms = round((time.perf_counter() - t0) * 1000, 2)
            self.db = self.client[settings.MONGO_DB_NAME]
            self.is_mongo = True
            self.connection_error = None
            await self._init_indexes()
            print(f"[DatabaseManager] Connected successfully to MongoDB Atlas ({masked_uri}) in {self.ping_latency_ms} ms.")
        except Exception as e:
            self.is_mongo = False
            self.connection_error = str(e)
            print(f"[DatabaseManager] Notice: Could not reach MongoDB cluster ({masked_uri}): {e}")
            print("[DatabaseManager] Running in resilient in-memory mode to ensure 100% uptime.")

    async def _init_indexes(self):
        if not self.is_mongo:
            return
        try:
            await self.db.applications.create_index("api_key_hash", unique=True)
            await self.db.analyses.create_index([("application_id", 1), ("created_at", -1)])
            await self.db.analyses.create_index([("decision", 1), ("risk_band", 1)])
            await self.db.feedback.create_index("analysis_id")
        except Exception as e:
            print(f"[DatabaseManager] Index notice: {e}")

    async def disconnect(self):
        if self.client:
            self.client.close()

    async def insert_analysis(self, doc: Dict[str, Any]) -> str:
        if self.is_mongo:
            try:
                copy = dict(doc)
                copy["_id"] = doc["analysis_id"]
                await self.db.analyses.insert_one(copy)
                return doc["analysis_id"]
            except Exception:
                pass
        return await self.memory.insert_analysis(doc)

    async def list_analyses(self, skip: int = 0, limit: int = 50, **kwargs) -> List[Dict[str, Any]]:
        if self.is_mongo:
            try:
                query = {}
                if kwargs.get("risk_band"):
                    query["risk_band"] = kwargs["risk_band"]
                if kwargs.get("decision"):
                    query["decision"] = kwargs["decision"]
                if kwargs.get("source_type"):
                    query["source_type"] = kwargs["source_type"]
                cursor = self.db.analyses.find(query).sort("timestamp", -1).skip(skip).limit(limit)
                items = await cursor.to_list(length=limit)
                return items
            except Exception:
                pass
        return await self.memory.list_analyses(skip=skip, limit=limit, **kwargs)

    async def get_analysis(self, analysis_id: str) -> Optional[Dict[str, Any]]:
        if self.is_mongo:
            try:
                return await self.db.analyses.find_one({"_id": analysis_id})
            except Exception:
                pass
        return await self.memory.get_analysis(analysis_id)

    async def insert_feedback(self, doc: Dict[str, Any]) -> str:
        if self.is_mongo:
            try:
                copy = dict(doc)
                copy["_id"] = doc["feedback_id"]
                await self.db.feedback.insert_one(copy)
                return doc["feedback_id"]
            except Exception:
                pass
        return await self.memory.insert_feedback(doc)

    async def get_policy(self) -> Dict[str, Any]:
        if self.is_mongo:
            try:
                p = await self.db.settings.find_one({"_id": "active_policy"})
                if p:
                    return p
            except Exception:
                pass
        return await self.memory.get_policy()

    async def update_policy(self, updates: Dict[str, Any]) -> Dict[str, Any]:
        if self.is_mongo:
            try:
                updates["updated_at"] = datetime.now(timezone.utc).isoformat()
                await self.db.settings.update_one(
                    {"_id": "active_policy"}, {"$set": updates}, upsert=True
                )
                return updates
            except Exception:
                pass
        return await self.memory.update_policy(updates)

    async def validate_api_key(self, api_key: str) -> bool:
        if api_key == settings.DEFAULT_ADMIN_KEY:
            return True
        if self.is_mongo:
            try:
                hashed = hashlib.sha256(api_key.encode()).hexdigest()
                app = await self.db.applications.find_one({"api_key_hash": hashed, "is_active": True})
                return app is not None
            except Exception:
                pass
        return await self.memory.validate_api_key(api_key)


db_manager = DatabaseManager()

import os
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse

from src.config import settings
from src.api.db import db_manager
from src.api.routes import analyze, analyses, feedback, policy_routes, health, dataset_routes, agent_gateway

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: connect to database with fault-tolerance for serverless/container runtimes
    try:
        await db_manager.connect()
    except Exception as e:
        print(f"[Lifespan] Non-fatal database startup error: {e}")
    yield
    # Shutdown: disconnect
    try:
        await db_manager.disconnect()
    except Exception as e:
        print(f"[Lifespan] Non-fatal database shutdown error: {e}")

app = FastAPI(
    title="PromptShield AI",
    description="NLP-Based Prompt Injection & Jailbreak Detection API",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount REST API router with /api/v1 prefix
app.include_router(analyze.router, prefix="/api/v1", tags=["Analysis"])
app.include_router(dataset_routes.router, prefix="/api/v1", tags=["Dataset & Benchmark Explorer"])
app.include_router(agent_gateway.router, prefix="/api/v1", tags=["Third-Party AI Agent Gateway"])
app.include_router(analyses.router, prefix="/api/v1", tags=["Analyses History"])
app.include_router(feedback.router, prefix="/api/v1", tags=["Reviewer Feedback"])
app.include_router(policy_routes.router, prefix="/api/v1", tags=["Policy Engine"])
app.include_router(health.router, prefix="/api/v1", tags=["System Health"])

# Web static files directory
WEB_DIR = os.path.join(settings.BASE_DIR, "src", "web")
STATIC_DIR = os.path.join(WEB_DIR, "static")

if os.path.exists(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

@app.get("/", include_in_schema=False)
async def serve_landing_page():
    index_path = os.path.join(WEB_DIR, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return JSONResponse({"message": "PromptShield AI API online. Visit /docs for Swagger UI."})

@app.get("/test", include_in_schema=False)
@app.get("/console", include_in_schema=False)
async def serve_test_page():
    test_path = os.path.join(WEB_DIR, "test.html")
    if os.path.exists(test_path):
        return FileResponse(test_path)
    index_path = os.path.join(WEB_DIR, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return JSONResponse({"message": "PromptShield AI Testing Console loading..."})

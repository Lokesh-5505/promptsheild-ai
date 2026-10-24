from fastapi import APIRouter, Depends, HTTPException, Query
from typing import List, Optional
from src.api.schemas import AnalyzeResponse
from src.api.auth import verify_api_key
from src.api.db import db_manager

router = APIRouter()

@router.get("/analyses", response_model=List[AnalyzeResponse])
async def list_analyses(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    risk_band: Optional[str] = None,
    decision: Optional[str] = None,
    source_type: Optional[str] = None,
    api_key: str = Depends(verify_api_key),
):
    """Retrieve paginated audit log of past analyses with optional filters."""
    items = await db_manager.list_analyses(
        skip=skip,
        limit=limit,
        risk_band=risk_band,
        decision=decision,
        source_type=source_type,
    )
    return items

@router.get("/analyses/{analysis_id}", response_model=AnalyzeResponse)
async def get_analysis(
    analysis_id: str,
    api_key: str = Depends(verify_api_key),
):
    """Retrieve detailed results for a specific analysis by ID."""
    doc = await db_manager.get_analysis(analysis_id)
    if not doc:
        raise HTTPException(status_code=404, detail="Analysis record not found.")
    return doc

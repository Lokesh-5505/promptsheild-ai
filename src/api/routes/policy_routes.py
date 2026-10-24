from fastapi import APIRouter, Depends, HTTPException
from src.api.schemas import PolicyResponse, PolicyUpdate
from src.api.auth import verify_api_key
from src.api.db import db_manager

router = APIRouter()

@router.get("/policy", response_model=PolicyResponse)
async def get_policy(api_key: str = Depends(verify_api_key)):
    """Retrieve active risk threshold parameters and policy configurations."""
    p = await db_manager.get_policy()
    return {
        "policy_version": p.get("policy_version", "v1.2"),
        "low_max": p.get("low_max", 24),
        "medium_max": p.get("medium_max", 49),
        "high_max": p.get("high_max", 74),
        "store_raw_text": p.get("store_raw_text", False),
        "updated_at": p.get("updated_at", "2026-10-12T00:00:00Z"),
    }

@router.put("/policy", response_model=PolicyResponse)
async def update_policy(
    updates: PolicyUpdate,
    api_key: str = Depends(verify_api_key),
):
    """Update active risk threshold parameters and data retention toggles."""
    if not (updates.low_max < updates.medium_max < updates.high_max):
        raise HTTPException(
            status_code=400,
            detail="Thresholds must satisfy: low_max < medium_max < high_max."
        )

    updated = await db_manager.update_policy(updates.model_dump())
    return {
        "policy_version": updated.get("policy_version", "v1.2"),
        "low_max": updated["low_max"],
        "medium_max": updated["medium_max"],
        "high_max": updated["high_max"],
        "store_raw_text": updated.get("store_raw_text", False),
        "updated_at": updated["updated_at"],
    }

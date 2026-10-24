import uuid
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException
from src.api.schemas import FeedbackRequest, FeedbackResponse
from src.api.auth import verify_api_key
from src.api.db import db_manager

router = APIRouter()

@router.post("/feedback", response_model=FeedbackResponse)
async def submit_feedback(
    request: FeedbackRequest,
    api_key: str = Depends(verify_api_key),
):
    """Submit human-in-the-loop reviewer evaluation feedback."""
    feedback_id = f"fb_{uuid.uuid4().hex[:10]}"
    now = datetime.now(timezone.utc).isoformat()

    doc = {
        "feedback_id": feedback_id,
        "analysis_id": request.analysis_id,
        "reviewer_label": request.reviewer_label,
        "notes": request.notes,
        "reviewer_id": request.reviewer_id or "analyst_admin",
        "created_at": now,
    }

    await db_manager.insert_feedback(doc)

    return {
        "feedback_id": feedback_id,
        "analysis_id": request.analysis_id,
        "reviewer_label": request.reviewer_label,
        "status": "recorded",
        "timestamp": now,
    }

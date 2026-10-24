from fastapi import APIRouter, Depends, HTTPException, Request
from src.api.schemas import AnalyzeRequest, AnalyzeResponse
from src.api.auth import verify_api_key
from src.api.db import db_manager
from src.pipeline.detector import PromptInjectionDetector

router = APIRouter()
detector_instance = PromptInjectionDetector()

@router.post("/analyze", response_model=AnalyzeResponse)
async def analyze_input(
    request: AnalyzeRequest,
    api_key: str = Depends(verify_api_key),
):
    """Analyze text payload for prompt injection, jailbreaks, or exfiltration commands."""
    try:
        # Fetch current policy version
        policy = await db_manager.get_policy()
        policy_ver = policy.get("policy_version", "v1.2")
        
        # Sync dynamic thresholds
        detector_instance.update_thresholds(
            low_max=policy.get("low_max", 24),
            medium_max=policy.get("medium_max", 49),
            high_max=policy.get("high_max", 74),
        )

        # Run pipeline
        result = detector_instance.analyze(
            text=request.text,
            source_type=request.source_type,
            application_id=request.application_id or "default_app",
            policy_version=policy_ver,
        )

        # Store in database
        await db_manager.insert_analysis(result)

        return result
    except Exception as e:
        # Guarantee fail-secure review response on server issue
        return {
            "analysis_id": "anl_fallback",
            "application_id": request.application_id or "default_app",
            "timestamp": "now",
            "source_type": request.source_type,
            "label": "uncertain",
            "risk_score": 65,
            "risk_band": "high",
            "decision": "review",
            "categories": ["unauthorized_action"],
            "evidence": [],
            "explanation": f"Internal exception during processing: {str(e)}. Fallback to review.",
            "detector_version": "1.0.0",
            "policy_version": "v1.2",
            "latency_ms": 1.0,
            "text": None,
        }

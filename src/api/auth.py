from fastapi import Header, HTTPException, status
from src.api.db import db_manager

async def verify_api_key(x_api_key: str = Header(..., description="API Key for authorization")) -> str:
    """Validate X-API-Key header against database or fallback store."""
    if not x_api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing required X-API-Key header."
        )
    is_valid = await db_manager.validate_api_key(x_api_key)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or deactivated API key."
        )
    return x_api_key

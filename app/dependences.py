"""
FastAPI dependencies for auth, DB sessions, and shared resources.
"""

from fastapi import Depends, HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.config import get_settings
from app.database import get_db_session

settings = get_settings()
security = HTTPBearer()


async def verify_internal_token(
    credentials: HTTPAuthorizationCredentials = Security(security),
) -> str:
    """
    Simple bearer token auth for service-to-service calls.
    In production, consider mTLS or JWT with JWKS.
    """
    if credentials.credentials != settings.api_auth_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing authentication token.",
        )
    return credentials.credentials


# Re-export for convenience
DBSession = Depends(get_db_session)
InternalAuth = Depends(verify_internal_token)
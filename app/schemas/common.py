from typing import Optional, Any
from pydantic import BaseModel, Field


class MessageResponse(BaseModel):
    message: str
    success: bool = True


class ErrorDetail(BaseModel):
    code: str
    message: str
    details: Optional[Any] = None


class ErrorResponse(BaseModel):
    error: ErrorDetail

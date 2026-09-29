import logging
from fastapi import APIRouter, Depends, status

from app.core.dependencies import get_current_patient_uid
from app.schemas.profile import (
    ProfileCreateRequest,
    ProfileUpdateRequest,
    ProfileResponse,
)
from app.schemas.common import MessageResponse, ErrorResponse
from app.services.profile_service import ProfileService

router = APIRouter(prefix="/profiles", tags=["Patient Profiles"])
logger = logging.getLogger(__name__)


@router.get(
    "/me",
    response_model=ProfileResponse,
    summary="Get current patient profile",
    description="Retrieves profile, parent info, and focus Urdu sound for the authenticated patient.",
    responses={
        401: {"model": ErrorResponse, "description": "Unauthorized"},
        404: {"model": ErrorResponse, "description": "Profile not found"},
    }
)
async def get_my_profile(patient_uid: str = Depends(get_current_patient_uid)):
    return ProfileService.get_profile(patient_uid)


@router.post(
    "",
    response_model=ProfileResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create patient profile",
    description="Creates a patient profile linked strictly to authenticated user's UID.",
    responses={
        400: {"model": ErrorResponse, "description": "Validation error"},
        409: {"model": ErrorResponse, "description": "Profile already exists"},
        422: {"model": ErrorResponse, "description": "Cross-field sound validation failed"},
    }
)
async def create_profile(
    req: ProfileCreateRequest,
    patient_uid: str = Depends(get_current_patient_uid)
):
    return ProfileService.create_profile(patient_uid, req)


@router.put(
    "",
    response_model=ProfileResponse,
    summary="Update patient profile",
    description="Updates parent, child, phone, and/or Urdu focus sound for authenticated patient.",
    responses={
        400: {"model": ErrorResponse, "description": "Validation error"},
        404: {"model": ErrorResponse, "description": "Profile not found"},
        422: {"model": ErrorResponse, "description": "Cross-field sound validation failed"},
    }
)
async def update_profile(
    req: ProfileUpdateRequest,
    patient_uid: str = Depends(get_current_patient_uid)
):
    return ProfileService.update_profile(patient_uid, req)


@router.delete(
    "/me",
    response_model=MessageResponse,
    summary="Delete patient profile",
    description="Deletes profile and associated focus sound data for the authenticated patient.",
    responses={
        401: {"model": ErrorResponse, "description": "Unauthorized"},
        404: {"model": ErrorResponse, "description": "Profile not found"},
    }
)
async def delete_profile(patient_uid: str = Depends(get_current_patient_uid)):
    return ProfileService.delete_profile(patient_uid)

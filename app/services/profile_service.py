import logging
from typing import Optional, Dict, Any
from app.core.exceptions import (
    ProfileNotFoundException,
    ProfileAlreadyExistsException,
    InvalidSoundFieldsException,
    AppException
)
from app.core.supabase import get_supabase
from app.schemas.profile import (
    ProfileCreateRequest,
    ProfileUpdateRequest,
    ProfileResponse,
    FocusSoundResponse
)
from app.schemas.common import MessageResponse

logger = logging.getLogger(__name__)


class ProfileService:
    @classmethod
    def get_profile(cls, patient_uid: str) -> ProfileResponse:
        """
        Retrieves the profile and focus_sound strictly for the authenticated patient_uid.
        """
        sb = get_supabase()

        # 1. Fetch profile
        prof_res = sb.table("profiles").select("*").eq("patient_uid", patient_uid).execute()
        if not prof_res.data:
            raise ProfileNotFoundException()

        profile = prof_res.data[0]

        # 2. Fetch associated focus_sound
        focus_res = sb.table("focus_sound").select("*").eq("patient_uid", patient_uid).execute()
        focus_sound_obj = None
        if focus_res.data:
            f = focus_res.data[0]
            focus_sound_obj = FocusSoundResponse(
                sound=f.get("sound"),
                alphabet_name=f.get("alphabet_name"),
                progress=float(f.get("progress") or 0.0),
                updated_at=f.get("updated_at")
            )

        return ProfileResponse(
            patient_uid=profile["patient_uid"],
            parent_name=profile["parent_name"],
            child_name=profile["child_name"],
            phone=profile.get("phone"),
            focus_sound=focus_sound_obj,
            created_at=profile.get("created_at"),
            updated_at=profile.get("updated_at")
        )

    @classmethod
    def create_profile(cls, patient_uid: str, req: ProfileCreateRequest) -> ProfileResponse:
        """
        Creates a new profile record for the authenticated patient.
        Enforces cross-field sound validation and uniqueness.
        """
        sb = get_supabase()

        # Check if already exists
        existing = sb.table("profiles").select("patient_uid").eq("patient_uid", patient_uid).execute()
        if existing.data:
            raise ProfileAlreadyExistsException()

        # Insert profile
        profile_data = {
            "patient_uid": patient_uid,
            "parent_name": req.parent_name.strip(),
            "child_name": req.child_name.strip(),
        }
        ins_res = sb.table("profiles").insert(profile_data).execute()
        if not ins_res.data:
            raise AppException(500, "PROFILE_CREATION_FAILED", "Failed to insert profile record.")

        created_profile = ins_res.data[0]

        # Handle focus_sound if provided
        focus_sound_obj = None
        if req.sound and req.alphabet_name:
            focus_data = {
                "patient_uid": patient_uid,
                "sound": req.sound.strip(),
                "alphabet_name": req.alphabet_name.strip(),
                "progress": float(req.progress or 0.0),
            }
            sb.table("focus_sound").upsert(focus_data).execute()
            focus_sound_obj = FocusSoundResponse(
                sound=req.sound.strip(),
                alphabet_name=req.alphabet_name.strip(),
                progress=float(req.progress or 0.0)
            )

        return ProfileResponse(
            patient_uid=created_profile["patient_uid"],
            parent_name=created_profile["parent_name"],
            child_name=created_profile["child_name"],
            phone=None,
            focus_sound=focus_sound_obj,
            created_at=created_profile.get("created_at"),
            updated_at=created_profile.get("updated_at")
        )

    @classmethod
    def update_profile(cls, patient_uid: str, req: ProfileUpdateRequest) -> ProfileResponse:
        """
        Updates an existing profile and/or focus_sound record for the authenticated patient.
        """
        sb = get_supabase()

        # Check profile exists
        existing = sb.table("profiles").select("*").eq("patient_uid", patient_uid).execute()
        if not existing.data:
            raise ProfileNotFoundException()

        profile_updates: Dict[str, Any] = {}
        if req.parent_name is not None:
            profile_updates["parent_name"] = req.parent_name.strip()
        if req.child_name is not None:
            profile_updates["child_name"] = req.child_name.strip()

        if profile_updates:
            sb.table("profiles").update(profile_updates).eq("patient_uid", patient_uid).execute()

        # Handle focus_sound updates
        has_sound = req.sound is not None
        has_alpha = req.alphabet_name is not None
        has_prog = req.progress is not None

        if has_sound or has_alpha or has_prog:
            existing_focus = sb.table("focus_sound").select("*").eq("patient_uid", patient_uid).execute()
            focus_data: Dict[str, Any] = {"patient_uid": patient_uid}

            if has_sound and has_alpha:
                focus_data["sound"] = req.sound.strip() if req.sound else None
                focus_data["alphabet_name"] = req.alphabet_name.strip() if req.alphabet_name else None
            elif existing_focus.data:
                focus_data["sound"] = existing_focus.data[0].get("sound")
                focus_data["alphabet_name"] = existing_focus.data[0].get("alphabet_name")

            if has_prog:
                focus_data["progress"] = float(req.progress)
            elif existing_focus.data:
                focus_data["progress"] = float(existing_focus.data[0].get("progress") or 0.0)

            sb.table("focus_sound").upsert(focus_data).execute()

        return cls.get_profile(patient_uid)

    @classmethod
    def delete_profile(cls, patient_uid: str) -> MessageResponse:
        """
        Deletes the profile and focus_sound records for the authenticated patient.
        """
        sb = get_supabase()
        existing = sb.table("profiles").select("patient_uid").eq("patient_uid", patient_uid).execute()
        if not existing.data:
            raise ProfileNotFoundException()

        sb.table("focus_sound").delete().eq("patient_uid", patient_uid).execute()
        sb.table("profiles").delete().eq("patient_uid", patient_uid).execute()

        return MessageResponse(message="Profile deleted successfully.")

from typing import Optional
from pydantic import BaseModel, Field, model_validator


class FocusSoundResponse(BaseModel):
    sound: Optional[str] = None
    alphabet_name: Optional[str] = None
    progress: float = 0.0
    updated_at: Optional[str] = None


class ProfileCreateRequest(BaseModel):
    parent_name: str = Field(..., min_length=2, description="Parent's full name")
    child_name: str = Field(..., min_length=2, description="Child's full name")
    phone: str = Field(..., min_length=7, max_length=20, pattern=r"^\+?[0-9\s\-]{7,20}$", description="Contact phone number")
    sound: Optional[str] = Field(None, description="Urdu target sound")
    alphabet_name: Optional[str] = Field(None, description="Urdu alphabet transliteration")
    progress: Optional[float] = Field(0.0, ge=0.0, le=100.0, description="Phoneme progress percentage")

    @model_validator(mode="after")
    def validate_sound_fields(self):
        sound_given = bool(self.sound and self.sound.strip())
        alphabet_given = bool(self.alphabet_name and self.alphabet_name.strip())

        if (sound_given and not alphabet_given) or (alphabet_given and not sound_given):
            raise ValueError("sound and alphabet_name must both be provided, or both omitted.")
        return self


class ProfileUpdateRequest(BaseModel):
    parent_name: Optional[str] = Field(None, min_length=2, description="Parent's full name")
    child_name: Optional[str] = Field(None, min_length=2, description="Child's full name")
    phone: Optional[str] = Field(None, min_length=7, max_length=20, pattern=r"^\+?[0-9\s\-]{7,20}$", description="Contact phone number")
    sound: Optional[str] = Field(None, description="Urdu target sound")
    alphabet_name: Optional[str] = Field(None, description="Urdu alphabet transliteration")
    progress: Optional[float] = Field(None, ge=0.0, le=100.0, description="Phoneme progress percentage")

    @model_validator(mode="after")
    def validate_sound_fields(self):
        # If either sound or alphabet_name is passed explicitly (even as empty or value)
        has_sound = self.sound is not None
        has_alpha = self.alphabet_name is not None

        if has_sound or has_alpha:
            sound_given = bool(self.sound and self.sound.strip())
            alpha_given = bool(self.alphabet_name and self.alphabet_name.strip())
            if sound_given != alpha_given:
                raise ValueError("sound and alphabet_name must both be provided, or both omitted.")
        return self


class ProfileResponse(BaseModel):
    patient_uid: str
    parent_name: str
    child_name: str
    phone: Optional[str] = None
    focus_sound: Optional[FocusSoundResponse] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None

import json
from typing import List, Union
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    ENVIRONMENT: str = "development"
    PORT: int = 8001
    HOST: str = "0.0.0.0"

    # Supabase
    SUPABASE_URL: str = "https://fwrkrpmqmqxlgvyzrizq.supabase.co"
    SUPABASE_SERVICE_ROLE_KEY: str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImZ3cmtycG1xbXF4bGd2eXpyaXpxIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTc5MDQ3MTQxOSwiZXhwIjoyMTA2MDQ3NDE5fQ.qCh5EDtm1EnWIlaBVkStFTF3_Wqqow1R5OjE924Re44"

    # JWT Security
    JWT_SECRET_KEY: str = "speecheasy_patient_super_secret_production_key_498273948729384792384"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 30

    # Token Lifespans
    EMAIL_VERIFICATION_TOKEN_EXPIRE_HOURS: int = 24
    PASSWORD_RESET_TOKEN_EXPIRE_MINUTES: int = 15

    # Google Auth
    GOOGLE_CLIENT_ID: str = "26703591720-pt9vo0tdkudsqfd3dteeqi1kf1l7dluv.apps.googleusercontent.com"

    # SMTP Configuration
    SMTP_HOST: str = "smtp.gmail.com"
    SMTP_PORT: int = 587
    SMTP_USERNAME: str = "alamgeermalik75@gmail.com"
    SMTP_PASSWORD: str = "mmxzdcwsqjnuklgo"
    SMTP_FROM_EMAIL: str = "alamgeermalik75@gmail.com"
    SMTP_FROM_NAME: str = "SpeechEasy Patient Care"
    SMTP_USE_TLS: bool = True

    # URLs
    FRONTEND_URL: str = "speecheasy://app"
    BACKEND_URL: str = "https://speecheasy-auth-service-production.up.railway.app"

    # CORS
    CORS_ORIGINS: Union[List[str], str] = ["*"]

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        if isinstance(v, str):
            if v.startswith("[") and v.endswith("]"):
                try:
                    return json.loads(v)
                except Exception:
                    pass
            return [i.strip() for i in v.split(",") if i.strip()]
        return v

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )


settings = Settings()

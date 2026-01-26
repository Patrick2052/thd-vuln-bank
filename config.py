from dotenv import load_dotenv
import os
from pydantic_settings import BaseSettings
from pydantic import field_validator
load_dotenv()

class Settings(BaseSettings):
    JWT_SECRET_KEY: str
    SECRET_KEY: str

    @field_validator('SECRET_KEY', 'JWT_SECRET_KEY')
    @classmethod
    def validate_key_length(cls, v: str) -> str:
        if len(v) < 32:
            raise ValueError('Key must be at least 32 characters long')
        return v

def get_settings():
    return Settings()

settings = get_settings()
from dotenv import load_dotenv
import os
from pydantic_settings import BaseSettings
load_dotenv()

class Settings(BaseSettings):
    JWT_SECRET_KEY: str
    SECRET_KEY: str


def get_settings():
    return Settings()

settings = get_settings()
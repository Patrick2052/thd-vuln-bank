from pydantic import BaseModel, field_validator
import bleach
from auth import check_password_strength

class RegisterFormModel(BaseModel):
    """
    Pydantic model for registration form data validation in the secure
    /register implementation.
    """

    username: str
    password: str

    @field_validator("username")
    @classmethod
    def username_must_not_be_empty(cls, v):
        if not v or v.strip() == "":
            raise ValueError("Username must not be empty")
        clean_username = bleach.clean(v, tags=[], strip=True)
        print(f"Sanitized username: {clean_username}")
        return clean_username

    @field_validator("password", mode="after")
    @classmethod
    def password_strength(cls, v):
        if not check_password_strength(v):
            raise ValueError("Password does not meet strength requirements")
        return v
    


class TransferFormModel(BaseModel):
    """
    Pydantic model for transfer form data validation in the secure
    /transfer route implementation.
    """

    amount: float
    to_account: int
    description: str | None = "Transfer"

    @field_validator("amount", mode="after")
    @classmethod
    def amount_must_be_positive(cls, v):
        if v <= 0:
            raise ValueError("Amount must be a positive number")
        return v

    @field_validator("description", mode="before")
    @classmethod
    def sanitize_description(cls, v):
        print(f"Sanitizing description: {v}")
        if v is not None:
            clean_description = bleach.clean(v, tags=[], strip=True)
            print(f"Sanitized description: {clean_description}")
            return clean_description
        return v
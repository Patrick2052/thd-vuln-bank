from pydantic import BaseModel, field_validator
import bleach


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

    @field_validator("password")
    @classmethod
    def password_strength(cls, v):
        # TODO : Implement more robust password strength checks
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters long")
        return v
    

"""
Pydantic Models for Request/Response Validation
These models define the structure of data going in and out of API
"""

from pydantic import BaseModel
from typing import Optional


class Token(BaseModel):
    """
    Response model for /token endpoint (login)
    This follows OAuth2 specification
    """
    access_token: str  # The JWT token string
    token_type: str    # Always "bearer" for this flow


class TokenData(BaseModel):
    """
    Data extracted from JWT token
    Used internally to pass username between functions
    """
    username: Optional[str] = None


class User(BaseModel):
    """
    User model - what we send to client
    NEVER includes password!
    """
    user_id: int
    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    disabled: Optional[bool] = False


class UserInDB(User):
    """
    User model as stored in database
    Inherits all fields from User + adds hashed_password
    This model is NEVER sent to client (password security)
    """
    hashed_password: str


class UserCreate(BaseModel):
    """
    Model for user registration
    Client sends this when creating new account
    """
    username: str
    email: str
    full_name: Optional[str] = None
    password: str  # Plain password (will be hashed before storing)
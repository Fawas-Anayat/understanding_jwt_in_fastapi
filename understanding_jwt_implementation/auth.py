"""
Authentication Logic
All JWT and password-related functions
"""

from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from schemas import TokenData, UserInDB
from database import fake_users_db


# ============================================
# CONFIGURATION
# ============================================

# SECRET_KEY: Used to sign JWT tokens
# CRITICAL: Keep this secret! Never commit to git!
# Generate with: python -c "import secrets; print(secrets.token_hex(32))"
SECRET_KEY = "edc324c1362bce0dbb2fc7cc0ffa4eda477a03a570947f0cf9b26366b86fd263"

# ALGORITHM: Cryptographic algorithm for JWT
ALGORITHM = "HS256"

# TOKEN EXPIRATION: How long tokens are valid (30 minutes)
ACCESS_TOKEN_EXPIRE_MINUTES = 30


# ============================================
# PASSWORD HASHING SETUP
# ============================================

# CryptContext: Handles password hashing with bcrypt
# schemes=['bcrypt']: Use bcrypt algorithm (industry standard)
# deprecated='auto': Auto-handle deprecated hash schemes
pwd_context = CryptContext(schemes=['bcrypt'], deprecated='auto')


# ============================================
# OAUTH2 SCHEME
# ============================================

# OAuth2PasswordBearer: Tells FastAPI how to get the token
# tokenUrl="token": URL where clients get tokens (our /token endpoint)
# 
# What this does:
# 1. Looks for "Authorization: Bearer <token>" header
# 2. Extracts the token automatically
# 3. If no token found → returns 401 Unauthorized
# 4. Creates "Authorize" button in interactive docs
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


# ============================================
# PASSWORD FUNCTIONS
# ============================================

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Compare plain-text password with hashed password
    
    How it works:
    1. Takes plain password (what user typed)
    2. Hashes it with same algorithm
    3. Compares with stored hash
    4. Returns True if match, False otherwise
    
    Example:
        plain: "secret123"
        hashed: "$2b$12$..."
        verify_password("secret123", "$2b$12$...") → True
        verify_password("wrong", "$2b$12$...") → False
    """
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """
    Hash a plain-text password
    
    How it works:
    1. Takes plain password
    2. Adds random "salt" (prevents rainbow table attacks)
    3. Hashes with bcrypt (slow algorithm, prevents brute force)
    4. Returns hash string
    
    Example:
        Input: "secret123"
        Output: "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW"
    
    Note: Same password produces DIFFERENT hashes each time (salt is random)
    """
    return pwd_context.hash(password)


# ============================================
# USER DATABASE FUNCTIONS
# ============================================

def get_user(username: str) -> Optional[UserInDB]:
    """
    Retrieve user from database by username
    
    Args:
        username: Username to look up
    
    Returns:
        UserInDB object if found, None otherwise
    
    Example:
        user = get_user("usman")
        if user:
            print(user.email)  # usman@example.com
    """
    # Check if username exists in database
    if username in fake_users_db:
        # Get user data dictionary
        user_dict = fake_users_db[username]
        
        # Convert dictionary to Pydantic model
        # **user_dict unpacks: {"user_id": 101, "username": "usman", ...}
        # Into: UserInDB(user_id=101, username="usman", ...)
        return UserInDB(**user_dict)
    
    # User not found
    return None


def authenticate_user(username: str, password: str):
    """
    Verify username and password are correct
    
    Process:
    1. Look up user in database
    2. If user doesn't exist → return False
    3. Verify password against stored hash
    4. If password wrong → return False
    5. If all good → return user object
    
    Args:
        username: Username entered by user
        password: Plain-text password entered by user
    
    Returns:
        UserInDB object if authentication successful
        False if authentication failed
    
    Example:
        user = authenticate_user("usman", "secret123")
        if user:
            print("Login successful!")
        else:
            print("Invalid credentials!")
    """
    # Step 1: Try to get user from database
    user = get_user(username)
    
    # Step 2: If user doesn't exist, authentication fails
    if not user:
        return False
    
    # Step 3: Verify password
    # Compares plain password with hashed password in database
    if not verify_password(password, user.hashed_password):
        return False
    
    # Step 4: Authentication successful!
    return user


# ============================================
# JWT TOKEN FUNCTIONS
# ============================================

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    Create a JWT access token
    
    JWT Structure:
    - Header: {"alg": "HS256", "typ": "JWT"}
    - Payload: data + expiration time
    - Signature: HMACSHA256(header + payload, SECRET_KEY)
    
    Args:
        data: Dictionary to encode in token (usually {"sub": username})
        expires_delta: Optional custom expiration time
    
    Returns:
        Encoded JWT token string
    
    Example:
        token = create_access_token(
            data={"sub": "usman"},
            expires_delta=timedelta(minutes=30)
        )
        # Returns: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
    """
    # Step 1: Make a copy of data (don't modify original)
    to_encode = data.copy()
    
    # Step 2: Calculate expiration time
    if expires_delta:
        # Use custom expiration if provided
        expire = datetime.utcnow() + expires_delta
    else:
        # Default: 15 minutes from now
        expire = datetime.utcnow() + timedelta(minutes=15)
    
    # Step 3: Add expiration to payload
    # "exp" is a standard JWT claim (registered claim name)
    # JWT libraries automatically check if token is expired
    to_encode.update({"exp": expire})
    
    # Step 4: Encode the JWT token
    # jwt.encode() does:
    # 1. Create header: {"alg": "HS256", "typ": "JWT"}
    # 2. Base64 encode header
    # 3. Base64 encode payload (to_encode)
    # 4. Create signature: HMACSHA256(header.payload, SECRET_KEY)
    # 5. Combine: header.payload.signature
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    
    # Step 5: Return the token
    return encoded_jwt


async def get_current_user(token: str = Depends(oauth2_scheme)) -> UserInDB:
    """
    Extract and validate user from JWT token
    This is a DEPENDENCY FUNCTION used in protected endpoints
    
    Process:
    1. Receive token from Authorization header (via oauth2_scheme)
    2. Decode and verify token
    3. Extract username from token
    4. Look up user in database
    5. Return user object
    
    Args:
        token: JWT token string (extracted automatically by oauth2_scheme)
    
    Returns:
        UserInDB object if token is valid
    
    Raises:
        HTTPException 401 if:
        - Token is expired
        - Token signature is invalid
        - Username not in token
        - User not found in database
    
    Example usage in endpoint:
        @app.get("/protected")
        async def protected_route(current_user: UserInDB = Depends(get_current_user)):
            return {"username": current_user.username}
    """
    # Define exception for invalid credentials
    # This will be raised if anything goes wrong
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},  # OAuth2 requires this header
    )
    
    try:
        # Step 1: Decode the JWT token
        # jwt.decode() does:
        # 1. Split token into header.payload.signature
        # 2. Verify signature using SECRET_KEY
        # 3. Check if token is expired (using "exp" claim)
        # 4. Return payload as dictionary
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        
        # Step 2: Extract username from payload
        # "sub" (subject) is standard JWT claim for user identifier
        username: str = payload.get("sub")
        
        # Step 3: Check if username exists in payload
        if username is None:
            raise credentials_exception
        
        # Step 4: Create TokenData object
        token_data = TokenData(username=username)
        
    except JWTError:
        # JWTError is raised if:
        # - Token is expired
        # - Signature is invalid
        # - Token is malformed
        raise credentials_exception
    
    # Step 5: Get user from database
    user = get_user(username=token_data.username)
    
    # Step 6: Check if user exists
    if user is None:
        raise credentials_exception
    
    # Step 7: Return user object
    # This user object is now available in the endpoint function
    return user


async def get_current_active_user(current_user: UserInDB = Depends(get_current_user)) -> UserInDB:
    """
    Verify user account is active (not disabled)
    This is an ADDITIONAL LAYER on top of get_current_user
    
    Dependency chain:
    get_current_active_user
        ↓ depends on
    get_current_user
        ↓ depends on
    oauth2_scheme (extracts token)
    
    Args:
        current_user: User object from get_current_user dependency
    
    Returns:
        User object if active
    
    Raises:
        HTTPException 400 if user is disabled
    
    Example:
        @app.get("/users/me")
        async def read_me(user: UserInDB = Depends(get_current_active_user)):
            return user
    """
    # Check if user account is disabled
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    
    # Return active user
    return current_user
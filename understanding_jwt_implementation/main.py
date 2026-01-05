"""
Main FastAPI Application
Defines all API endpoints
"""

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from datetime import timedelta
from typing import List

# Import our modules
from schemas import Token, User, UserCreate
from auth import (
    authenticate_user,
    create_access_token,
    get_current_active_user,
    get_password_hash,
    ACCESS_TOKEN_EXPIRE_MINUTES
)
from database import fake_users_db


# ============================================
# CREATE FASTAPI APP
# ============================================

app = FastAPI(
    title="Personal Finance Tracker API",
    description="JWT Authentication Example",
    version="1.0.0"
)


# ============================================
# PUBLIC ENDPOINTS (No authentication required)
# ============================================

@app.get("/")
async def root():
    """
    Root endpoint - anyone can access
    """
    return {
        "message": "Welcome to Personal Finance Tracker API",
        "docs": "/docs",
        "endpoints": {
            "login": "/token",
            "register": "/register",
            "protected": "/users/me"
        }
    }


@app.post("/register", response_model=User, status_code=status.HTTP_201_CREATED)
async def register(user: UserCreate):
    """
    Register a new user
    
    Process:
    1. Check if username already exists
    2. Hash the password
    3. Create user in database
    4. Return user object (without password)
    
    Request Body:
    {
        "username": "newuser",
        "email": "newuser@example.com",
        "full_name": "New User",
        "password": "securepassword123"
    }
    
    Response:
    {
        "user_id": 104,
        "username": "newuser",
        "email": "newuser@example.com",
        "full_name": "New User",
        "disabled": false
    }
    """
    # Step 1: Check if username already exists
    if user.username in fake_users_db:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered"
        )
    
    # Step 2: Hash the password
    # NEVER store plain passwords!
    hashed_password = get_password_hash(user.password)
    
    # Step 3: Create new user in database
    new_user_id = len(fake_users_db) + 101  # Simple ID generation
    
    fake_users_db[user.username] = {
        "user_id": new_user_id,
        "username": user.username,
        "email": user.email,
        "full_name": user.full_name,
        "hashed_password": hashed_password,
        "disabled": False,
    }
    
    # Step 4: Return user object (without password)
    return User(
        user_id=new_user_id,
        username=user.username,
        email=user.email,
        full_name=user.full_name,
        disabled=False
    )


@app.post("/token", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):     #makes the coming data in some specific json format, otherwise the incoming data that is incmoing with the request is not in the valid format and its difficult to extract the username and the password from it 
    
    """
    Login endpoint - exchanges username/password for JWT token
    
    This endpoint follows OAuth2 specification
    
    Process:
    1. Receive username and password from form
    2. Authenticate user
    3. Create JWT token
    4. Return token
    
    Request (Form Data):
        username: usman
        password: secret123
    
    Response:
    {
        "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
        "token_type": "bearer"
    }
    
    What happens behind the scenes:
    
    1. OAuth2PasswordRequestForm extracts username and password from request
       - Expects: application/x-www-form-urlencoded
       - Fields: username, password
    
    2. authenticate_user() checks credentials:
       - Looks up user in database
       - Verifies password hash
       - Returns user object or False
    
    3. If authentication fails:
       - Raise 401 Unauthorized exception
       - Client knows login failed
    
    4. If authentication succeeds:
       - Create JWT token with username
       - Set expiration time (30 minutes)
       - Return token to client
    
    5. Client stores token and includes it in future requests:
       - Header: Authorization: Bearer <token>
    """
    # Step 1: Authenticate user with username and password
    user = authenticate_user(form_data.username, form_data.password)
    
    # Step 2: If authentication failed, raise exception
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Step 3: Set token expiration time
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    # Step 4: Create JWT token
    # "sub" (subject) is standard claim for user identifier
    access_token = create_access_token(
        data={"sub": user.username},
        expires_delta=access_token_expires
    )
    
    # Step 5: Return token in OAuth2 format
    return {
        "access_token": access_token,
        "token_type": "bearer"
    }


# ============================================
# PROTECTED ENDPOINTS (Require authentication)
# ============================================

@app.get("/users/me", response_model=User)
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    """
    Get current logged-in user information
    This is a PROTECTED endpoint - requires valid JWT token
    
    How it works:
    1. Client sends request with Authorization header
       GET /users/me
       Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
    
    2. oauth2_scheme (in get_current_user) extracts token
    
    3. get_current_user dependency:
       - Decodes JWT token
       - Verifies signature
       - Checks expiration
       - Extracts username
       - Looks up user in database
    
    4. get_current_active_user dependency:
       - Checks if user is active (not disabled)
    
    5. If all checks pass:
       - current_user object is available
       - Function can use user data
    
    6. Return user information
    
    Response:
    {
        "user_id": 101,
        "username": "usman",
        "email": "usman@example.com",
        "full_name": "Usman Khan",
        "disabled": false
    }
    """
    # current_user is automatically injected by dependency
    # It's already validated and extracted from JWT token
    return current_user


@app.get("/users/me/items")
async def read_own_items(current_user: User = Depends(get_current_active_user)):
    """
    Get items belonging to current user
    Another example of protected endpoint
    
    In real app, this would:
    1. Query database for user's transactions
    2. Filter by user_id
    3. Return user's data only
    """
    # Mock data - in real app, query database
    return [
        {"item_id": 1, "title": "Salary", "owner": current_user.username},
        {"item_id": 2, "title": "Groceries", "owner": current_user.username},
    ]


@app.get("/admin/users", response_model=List[User])
async def list_all_users(current_user: User = Depends(get_current_active_user)):
    """
    Admin endpoint - list all users
    
    Note: In real app, add role-based access control (RBAC)
    to ensure only admins can access this
    """
    # Convert all users to User objects (without passwords)
    users = []
    for username, user_data in fake_users_db.items():
        users.append(User(**user_data))
    return users


# ============================================
# UTILITY ENDPOINTS
# ============================================

@app.get("/health")
async def health_check():
    """
    Health check endpoint
    Used by load balancers, monitoring systems
    """
    return {"status": "healthy"}

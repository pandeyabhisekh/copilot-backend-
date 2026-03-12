import os
import uvicorn
from fastapi import FastAPI, HTTPException, status
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
import datetime
from pydantic import BaseModel, EmailStr, field_validator
from typing import Optional
import secrets

# Load environment variables from .env file
load_dotenv()

app = FastAPI(
    title="Auth Service",
    version="1.0.0",
    description="Authentication microservice for AI Copilot",
    docs_url="/docs",
    redoc_url="/redoc",
)

# Configure CORS for Angular frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:4200",  # Angular dev server
        "http://127.0.0.1:4200",
        "*"  # Allow all for testing (remove in production)
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ========== DATA MODELS ==========

class UserRegister(BaseModel):
    name: str
    email: EmailStr
    password: str
    
    @field_validator('password')
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters')
        if not any(char.isupper() for char in v):
            raise ValueError('Password must contain uppercase letter')
        if not any(char.islower() for char in v):
            raise ValueError('Password must contain lowercase letter')
        if not any(char.isdigit() for char in v):
            raise ValueError('Password must contain number')
        return v

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class UserResponse(BaseModel):
    id: str
    name: str
    email: str
    created_at: str

class AuthResponse(BaseModel):
    success: bool
    message: str
    token: Optional[str] = None
    user: Optional[UserResponse] = None

# ========== MOCK DATABASE ==========
users_db = {}
tokens_db = {}

# ========== HELPER FUNCTIONS ==========

def generate_token():
    """Generate a random auth token"""
    return secrets.token_hex(32)

def find_user_by_email(email: str):
    """Find user by email"""
    for user_id, user in users_db.items():
        if user['email'] == email:
            return user_id, user
    return None, None

# ========== BASIC API ENDPOINTS ==========

@app.get("/")
def root():
    return {
        "service": "auth-service",
        "status": "running",
        "version": "1.0.0"
    }

@app.get("/health")
def health():
    return {
        "status": "healthy",
        "service": "auth-service",
        "timestamp": datetime.datetime.now().isoformat()
    }

@app.get("/info")
def info():
    """Get service information"""
    return {
        "service": app.title,
        "version": app.version,
        "environment": os.getenv("ENVIRONMENT", "development"),
        "port": int(os.getenv("PORT", 8000))
    }

# ========== AUTH ENDPOINTS ==========

@app.post("/auth/register", response_model=AuthResponse, status_code=status.HTTP_201_CREATED)
async def register(user_data: UserRegister):
    """
    Register a new user
    """
    try:
        print(f"📝 Registration attempt: {user_data.email}")
        
        # Check if user already exists
        user_id, existing_user = find_user_by_email(user_data.email)
        if existing_user:
            return JSONResponse(
                status_code=status.HTTP_409_CONFLICT,
                content={
                    "success": False,
                    "message": "Email already exists. Please use a different email."
                }
            )
        
        # Create new user
        user_id = str(len(users_db) + 1)
        new_user = {
            "id": user_id,
            "name": user_data.name,
            "email": user_data.email,
            "password": user_data.password,  # TODO: Hash this in production!
            "created_at": datetime.datetime.now().isoformat()
        }
        
        # Store user
        users_db[user_id] = new_user
        print(f"✅ User registered: {user_data.email}")
        
        # Generate token
        token = generate_token()
        tokens_db[token] = user_id
        
        # Return success response
        return {
            "success": True,
            "message": "Registration successful",
            "token": token,
            "user": {
                "id": user_id,
                "name": user_data.name,
                "email": user_data.email,
                "created_at": new_user["created_at"]
            }
        }
        
    except Exception as e:
        print(f"❌ Registration error: {str(e)}")
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "success": False,
                "message": str(e)
            }
        )

@app.post("/auth/login", response_model=AuthResponse)
async def login(login_data: UserLogin):
    """
    Login existing user
    """
    try:
        print(f"🔑 Login attempt: {login_data.email}")
        
        # Find user by email
        user_id, user = find_user_by_email(login_data.email)
        
        if not user:
            print(f"❌ User not found: {login_data.email}")
            return JSONResponse(
                status_code=status.HTTP_404_NOT_FOUND,
                content={
                    "success": False,
                    "message": "User not found. Please register first."
                }
            )
        
        # Check password
        if user["password"] != login_data.password:
            print(f"❌ Invalid password for: {login_data.email}")
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={
                    "success": False,
                    "message": "Invalid email or password."
                }
            )
        
        # Generate new token
        token = generate_token()
        tokens_db[token] = user_id
        print(f"✅ Login successful: {login_data.email}")
        
        # Return success response
        return {
            "success": True,
            "message": "Login successful",
            "token": token,
            "user": {
                "id": user["id"],
                "name": user["name"],
                "email": user["email"],
                "created_at": user["created_at"]
            }
        }
        
    except Exception as e:
        print(f"❌ Login error: {str(e)}")
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "success": False,
                "message": str(e)
            }
        )

@app.post("/auth/logout")
async def logout(token: str):
    """
    Logout user by invalidating token
    """
    if token in tokens_db:
        del tokens_db[token]
        return {"success": True, "message": "Logged out successfully"}
    return {"success": False, "message": "Invalid token"}

@app.get("/auth/verify")
async def verify_token(token: str):
    """
    Verify if token is valid
    """
    if token in tokens_db:
        user_id = tokens_db[token]
        user = users_db.get(user_id)
        if user:
            return {
                "success": True,
                "valid": True,
                "user": {
                    "id": user["id"],
                    "name": user["name"],
                    "email": user["email"]
                }
            }
    return {
        "success": False,
        "valid": False,
        "message": "Invalid or expired token"
    }

# ========== USER MANAGEMENT ENDPOINTS ==========

@app.get("/auth/users")
async def get_all_users():
    """
    Get all users (for testing purposes)
    """
    users = []
    for user_id, user in users_db.items():
        users.append({
            "id": user["id"],
            "name": user["name"],
            "email": user["email"],
            "created_at": user["created_at"]
        })
    return {
        "success": True,
        "count": len(users),
        "users": users
    }

@app.get("/auth/users/{user_id}")
async def get_user(user_id: str):
    """
    Get user by ID
    """
    user = users_db.get(user_id)
    if user:
        return {
            "success": True,
            "user": {
                "id": user["id"],
                "name": user["name"],
                "email": user["email"],
                "created_at": user["created_at"]
            }
        }
    return {
        "success": False,
        "message": "User not found"
    }

# ========== DEBUG ENDPOINT ==========

@app.get("/debug/routes")
async def debug_routes():
    """List all available routes"""
    routes = []
    for route in app.routes:
        if hasattr(route, 'methods') and route.path != '/favicon.ico':
            routes.append({
                "path": route.path,
                "methods": list(route.methods)
            })
    return {
        "total_routes": len(routes),
        "routes": routes
    }

# ========== FAVICON ==========

@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    favicon_path = "static/favicon.ico"
    if os.path.exists(favicon_path):
        return FileResponse(favicon_path)
    return JSONResponse(status_code=204, content=None)

# ========== STARTUP EVENT ==========

@app.on_event("startup")
async def startup_event():
    """Create test user on startup"""
    # Clear existing data for clean start
    users_db.clear()
    tokens_db.clear()
    
    # Create a test user
    test_user = {
        "id": "1",
        "name": "Test User",
        "email": "test@example.com",
        "password": "Test@123",  # In production, this would be hashed
        "created_at": datetime.datetime.now().isoformat()
    }
    users_db["1"] = test_user
    
    # Print beautiful startup message
    print("\n" + "="*70)
    print("🚀 AUTH SERVICE STARTED SUCCESSFULLY!")
    print("="*70)
    print(f"📡 Server: http://localhost:{os.getenv('PORT', 8000)}")
    print(f"📝 API Docs: http://localhost:{os.getenv('PORT', 8000)}/docs")
    print(f"🔧 Environment: {os.getenv('ENVIRONMENT', 'development')}")
    print(f"🐛 Debug mode: {os.getenv('DEBUG', 'False')}")
    print("\n✅ Test User Created:")
    print("   └─ 📧 Email: test@example.com")
    print("   └─ 🔑 Password: Test@123")
    print("\n✅ Registered Users:")
    print("   └─ Total users:", len(users_db))
    print("\n📍 Available Endpoints:")
    
    # List all endpoints
    endpoints = [
        ("GET", "/", "Root endpoint"),
        ("GET", "/health", "Health check"),
        ("GET", "/info", "Service info"),
        ("POST", "/auth/register", "Register new user"),
        ("POST", "/auth/login", "Login user"),
        ("POST", "/auth/logout", "Logout user"),
        ("GET", "/auth/verify", "Verify token"),
        ("GET", "/auth/users", "Get all users"),
        ("GET", "/auth/users/{id}", "Get user by ID"),
        ("GET", "/debug/routes", "Debug routes"),
    ]
    
    for method, path, desc in endpoints:
        print(f"   ├─ {method:4} {path:20} - {desc}")
    
    print("="*70 + "\n")

# ========== MAIN ==========

if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    host = os.getenv("HOST", "0.0.0.0")
    debug = os.getenv("DEBUG", "False").lower() == "true"
    
    uvicorn.run(
        "main:app",
        host=host,
        port=port,
        reload=debug,
        log_level="info"
    )
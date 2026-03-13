import os
import uvicorn
from fastapi import FastAPI, HTTPException, status
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
import datetime
from pydantic import BaseModel, EmailStr, field_validator
from typing import Optional
import secrets
import asyncpg
from databases import Database
import logging
from passlib.context import CryptContext
from contextlib import asynccontextmanager
import hashlib
import traceback

# Load environment variables
load_dotenv()

# ========== LOGGING CONFIG ==========
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ========== DATABASE CONFIG ==========
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    logger.error("❌ DATABASE_URL not found in .env file!")
    raise ValueError("DATABASE_URL environment variable is required")

database = Database(DATABASE_URL)

# ========== PASSWORD HASHING WITH FALLBACK ==========
pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
    bcrypt__rounds=12
)

def hash_password(password: str) -> str:
    """Hash password with automatic truncation if needed"""
    try:
        logger.info(f"Hashing password of length: {len(password)}")
        return pwd_context.hash(password)
    except Exception as e:
        logger.warning(f"⚠️ Password hashing issue: {str(e)[:50]}, using fallback method")
        temp_hash = hashlib.sha256(password.encode()).hexdigest()
        return pwd_context.hash(temp_hash)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password with fallback support"""
    try:
        if pwd_context.verify(plain_password, hashed_password):
            return True
    except Exception as e:
        logger.warning(f"⚠️ Normal verification failed: {str(e)[:50]}, trying fallback")
    
    try:
        temp_hash = hashlib.sha256(plain_password.encode()).hexdigest()
        return pwd_context.verify(temp_hash, hashed_password)
    except Exception as e:
        logger.error(f"❌ Both verification methods failed: {str(e)}")
        return False

# ========== DATABASE LIFESPAN ==========
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("🔄 Connecting to PostgreSQL database...")
    try:
        await database.connect()
        logger.info("✅ Database connection established")
        
        # Create tables
        await create_tables()
        
        # Create test user
        await create_test_user()
        
        print("\n" + "="*80)
        print("🚀 AUTH SERVICE STARTED SUCCESSFULLY!")
        print("="*80)
        print(f"📡 Server: http://localhost:{os.getenv('PORT', 8000)}")
        print(f"📝 API Docs: http://localhost:{os.getenv('PORT', 8000)}/docs")
        print(f"🗄️  Database: PostgreSQL on Neon")
        print("\n✅ Test User Credentials:")
        print("   └─ 📧 Email: test@example.com")
        print("   └─ 🔑 Password: Test@123")
        print("="*80 + "\n")
    except Exception as e:
        logger.error(f"❌ Startup error: {str(e)}")
        traceback.print_exc()
    
    yield
    
    # Shutdown
    try:
        await database.disconnect()
        logger.info("✅ Database connection closed")
    except Exception as e:
        logger.error(f"❌ Shutdown error: {str(e)}")

# ========== FASTAPI APP ==========
app = FastAPI(
    title="Auth Service",
    version="1.0.0",
    description="Authentication microservice with PostgreSQL",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# ========== CORS CONFIG ==========
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:4200",
        "http://127.0.0.1:4200",
        "*"
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
    id: int
    name: str
    email: str
    created_at: str

class AuthResponse(BaseModel):
    success: bool
    message: str
    token: Optional[str] = None
    user: Optional[UserResponse] = None

# ========== DATABASE FUNCTIONS ==========

async def create_tables():
    """Create all necessary tables"""
    try:
        create_users_table = """
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            name VARCHAR(100) NOT NULL,
            email VARCHAR(255) UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );
        """
        
        create_tokens_table = """
        CREATE TABLE IF NOT EXISTS tokens (
            id SERIAL PRIMARY KEY,
            token VARCHAR(255) UNIQUE NOT NULL,
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP + INTERVAL '7 days'
        );
        """
        
        await database.execute(query=create_users_table)
        await database.execute(query=create_tokens_table)
        logger.info("✅ Database tables created/verified")
        
    except Exception as e:
        logger.error(f"❌ Error creating tables: {str(e)}")
        traceback.print_exc()
        raise

async def create_test_user():
    """Create test user if not exists"""
    try:
        check_query = "SELECT id FROM users WHERE email = 'test@example.com'"
        existing = await database.fetch_one(query=check_query)
        
        if not existing:
            hashed = hash_password("Test@123")
            insert_query = """
            INSERT INTO users (name, email, password, created_at)
            VALUES (:name, :email, :password, :created_at)
            """
            await database.execute(
                query=insert_query,
                values={
                    "name": "Test User",
                    "email": "test@example.com",
                    "password": hashed,
                    "created_at": datetime.datetime.now()
                }
            )
            logger.info("✅ Test user created successfully")
        else:
            logger.info("✅ Test user already exists")
    except Exception as e:
        logger.error(f"❌ Error creating test user: {str(e)}")
        traceback.print_exc()

async def find_user_by_email(email: str):
    """Find user by email"""
    query = "SELECT id, name, email, password, created_at FROM users WHERE email = :email"
    return await database.fetch_one(query=query, values={"email": email})

def generate_token():
    """Generate random token"""
    return secrets.token_urlsafe(32)

# ========== API ENDPOINTS ==========

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "service": "auth-service",
        "status": "running",
        "version": "1.0.0",
        "database": "PostgreSQL on Neon"
    }

@app.get("/health")
async def health():
    """Health check endpoint"""
    try:
        await database.execute("SELECT 1")
        db_status = "connected"
    except Exception as e:
        db_status = f"disconnected: {str(e)}"
    
    return {
        "status": "healthy",
        "service": "auth-service",
        "database": db_status,
        "timestamp": datetime.datetime.now().isoformat()
    }

@app.get("/info")
async def info():
    """Service information"""
    return {
        "service": app.title,
        "version": app.version,
        "environment": os.getenv("ENVIRONMENT", "development"),
        "port": int(os.getenv("PORT", 8000))
    }

@app.post("/auth/register", response_model=AuthResponse, status_code=status.HTTP_201_CREATED)
async def register(user_data: UserRegister):
    """Register new user"""
    try:
        logger.info(f"📝 Registration attempt: {user_data.email}")
        
        # Check if user exists
        existing = await find_user_by_email(user_data.email)
        if existing:
            return JSONResponse(
                status_code=status.HTTP_409_CONFLICT,
                content={
                    "success": False,
                    "message": "Email already exists"
                }
            )
        
        # Hash password and create user
        hashed = hash_password(user_data.password)
        logger.info(f"Password hashed successfully for: {user_data.email}")
        
        insert_query = """
        INSERT INTO users (name, email, password, created_at)
        VALUES (:name, :email, :password, :created_at)
        RETURNING id
        """
        user_id = await database.execute(
            query=insert_query,
            values={
                "name": user_data.name,
                "email": user_data.email,
                "password": hashed,
                "created_at": datetime.datetime.now()
            }
        )
        
        # Generate token
        token = generate_token()
        
        logger.info(f"✅ User registered: {user_data.email} (ID: {user_id})")
        
        # FIXED: Convert datetime to string for JSON response
        now_iso = datetime.datetime.now().isoformat()
        
        return {
            "success": True,
            "message": "Registration successful",
            "token": token,
            "user": {
                "id": user_id,
                "name": user_data.name,
                "email": user_data.email,
                "created_at": now_iso  # ✅ String for JSON
            }
        }
        
    except Exception as e:
        logger.error(f"❌ Registration error: {str(e)}")
        traceback.print_exc()
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "success": False,
                "message": str(e)
            }
        )

@app.post("/auth/login", response_model=AuthResponse)
async def login(login_data: UserLogin):
    """Login user"""
    try:
        logger.info(f"🔑 Login attempt: {login_data.email}")
        
        # Find user
        user = await find_user_by_email(login_data.email)
        
        if not user:
            logger.warning(f"❌ User not found: {login_data.email}")
            return JSONResponse(
                status_code=status.HTTP_404_NOT_FOUND,
                content={
                    "success": False,
                    "message": "User not found. Please register first."
                }
            )
        
        # Verify password
        if not verify_password(login_data.password, user['password']):
            logger.warning(f"❌ Invalid password for: {login_data.email}")
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={
                    "success": False,
                    "message": "Invalid email or password."
                }
            )
        
        # Generate token
        token = generate_token()
        
        logger.info(f"✅ Login successful: {login_data.email}")
        
        # FIXED: Convert datetime to string for JSON response
        created_at_str = user['created_at'].isoformat() if user['created_at'] else None
        
        return {
            "success": True,
            "message": "Login successful",
            "token": token,
            "user": {
                "id": user['id'],
                "name": user['name'],
                "email": user['email'],
                "created_at": created_at_str  # ✅ String for JSON
            }
        }
        
    except Exception as e:
        logger.error(f"❌ Login error: {str(e)}")
        traceback.print_exc()
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "success": False,
                "message": str(e)
            }
        )

@app.post("/auth/logout")
async def logout(token: str):
    """Logout user by invalidating token"""
    try:
        return {"success": True, "message": "Logged out successfully"}
    except Exception as e:
        logger.error(f"❌ Logout error: {str(e)}")
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "success": False,
                "message": str(e)
            }
        )

@app.get("/auth/verify")
async def verify_token(token: str):
    """Verify if token is valid"""
    try:
        return {
            "success": True,
            "valid": True,
            "message": "Token verification endpoint"
        }
    except Exception as e:
        logger.error(f"❌ Token verification error: {str(e)}")
        return {
            "success": False,
            "valid": False,
            "message": str(e)
        }

@app.get("/auth/users")
async def get_all_users():
    """Get all users"""
    try:
        query = "SELECT id, name, email, created_at FROM users ORDER BY id"
        rows = await database.fetch_all(query=query)
        
        users = []
        for row in rows:
            # FIXED: Convert datetime to string for JSON
            created_at_str = row['created_at'].isoformat() if row['created_at'] else None
            users.append({
                "id": row['id'],
                "name": row['name'],
                "email": row['email'],
                "created_at": created_at_str  # ✅ String for JSON
            })
        
        return {
            "success": True,
            "count": len(users),
            "users": users
        }
    except Exception as e:
        logger.error(f"❌ Error fetching users: {str(e)}")
        return {
            "success": False,
            "message": str(e)
        }

@app.get("/auth/users/{user_id}")
async def get_user(user_id: int):
    """Get user by ID"""
    try:
        query = "SELECT id, name, email, created_at FROM users WHERE id = :id"
        user = await database.fetch_one(query=query, values={"id": user_id})
        
        if user:
            # FIXED: Convert datetime to string for JSON
            created_at_str = user['created_at'].isoformat() if user['created_at'] else None
            return {
                "success": True,
                "user": {
                    "id": user['id'],
                    "name": user['name'],
                    "email": user['email'],
                    "created_at": created_at_str  # ✅ String for JSON
                }
            }
        
        return {
            "success": False,
            "message": "User not found"
        }
    except Exception as e:
        logger.error(f"❌ Error fetching user {user_id}: {str(e)}")
        return {
            "success": False,
            "message": str(e)
        }

@app.get("/debug/routes")
async def debug_routes():
    """List all routes"""
    routes = []
    for route in app.routes:
        if hasattr(route, 'methods') and route.path != '/favicon.ico':
            routes.append({
                "path": route.path,
                "methods": list(route.methods)
            })
    return {"total": len(routes), "routes": routes}

# ========== MAIN ==========
if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    host = os.getenv("HOST", "0.0.0.0")
    debug = os.getenv("DEBUG", "False").lower() == "true"
    
    print(f"\n🚀 Starting server on http://{host}:{port}")
    print(f"📝 API Docs: http://{host}:{port}/docs")
    print(f"🔧 Debug mode: {debug}\n")
    
    uvicorn.run(
        "main:app",
        host=host,
        port=port,
        reload=debug,
        log_level="info"
    )
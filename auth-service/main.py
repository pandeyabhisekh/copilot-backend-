import os
import uvicorn
from fastapi import FastAPI, HTTPException, status, Depends, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from dotenv import load_dotenv
import datetime
from pydantic import BaseModel, EmailStr, field_validator
from typing import Optional, List
import secrets
import asyncpg
from databases import Database
import logging
from contextlib import asynccontextmanager
import hashlib
import traceback
from jose import JWTError, jwt
from passlib.context import CryptContext
import httpx
from urllib.parse import urlencode

# Load environment variables
load_dotenv()

# ========== LOGGING CONFIG ==========
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ========== JWT CONFIG ==========
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-change-in-production")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30))

# ========== GITHUB OAUTH CONFIG ==========
GITHUB_CLIENT_ID = os.getenv("GITHUB_CLIENT_ID")
GITHUB_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET")
GITHUB_REDIRECT_URI = os.getenv("GITHUB_REDIRECT_URI")
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:4200")

# ========== DATABASE CONFIG ==========
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    logger.error("❌ DATABASE_URL not found in .env file!")
    raise ValueError("DATABASE_URL environment variable is required")

database = Database(DATABASE_URL)

# ========== PASSWORD HASHING ==========
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    """Hash password using bcrypt"""
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against hash"""
    try:
        from passlib.hash import bcrypt
        return bcrypt.verify(plain_password, hashed_password)
    except Exception as e:
        logger.error(f"❌ Password verification error: {str(e)}")
        return False

# ========== JWT FUNCTIONS ==========
def create_access_token(data: dict, expires_delta: Optional[datetime.timedelta] = None):
    """Create JWT access token"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.datetime.now(datetime.timezone.utc) + expires_delta
    else:
        expire = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login", auto_error=False)

async def get_current_user(token: str = Depends(oauth2_scheme)):
    """Get current user from JWT token"""
    if not token:
        return None
    
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    user = await find_user_by_id(int(user_id))
    if user is None:
        raise credentials_exception
    return user

# ========== DATABASE LIFESPAN ==========
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("🔄 Connecting to PostgreSQL database...")
    try:
        await database.connect()
        logger.info("✅ Database connection established")
        
        # Drop and recreate tables to ensure schema is correct
        await drop_tables()
        
        # Create tables
        await create_tables()
        
        # Create test users
        await create_test_users()
        
        print("\n" + "="*80)
        print("🚀 AUTH SERVICE STARTED SUCCESSFULLY!")
        print("="*80)
        print(f"📡 Server: http://localhost:{os.getenv('PORT', 8000)}")
        print(f"📝 API Docs: http://localhost:{os.getenv('PORT', 8000)}/docs")
        print(f"🗄️  Database: PostgreSQL on Neon")
        print("\n✅ Test Users:")
        print("   └─ 📧 test@example.com / Test@123")
        print("   └─ 📧 john@example.com / Test@123")
        print("\n🔐 GitHub OAuth Ready!")
        print("   └─ Client ID:", GITHUB_CLIENT_ID[:10] + "..." if GITHUB_CLIENT_ID else "Not Set")
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
    description="Authentication microservice with GitHub OAuth",
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
        "http://192.168.1.42:4200",
        FRONTEND_URL
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
    github_id: Optional[str] = None
    avatar_url: Optional[str] = None
    github_access_token: Optional[str] = None

class AuthResponse(BaseModel):
    success: bool
    message: str
    token: Optional[str] = None
    user: Optional[UserResponse] = None

class Repository(BaseModel):
    id: int
    name: str
    full_name: str
    description: Optional[str] = None
    html_url: str
    language: Optional[str] = None
    stargazers_count: int
    forks_count: int
    private: bool
    updated_at: str

# ========== DATABASE FUNCTIONS ==========

async def drop_tables():
    """Drop existing tables for clean schema"""
    try:
        await database.execute("DROP TABLE IF EXISTS users CASCADE")
        logger.info("✅ Dropped existing tables")
    except Exception as e:
        logger.error(f"❌ Error dropping tables: {str(e)}")

async def create_tables():
    """Create all necessary tables"""
    try:
        # Users table with all required columns
        create_users_table = """
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            name VARCHAR(100) NOT NULL,
            email VARCHAR(255) UNIQUE NOT NULL,
            password VARCHAR(255),
            github_id VARCHAR(100) UNIQUE,
            avatar_url TEXT,
            github_access_token TEXT,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );
        """
        
        await database.execute(query=create_users_table)
        logger.info("✅ Database tables created/verified")
        
    except Exception as e:
        logger.error(f"❌ Error creating tables: {str(e)}")
        traceback.print_exc()
        raise

async def create_test_users():
    """Create test users if not exists"""
    try:
        # Check if test user exists
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
            
            await database.execute(
                query=insert_query,
                values={
                    "name": "John Doe",
                    "email": "john@example.com",
                    "password": hashed,
                    "created_at": datetime.datetime.now()
                }
            )
            logger.info("✅ Test users created")
        else:
            logger.info("✅ Test users already exist")
            
    except Exception as e:
        logger.error(f"❌ Error creating test users: {str(e)}")
        traceback.print_exc()

async def find_user_by_email(email: str):
    """Find user by email"""
    query = "SELECT id, name, email, password, created_at, github_id, avatar_url, github_access_token FROM users WHERE email = :email"
    return await database.fetch_one(query=query, values={"email": email})

async def find_user_by_github_id(github_id: str):
    """Find user by GitHub ID"""
    query = "SELECT id, name, email, created_at, github_id, avatar_url, github_access_token FROM users WHERE github_id = :github_id"
    return await database.fetch_one(query=query, values={"github_id": github_id})

async def find_user_by_id(user_id: int):
    """Find user by ID"""
    query = "SELECT id, name, email, created_at, github_id, avatar_url, github_access_token FROM users WHERE id = :id"
    return await database.fetch_one(query=query, values={"id": user_id})

async def update_user_github_token(user_id: int, access_token: str):
    """Update user's GitHub access token"""
    query = """
    UPDATE users 
    SET github_access_token = :token 
    WHERE id = :id
    """
    await database.execute(
        query=query,
        values={
            "token": access_token,
            "id": user_id
        }
    )

async def create_github_user(github_data: dict, access_token: str = None):
    """Create or update user from GitHub data"""
    try:
        existing = await find_user_by_github_id(str(github_data['id']))
        
        if existing:
            # Update existing user
            update_query = """
            UPDATE users 
            SET name = :name, email = :email, avatar_url = :avatar_url,
                github_access_token = COALESCE(:token, github_access_token)
            WHERE github_id = :github_id
            RETURNING id
            """
            user_id = await database.execute(
                query=update_query,
                values={
                    "name": github_data['name'] or github_data['login'],
                    "email": github_data['email'] or f"{github_data['login']}@github.user",
                    "avatar_url": github_data['avatar_url'],
                    "github_id": str(github_data['id']),
                    "token": access_token
                }
            )
        else:
            # Check if email exists
            if github_data.get('email'):
                email_user = await find_user_by_email(github_data['email'])
                if email_user:
                    # Link GitHub to existing account
                    update_query = """
                    UPDATE users 
                    SET github_id = :github_id, avatar_url = :avatar_url,
                        github_access_token = :token
                    WHERE id = :id
                    RETURNING id
                    """
                    user_id = await database.execute(
                        query=update_query,
                        values={
                            "github_id": str(github_data['id']),
                            "avatar_url": github_data['avatar_url'],
                            "token": access_token,
                            "id": email_user['id']
                        }
                    )
                    return user_id
            
            # Create new user
            insert_query = """
            INSERT INTO users (name, email, password, github_id, avatar_url, github_access_token, created_at)
            VALUES (:name, :email, :password, :github_id, :avatar_url, :token, :created_at)
            RETURNING id
            """
            user_id = await database.execute(
                query=insert_query,
                values={
                    "name": github_data['name'] or github_data['login'],
                    "email": github_data['email'] or f"{github_data['login']}@github.user",
                    "password": None,
                    "github_id": str(github_data['id']),
                    "avatar_url": github_data['avatar_url'],
                    "token": access_token,
                    "created_at": datetime.datetime.now()
                }
            )
        
        return user_id
    except Exception as e:
        logger.error(f"❌ Error creating GitHub user: {str(e)}")
        traceback.print_exc()
        raise

# ========== GITHUB OAUTH ENDPOINTS ==========

@app.get("/auth/github/login")
async def github_login():
    """Redirect to GitHub OAuth login"""
    if not GITHUB_CLIENT_ID:
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"success": False, "message": "GitHub OAuth not configured"}
        )
    
    params = {
        "client_id": GITHUB_CLIENT_ID,
        "redirect_uri": GITHUB_REDIRECT_URI,
        "scope": "user:email repo",  # Added 'repo' scope for private repos
        "state": secrets.token_urlsafe(16)
    }
    
    github_auth_url = f"https://github.com/login/oauth/authorize?{urlencode(params)}"
    return RedirectResponse(url=github_auth_url)

@app.get("/auth/github/callback")
async def github_callback(code: str, state: str = None):
    """GitHub OAuth callback"""
    try:
        token_url = "https://github.com/login/oauth/access_token"
        token_params = {
            "client_id": GITHUB_CLIENT_ID,
            "client_secret": GITHUB_CLIENT_SECRET,
            "code": code,
            "redirect_uri": GITHUB_REDIRECT_URI
        }
        
        async with httpx.AsyncClient() as client:
            # Get access token
            token_response = await client.post(
                token_url,
                params=token_params,
                headers={"Accept": "application/json"}
            )
            token_data = token_response.json()
            
            if "error" in token_data:
                logger.error(f"GitHub token error: {token_data}")
                return RedirectResponse(url=f"{FRONTEND_URL}/auth/login?error=github_auth_failed")
            
            access_token = token_data.get("access_token")
            
            # Get user info from GitHub
            user_response = await client.get(
                "https://api.github.com/user",
                headers={"Authorization": f"Bearer {access_token}"}
            )
            github_user = user_response.json()
            
            # Get user emails
            emails_response = await client.get(
                "https://api.github.com/user/emails",
                headers={"Authorization": f"Bearer {access_token}"}
            )
            emails = emails_response.json()
            
            primary_email = None
            for email in emails:
                if email.get("primary") and email.get("verified"):
                    primary_email = email.get("email")
                    break
            
            if not primary_email:
                primary_email = emails[0].get("email") if emails else None
            
            github_user["email"] = primary_email
        
        # Create or update user in database with access token
        user_id = await create_github_user(github_user, access_token)
        
        # Create JWT token
        jwt_token = create_access_token(data={"sub": str(user_id)})
        
        # Redirect to frontend
        frontend_url = f"{FRONTEND_URL}/auth/github-callback?token={jwt_token}"
        
        return RedirectResponse(url=frontend_url)
        
    except Exception as e:
        logger.error(f"❌ GitHub callback error: {str(e)}")
        traceback.print_exc()
        return RedirectResponse(url=f"{FRONTEND_URL}/auth/login?error=github_auth_failed")

@app.get("/auth/github/token")
async def github_token_exchange(token: str):
    """Exchange GitHub token for user info"""
    try:
        # Decode token to get user_id
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            user_id = payload.get("sub")
            if not user_id:
                return JSONResponse(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    content={"success": False, "message": "Invalid token"}
                )
        except JWTError:
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"success": False, "message": "Invalid token"}
            )
        
        # Get user from database
        user = await find_user_by_id(int(user_id))
        if not user:
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"success": False, "message": "User not found"}
            )
        
        # Convert to dict
        user_dict = dict(user)
        
        return {
            "success": True,
            "user": {
                "id": user_dict.get('id'),
                "name": user_dict.get('name'),
                "email": user_dict.get('email'),
                "avatar_url": user_dict.get('avatar_url'),
                "github_id": user_dict.get('github_id')
            }
        }
    except Exception as e:
        logger.error(f"❌ Token exchange error: {str(e)}")
        traceback.print_exc()
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"success": False, "message": str(e)}
        )

# ========== GITHUB REPOSITORIES ENDPOINTS ==========

@app.get("/github/repositories")
async def get_github_repositories(current_user = Depends(get_current_user)):
    """Get GitHub repositories for the authenticated user"""
    try:
        if not current_user:
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"success": False, "message": "Not authenticated"}
            )
        
        # Get user's GitHub access token from database
        query = "SELECT github_access_token, github_id FROM users WHERE id = :id"
        user_token = await database.fetch_one(query=query, values={"id": current_user['id']})
        
        if not user_token or not user_token['github_access_token']:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"success": False, "message": "No GitHub account connected"}
            )
        
        # Fetch repositories from GitHub API
        async with httpx.AsyncClient() as client:
            repos_response = await client.get(
                "https://api.github.com/user/repos?sort=updated&per_page=100",
                headers={
                    "Authorization": f"Bearer {user_token['github_access_token']}",
                    "Accept": "application/vnd.github.v3+json"
                }
            )
            
            if repos_response.status_code != 200:
                logger.error(f"GitHub API error: {repos_response.status_code}")
                return JSONResponse(
                    status_code=repos_response.status_code,
                    content={"success": False, "message": "Failed to fetch repositories"}
                )
            
            repos_data = repos_response.json()
            
            # Format repositories
            repositories = []
            for repo in repos_data:
                repositories.append({
                    "id": repo["id"],
                    "name": repo["name"],
                    "full_name": repo["full_name"],
                    "description": repo["description"],
                    "html_url": repo["html_url"],
                    "language": repo["language"],
                    "stargazers_count": repo["stargazers_count"],
                    "forks_count": repo["forks_count"],
                    "private": repo["private"],
                    "updated_at": repo["updated_at"]
                })
            
            return repositories
            
    except Exception as e:
        logger.error(f"❌ Error fetching repositories: {str(e)}")
        traceback.print_exc()
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"success": False, "message": str(e)}
        )

@app.get("/github/repo/{owner}/{repo}")
async def get_github_repository(owner: str, repo: str, current_user = Depends(get_current_user)):
    """Get a specific GitHub repository"""
    try:
        if not current_user:
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"success": False, "message": "Not authenticated"}
            )
        
        # Get user's GitHub access token from database
        query = "SELECT github_access_token FROM users WHERE id = :id"
        user_token = await database.fetch_one(query=query, values={"id": current_user['id']})
        
        if not user_token or not user_token['github_access_token']:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"success": False, "message": "No GitHub account connected"}
            )
        
        # Fetch repository from GitHub API
        async with httpx.AsyncClient() as client:
            repo_response = await client.get(
                f"https://api.github.com/repos/{owner}/{repo}",
                headers={
                    "Authorization": f"Bearer {user_token['github_access_token']}",
                    "Accept": "application/vnd.github.v3+json"
                }
            )
            
            if repo_response.status_code != 200:
                error_msg = "Repository not found"
                try:
                    error_data = repo_response.json()
                    error_msg = error_data.get('message', error_msg)
                except:
                    pass
                    
                return JSONResponse(
                    status_code=repo_response.status_code,
                    content={"success": False, "message": error_msg}
                )
            
            repo_data = repo_response.json()
            
            return {
                "id": repo_data["id"],
                "name": repo_data["name"],
                "full_name": repo_data["full_name"],
                "description": repo_data["description"],
                "html_url": repo_data["html_url"],
                "language": repo_data["language"],
                "stargazers_count": repo_data["stargazers_count"],
                "forks_count": repo_data["forks_count"],
                "private": repo_data["private"],
                "updated_at": repo_data["updated_at"]
            }
            
    except Exception as e:
        logger.error(f"❌ Error fetching repository: {str(e)}")
        traceback.print_exc()
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"success": False, "message": str(e)}
        )

# ========== EMAIL/PASSWORD ENDPOINTS ==========

@app.post("/auth/register", response_model=AuthResponse, status_code=status.HTTP_201_CREATED)
async def register(user_data: UserRegister):
    """Register new user"""
    try:
        logger.info(f"📝 Registration attempt: {user_data.email}")
        
        existing = await find_user_by_email(user_data.email)
        if existing:
            return JSONResponse(
                status_code=status.HTTP_409_CONFLICT,
                content={
                    "success": False,
                    "message": "Email already exists"
                }
            )
        
        hashed = hash_password(user_data.password)
        
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
        
        access_token = create_access_token(data={"sub": str(user_id)})
        
        logger.info(f"✅ User registered: {user_data.email} (ID: {user_id})")
        
        return {
            "success": True,
            "message": "Registration successful",
            "token": access_token,
            "user": {
                "id": user_id,
                "name": user_data.name,
                "email": user_data.email,
                "created_at": datetime.datetime.now().isoformat(),
                "github_id": None,
                "avatar_url": None
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
        
        user_record = await find_user_by_email(login_data.email)
        
        if not user_record:
            logger.warning(f"❌ User not found: {login_data.email}")
            return JSONResponse(
                status_code=status.HTTP_404_NOT_FOUND,
                content={
                    "success": False,
                    "message": "User not found. Please register first."
                }
            )
        
        user = dict(user_record)
        
        if not user.get('password'):
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={
                    "success": False,
                    "message": "This account uses GitHub login. Please login with GitHub."
                }
            )
        
        if not verify_password(login_data.password, user['password']):
            logger.warning(f"❌ Invalid password for: {login_data.email}")
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={
                    "success": False,
                    "message": "Invalid email or password."
                }
            )
        
        access_token = create_access_token(data={"sub": str(user['id'])})
        
        logger.info(f"✅ Login successful: {login_data.email}")
        
        created_at_str = None
        if user.get('created_at'):
            created_at_str = user['created_at'].isoformat() if hasattr(user['created_at'], 'isoformat') else str(user['created_at'])
        
        return {
            "success": True,
            "message": "Login successful",
            "token": access_token,
            "user": {
                "id": user.get('id'),
                "name": user.get('name'),
                "email": user.get('email'),
                "created_at": created_at_str,
                "github_id": user.get('github_id'),
                "avatar_url": user.get('avatar_url')
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

# ========== PROTECTED ENDPOINTS ==========

@app.get("/auth/me")
async def get_current_user_info(current_user = Depends(get_current_user)):
    """Get current user info"""
    if not current_user:
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"success": False, "message": "Not authenticated"}
        )
    
    if hasattr(current_user, '_mapping'):
        current_user = dict(current_user)
    
    return {
        "success": True,
        "user": {
            "id": current_user.get('id'),
            "name": current_user.get('name'),
            "email": current_user.get('email'),
            "avatar_url": current_user.get('avatar_url'),
            "github_id": current_user.get('github_id'),
            "created_at": current_user.get('created_at').isoformat() if current_user.get('created_at') else None
        }
    }

@app.post("/auth/logout")
async def logout():
    """Logout user"""
    return {"success": True, "message": "Logged out successfully"}

@app.get("/auth/users")
async def get_all_users():
    """Get all users"""
    try:
        query = "SELECT id, name, email, created_at, github_id, avatar_url, github_access_token FROM users ORDER BY id"
        rows = await database.fetch_all(query=query)
        
        users = []
        for row in rows:
            user_dict = dict(row)
            created_at_str = None
            if user_dict.get('created_at'):
                created_at_str = user_dict['created_at'].isoformat() if hasattr(user_dict['created_at'], 'isoformat') else str(user_dict['created_at'])
            
            users.append({
                "id": user_dict.get('id'),
                "name": user_dict.get('name'),
                "email": user_dict.get('email'),
                "github_id": user_dict.get('github_id'),
                "avatar_url": user_dict.get('avatar_url'),
                "created_at": created_at_str
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
@app.get("/github/repo/{owner}/{repo}/contents/{path:path}")
async def get_repo_contents(owner: str, repo: str, path: str = "", current_user = Depends(get_current_user)):
    """Get contents of a repository path"""
    try:
        if not current_user:
            return JSONResponse(status_code=401, content={"success": False, "message": "Not authenticated"})
        
        # Get user's GitHub access token
        query = "SELECT github_access_token FROM users WHERE id = :id"
        user_token = await database.fetch_one(query=query, values={"id": current_user['id']})
        
        if not user_token or not user_token['github_access_token']:
            return JSONResponse(status_code=400, content={"success": False, "message": "No GitHub account connected"})
        
        # Fetch contents from GitHub API
        async with httpx.AsyncClient() as client:
            contents_response = await client.get(
                f"https://api.github.com/repos/{owner}/{repo}/contents/{path}",
                headers={
                    "Authorization": f"Bearer {user_token['github_access_token']}",
                    "Accept": "application/vnd.github.v3+json"
                }
            )
            
            if contents_response.status_code != 200:
                return JSONResponse(
                    status_code=contents_response.status_code,
                    content={"success": False, "message": "Failed to fetch contents"}
                )
            
            contents = contents_response.json()
            
            # Format the response
            formatted_contents = []
            for item in contents:
                formatted_contents.append({
                    "name": item["name"],
                    "path": item["path"],
                    "type": item["type"],  # "file" or "dir"
                    "size": item.get("size", 0),
                    "download_url": item.get("download_url"),
                    "html_url": item["html_url"]
                })
            
            return formatted_contents
            
    except Exception as e:
        logger.error(f"❌ Error fetching contents: {str(e)}")
        return JSONResponse(status_code=500, content={"success": False, "message": str(e)})
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

# ========== BASIC ENDPOINTS ==========
@app.get("/")
async def root():
    return {"service": "auth-service", "status": "running"}

@app.get("/health")
async def health():
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
    return {
        "service": "Auth Service",
        "version": "1.0.0",
        "environment": os.getenv("ENVIRONMENT", "development")
    }

@app.get("/test")
async def test():
    return {"message": "Backend is working!"}

@app.get("/api-status")
async def api_status():
    return {
        "status": "running",
        "endpoints": {
            "root": "/",
            "health": "/health",
            "info": "/info",
            "test": "/test",
            "api-status": "/api-status",
            "auth": {
                "register": "/auth/register",
                "login": "/auth/login",
                "logout": "/auth/logout",
                "me": "/auth/me",
                "github_login": "/auth/github/login",
                "github_callback": "/auth/github/callback",
                "github_token": "/auth/github/token"
            },
            "github": {
                "repositories": "/github/repositories",
                "repo": "/github/repo/{owner}/{repo}"
            },
            "users": {
                "all": "/auth/users"
            },
            "debug": "/debug/routes"
        }
    }
    

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
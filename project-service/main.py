import os
import uvicorn
from fastapi import FastAPI, HTTPException, status, Depends, File, UploadFile, Form, Request
from fastapi.responses import JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
import datetime
from pydantic import BaseModel
from typing import Optional, List
import asyncpg
from databases import Database
import logging
import traceback
import httpx
import aiofiles
import re
from pathlib import Path

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
AUTH_SERVICE_URL = os.getenv("AUTH_SERVICE_URL", "http://localhost:8000")

# ========== DATABASE CONFIG ==========
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    logger.error("❌ DATABASE_URL not found in .env file!")
    raise ValueError("DATABASE_URL environment variable is required")

database = Database(DATABASE_URL)

# ========== FILE STORAGE CONFIG ==========
UPLOAD_DIR = "uploads"
Path(UPLOAD_DIR).mkdir(exist_ok=True)

# ========== FASTAPI APP ==========
app = FastAPI(
    title="Project Service",
    version="1.0.0",
    description="Project management and file handling service",
    docs_url="/docs",
    redoc_url="/redoc"
)

# ========== CORS CONFIG ==========
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:4200",
        "http://127.0.0.1:4200",
        "http://localhost:8000",
        "http://localhost:8001",
        "http://localhost:8002",
        "http://localhost:8003",
        "http://localhost:8004",
        "http://localhost:8005"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*", "Authorization", "Content-Type"],
    expose_headers=["*"]
)

# ========== HTTPX CLIENT ==========
client = httpx.AsyncClient(timeout=30.0)

# ========== JWT VALIDATION - ONLY THROUGH AUTH SERVICE ==========

async def verify_token_with_auth_service(token: str):
    """Verify JWT token with auth service only"""
    try:
        logger.info(f"🔐 Verifying token with auth service: {token[:30]}...")
        
        async with httpx.AsyncClient(timeout=10.0) as auth_client:
            response = await auth_client.get(
                f"{AUTH_SERVICE_URL}/auth/me",
                headers={"Authorization": f"Bearer {token}"}
            )
            
            logger.info(f"📡 Auth service response status: {response.status_code}")
            
            if response.status_code == 200:
                data = response.json()
                logger.info(f"✅ Auth service verification successful")
                return data.get("user")
            else:
                logger.warning(f"❌ Auth service returned {response.status_code}")
                logger.warning(f"❌ Response: {response.text}")
                return None
            
    except Exception as e:
        logger.error(f"❌ Auth service connection failed: {str(e)}")
        return None

async def get_current_user(request: Request):
    """Get current user from token using auth service only"""
    try:
        # Get authorization header from request
        authorization = request.headers.get("authorization")
        
        # Log the authorization header for debugging
        logger.info(f"🔑 get_current_user called")
        logger.info(f"🔑 Authorization header: '{authorization}'")
        
        if not authorization:
            logger.warning("❌ No authorization header received")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Not authenticated - No token provided"
            )
        
        # Extract token from Bearer header
        if authorization.startswith("Bearer "):
            token = authorization[7:]
            logger.info(f"✅ Bearer token extracted, length: {len(token)}")
        else:
            token = authorization
            logger.info(f"⚠️ Raw token (no Bearer prefix), length: {len(token)}")
        
        logger.info(f"🔑 Token preview: {token[:30]}...")
        
        # Verify token with auth service
        auth_url = f"{AUTH_SERVICE_URL}/auth/me"
        logger.info(f"📡 Calling auth service at: {auth_url}")
        
        async with httpx.AsyncClient(timeout=10.0) as auth_client:
            response = await auth_client.get(
                auth_url,
                headers={"Authorization": f"Bearer {token}"}
            )
            
            logger.info(f"📡 Auth service response status: {response.status_code}")
            
            if response.status_code == 200:
                data = response.json()
                user = data.get("user")
                logger.info(f"✅ User authenticated: {user}")
                return user
            else:
                response_text = await response.aread()
                logger.error(f"❌ Auth service returned {response.status_code}: {response_text[:200]}")
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail=f"Authentication failed - Auth service returned {response.status_code}"
                )
        
    except httpx.ConnectError as e:
        logger.error(f"❌ Cannot connect to auth service at {AUTH_SERVICE_URL}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Auth service unavailable - {AUTH_SERVICE_URL}"
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error in get_current_user: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Authentication failed: {str(e)}"
        )

# ========== DATA MODELS ==========

class ProjectCreate(BaseModel):
    name: str
    description: Optional[str] = None
    github_url: Optional[str] = None

class ProjectResponse(BaseModel):
    id: int
    name: str
    description: Optional[str] = None
    github_url: Optional[str] = None
    user_id: int
    created_at: str
    updated_at: str

class SearchHistoryResponse(BaseModel):
    id: int
    user_id: int
    search_type: str
    query: str
    result_summary: Optional[str] = None
    created_at: str

class FileUploadResponse(BaseModel):
    filename: str
    file_size: int
    file_type: str
    upload_path: str
    user_id: int
    created_at: str

# ========== DATABASE FUNCTIONS ==========

async def create_tables():
    """Create all necessary tables"""
    try:
        # Projects table
        create_projects_table = """
        CREATE TABLE IF NOT EXISTS projects (
            id SERIAL PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            description TEXT,
            github_url VARCHAR(500),
            user_id INTEGER NOT NULL,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );
        """
        
        # Search history table
        create_history_table = """
        CREATE TABLE IF NOT EXISTS search_history (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL,
            search_type VARCHAR(50) NOT NULL,
            query TEXT NOT NULL,
            result_summary TEXT,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );
        """
        
        # Uploaded files table
        create_files_table = """
        CREATE TABLE IF NOT EXISTS uploaded_files (
            id SERIAL PRIMARY KEY,
            filename VARCHAR(500) NOT NULL,
            file_path VARCHAR(1000) NOT NULL,
            file_size INTEGER NOT NULL,
            file_type VARCHAR(100),
            user_id INTEGER NOT NULL,
            project_id INTEGER REFERENCES projects(id) ON DELETE SET NULL,
            created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
        );
        """
        
        await database.execute(query=create_projects_table)
        await database.execute(query=create_history_table)
        await database.execute(query=create_files_table)
        
        logger.info("✅ Database tables created/verified")
        
    except Exception as e:
        logger.error(f"❌ Error creating tables: {str(e)}")
        traceback.print_exc()
        raise

async def save_search_history(user_id: int, search_type: str, query: str, result_summary: str = None):
    """Save user search history"""
    try:
        query_insert = """
        INSERT INTO search_history (user_id, search_type, query, result_summary, created_at)
        VALUES (:user_id, :search_type, :query, :result_summary, :created_at)
        """
        await database.execute(
            query=query_insert,
            values={
                "user_id": user_id,
                "search_type": search_type,
                "query": query,
                "result_summary": result_summary,
                "created_at": datetime.datetime.now()
            }
        )
        logger.info(f"✅ Search history saved for user {user_id}")
    except Exception as e:
        logger.error(f"❌ Error saving search history: {str(e)}")

async def get_user_search_history(user_id: int, limit: int = 20):
    """Get user's search history"""
    query = """
    SELECT id, user_id, search_type, query, result_summary, created_at
    FROM search_history
    WHERE user_id = :user_id
    ORDER BY created_at DESC
    LIMIT :limit
    """
    return await database.fetch_all(query=query, values={"user_id": user_id, "limit": limit})

async def get_user_github_token(user_id: int):
    """Get user's GitHub token from auth service"""
    try:
        response = await client.get(
            f"{AUTH_SERVICE_URL}/auth/github/token/user/{user_id}"
        )
        
        if response.status_code == 200:
            data = response.json()
            return data.get("github_access_token")
        else:
            logger.warning(f"Failed to get GitHub token for user {user_id}")
            return None
    except Exception as e:
        logger.error(f"Error getting GitHub token: {str(e)}")
        return None

# ========== PROJECT ENDPOINTS ==========

@app.post("/projects", response_model=ProjectResponse, status_code=status.HTTP_201_CREATED)
async def create_project(
    request: Request,
    project: ProjectCreate
):
    """Create a new project"""
    try:
        logger.info("📝 Create project request received")
        
        user = await get_current_user(request)
        if not user:
            logger.error("❌ User authentication failed")
            raise HTTPException(status_code=401, detail="Not authenticated")
        
        logger.info(f"✅ User authenticated: {user}")
        
        insert_query = """
        INSERT INTO projects (name, description, github_url, user_id, created_at, updated_at)
        VALUES (:name, :description, :github_url, :user_id, :created_at, :created_at)
        RETURNING id
        """
        created_at = datetime.datetime.now()
        
        project_id = await database.execute(
            query=insert_query,
            values={
                "name": project.name,
                "description": project.description,
                "github_url": project.github_url,
                "user_id": user["id"],
                "created_at": created_at
            }
        )
        
        # Save search history
        await save_search_history(
            user_id=user["id"],
            search_type="project_create",
            query=project.name,
            result_summary=project.description
        )
        
        return {
            "id": project_id,
            "name": project.name,
            "description": project.description,
            "github_url": project.github_url,
            "user_id": user["id"],
            "created_at": created_at.isoformat(),
            "updated_at": created_at.isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error creating project: {str(e)}")
        traceback.print_exc()
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"success": False, "message": str(e)}
        )

@app.get("/projects", response_model=List[ProjectResponse])
async def get_user_projects(request: Request):
    """Get all projects for current user"""
    try:
        logger.info("📋 Get projects request received")
        
        user = await get_current_user(request)
        if not user:
            logger.error("❌ User authentication failed")
            raise HTTPException(status_code=401, detail="Not authenticated")
        
        query = """
        SELECT id, name, description, github_url, user_id, created_at, updated_at
        FROM projects
        WHERE user_id = :user_id
        ORDER BY created_at DESC
        """
        rows = await database.fetch_all(query=query, values={"user_id": user["id"]})
        
        projects = []
        for row in rows:
            projects.append({
                "id": row["id"],
                "name": row["name"],
                "description": row["description"],
                "github_url": row["github_url"],
                "user_id": row["user_id"],
                "created_at": row["created_at"].isoformat(),
                "updated_at": row["updated_at"].isoformat()
            })
        
        logger.info(f"✅ Found {len(projects)} projects")
        return projects
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error fetching projects: {str(e)}")
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"success": False, "message": str(e)}
        )

# ========== SEARCH HISTORY ENDPOINTS ==========

@app.get("/history", response_model=List[SearchHistoryResponse])
async def get_search_history(request: Request):
    """Get user's search history"""
    try:
        logger.info("📜 Get search history request received")
        
        user = await get_current_user(request)
        if not user:
            raise HTTPException(status_code=401, detail="Not authenticated")
        
        history = await get_user_search_history(user["id"])
        
        result = []
        for h in history:
            result.append({
                "id": h["id"],
                "user_id": h["user_id"],
                "search_type": h["search_type"],
                "query": h["query"],
                "result_summary": h["result_summary"],
                "created_at": h["created_at"].isoformat()
            })
        
        logger.info(f"✅ Found {len(result)} history items")
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error fetching history: {str(e)}")
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"success": False, "message": str(e)}
        )

@app.post("/history/github")
async def save_github_search(
    request: Request,
    repo_url: str,
    repo_data: dict
):
    """Save GitHub repository search to history"""
    try:
        logger.info(f"💾 Saving GitHub search to history: {repo_url}")
        
        user = await get_current_user(request)
        if not user:
            raise HTTPException(status_code=401, detail="Not authenticated")
        
        await save_search_history(
            user_id=user["id"],
            search_type="github_repo",
            query=repo_url,
            result_summary=f"Repository: {repo_data.get('full_name')} - {repo_data.get('description', 'No description')}"
        )
        
        return {"success": True, "message": "Search saved to history"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error saving search: {str(e)}")
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"success": False, "message": str(e)}
        )

# ========== FILE HANDLING ENDPOINTS ==========

@app.post("/files/upload", response_model=FileUploadResponse)
async def upload_file(
    request: Request,
    file: UploadFile = File(...),
    project_id: Optional[int] = Form(None)
):
    """Upload a file"""
    try:
        logger.info(f"📤 File upload request: {file.filename}")
        
        user = await get_current_user(request)
        if not user:
            raise HTTPException(status_code=401, detail="Not authenticated")
        
        # Create user directory if not exists
        user_dir = Path(f"{UPLOAD_DIR}/user_{user['id']}")
        user_dir.mkdir(exist_ok=True)
        
        # Generate unique filename
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_filename = f"{timestamp}_{file.filename}"
        file_path = user_dir / safe_filename
        
        # Save file
        file_size = 0
        async with aiofiles.open(file_path, 'wb') as f:
            content = await file.read()
            file_size = len(content)
            await f.write(content)
        
        # Save to database
        insert_query = """
        INSERT INTO uploaded_files (filename, file_path, file_size, file_type, user_id, project_id, created_at)
        VALUES (:filename, :file_path, :file_size, :file_type, :user_id, :project_id, :created_at)
        RETURNING id
        """
        
        file_id = await database.execute(
            query=insert_query,
            values={
                "filename": file.filename,
                "file_path": str(file_path),
                "file_size": file_size,
                "file_type": file.content_type,
                "user_id": user["id"],
                "project_id": project_id,
                "created_at": datetime.datetime.now()
            }
        )
        
        # Save search history
        await save_search_history(
            user_id=user["id"],
            search_type="file_upload",
            query=file.filename,
            result_summary=f"Uploaded file: {file.filename} ({file_size} bytes)"
        )
        
        return {
            "filename": file.filename,
            "file_size": file_size,
            "file_type": file.content_type,
            "upload_path": str(file_path),
            "user_id": user["id"],
            "created_at": datetime.datetime.now().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error uploading file: {str(e)}")
        traceback.print_exc()
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"success": False, "message": str(e)}
        )

@app.get("/files")
async def get_user_files(request: Request):
    """Get all files for current user"""
    try:
        logger.info("📋 Get files request received")
        
        user = await get_current_user(request)
        if not user:
            raise HTTPException(status_code=401, detail="Not authenticated")
        
        query = """
        SELECT id, filename, file_path, file_size, file_type, project_id, created_at
        FROM uploaded_files
        WHERE user_id = :user_id
        ORDER BY created_at DESC
        """
        rows = await database.fetch_all(query=query, values={"user_id": user["id"]})
        
        files = []
        for row in rows:
            files.append({
                "id": row["id"],
                "filename": row["filename"],
                "file_path": row["file_path"],
                "file_size": row["file_size"],
                "file_type": row["file_type"],
                "project_id": row["project_id"],
                "created_at": row["created_at"].isoformat()
            })
        
        logger.info(f"✅ Found {len(files)} files")
        return files
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error fetching files: {str(e)}")
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"success": False, "message": str(e)}
        )

@app.get("/files/{file_id}/download")
async def download_file(
    file_id: int,
    request: Request
):
    """Download a file"""
    try:
        logger.info(f"⬇️ Download file request: {file_id}")
        
        user = await get_current_user(request)
        if not user:
            raise HTTPException(status_code=401, detail="Not authenticated")
        
        query = "SELECT file_path, filename FROM uploaded_files WHERE id = :id AND user_id = :user_id"
        file_record = await database.fetch_one(query=query, values={"id": file_id, "user_id": user["id"]})
        
        if not file_record:
            raise HTTPException(status_code=404, detail="File not found")
        
        return FileResponse(
            path=file_record["file_path"],
            filename=file_record["filename"],
            media_type="application/octet-stream"
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error downloading file: {str(e)}")
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"success": False, "message": str(e)}
        )

# ========== SEARCH ENDPOINTS ==========

@app.post("/search/github")
async def search_github_repo(
    request: Request,
    repo_url: str
):
    """Search and save GitHub repository"""
    try:
        logger.info(f"🔍 GitHub search request: {repo_url}")
        
        user = await get_current_user(request)
        if not user:
            raise HTTPException(status_code=401, detail="Not authenticated")
        
        # Extract owner and repo from URL
        match = re.match(r"github\.com[\/:]([^\/]+)\/([^\/\s]+)", repo_url)
        if not match:
            raise HTTPException(status_code=400, detail="Invalid GitHub URL")
        
        owner, repo = match.groups()
        
        # Get user's GitHub token from auth service
        github_token = await get_user_github_token(user["id"])
        
        if not github_token:
            raise HTTPException(status_code=400, detail="GitHub account not connected")
        
        # Fetch repo data from GitHub
        repo_response = await client.get(
            f"https://api.github.com/repos/{owner}/{repo}",
            headers={"Authorization": f"Bearer {github_token}"}
        )
        
        if repo_response.status_code != 200:
            raise HTTPException(status_code=400, detail="Repository not found")
        
        repo_data = repo_response.json()
        
        # Save to search history
        await save_search_history(
            user_id=user["id"],
            search_type="github_repo",
            query=repo_url,
            result_summary=f"Repository: {repo_data.get('full_name')} - {repo_data.get('description', 'No description')}"
        )
        
        return {
            "success": True,
            "repo_data": repo_data,
            "message": "Repository search saved to history"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error searching GitHub: {str(e)}")
        traceback.print_exc()
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"success": False, "message": str(e)}
        )

# ========== GITHUB FILE CONTENT ENDPOINT ==========

@app.get("/github/repo/{owner}/{repo}/file/{path:path}")
async def get_file_content(owner: str, repo: str, path: str, request: Request):
    """Get content of a specific file from GitHub"""
    try:
        logger.info(f"📄 Getting file content: {owner}/{repo}/{path}")
        
        user = await get_current_user(request)
        if not user:
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"success": False, "message": "Not authenticated"}
            )
        
        # Get user's GitHub access token from database
        query = "SELECT github_access_token FROM users WHERE id = :id"
        user_token = await database.fetch_one(query=query, values={"id": user['id']})
        
        if not user_token or not user_token['github_access_token']:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"success": False, "message": "No GitHub account connected"}
            )
        
        # Fetch file content from GitHub API
        async with httpx.AsyncClient() as github_client:
            # First, get file metadata to check if it's a file
            file_response = await github_client.get(
                f"https://api.github.com/repos/{owner}/{repo}/contents/{path}",
                headers={
                    "Authorization": f"Bearer {user_token['github_access_token']}",
                    "Accept": "application/vnd.github.v3+json"
                }
            )
            
            if file_response.status_code != 200:
                return JSONResponse(
                    status_code=file_response.status_code,
                    content={"success": False, "message": "File not found"}
                )
            
            file_data = file_response.json()
            
            # If it's a file, get the content
            if file_data.get('type') == 'file':
                # For text files, get the content from download_url
                if file_data.get('download_url'):
                    content_response = await github_client.get(file_data['download_url'])
                    
                    # Detect if it's a binary file
                    content_type = content_response.headers.get('content-type', '')
                    
                    if 'text' in content_type or 'json' in content_type or 'javascript' in content_type:
                        # Text content
                        return {
                            "success": True,
                            "type": "text",
                            "name": file_data['name'],
                            "path": file_data['path'],
                            "content": content_response.text,
                            "size": file_data['size'],
                            "encoding": "utf-8",
                            "html_url": file_data['html_url']
                        }
                    else:
                        # Binary file - return as base64
                        import base64
                        content_bytes = content_response.content
                        content_base64 = base64.b64encode(content_bytes).decode('utf-8')
                        
                        return {
                            "success": True,
                            "type": "binary",
                            "name": file_data['name'],
                            "path": file_data['path'],
                            "content": content_base64,
                            "size": file_data['size'],
                            "encoding": "base64",
                            "html_url": file_data['html_url']
                        }
            
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"success": False, "message": "Not a file"}
            )
            
    except Exception as e:
        logger.error(f"❌ Error fetching file content: {str(e)}")
        traceback.print_exc()
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"success": False, "message": str(e)}
        )

# ========== DEBUG ENDPOINTS ==========

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
    return {"service": "project-service", "status": "running", "port": 8005}

@app.get("/health")
async def health():
    try:
        await database.execute("SELECT 1")
        db_status = "connected"
    except Exception as e:
        db_status = f"disconnected: {str(e)}"
    
    return {
        "status": "healthy",
        "service": "project-service",
        "database": db_status,
        "timestamp": datetime.datetime.now().isoformat()
    }

@app.get("/info")
async def info():
    return {
        "service": "Project Service",
        "version": "1.0.0",
        "port": 8005,
        "environment": os.getenv("ENVIRONMENT", "development")
    }

# ========== LIFESPAN ==========

@app.on_event("startup")
async def startup():
    print("\n" + "="*80)
    print("🚀 PROJECT SERVICE STARTING...")
    print("="*80)
    print(f"📡 Port: 8005")
    print(f"📝 API Docs: http://localhost:8005/docs")
    print(f"🔗 Auth Service: {AUTH_SERVICE_URL}")
    print("="*80 + "\n")
    
    await database.connect()
    await create_tables()

@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()
    await client.aclose()
    print("✅ Database connection closed")

# ========== MAIN ==========
if __name__ == "__main__":
    port = int(os.getenv("PORT", 8005))
    host = os.getenv("HOST", "0.0.0.0")
    debug = os.getenv("DEBUG", "False").lower() == "true"
    
    uvicorn.run(
        "main:app",
        host=host,
        port=port,
        reload=debug,
        log_level="info"
    )
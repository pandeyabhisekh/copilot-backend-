import os
import uvicorn
from fastapi import FastAPI, HTTPException, status, Depends, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
import datetime
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import httpx
import logging
import traceback
import asyncio
from pathlib import Path

# Load environment variables
load_dotenv()

# ========== LOGGING CONFIG ==========
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ========== OLLAMA CONFIG ==========
OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama2")
AUTH_SERVICE_URL = os.getenv("AUTH_SERVICE_URL", "http://localhost:8000")
PROJECT_SERVICE_URL = os.getenv("PROJECT_SERVICE_URL", "http://localhost:8005")

# ========== FASTAPI APP ==========
app = FastAPI(
    title="AI Code Analysis Service",
    version="1.0.0",
    description="AI-powered code analysis service using Ollama",
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
    allow_headers=["*"],
)

# ========== HTTPX CLIENT WITH LONGER TIMEOUT ==========
client = httpx.AsyncClient(timeout=120.0)

# ========== DATA MODELS ==========

class ChatMessage(BaseModel):
    role: str
    content: str

class QueryRequest(BaseModel):
    repo_full_name: str
    question: str
    user_id: int
    conversation_history: Optional[List[ChatMessage]] = []

class QueryResponse(BaseModel):
    success: bool
    answer: str
    sources: List[str] = []
    model_used: str
    processing_time: float

class RepoDocsRequest(BaseModel):
    repo_full_name: str
    user_id: int

# ========== AUTHENTICATION ==========

async def verify_token(authorization: str):
    """Verify token with auth service"""
    if not authorization:
        return None
    
    try:
        async with httpx.AsyncClient() as auth_client:
            response = await auth_client.get(
                f"{AUTH_SERVICE_URL}/auth/me",
                headers={"Authorization": authorization}
            )
            if response.status_code == 200:
                return response.json().get("user")
    except Exception as e:
        logger.error(f"Token verification error: {str(e)}")
    return None

async def get_current_user(request: Request):
    """Get current user from token"""
    authorization = request.headers.get("authorization")
    
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated"
        )
    
    user = await verify_token(authorization)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials"
        )
    
    return user

# ========== REPO ANALYSIS FUNCTIONS ==========

async def get_repo_contents_with_auth(repo_full_name: str, user_id: int, path: str = ""):
    """Get repository contents using project service with proper auth"""
    try:
        [owner, repo] = repo_full_name.split('/')
        
        # First get user's GitHub token from auth service
        async with httpx.AsyncClient() as auth_client:
            token_response = await auth_client.get(
                f"{AUTH_SERVICE_URL}/auth/github/token/user/{user_id}"
            )
            
            if token_response.status_code != 200:
                logger.error(f"Failed to get GitHub token for user {user_id}")
                return None
            
            github_token = token_response.json().get("github_access_token")
            if not github_token:
                logger.error(f"No GitHub token found for user {user_id}")
                return None
        
        # Use GitHub token directly to fetch repo contents
        async with httpx.AsyncClient() as github_client:
            url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"
            headers = {
                "Authorization": f"Bearer {github_token}",
                "Accept": "application/vnd.github.v3+json"
            }
            
            response = await github_client.get(url, headers=headers)
            
            if response.status_code == 200:
                return response.json()
            else:
                logger.error(f"GitHub API error: {response.status_code}")
                return None
                
    except Exception as e:
        logger.error(f"Error getting repo contents: {str(e)}")
        return None

async def get_all_files(repo_full_name: str, user_id: int, path: str = ""):
    """Recursively get all files from repository"""
    try:
        contents = await get_repo_contents_with_auth(repo_full_name, user_id, path)
        
        if not contents:
            return []
        
        all_files = []
        for item in contents:
            if item['type'] == 'dir':
                # Recursively get files from subdirectory
                sub_files = await get_all_files(repo_full_name, user_id, item['path'])
                all_files.extend(sub_files)
            else:
                all_files.append({
                    'name': item['name'],
                    'path': item['path'],
                    'type': 'file',
                    'size': item.get('size', 0),
                    'download_url': item.get('download_url'),
                    'html_url': item.get('html_url')
                })
        
        return all_files
        
    except Exception as e:
        logger.error(f"Error in get_all_files: {str(e)}")
        return []

async def get_file_content_direct(owner: str, repo: str, path: str, github_token: str):
    """Get file content directly from GitHub"""
    try:
        async with httpx.AsyncClient() as github_client:
            url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"
            headers = {
                "Authorization": f"Bearer {github_token}",
                "Accept": "application/vnd.github.v3+json"
            }
            
            response = await github_client.get(url, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('type') == 'file' and data.get('download_url'):
                    # Fetch actual content
                    content_response = await github_client.get(data['download_url'])
                    return content_response.text
            
    except Exception as e:
        logger.error(f"Error getting file content: {str(e)}")
    
    return None

# ========== API ENDPOINTS ==========

@app.get("/")
async def root():
    return {
        "service": "ai-code-analysis",
        "status": "running",
        "port": int(os.getenv("PORT", 8002)),
        "ollama_model": OLLAMA_MODEL
    }

@app.get("/health")
async def health():
    """Health check with Ollama status"""
    ollama_status = "unknown"
    try:
        async with httpx.AsyncClient(timeout=5.0) as ollama_client:
            response = await ollama_client.get(f"{OLLAMA_HOST}/api/tags")
            if response.status_code == 200:
                models = response.json().get('models', [])
                ollama_status = f"connected ({len(models)} models)"
            else:
                ollama_status = "not responding"
    except Exception as e:
        ollama_status = f"not reachable: {str(e)}"
    
    return {
        "status": "healthy",
        "service": "ai-code-analysis",
        "ollama": ollama_status,
        "timestamp": datetime.datetime.now().isoformat()
    }

@app.post("/api/analyze-repo")
async def analyze_repository(
    request: RepoDocsRequest,
    current_user = Depends(get_current_user)
):
    """Analyze repository structure and key components"""
    try:
        if current_user['id'] != request.user_id:
            raise HTTPException(status_code=403, detail="User ID mismatch")
        
        logger.info(f"🔍 Analyzing repo: {request.repo_full_name}")
        
        # Get all files
        all_files = await get_all_files(request.repo_full_name, request.user_id)
        
        # Categorize files
        backend_files = []
        frontend_files = []
        config_files = []
        docs_files = []
        
        for file in all_files:
            name = file['name'].lower()
            path = file['path'].lower()
            
            # Backend files
            if any(name.endswith(ext) for ext in ['.py', '.java', '.go', '.rb', '.php']):
                backend_files.append(file['path'])
            # Frontend files
            elif any(name.endswith(ext) for ext in ['.html', '.css', '.js', '.ts', '.jsx', '.tsx']):
                frontend_files.append(file['path'])
            # Config files
            elif any(name == f for f in ['package.json', 'requirements.txt', 'dockerfile', '.env.example']):
                config_files.append(file['path'])
            # Docs
            elif any(name.endswith(ext) for ext in ['.md', '.txt', '.rst']):
                docs_files.append(file['path'])
        
        structure = {
            'total_files': len(all_files),
            'backend_files': backend_files,
            'frontend_files': frontend_files,
            'config_files': config_files,
            'documentation_files': docs_files
        }
        
        # Get key files content (first 500 chars of important files)
        key_files = []
        important_paths = ['README.md', 'main.py', 'app.py', 'package.json', 'requirements.txt']
        
        for file in all_files:
            if file['name'] in important_paths:
                # Get file content
                [owner, repo] = request.repo_full_name.split('/')
                
                # Get GitHub token
                async with httpx.AsyncClient() as auth_client:
                    token_response = await auth_client.get(
                        f"{AUTH_SERVICE_URL}/auth/github/token/user/{request.user_id}"
                    )
                    if token_response.status_code == 200:
                        github_token = token_response.json().get("github_access_token")
                        if github_token:
                            content = await get_file_content_direct(owner, repo, file['path'], github_token)
                            if content:
                                key_files.append({
                                    'path': file['path'],
                                    'content': content[:500] + "..." if len(content) > 500 else content
                                })
        
        return {
            "success": True,
            "structure": structure,
            "key_files": key_files
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Analysis error: {str(e)}")
        traceback.print_exc()
        return JSONResponse(
            status_code=500,
            content={"success": False, "message": str(e)}
        )

@app.post("/api/query", response_model=QueryResponse)
async def query_codebase(
    request: QueryRequest,
    current_user = Depends(get_current_user)
):
    """Query the codebase using AI"""
    start_time = datetime.datetime.now()
    
    try:
        logger.info(f"🔍 AI Query for {request.repo_full_name}")
        
        if current_user['id'] != request.user_id:
            raise HTTPException(status_code=403, detail="User ID mismatch")
        
        # Get all files
        all_files = await get_all_files(request.repo_full_name, request.user_id)
        
        if not all_files:
            return QueryResponse(
                success=False,
                answer="Could not access repository files. Make sure you have access.",
                sources=[],
                model_used=OLLAMA_MODEL,
                processing_time=(datetime.datetime.now() - start_time).total_seconds()
            )
        
        # Get important files for context
        context_files = []
        [owner, repo] = request.repo_full_name.split('/')
        
        # Get GitHub token
        async with httpx.AsyncClient() as auth_client:
            token_response = await auth_client.get(
                f"{AUTH_SERVICE_URL}/auth/github/token/user/{request.user_id}"
            )
            if token_response.status_code != 200:
                return QueryResponse(
                    success=False,
                    answer="Failed to get GitHub access token.",
                    sources=[],
                    model_used=OLLAMA_MODEL,
                    processing_time=(datetime.datetime.now() - start_time).total_seconds()
                )
            
            github_token = token_response.json().get("github_access_token")
            
            if not github_token:
                return QueryResponse(
                    success=False,
                    answer="No GitHub token found. Please login with GitHub.",
                    sources=[],
                    model_used=OLLAMA_MODEL,
                    processing_time=(datetime.datetime.now() - start_time).total_seconds()
                )
        
        # Get content of key files
        for file in all_files[:10]:  # Limit to 10 files to avoid context overflow
            if file['size'] < 50000:  # Skip files larger than 50KB
                content = await get_file_content_direct(owner, repo, file['path'], github_token)
                if content:
                    context_files.append({
                        'path': file['path'],
                        'content': content[:1000]  # First 1000 chars
                    })
        
        # Prepare context for AI
        context = f"Repository: {request.repo_full_name}\n"
        context += f"Total files: {len(all_files)}\n\n"
        context += "Key files content:\n"
        
        for file in context_files:
            context += f"\n--- {file['path']} ---\n{file['content']}\n"
        
        # Query Ollama with timeout
        messages = [
            {
                "role": "system",
                "content": """You are an expert code analyst. Analyze the provided code and answer questions about:
- Authentication mechanisms
- Login/registration flow
- API endpoints and routing
- Database connections
- Code structure and architecture

Base your answers ONLY on the provided code context. Be specific about file names and line numbers if possible."""
            },
            {
                "role": "user",
                "content": f"Context:\n{context}\n\nQuestion: {request.question}"
            }
        ]
        
        try:
            async with httpx.AsyncClient(timeout=60.0) as ollama_client:
                response = await ollama_client.post(
                    f"{OLLAMA_HOST}/api/chat",
                    json={
                        "model": OLLAMA_MODEL,
                        "messages": messages,
                        "stream": False,
                        "options": {
                            "temperature": 0.1,
                            "num_predict": 500
                        }
                    }
                )
                
                if response.status_code == 200:
                    result = response.json()
                    answer = result.get('message', {}).get('content', '')
                    
                    processing_time = (datetime.datetime.now() - start_time).total_seconds()
                    
                    return QueryResponse(
                        success=True,
                        answer=answer,
                        sources=[file['path'] for file in context_files[:5]],
                        model_used=OLLAMA_MODEL,
                        processing_time=processing_time
                    )
                else:
                    return QueryResponse(
                        success=False,
                        answer=f"Ollama error: {response.status_code}",
                        sources=[],
                        model_used=OLLAMA_MODEL,
                        processing_time=(datetime.datetime.now() - start_time).total_seconds()
                    )
                    
        except httpx.TimeoutException:
            return QueryResponse(
                success=False,
                answer="AI model is taking too long to respond. Try a simpler question.",
                sources=[],
                model_used=OLLAMA_MODEL,
                processing_time=(datetime.datetime.now() - start_time).total_seconds()
            )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Query error: {str(e)}")
        traceback.print_exc()
        return JSONResponse(
            status_code=500,
            content={
                "success": False,
                "answer": str(e),
                "sources": [],
                "model_used": OLLAMA_MODEL,
                "processing_time": (datetime.datetime.now() - start_time).total_seconds()
            }
        )

@app.post("/api/docs/list")
async def list_repository_files(
    request: RepoDocsRequest,
    current_user = Depends(get_current_user)
):
    """List all files in repository"""
    try:
        if current_user['id'] != request.user_id:
            raise HTTPException(status_code=403, detail="User ID mismatch")
        
        files = await get_all_files(request.repo_full_name, request.user_id)
        
        return {
            "success": True,
            "total": len(files),
            "files": files
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Error listing files: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={"success": False, "message": str(e)}
        )

@app.get("/api/models")
async def list_ollama_models(current_user = Depends(get_current_user)):
    """List available Ollama models"""
    try:
        async with httpx.AsyncClient(timeout=10.0) as ollama_client:
            response = await ollama_client.get(f"{OLLAMA_HOST}/api/tags")
            
            if response.status_code == 200:
                models = response.json().get('models', [])
                return {
                    "success": True,
                    "models": models,
                    "current_model": OLLAMA_MODEL
                }
            else:
                return {
                    "success": False,
                    "message": "Could not fetch models from Ollama"
                }
    except Exception as e:
        logger.error(f"❌ Error fetching models: {str(e)}")
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

@app.get("/info")
async def info():
    return {
        "service": "AI Code Analysis Service",
        "version": "1.0.0",
        "port": int(os.getenv("PORT", 8002)),
        "environment": os.getenv("ENVIRONMENT", "development"),
        "ollama_model": OLLAMA_MODEL,
        "ollama_host": OLLAMA_HOST
    }

# ========== LIFESPAN ==========

@app.on_event("startup")
async def startup():
    print("\n" + "="*80)
    print("🚀 AI CODE ANALYSIS SERVICE STARTING...")
    print("="*80)
    print(f"📡 Port: {os.getenv('PORT', 8002)}")
    print(f"📝 API Docs: http://localhost:{os.getenv('PORT', 8002)}/docs")
    print(f"🤖 Ollama Model: {OLLAMA_MODEL}")
    print(f"🔗 Ollama Host: {OLLAMA_HOST}")
    
    # Test Ollama connection
    try:
        async with httpx.AsyncClient(timeout=5.0) as test_client:
            response = await test_client.get(f"{OLLAMA_HOST}/api/tags")
            if response.status_code == 200:
                models = response.json().get('models', [])
                print(f"✅ Ollama connected with {len(models)} models")
            else:
                print(f"⚠️ Ollama responded with status {response.status_code}")
    except Exception as e:
        print(f"⚠️ Could not connect to Ollama: {str(e)}")
        print("   Make sure Ollama is running: 'ollama serve'")
    
    print("="*80 + "\n")

@app.on_event("shutdown")
async def shutdown():
    await client.aclose()
    print("✅ AI Code Analysis Service shutdown complete")

# ========== MAIN ==========
if __name__ == "__main__":
    port = int(os.getenv("PORT", 8002))
    host = os.getenv("HOST", "0.0.0.0")
    debug = os.getenv("DEBUG", "False").lower() == "true"
    
    uvicorn.run(
        "main:app",
        host=host,
        port=port,
        reload=debug,
        log_level="info"
    )
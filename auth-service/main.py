import os
import uvicorn
from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse
from dotenv import load_dotenv
import datetime

# Load environment variables from .env file
load_dotenv()

app = FastAPI(
    title="Auth Service",
    version="1.0.0",
    description="Authentication microservice",
    docs_url="/docs",
    redoc_url="/redoc",
)

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

# Fix for favicon.ico
@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    return FileResponse("static/favicon.ico") if os.path.exists("static/favicon.ico") else JSONResponse(status_code=204)

if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    host = os.getenv("HOST", "0.0.0.0")
    debug = os.getenv("DEBUG", "False").lower() == "true"
    
    print(f"\n🚀 Auth Service starting...")
    print(f"📡 Server: http://{host}:{port}")
    print(f"📝 Docs: http://{host}:{port}/docs")
    print(f"🔧 Environment: {os.getenv('ENVIRONMENT', 'development')}")
    print(f"🐛 Debug mode: {debug}\n")
    
    uvicorn.run(
        "main:app",
        host=host,
        port=port,
        reload=debug,
        log_level="info"
    )
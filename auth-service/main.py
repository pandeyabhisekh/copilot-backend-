from fastapi import FastAPI

app = FastAPI(
    title="Auth Service",
    version="1.0.0"
)

@app.get("/")
def root():
    return {"service": "auth-service", "status": "running"}

@app.get("/health")
def health():
    return {"message": "Auth service healthy"}
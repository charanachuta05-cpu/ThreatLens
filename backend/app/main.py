from fastapi import FastAPI

app = FastAPI(
    title="ThreatLens API",
    description="Enterprise Cyber Threat Intelligence Dashboard",
    version="1.0.0"
)

@app.get("/")
async def root():
    return {
        "message": "Welcome to ThreatLens",
        "status": "Running Successfully"
    }

@app.get("/health")
async def health_check():
    return {
        "status": "healthy"
    }
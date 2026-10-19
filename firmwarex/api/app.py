"""
Project Unit42-FirmwareX — FastAPI Application Server
Palo Alto Networks // Unit 42 Threat Research & Security Engineering
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from firmwarex.config import settings
from firmwarex.api.routes import router

app = FastAPI(
    title="Unit42-FirmwareX API",
    description="Automated IoT / Embedded Firmware Attack Surface & Vulnerability Analysis Engine",
    version=settings.VERSION,
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS setup
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)

@app.get("/")
async def root():
    return {
        "project": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "organisation": settings.ORGANISATION,
        "status": "operational",
        "docs": "/docs"
    }

@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "unit42-firmwarex-api"}

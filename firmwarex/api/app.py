"""
Project Unit42-FirmwareX — FastAPI Application Server
Palo Alto Networks // Unit 42 Threat Research & Security Engineering
"""

from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse
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

# Production Security Headers Middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router)

@app.get("/")
async def root(request: Request):
    accept = request.headers.get("accept", "")
    # If accessed from a web browser, redirect directly to the interactive Swagger UI
    if "text/html" in accept and "application/json" not in accept:
        return RedirectResponse(url="/docs")
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

import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from api.routes import router
from config import REPORTS_DIR

# ── Logging ────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("vigilancecore")

# ── Paths ──────────────────────────────────────────────────────────────────────
BASE_DIR     = Path(__file__).parent.resolve()
FRONTEND_DIR = BASE_DIR / "frontend"

# ── Lifespan — startup / shutdown ─────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    if not FRONTEND_DIR.exists():
        logger.warning("Frontend directory not found at %s — UI will not be served.", FRONTEND_DIR)
    logger.info("VigilanceCore API started.")
    logger.info("Frontend : %s", FRONTEND_DIR)
    logger.info("Reports  : %s", REPORTS_DIR)
    yield
    # Shutdown
    logger.info("VigilanceCore API shutting down.")


# ── App ────────────────────────────────────────────────────────────────────────
app = FastAPI(
    title       = "VigilanceCore",
    description = "AI-enhanced smart contract security analysis API.",
    version     = "1.1.0",
    docs_url    = "/docs",
    redoc_url   = "/redoc",
    lifespan    = lifespan,
)

# ── CORS ───────────────────────────────────────────────────────────────────────
# Allows both FastAPI-served frontend and Live Server during development
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:8000",
        "http://localhost:8000",
        "http://127.0.0.1:5500",
        "http://localhost:5500",
    ],
    allow_credentials = True,
    allow_methods     = ["*"],
    allow_headers     = ["*"],
)

# ── API routes ─────────────────────────────────────────────────────────────────
app.include_router(router)

# ── Serve frontend static assets (css, js, images) ────────────────────────────
# Only mount if the frontend directory exists
if FRONTEND_DIR.exists():
    app.mount(
        "/frontend",
        StaticFiles(directory=str(FRONTEND_DIR)),
        name="frontend",
    )

# ── HTML page routes ───────────────────────────────────────────────────────────
@app.get("/", include_in_schema=False)
async def serve_index():
    index = FRONTEND_DIR / "index.html"
    if not index.exists():
        return JSONResponse(
            status_code=503,
            content={"detail": "Frontend not found. Run the UI separately or add frontend/ directory."},
        )
    return FileResponse(str(index))


@app.get("/input", include_in_schema=False)
async def serve_input():
    page = FRONTEND_DIR / "input.html"
    if not page.exists():
        return JSONResponse(status_code=404, content={"detail": "input.html not found."})
    return FileResponse(str(page))


@app.get("/results", include_in_schema=False)
async def serve_results():
    page = FRONTEND_DIR / "results.html"
    if not page.exists():
        return JSONResponse(status_code=404, content={"detail": "results.html not found."})
    return FileResponse(str(page))


# ── Global exception handler ───────────────────────────────────────────────────
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error("Unhandled exception on %s %s: %s", request.method, request.url.path, exc, exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"detail": "An internal server error occurred. Check server logs."},
    )
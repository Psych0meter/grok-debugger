from typing import Optional
from fastapi import FastAPI, Request
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from app.config import settings
from app.grok_engine import GrokDebuggerEngine

# Initialize FastAPI app with title and dynamic metadata from config
app = FastAPI(
    title="Modern Grok Debugger",
    version=settings.version
)

engine = GrokDebuggerEngine()
templates = Jinja2Templates(directory="app/templates")


class DebugRequest(BaseModel):
    pattern: str
    custom_patterns: Optional[str] = ""
    log_text: str
    naming_format: Optional[str] = "dot"  # "dot" or "bracket"


@app.get("/api/config")
async def get_config():
    """
    Serves application properties, versioning, and feature flags
    directly to Alpine.js upon application startup.
    """
    return settings.get_public_config()


@app.get("/")
async def render_index(request: Request):
    return templates.TemplateResponse(request=request, name="index.html")


@app.post("/api/match")
async def match_grok(data: DebugRequest):
    try:
        matches = engine.execute_match(
            data.pattern, 
            data.custom_patterns or "", 
            data.log_text
        )
        return {"success": True, "results": matches}
    except Exception as e:
        return {"success": False, "error": str(e)}


@app.post("/api/generate")
async def generate_pattern(data: DebugRequest):
    try:
        guessed_pattern = engine.pregenerate_pattern(
            data.log_text, 
            data.naming_format or "dot"
        )
        return {"success": True, "generated_pattern": guessed_pattern}
    except Exception as e:
        return {"success": False, "error": str(e)}
from typing import Optional
from fastapi import FastAPI, Request, HTTPException
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
import logging
from pydantic import BaseModel

from app.config import settings
from app.grok_engine import GrokDebuggerEngine

# Configure logging to output to console
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Modern Grok Debugger",
    version=settings.version
)

app.mount("/static", StaticFiles(directory="static"), name="static")

# Initialize the Grok engine and templates
engine = GrokDebuggerEngine()
templates = Jinja2Templates(directory="app/templates")

class DebugRequest(BaseModel):
    """
    Request model for Grok debugging API endpoints.

    Attributes:
        pattern: The Grok pattern to test.
        custom_patterns: Optional custom Grok patterns (one per line).
        log_text: The log text to match against the pattern.
        naming_format: Field naming format ("dot" for `client.ip` or "bracket" for `[client][ip]`).
        strict_mode: If True, require a full line match (^...$). Otherwise, allow substring matches.
    """
    pattern: str
    custom_patterns: Optional[str] = ""
    log_text: str
    naming_format: Optional[str] = "dot"
    strict_mode: Optional[bool] = False

@app.get("/api/config")
async def get_config() -> dict:
    """
    Get the public configuration of the application.

    Returns:
        Dictionary containing the public configuration (e.g., version).
    """
    return settings.get_public_config()

@app.get("/")
async def render_index(request: Request):
    """
    Render the main index page with the Alpine.js frontend.

    Args:
        request: FastAPI request object.

    Returns:
        Rendered template response for the index page.
    """
    return templates.TemplateResponse(request=request, name="index.html")

@app.post("/api/match")
async def match_grok(data: DebugRequest):
    """
    Match a Grok pattern against log text.

    Args:
        data: DebugRequest containing the pattern, log text, and options.

    Returns:
        JSON response with:
        - success: Whether the operation succeeded.
        - results: List of match results (if successful).
        - error: Error message (if failed).

    Raises:
        HTTPException: If there is a validation or internal error.
    """
    try:
        # Explicitly handle empty custom_patterns
        custom_patterns = data.custom_patterns if data.custom_patterns else ""
        matches = engine.execute_match(
            data.pattern,
            custom_patterns,
            data.log_text,
            strict_mode=data.strict_mode or False
        )
        return {"success": True, "results": matches}
    except ValueError as e:
        logger.warning(f"Validation error in match_grok: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Unexpected error in match_grok: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail="An internal error occurred. Please try again."
        )

@app.post("/api/generate")
async def generate_pattern(data: DebugRequest):
    """
    Automatically generate a Grok pattern from sample log text.

    Args:
        data: DebugRequest containing the log text and naming format.

    Returns:
        JSON response with:
        - success: Whether the operation succeeded.
        - generated_pattern: The generated Grok pattern (if successful).
        - error: Error message (if failed).
    """
    try:
        guessed_pattern = engine.pregenerate_pattern(
            data.log_text,
            data.naming_format or "dot"
        )
        return {"success": True, "generated_pattern": guessed_pattern}
    except Exception as e:
        logger.error(f"Error in generate_pattern: {e}", exc_info=True)
        return {"success": False, "error": str(e)}

@app.get("/api/health")
async def health_check() -> dict:
    """
    Health check endpoint to verify the API is running.

    Returns:
        Dictionary with the health status.
    """
    return {"status": "healthy"}

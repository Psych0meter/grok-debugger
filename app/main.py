import asyncio
import functools
import logging
import os
from concurrent.futures import ThreadPoolExecutor

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

from app.config import settings
from app.grok_engine import GrokDebuggerEngine

# Configure logging to output to console
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Modern Grok Debugger",
    version=settings.version
)

# Initialize the Grok engine, templates, and static assets (CSS/JS)
engine = GrokDebuggerEngine()
templates = Jinja2Templates(directory="app/templates")
app.mount("/static", StaticFiles(directory="app/static"), name="static")

# Request size limits. A Grok/regex pattern or sample log pasted by mistake
# (or crafted deliberately) can be arbitrarily large; these bound the request
# body pydantic will accept before it ever reaches the matching engine.
MAX_PATTERN_LENGTH = 5_000
MAX_CUSTOM_PATTERNS_LENGTH = 20_000
MAX_LOG_TEXT_LENGTH = 200_000

# Grok/regex matching is CPU-bound and runs off the event loop with a hard
# wall-clock budget: a pathological pattern (catastrophic backtracking) could
# otherwise hang a request - and, since uvicorn's default worker is
# single-threaded for the event loop, every other in-flight request - forever.
#
# Note pygrok prefers the third-party `regex` package over stdlib `re` when
# it's installed (it's one of pygrok's own dependencies, so in practice it
# normally is - see `pip show regex`), and `regex` already handles some
# classically pathological patterns (e.g. `(a+)+` against a run of matching
# characters) far better than stdlib `re`. This timeout is still worth
# keeping regardless: it's a single wall-clock budget around the *entire*
# engine call - not just one regex operation - so it also covers
# find_partial_match's loop of progressively-longer sub-pattern compiles and
# pregenerate_pattern's diff-based alignment, neither of which is a single
# regex op a timeout=... kwarg could bound on its own.
#
# What it does NOT do is bound CPU usage: Python cannot forcibly interrupt a
# C-level regex match mid-flight, so if the underlying call ever is slow
# enough to hit this timeout, that worker thread keeps running in the
# background even after asyncio.wait_for gives up on it and returns an error
# to the caller. Combined with the size limits above, this keeps the API
# responsive for trusted/internal use; it is not a complete DoS defense for
# an untrusted multi-tenant deployment.
_match_executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="grok-match")
MATCH_TIMEOUT_SECONDS = float(os.getenv("MATCH_TIMEOUT_SECONDS", "3"))


async def _run_with_timeout(func, *args, **kwargs):
    """
    Run a blocking engine call off the event loop with a wall-clock timeout.

    Args:
        func: The blocking callable to run (e.g. engine.execute_match).
        *args: Positional arguments to pass to func.
        **kwargs: Keyword arguments to pass to func.

    Returns:
        The return value of func.

    Raises:
        ValueError: If func does not complete within MATCH_TIMEOUT_SECONDS.
    """
    loop = asyncio.get_running_loop()
    call = functools.partial(func, *args, **kwargs)
    try:
        return await asyncio.wait_for(
            loop.run_in_executor(_match_executor, call),
            timeout=MATCH_TIMEOUT_SECONDS
        )
    except asyncio.TimeoutError as e:
        raise ValueError(
            "Pattern evaluation timed out - the pattern or input is likely too "
            "complex (possible catastrophic backtracking). Try simplifying the "
            "pattern or reducing the sample size."
        ) from e


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(
    _request: Request, exc: RequestValidationError
) -> JSONResponse:
    """
    Flatten pydantic's default multi-error body into the single-string
    `{"detail": "..."}` shape the frontend already expects from
    HTTPException responses (see app.js's triggerMatch/autoGenerate),
    so a request-size violation displays the same way a 400 does instead
    of rendering "[object Object]".

    Args:
        _request: The FastAPI request that failed validation (unused;
            required by FastAPI's exception handler signature).
        exc: The validation error raised by pydantic.

    Returns:
        A 422 JSON response with a single human-readable `detail` string.
    """
    first_error = exc.errors()[0] if exc.errors() else {}
    field = ".".join(str(p) for p in first_error.get("loc", []) if p != "body")
    message = first_error.get("msg", "Invalid request.")
    detail = f"{field}: {message}" if field else message
    logger.warning(f"Request validation error: {detail}")
    return JSONResponse(status_code=422, content={"detail": detail})


class DebugRequest(BaseModel):
    """
    Request model for Grok debugging API endpoints.

    Attributes:
        pattern: The Grok pattern to test.
        custom_patterns: Optional custom Grok patterns (one per line).
        log_text: The log text to match against the pattern.
        naming_format: Field naming format ("dot" for `client.ip` or
            "bracket" for `[client][ip]`).
        strict_mode: If True, require a full line match (^...$).
            Otherwise, allow substring matches.
    """
    pattern: str = Field(max_length=MAX_PATTERN_LENGTH)
    custom_patterns: str | None = Field(default="", max_length=MAX_CUSTOM_PATTERNS_LENGTH)
    log_text: str = Field(max_length=MAX_LOG_TEXT_LENGTH)
    naming_format: str | None = "dot"
    strict_mode: bool | None = False

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
        matches = await _run_with_timeout(
            engine.execute_match,
            data.pattern,
            custom_patterns,
            data.log_text,
            strict_mode=data.strict_mode or False
        )
        return {"success": True, "results": matches}
    except ValueError as e:
        logger.warning(f"match_grok request rejected: {e}")
        raise HTTPException(status_code=400, detail=str(e)) from e
    except Exception as e:
        logger.exception("Unexpected error in match_grok")
        raise HTTPException(
            status_code=500,
            detail="An internal error occurred. Please try again."
        ) from e

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
        guessed_pattern = await _run_with_timeout(
            engine.pregenerate_pattern,
            data.log_text,
            data.naming_format or "dot"
        )
        return {"success": True, "generated_pattern": guessed_pattern}
    except Exception as e:
        logger.exception("Error in generate_pattern")
        return {"success": False, "error": str(e)}

@app.get("/api/health")
async def health_check() -> dict:
    """
    Health check endpoint to verify the API is running.

    Returns:
        Dictionary with the health status.
    """
    return {"status": "healthy"}

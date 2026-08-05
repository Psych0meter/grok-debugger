from fastapi import FastAPI, Request
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from typing import Optional

from app.grok_engine import GrokDebuggerEngine

app = FastAPI(title="Modern Grok Debugger")
engine = GrokDebuggerEngine()

templates = Jinja2Templates(directory="app/templates")

class DebugRequest(BaseModel):
    pattern: str
    custom_patterns: Optional[str] = ""
    log_text: str

@app.get("/")
async def render_index(request: Request):
    # Updated to pass request as a keyword argument
    return templates.TemplateResponse(request=request, name="index.html")

@app.post("/api/match")
async def match_grok(data: DebugRequest):
    try:
        matches = engine.execute_match(data.pattern, data.custom_patterns or "", data.log_text)
        return {"success": True, "results": matches}
    except Exception as e:
        return {"success": False, "error": str(e)}

@app.post("/api/generate")
async def generate_pattern(data: DebugRequest):
    guessed_pattern = engine.pregenerate_pattern(data.log_text)
    return {"success": True, "generated_pattern": guessed_pattern}

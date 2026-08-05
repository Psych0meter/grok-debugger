# Modern Grok Debugger

A fast Grok and Regexp debugger inspired by Grok Debugger and Grok Constructor built with FastAPI and Alpine.js.

## Features
- **Real-time Parsing:** Instant regex/grok evaluations without full page reloads.
- **ECS Bracket Support:** Fully supports nested target variables like `%{WORD:[observer][ingress][vlan][id]}`.
- **Sub-pattern Definitions:** Define inline custom regex patterns.
- **LocalStorage State:** Automatically keeps inputs saved across browser refreshes.
- **Pattern Auto-Generation:** Basic heuristic helper for unparsed log text.

## Running in GitHub Codespaces

1. Open in GitHub Codespaces.
2. Run the application:
   ```bash
   uvicorn app.main:app --reload --port 8000

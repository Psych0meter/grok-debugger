# Modern Grok Debugger

A fast, interactive Grok and Regexp debugger and pattern generator built with **FastAPI**, **PyGrok**, and **Alpine.js**. Designed for security analysts, log engineers, and DevOps teams working with Logstash, Elastic Common Schema (ECS), and Vector log pipelines.

---

## Features

- **Real-Time Log Parsing:** Instant Grok pattern and standard regular expression evaluations without page reloads.
- **ECS Bracket & Dot Notation Support:** Native parsing and validation for nested target variables such as `%{WORD:[observer][ingress][vlan][id]}` or `%{IP:client.ip}`.
- **Partial Match Diagnostics:** When a pattern fails to match a log line, the engine highlights the exact token where parsing broke down.
- **Pattern Auto-Generator (Beta):** Generates starter Grok patterns from raw sample logs. Uses sequence alignment (not just positional matching) across samples, so it correctly handles optional or variable-length segments — e.g. a log line missing a tag another sample has — by wrapping them in `(?:...)?` instead of failing to match.
- **Custom Pattern Definitions:** Inline custom pattern definitions with line-number gutter synchronization.
- **Color-Coded Token Highlighting:** Automatic visual mapping connecting extracted fields to corresponding segments in sample logs.
- **LocalStorage State Persistence:** Automatically retains log inputs, custom definitions, and patterns across browser refreshes.

---

## Inspirations & Credits

This project was built to modernize and combine capabilities of Grok debugging tools:

- [Grok Debugger](https://grokdebugger.com/) ([GitHub: `cjslack/grok-debugger`](https://github.com/cjslack/grok-debugger)) — Inspired the live pattern evaluation interface and custom definition syntax.
- [Grok Constructor](https://grokconstructor.appspot.com/do/match#result) ([GitHub: `stoerr/GrokConstructor`](https://github.com/stoerr/GrokConstructor)) — Inspired the partial matching and pattern auto-generation capabilities.

---

## Project Structure

```
.
├── .devcontainer/
│   └── devcontainer.json      # VS Code dev container config
├── .github/
│   └── workflows/
│       └── ci.yml             # Lint (ruff), security scan (bandit) & tests (pytest) on push/PR
├── app/
│   ├── main.py                # FastAPI application & API routes
│   ├── config.py              # App settings & version/feature metadata
│   ├── grok_engine.py         # Core Grok evaluation, sanitization & auto-generation engine
│   ├── templates/
│   │   └── index.html         # Single-page UI shell (Alpine.js & Tailwind CSS via CDN)
│   └── static/
│       ├── css/style.css      # UI styling
│       └── js/app.js          # Alpine.js application logic
├── tests/
│   ├── test_grok_engine.py    # Unit tests for the matching/generation engine
│   └── test_api.py            # API-level tests (FastAPI TestClient)
├── pyproject.toml             # Project metadata, ruff config, pytest config
├── requirements.txt           # Runtime dependencies
├── requirements-dev.txt       # + ruff, bandit, pytest, httpx
└── README.md
```

---

## Getting Started

### Prerequisites

- Python 3.10+

### Local Setup

1. **Create and activate a virtual environment:**

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. **Install dependencies:**

```bash
pip install -r requirements.txt
```

3. **Run the application:**

```bash
uvicorn app.main:app --reload --port 8000
```

4. Open [http://localhost:8000](http://localhost:8000) in your browser.

---

## Development

Install the dev extras (adds ruff, bandit, pytest, httpx on top of the runtime dependencies):

```bash
pip install -r requirements-dev.txt
```

**Run the tests:**

```bash
pytest
```

**Lint:**

```bash
ruff check app/ tests/
```

The lint ruleset is pinned in `pyproject.toml` under `[tool.ruff.lint]` so `ruff check` gives the same result locally and in CI.

**Security scan:**

```bash
bandit -r app/
```

All three run automatically on every push and pull request via [`.github/workflows/ci.yml`](.github/workflows/ci.yml), across Python 3.10–3.12.

---

## Request Limits & Timeouts

`/api/match` and `/api/generate` accept arbitrary user-supplied patterns and sample text, so a few limits are enforced server-side (see `app/main.py`):

| Limit | Default | Purpose |
|---|---|---|
| Pattern length | 5,000 chars | Bounds pathological input |
| Custom pattern definitions length | 20,000 chars | Bounds pathological input |
| Log text length | 200,000 chars | Bounds pathological input |
| Match/generate timeout | 3s (`MATCH_TIMEOUT_SECONDS` env var) | Fails fast instead of hanging a request |

The timeout bounds *response time*, not CPU usage — Python can't forcibly interrupt a regex match mid-flight, so it's a practical safeguard for trusted/internal use rather than a complete denial-of-service defense. See the comment above `MATCH_TIMEOUT_SECONDS` in `app/main.py` for the full reasoning, including why pygrok's use of the third-party `regex` package (installed automatically as one of pygrok's own dependencies) already mitigates some classic catastrophic-backtracking patterns on its own.

---

## Production Notes

The frontend is intentionally dependency-light for easy self-hosting, with two trade-offs worth knowing about before deploying it beyond a trusted local/internal setting:

- **Tailwind via the CDN script** (`cdn.tailwindcss.com`) is Tailwind's "Play CDN" — convenient for zero-build local use, but Tailwind's own docs note it isn't intended for production (it compiles styles in the browser on every load). For a production build, compile Tailwind via its CLI or a bundler and link the resulting stylesheet instead.
- **Alpine.js is loaded from a floating version range** (`alpinejs@3.x.x`). Consider pinning it to an exact version (e.g. `alpinejs@3.17.1`) and adding a [Subresource Integrity](https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity) hash, e.g.:

  ```bash
  curl -s https://cdn.jsdelivr.net/npm/alpinejs@3.17.1/dist/cdn.min.js \
    | openssl dgst -sha384 -binary | openssl base64 -A
  ```

  and add `integrity="sha384-<hash>" crossorigin="anonymous"` to the `<script>` tag. This wasn't done automatically here since a wrong hash would break the app entirely (the browser refuses to run a script whose hash doesn't match) — generate and verify it yourself before deploying.

---

## License

GPLv3 — see [LICENSE](LICENSE).

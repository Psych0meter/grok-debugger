# Modern Grok Debugger

A fast, interactive Grok and Regexp debugger and pattern generator built with **FastAPI**, **PyGrok**, and **Alpine.js**. Designed for security analysts, log engineers, and DevOps teams working with Logstash, Elastic Common Schema (ECS), and Vector log pipelines.

---

## Features

- **Real-Time Log Parsing:** Instant Grok pattern and standard regular expression evaluations without page reloads.
- **ECS Bracket & Dot Notation Support:** Native parsing and validation for nested target variables such as `%{WORD:[observer][ingress][vlan][id]}` or `%{IP:client.ip}`.
- **Partial Match Diagnostics:** When a pattern fails to match a log line, the engine highlights the exact token where parsing broke down.
- **Pattern Auto-Generator (Beta):** Generates starter Grok patterns automatically from raw sample logs.
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
├── app/
│   ├── main.py              # FastAPI application & API routes
│   ├── grok_engine.py       # Core Grok evaluation, sanitization & auto-generation engine
│   └── templates/
│       └── index.html       # Single-page UI built with Alpine.js & Tailwind CSS
├── requirements.txt         # Python dependencies
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

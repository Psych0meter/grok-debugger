# Changelog

## [1.1.5] - 2026-09-22

### Added
- Request size limits on `pattern` (5,000 chars), `custom_patterns` (20,000
  chars) and `log_text` (200,000 chars).
- A wall-clock timeout (`MATCH_TIMEOUT_SECONDS`, default 3s, env-overridable)
  around pattern matching and auto-generation, so a pathological pattern
  can't hang a request indefinitely.
- A pytest test suite (`tests/test_grok_engine.py`, `tests/test_api.py`)
  covering the matching engine and all four API endpoints - the project had
  no tests before this.
- CI (`.github/workflows/ci.yml`): ruff, bandit and pytest run on every push
  to `main` and every pull request, across Python 3.10-3.12.
- `requirements-dev.txt` and a `dev` extra in `pyproject.toml` (ruff, bandit,
  pytest, httpx) for local linting and testing.
- README: Development, Request Limits & Timeouts, Production Notes and
  License sections.

### Fixed
- A pydantic validation error (e.g. a request exceeding the new size limits,
  or a missing required field) used to return a list of error objects as
  `detail`, which the frontend rendered as `[object Object]`. Validation
  errors now return a single human-readable string, consistent with every
  other error response.

## [1.1.4] - 2026-09-22

### Fixed
- `find_partial_match` mis-tokenized patterns that mixed a `%{...}` Grok
  field with a `(?P<name>...)` / `(?<name>...)` regex group, silently
  breaking Partial Match Diagnostics for any such pattern. Replaced the
  tokenizer with a paren-balancing version that also handles nested parens
  inside a group's body.
- API error handlers now chain exceptions with `raise ... from e` instead of
  discarding the original traceback.

### Changed
- Pinned a `[tool.ruff]` lint configuration (previously unconfigured, so
  `ruff check` meant whatever ruleset happened to be run by hand, and a
  `# noqa: BLE001` comment in `grok_engine.py` referenced a rule nothing
  enabled).
- `config.py` uses `Path.open()` instead of the builtin `open()`.

## [1.1.3] - 2026-08-07

### Changed
- `pregenerate_pattern` uses diff-based sequence alignment across sample
  lines instead of a positional zip, so it correctly handles optional or
  variable-length segments between samples instead of misaligning on them.

## [1.1.2] - 2026-08-07

### Changed
- Backend review pass: field-name sanitization regex fixes, improved IP
  detection, lint cleanup, and split the inline CSS/JS out of `index.html`
  into `app/static/`.
- Fixes to error message display, field matching, and suggested-pattern
  replacement.

## [1.1.1] - 2026-08-06

### Added
- Flexible vs. strict match mode toggle for the pattern checker.

## [1.1.0] - 2026-08-05

### Added
- Initial tagged release: live Grok/regex matching, the pattern
  auto-generator, a JSON view of results, ECS bracket/dot notation support,
  pattern format-consistency normalization, and version/config loading from
  `pyproject.toml`.

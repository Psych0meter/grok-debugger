"""Tests for the FastAPI endpoints in app.main."""
import time

import app.main as main_module
from fastapi.testclient import TestClient

client = TestClient(main_module.app)


def test_health_check_reports_healthy():
    res = client.get("/api/health")
    assert res.status_code == 200
    assert res.json() == {"status": "healthy"}


def test_get_config_returns_version_and_features():
    res = client.get("/api/config")
    assert res.status_code == 200
    body = res.json()
    assert "version" in body
    assert "features" in body


def test_index_page_renders():
    res = client.get("/")
    assert res.status_code == 200
    assert "text/html" in res.headers["content-type"]


def test_match_returns_extracted_fields_for_a_valid_pattern():
    res = client.post(
        "/api/match",
        json={
            "pattern": "%{IP:client_ip} %{WORD:method} %{NUMBER:status}",
            "custom_patterns": "",
            "log_text": "192.168.1.1 GET 200",
            "naming_format": "dot",
            "strict_mode": False,
        },
    )
    assert res.status_code == 200
    body = res.json()
    assert body["success"] is True
    assert body["results"][0]["matches"] == {
        "client_ip": "192.168.1.1",
        "method": "GET",
        "status": "200",
    }


def test_match_reports_a_partial_match_for_a_mixed_grok_and_regex_pattern():
    """Regression test: this used to return an empty partial_match due to a
    broken tokenizer in find_partial_match (see app/grok_engine.py)."""
    res = client.post(
        "/api/match",
        json={
            "pattern": r"(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) (?P<status>[0-9]{3})",
            "custom_patterns": "",
            "log_text": "192.168.1.1 wrong-status",
            "naming_format": "dot",
            "strict_mode": False,
        },
    )
    assert res.status_code == 200
    partial = res.json()["results"][0]["partial_match"]
    assert partial["matched_fields"] == {"ip": "192.168.1.1"}


def test_match_with_invalid_pattern_returns_400_with_string_detail():
    res = client.post(
        "/api/match",
        json={
            "pattern": "%{NOT_A_REAL_GROK_TYPE:x}",
            "custom_patterns": "",
            "log_text": "some text",
        },
    )
    assert res.status_code == 400
    assert isinstance(res.json()["detail"], str)


def test_match_missing_required_field_returns_422_with_flattened_string_detail():
    """Regression test: pydantic's default validation-error body is a list of
    objects, which the frontend can't render as-is (see the
    RequestValidationError handler in app/main.py)."""
    res = client.post("/api/match", json={"custom_patterns": ""})
    assert res.status_code == 422
    assert isinstance(res.json()["detail"], str)


def test_match_pattern_over_the_length_limit_is_rejected():
    res = client.post(
        "/api/match",
        json={
            "pattern": "a" * (main_module.MAX_PATTERN_LENGTH + 1),
            "custom_patterns": "",
            "log_text": "some text",
        },
    )
    assert res.status_code == 422
    assert isinstance(res.json()["detail"], str)


def test_generate_pattern_produces_a_pattern_that_matches_its_own_sample():
    log_line = "2024-01-01T10:00:00 192.168.1.1 GET 200"
    gen_res = client.post(
        "/api/generate",
        json={"pattern": "", "custom_patterns": "", "log_text": log_line},
    )
    assert gen_res.status_code == 200
    gen_body = gen_res.json()
    assert gen_body["success"] is True

    match_res = client.post(
        "/api/match",
        json={
            "pattern": gen_body["generated_pattern"],
            "custom_patterns": "",
            "log_text": log_line,
        },
    )
    assert match_res.json()["results"][0]["matched"] is True


def test_match_times_out_when_the_engine_call_takes_too_long(monkeypatch):
    """The timeout wrapper must fail fast with a clear message rather than
    hang the request indefinitely.

    This mocks a slow engine call instead of relying on a genuinely
    catastrophic-backtracking pattern: pygrok prefers the third-party
    `regex` package over stdlib `re` when it's installed (it's one of
    pygrok's own dependencies, so it normally is), and `regex` handles some
    classically pathological patterns - like (a+)+ against a run of "a"s -
    far better than stdlib re does. Testing against a specific pattern's
    wall-clock time would make this test flaky across environments; testing
    the timeout mechanism itself does not.
    """
    monkeypatch.setattr(main_module, "MATCH_TIMEOUT_SECONDS", 0.1)

    def slow_execute_match(*_args, **_kwargs):
        time.sleep(1)
        return []

    monkeypatch.setattr(main_module.engine, "execute_match", slow_execute_match)

    res = client.post(
        "/api/match",
        json={"pattern": "%{IP:ip}", "custom_patterns": "", "log_text": "192.168.1.1"},
    )
    assert res.status_code == 400
    assert "timed out" in res.json()["detail"].lower()

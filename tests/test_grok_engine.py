"""Unit tests for app.grok_engine.GrokDebuggerEngine."""
import pytest

from app.grok_engine import GrokDebuggerEngine


@pytest.fixture
def engine() -> GrokDebuggerEngine:
    return GrokDebuggerEngine()


class TestExecuteMatch:
    def test_matches_a_simple_grok_pattern(self, engine):
        results = engine.execute_match(
            "%{IP:client_ip} %{WORD:method} %{NUMBER:status}",
            "",
            "192.168.1.1 GET 200",
        )
        assert len(results) == 1
        assert results[0]["matched"] is True
        assert results[0]["matches"] == {
            "client_ip": "192.168.1.1",
            "method": "GET",
            "status": "200",
        }

    def test_dot_notation_fields_are_unflattened_into_nested_json(self, engine):
        results = engine.execute_match(
            "%{IP:client.ip} %{NUMBER:client.port}",
            "",
            "10.0.0.1 8080",
        )
        assert results[0]["json_data"] == {"client": {"ip": "10.0.0.1", "port": "8080"}}

    def test_bracket_notation_fields_are_unflattened_into_nested_json(self, engine):
        results = engine.execute_match(
            "%{IP:[client][ip]} %{NUMBER:[client][port]}",
            "",
            "10.0.0.1 8080",
        )
        assert results[0]["json_data"] == {"client": {"ip": "10.0.0.1", "port": "8080"}}

    def test_named_regex_groups_work_alongside_grok_fields(self, engine):
        results = engine.execute_match(
            r"%{IP:client_ip} (?P<status>[0-9]{3})",
            "",
            "192.168.1.1 200",
        )
        assert results[0]["matched"] is True
        assert results[0]["matches"] == {"client_ip": "192.168.1.1", "status": "200"}

    def test_unmatched_line_reports_no_matches(self, engine):
        results = engine.execute_match("%{IP:client_ip}", "", "not-an-ip at all")
        assert results[0]["matched"] is False
        assert results[0]["matches"] == {}

    def test_strict_mode_requires_a_full_line_match(self, engine):
        loose = engine.execute_match("%{IP:ip}", "", "192.168.1.1 extra text")
        strict = engine.execute_match(
            "%{IP:ip}", "", "192.168.1.1 extra text", strict_mode=True
        )
        assert loose[0]["matched"] is True
        assert strict[0]["matched"] is False

    def test_blank_lines_are_skipped(self, engine):
        results = engine.execute_match("%{IP:ip}", "", "192.168.1.1\n\n10.0.0.1")
        assert [r["line_number"] for r in results] == [1, 3]

    def test_empty_pattern_or_text_returns_no_results(self, engine):
        assert engine.execute_match("", "", "some text") == []
        assert engine.execute_match("%{IP:ip}", "", "") == []

    def test_invalid_pattern_raises_value_error(self, engine):
        with pytest.raises(ValueError, match="Pattern Compilation Error"):
            engine.execute_match("%{NOT_A_REAL_GROK_TYPE:x}", "", "some text")

    def test_custom_pattern_definitions_are_honored(self, engine):
        results = engine.execute_match(
            "%{MY_ID:id}",
            "MY_ID [a-z]+-[0-9]+",
            "abc-123",
        )
        assert results[0]["matched"] is True
        assert results[0]["matches"] == {"id": "abc-123"}


class TestFindPartialMatch:
    """Regression tests for the tokenizer bug in find_partial_match.

    The tokenizer used to split (?P<name>...) into two invalid fragments
    ('(?P' and '<name>...)'), so any progressively-built prefix containing
    one of those fragments failed to compile and the diagnostic silently
    reported no partial match at all.
    """

    def test_reports_the_longest_matching_prefix_for_a_named_regex_group(self, engine):
        result = engine.find_partial_match(
            r"(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) (?P<status>[0-9]{3})",
            {},
            "192.168.1.1 wrong-status",
        )
        assert result["matched_fields"] == {"ip": "192.168.1.1"}
        assert result["unmatched_remainder"] == "wrong-status"

    def test_handles_nested_parens_inside_a_named_group_body(self, engine):
        result = engine.find_partial_match(
            r"(?P<mac>(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}) (?P<status>[0-9]{3})",
            {},
            "00:1A:2B:3C:4D:5E nope",
        )
        assert result["matched_fields"] == {"mac": "00:1A:2B:3C:4D:5E"}
        assert result["unmatched_remainder"] == "nope"

    def test_reports_the_longest_matching_prefix_for_a_grok_field(self, engine):
        result = engine.find_partial_match(
            "%{IP:ip} %{WORD:method} %{NUMBER:status}",
            {},
            "192.168.1.1 GET not-a-number",
        )
        assert result["matched_fields"] == {"ip": "192.168.1.1", "method": "GET"}

    def test_no_match_at_all_reports_empty_prefix(self, engine):
        result = engine.find_partial_match("%{IP:ip}", {}, "definitely not an ip")
        assert result["matched_prefix"] == ""
        assert result["matched_fields"] == {}
        assert result["unmatched_remainder"] == "definitely not an ip"


class TestFieldNameValidation:
    def test_accepts_dot_notation(self, engine):
        engine.validate_logstash_field_name("client.ip")  # does not raise

    def test_accepts_bracket_notation(self, engine):
        engine.validate_logstash_field_name("[client][ip]")  # does not raise

    def test_rejects_mixed_or_malformed_notation(self, engine):
        with pytest.raises(ValueError, match="Invalid Logstash field name"):
            engine.validate_logstash_field_name("client.[ip]")


class TestDetectGrokType:
    @pytest.mark.parametrize(
        ("value", "expected_type"),
        [
            ("192.168.1.1", "IP"),
            ("2001:db8::1", "IP"),
            ("/var/log/syslog", "PATH"),
            ("2024-01-01T10:00:00", "TIMESTAMP_ISO8601"),
            ("42", "INT"),
            ("3.14", "NUMBER"),
            ("hello", "NOTSPACE"),
            ("10:23:01", "NOTSPACE"),  # plain HH:MM:SS, not IPv6
        ],
    )
    def test_detects_expected_type(self, engine, value, expected_type):
        assert engine.detect_grok_type(value) == expected_type


class TestUnflattenDict:
    def test_unflattens_dot_and_bracket_keys_together(self, engine):
        flat = {"client.ip": "192.168.1.1", "[server][port]": "80"}
        assert engine.unflatten_dict(flat) == {
            "client": {"ip": "192.168.1.1"},
            "server": {"port": "80"},
        }


class TestParseCustomPatterns:
    def test_parses_name_and_pattern_pairs_and_skips_comments(self, engine):
        raw = "# a comment\nMY_ID [a-z]+-[0-9]+\n\nOTHER \\d+"
        assert engine.parse_custom_patterns(raw) == {
            "MY_ID": "[a-z]+-[0-9]+",
            "OTHER": "\\d+",
        }


class TestPregeneratePattern:
    def test_empty_text_falls_back_to_greedydata(self, engine):
        assert engine.pregenerate_pattern("") == "%{GREEDYDATA:message}"

    def test_generated_pattern_matches_the_sample_it_was_built_from(self, engine):
        log_line = "2024-01-01T10:00:00 192.168.1.1 GET 200"
        pattern = engine.pregenerate_pattern(log_line)
        results = engine.execute_match(pattern, "", log_line)
        assert results[0]["matched"] is True

    def test_single_sample_line_has_nothing_to_diff_against_and_stays_literal(self, engine):
        # pregenerate_pattern detects *variable* content by diffing multiple
        # sample lines; a lone "key=value" line has nothing to compare
        # against, so it's correctly returned as a literal, not a field.
        assert engine.pregenerate_pattern("user=alice") == "user=alice"

    def test_bracket_format_mode_produces_bracket_field_names(self, engine):
        pattern = engine.pregenerate_pattern(
            "user=alice\nuser=bob", format_mode="bracket"
        )
        assert "[user]" in pattern

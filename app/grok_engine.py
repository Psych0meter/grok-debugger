import re
from typing import Dict, Any, List, Tuple
from pygrok import Grok

class GrokDebuggerEngine:
    def __init__(self):
        self.grok_field_re = re.compile(r'%\{([A-Z0-9_]+):([^}:]+)(:[a-zA-Z0-9_]+)?\}')
        # Regex to support (?<field_name>...) and (?P<field_name>...), including bracketed notation like (?<[syslog][sequence]>)
        self.regex_group_re = re.compile(r'\(\?(?:<|P<)([^>]+)>')

        self.valid_dot_field = re.compile(r'^[a-zA-Z0-9_\-]+(\.[a-zA-Z0-9_\-]+)*$')
        self.valid_bracket_field = re.compile(r'^(\[[a-zA-Z0-9_\-]+\])+$')

    def parse_custom_patterns(self, custom_patterns_raw: str) -> Dict[str, str]:
        patterns = {}
        for line in custom_patterns_raw.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parts = line.split(maxsplit=1)
            if len(parts) == 2:
                patterns[parts[0]] = parts[1]
        return patterns

    def validate_logstash_field_name(self, field_name: str):
        if not (self.valid_dot_field.match(field_name) or self.valid_bracket_field.match(field_name)):
            raise ValueError(
                f"Invalid Logstash field name '{field_name}'. "
                f"Logstash requires either dot-notation (e.g. 'client.ip') "
                f"or bracket-notation (e.g. '[client][ip]')."
            )

    def _sanitize_string(self, text: str, mapping: Dict[str, str], counter: List[int]) -> str:
        def grok_repl(match):
            pattern_name = match.group(1)
            field_name = match.group(2)
            type_spec = match.group(3) or ""
            
            self.validate_logstash_field_name(field_name)

            safe_key = f"__FIELD_{counter[0]}__"
            counter[0] += 1
            mapping[safe_key] = field_name
            return f"%{{{pattern_name}:{safe_key}{type_spec}}}"

        def regex_repl(match):
            field_name = match.group(1)
            self.validate_logstash_field_name(field_name)

            safe_key = f"__FIELD_{counter[0]}__"
            counter[0] += 1
            mapping[safe_key] = field_name
            return f"(?P<{safe_key}>"

        text = self.grok_field_re.sub(grok_repl, text)
        text = self.regex_group_re.sub(regex_repl, text)
        return text

    def sanitize_field_names(self, pattern_str: str, custom_patterns: Dict[str, str]) -> Tuple[str, Dict[str, str], Dict[str, str]]:
        mapping = {}
        counter = [0]

        sanitized_pattern = self._sanitize_string(pattern_str, mapping, counter)
        
        sanitized_custom = {}
        for k, v in custom_patterns.items():
            sanitized_custom[k] = self._sanitize_string(v, mapping, counter)

        return sanitized_pattern, sanitized_custom, mapping

    def find_partial_match(self, pattern_str: str, custom_patterns: Dict[str, str], line: str) -> Dict[str, Any]:
        """Progressively tests pattern tokens to find the longest matching prefix when a full match fails."""
        tokens = re.split(r'(%\{[^{}]+\}|\(\?<[^>]+>.*?\))', pattern_str)
        tokens = [t for t in tokens if t]

        longest_matched_prefix = ""
        longest_matched_dict = {}
        longest_unmatched_remainder = line

        for i in range(1, len(tokens) + 1):
            sub_pattern = "".join(tokens[:i])
            try:
                sanitized_pattern, sanitized_custom, field_map = self.sanitize_field_names(sub_pattern, custom_patterns)
                sub_grok = Grok(sanitized_pattern, custom_patterns=sanitized_custom)
                match = sub_grok.regex_obj.match(line)
                
                if match:
                    matched_len = match.end()
                    raw_dict = match.groupdict()
                    cleaned_dict = {field_map.get(k, k): v for k, v in raw_dict.items() if v is not None}
                    
                    longest_matched_prefix = sub_pattern
                    longest_matched_dict = cleaned_dict
                    longest_unmatched_remainder = line[matched_len:]
                else:
                    break
            except Exception:
                break

        return {
            "matched_prefix": longest_matched_prefix,
            "matched_fields": longest_matched_dict,
            "unmatched_remainder": longest_unmatched_remainder
        }

    def execute_match(self, pattern_str: str, custom_patterns_raw: str, text: str) -> List[Dict[str, Any]]:
        if not pattern_str or not text:
            return []

        custom_patterns = self.parse_custom_patterns(custom_patterns_raw)
        sanitized_pattern, sanitized_custom, field_map = self.sanitize_field_names(pattern_str, custom_patterns)

        try:
            grok = Grok(sanitized_pattern, custom_patterns=sanitized_custom)
            compiled_regex = grok.regex_obj
        except Exception as e:
            raise ValueError(f"Pattern Compilation Error: {str(e)}")

        results = []
        for line_idx, line in enumerate(text.splitlines()):
            if not line.strip():
                continue

            match = compiled_regex.match(line)
            if match:
                raw_dict = match.groupdict()
                matches_dict = {}
                spans_list = []

                for key, val in raw_dict.items():
                    if val is None:
                        continue
                    final_key = field_map.get(key, key)
                    matches_dict[final_key] = val
                    
                    s_start, s_end = match.span(key)
                    if s_end > s_start:
                        spans_list.append({
                            "field": final_key,
                            "span": (s_start, s_end)
                        })

                spans_list.sort(key=lambda x: x["span"][0])

                segments = []
                curr = 0
                for item in spans_list:
                    s_start, s_end = item["span"]
                    if s_start >= curr:
                        if s_start > curr:
                            segments.append({"text": line[curr:s_start], "field": None})
                        if s_end > s_start:
                            segments.append({"text": line[s_start:s_end], "field": item["field"]})
                        curr = max(curr, s_end)
                if curr < len(line):
                    segments.append({"text": line[curr:], "field": None})

                results.append({
                    "line_number": line_idx + 1,
                    "matched": True,
                    "line_text": line,
                    "segments": segments,
                    "matches": matches_dict
                })
            else:
                partial_info = self.find_partial_match(pattern_str, custom_patterns, line)
                results.append({
                    "line_number": line_idx + 1,
                    "matched": False,
                    "line_text": line,
                    "segments": [{"text": line, "field": None}],
                    "matches": {},
                    "partial_match": partial_info
                })

        return results

    def pregenerate_pattern(self, text: str, format_mode: str = "dot") -> str:
        lines = [line.strip() for line in text.splitlines() if line.strip()]

        def format_field(dot_name: str) -> str:
            if format_mode == "bracket":
                parts = dot_name.split(".")
                return "".join(f"[{p}]" for p in parts)
            return dot_name

        if not lines:
            return f"%{{GREEDYDATA:{format_field('message')}}}"

        line_tails = list(lines)
        pattern_parts = []

        def consume_spaces():
            nonlocal line_tails, pattern_parts
            if not line_tails:
                return
            min_spaces = min(len(l) - len(l.lstrip(' ')) for l in line_tails)
            if min_spaces > 0:
                pattern_parts.append(" " * min_spaces)
                line_tails = [l[min_spaces:] for l in line_tails]

        pri_m = [re.match(r'^<(\d+)>(.*)', l) for l in line_tails]
        if all(m for m in pri_m):
            pattern_parts.append(f"<%{{INT:{format_field('syslog.pri')}}}>")
            line_tails = [m.group(2) for m in pri_m]

        consume_spaces()

        sys_ts = [re.match(r'^([A-Za-z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2})(.*)', l) for l in line_tails]
        iso_ts = [re.match(r'^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)(.*)', l) for l in line_tails]
        http_ts = [re.match(r'^\[(\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4})\](.*)', l) for l in line_tails]

        if all(m for m in sys_ts):
            pattern_parts.append(f"%{{SYSLOGTIMESTAMP:{format_field('timestamp')}}}")
            line_tails = [m.group(2) for m in sys_ts]
        elif all(m for m in iso_ts):
            pattern_parts.append(f"%{{TIMESTAMP_ISO8601:{format_field('timestamp')}}}")
            line_tails = [m.group(2) for m in iso_ts]
        elif all(m for m in http_ts):
            pattern_parts.append(f"[%{{HTTPDATE:{format_field('timestamp')}}}]")
            line_tails = [m.group(2) for m in http_ts]

        consume_spaces()

        level_m = [re.match(r'^(DEBUG|INFO|WARN|WARNING|ERROR|FATAL|CRITICAL)(.*)', l, re.IGNORECASE) for l in line_tails]
        if all(m for m in level_m):
            pattern_parts.append(f"%{{LOGLEVEL:{format_field('log.level')}}}")
            line_tails = [m.group(2) for m in level_m]

        consume_spaces()

        ip_m = [re.match(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(.*)', l) for l in line_tails]
        host_m = [re.match(r'^([a-zA-Z0-9_\-\.]+)(.*)', l) for l in line_tails]

        if all(m for m in ip_m):
            pattern_parts.append(f"%{{IP:{format_field('client.ip')}}}")
            line_tails = [m.group(2) for m in ip_m]
        elif all(m for m in host_m):
            pattern_parts.append(f"%{{SYSLOGHOST:{format_field('host.hostname')}}}")
            line_tails = [m.group(2) for m in host_m]

        consume_spaces()

        seq_m = [re.match(r'^(\d+)(.*)', l) for l in line_tails]
        if all(m for m in seq_m):
            pattern_parts.append(f"%{{INT:{format_field('syslog.sequence')}}}")
            line_tails = [m.group(2) for m in seq_m]

        consume_spaces()

        proc_m = [re.match(r'^([a-zA-Z0-9_\-\.]+):(.*)', l) for l in line_tails]
        if all(m for m in proc_m):
            pattern_parts.append(f"%{{WORD:{format_field('process.name')}}}:")
            line_tails = [m.group(2) for m in proc_m]

        consume_spaces()

        pattern_parts.append(f"%{{GREEDYDATA:{format_field('message')}}}")

        return "".join(pattern_parts)

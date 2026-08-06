import re
from typing import Dict, Any, List, Tuple
from pygrok import Grok


class GrokDebuggerEngine:
    def __init__(self):
        self.grok_field_re = re.compile(r'%\{([A-Z0-9_]+):([^}:]+)(:[a-zA-Z0-9_]+)?\}')
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

    def unflatten_dict(self, flat_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Converts flat dot/bracket notation dictionary keys into nested dictionary structures."""
        result = {}
        for key, value in flat_dict.items():
            parts = [p for p in re.split(r'[\[\]\.]+', key) if p]
            if not parts:
                continue
            curr = result
            for part in parts[:-1]:
                if part not in curr or not isinstance(curr[part], dict):
                    curr[part] = {}
                curr = curr[part]
            curr[parts[-1]] = value
        return result

    def find_partial_match(self, pattern_str: str, custom_patterns: Dict[str, str], line: str, strict_mode: bool = False) -> Dict[str, Any]:
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
                match = sub_grok.regex_obj.fullmatch(line) if strict_mode else sub_grok.regex_obj.search(line)
                
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

    def execute_match(self, pattern_str: str, custom_patterns_raw: str, text: str, strict_mode: bool = False) -> List[Dict[str, Any]]:
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

            # Switch between Strict Full Match (^...$) and Flexible Substring Search
            match = compiled_regex.fullmatch(line) if strict_mode else compiled_regex.search(line)

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

                ordered_matches = [
                    {"key": item["field"], "value": matches_dict[item["field"]]}
                    for item in spans_list if item["field"] in matches_dict
                ]

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

                ordered_flat_dict = {}
                for item in spans_list:
                    f_key = item["field"]
                    if f_key in matches_dict and f_key not in ordered_flat_dict:
                        ordered_flat_dict[f_key] = matches_dict[f_key]

                json_nested = self.unflatten_dict(ordered_flat_dict)

                results.append({
                    "line_number": line_idx + 1,
                    "matched": True,
                    "line_text": line,
                    "segments": segments,
                    "matches": matches_dict,
                    "ordered_matches": ordered_matches,
                    "json_data": json_nested
                })
            else:
                partial_info = self.find_partial_match(pattern_str, custom_patterns, line, strict_mode=strict_mode)
                results.append({
                    "line_number": line_idx + 1,
                    "matched": False,
                    "line_text": line,
                    "segments": [{"text": line, "field": None}],
                    "matches": {},
                    "ordered_matches": [],
                    "partial_match": partial_info,
                    "json_data": {}
                })

        return results

    def pregenerate_pattern(self, text: str, format_mode: str = "dot") -> str:
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        if not lines:
            return "%{GREEDYDATA:message}"

        def format_field(name: str, index: int) -> str:
            field_name = name if name else f"field{index}"
            if format_mode == "bracket":
                parts = field_name.strip('[]').split('.')
                return "".join(f"[{p}]" for p in parts)
            return field_name

        def escape_literal(s: str) -> str:
            return re.sub(r'([\\^$\.|?*+()\[\]{}])', r'\\\1', s)

        def detect_grok_type(val: str) -> str:
            if not val:
                return "DATA"
            
            cleaned = val.strip('\'"<>()[]{}')

            if re.match(r'^(\d{1,3}\.){3}\d{1,3}$', cleaned) or (':' in cleaned and re.match(r'^[0-9a-fA-F:]+$', cleaned)):
                return "IP"

            if '/' in cleaned and re.match(r'^(?:/[a-zA-Z0-9_.\-~+]+)+/?$', cleaned):
                return "PATH"

            if re.match(r'^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}', cleaned):
                return "TIMESTAMP_ISO8601"

            if cleaned.isdigit():
                return "INT"

            if re.match(r'^\d+\.\d+$', cleaned):
                return "NUMBER"

            return "NOTSPACE"

        def tokenize_line(line: str) -> List[Tuple[str, bool]]:
            pattern = (
                r'([a-zA-Z0-9_\-]+=)|'                # Key=Value prefixes
                r'(?:/[a-zA-Z0-9_.\-~+]+)+/?|'        # Unix File Paths
                r'(?:\d{1,3}\.){3}\d{1,3}|'           # IPv4 Addresses
                r'([0-9a-fA-F:]+:[0-9a-fA-F:]+)|'     # IPv6 / MAC
                r'(\d+\.\d+)|\d+|'                    # Numbers / Ints
                r'([a-zA-Z0-9_\-]+)|'                 # Words
                r'([^\w\s])|'                         # Punctuation
                r'(\s+)'                              # Whitespace
            )
            tokens = []
            for match in re.finditer(pattern, line):
                val = match.group(0)
                is_cand = not re.match(r'^[\s,:<>\(\)\[\]\'"=]+$', val)
                tokens.append((val, is_cand))
            return tokens

        sample_lines = lines[:min(5, len(lines))]
        tokenized_samples = [tokenize_line(line) for line in sample_lines]

        base_tokens = tokenized_samples[0]
        valid_samples = [s for s in tokenized_samples if len(s) == len(base_tokens)]

        field_counter = 0
        pattern_parts = []
        next_field_name = None

        SPECIFIC_TYPES = {"IP", "PATH", "INT", "NUMBER", "TIMESTAMP_ISO8601"}

        for idx, (base_val, is_cand) in enumerate(base_tokens):
            if not is_cand:
                pattern_parts.append(escape_literal(base_val))
                continue

            values_at_pos = []
            for sample in valid_samples:
                values_at_pos.append(sample[idx][0])

            kv_match = re.match(r'^([a-zA-Z0-9_\-]+)=', base_val)
            if kv_match:
                next_field_name = kv_match.group(1)
                pattern_parts.append(escape_literal(base_val))
                continue

            is_variable = len(set(values_at_pos)) > 1
            grok_type = detect_grok_type(base_val)

            if grok_type in SPECIFIC_TYPES or is_variable:
                field_counter += 1
                suggested_name = next_field_name if next_field_name else ""
                field_ref = format_field(suggested_name, field_counter)
                pattern_parts.append(f"%{{{grok_type}:{field_ref}}}")
                next_field_name = None
            else:
                pattern_parts.append(escape_literal(base_val))

        pattern = "".join(pattern_parts)
        pattern = re.sub(r' +', ' ', pattern)
        return pattern

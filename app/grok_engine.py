import re
from typing import Dict, Any, List, Tuple
from pygrok import Grok

class GrokDebuggerEngine:
    def __init__(self):
        # Escapes [field][subfield] syntax so Python's `re` module won't crash
        self.ecs_pattern = re.compile(r'(\?<|%\{[A-Z0-9_]+:)(\[[a-zA-Z0-9_\[\]\-]+\])')

    def parse_custom_patterns(self, custom_patterns_raw: str) -> Dict[str, str]:
        """Parses custom sub-patterns like: GREEDYDATA_NO_COLON [^:]*"""
        patterns = {}
        for line in custom_patterns_raw.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parts = line.split(maxsplit=1)
            if len(parts) == 2:
                patterns[parts[0]] = parts[1]
        return patterns

    def sanitize_ecs_fields(self, pattern_str: str) -> Tuple[str, Dict[str, str]]:
        """Maps bracketed fields like [network][protocol] to safe Python regex group names."""
        mapping = {}
        counter = 0

        def replacer(match):
            nonlocal counter
            prefix = match.group(1)
            bracket_val = match.group(2)
            safe_key = f"__ECS_{counter}__"
            mapping[safe_key] = bracket_val
            counter += 1
            return f"{prefix}{safe_key}"

        sanitized_pattern = self.ecs_pattern.sub(replacer, pattern_str)
        return sanitized_pattern, mapping

    def execute_match(self, pattern_str: str, custom_patterns_raw: str, text: str) -> List[Dict[str, Any]]:
        if not pattern_str or not text:
            return []

        custom_patterns = self.parse_custom_patterns(custom_patterns_raw)
        sanitized_pattern, ecs_map = self.sanitize_ecs_fields(pattern_str)

        try:
            grok = Grok(sanitized_pattern, custom_patterns=custom_patterns)
            compiled_regex = grok.regex_obj
        except Exception as e:
            raise ValueError(f"Pattern Compilation Error: {str(e)}")

        results = []
        for line_idx, line in enumerate(text.splitlines()):
            if not line.strip():
                continue

            match = compiled_regex.search(line)
            if match:
                raw_dict = match.groupdict()
                matches_dict = {}

                # Unmap safe internal keys back to ECS bracketed keys
                for key, val in raw_dict.items():
                    if val is None:
                        continue
                    final_key = ecs_map.get(key, key)
                    matches_dict[final_key] = val

                start, end = match.span()
                results.append({
                    "line_number": line_idx + 1,
                    "matched": True,
                    "line_text": line,
                    "span": [start, end],
                    "matched_text": match.group(0),
                    "matches": matches_dict
                })
            else:
                results.append({
                    "line_number": line_idx + 1,
                    "matched": False,
                    "line_text": line,
                    "span": None,
                    "matched_text": None,
                    "matches": {}
                })

        return results

    def pregenerate_pattern(self, text: str) -> str:
        """Basic heuristic pattern generator helper."""
        first_line = next((line for line in text.splitlines() if line.strip()), "")
        if not first_line:
            return "%{GREEDYDATA:message}"

        # Common simple auto-detection
        pattern = first_line
        pattern = re.sub(r'\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?\b', '%{TIMESTAMP_ISO8601:timestamp}', pattern)
        pattern = re.sub(r'\b(DEBUG|INFO|WARN|WARNING|ERROR|FATAL|CRITICAL)\b', '%{LOGLEVEL:log.level}', pattern)
        pattern = re.sub(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', '%{IP:client.ip}', pattern)
        
        if pattern == first_line:
            return "%{GREEDYDATA:message}"
            
        return pattern

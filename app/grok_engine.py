import difflib
import re
from typing import Any

from pygrok import Grok


class GrokDebuggerEngine:
    """
    Core engine for Grok pattern matching, validation, and generation.
    Handles pattern sanitization, field name validation, and partial matching diagnostics.
    """

    def __init__(self):
        """
        Initialize the GrokDebuggerEngine with precompiled regex patterns for performance.
        Precompiled patterns include:
        - Grok field patterns (e.g., `%{IP:client.ip}`)
        - Regex group patterns (e.g., `(?P<client.ip>...)`)
        - Field name validation patterns (dot and bracket notation)
        - Type detection patterns (IPv4, IPv6, paths, timestamps, etc.)
        """
        # Regex for Grok field patterns (e.g., `%{IP:client.ip}`)
        self.grok_field_re = re.compile(r'%\{([A-Z0-9_]+):([^}:]+)(:[a-zA-Z0-9_]+)?\}')

        # Regex for named regex groups (e.g., `(?P<client.ip>...)`)
        self.regex_group_re = re.compile(r'\(\?(?:<|P<)([^>]+)>')

        # Regex for validating Logstash field names in dot notation (e.g., `client.ip`)
        self.valid_dot_field = re.compile(r'^[a-zA-Z0-9_\-]+(\.[a-zA-Z0-9_\-]+)*$')

        # Regex for validating Logstash field names in bracket notation (e.g., `[client][ip]`)
        self.valid_bracket_field = re.compile(r'^(\[[a-zA-Z0-9_\-]+\])+$')

        # Precompiled regex for type detection (used in `detect_grok_type`)
        self.ipv4_re = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
        self.ipv6_re = re.compile(r'^[0-9a-fA-F:]+$')
        self.path_re = re.compile(r'^(?:/[a-zA-Z0-9_.\-~+]+)+/?$')
        self.timestamp_iso8601_re = re.compile(r'^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}')
        self.number_re = re.compile(r'^\d+\.?\d*$')

    def parse_custom_patterns(self, custom_patterns_raw: str) -> dict[str, str]:
        """
        Parse custom Grok patterns from a raw string.

        Args:
            custom_patterns_raw: Raw string containing custom patterns, one per line.
                                Lines starting with `#` are treated as comments.

        Returns:
            Dictionary of custom patterns, where keys are pattern names and values are regex patterns.
        """
        patterns = {}
        for line in custom_patterns_raw.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parts = line.split(maxsplit=1)
            if len(parts) == 2:
                patterns[parts[0]] = parts[1]
        return patterns

    def validate_logstash_field_name(self, field_name: str) -> None:
        """
        Validate a Logstash field name (dot or bracket notation).

        Args:
            field_name: The field name to validate.

        Raises:
            ValueError: If the field name is invalid (not in dot or bracket notation).
        """
        if not (self.valid_dot_field.match(field_name) or self.valid_bracket_field.match(field_name)):
            raise ValueError(
                f"Invalid Logstash field name '{field_name}'. "
                f"Logstash requires either dot-notation (e.g., 'client.ip') "
                f"or bracket-notation (e.g., '[client][ip]')."
            )

    def _sanitize_string(
        self,
        text: str,
        mapping: dict[str, str],
        counter: list[int]
    ) -> str:
        """
        Sanitize field names in Grok and regex patterns by replacing them with safe keys.

        Args:
            text: The input text (Grok or regex pattern).
            mapping: Dictionary to store the mapping between safe keys and original field names.
            counter: List containing a single integer used to generate unique safe keys.

        Returns:
            Sanitized text with field names replaced by safe keys.
        """
        def grok_repl(match: re.Match) -> str:
            pattern_name = match.group(1)
            field_name = match.group(2)
            type_spec = match.group(3) or ""

            self.validate_logstash_field_name(field_name)

            safe_key = f"__FIELD_{counter[0]}__"
            counter[0] += 1
            mapping[safe_key] = field_name
            return f"%{{{pattern_name}:{safe_key}{type_spec}}}"

        def regex_repl(match: re.Match) -> str:
            field_name = match.group(1)
            self.validate_logstash_field_name(field_name)

            safe_key = f"__FIELD_{counter[0]}__"
            counter[0] += 1
            mapping[safe_key] = field_name
            return f"(?P<{safe_key}>"

        text = self.grok_field_re.sub(grok_repl, text)
        text = self.regex_group_re.sub(regex_repl, text)
        return text

    def sanitize_field_names(
        self,
        pattern_str: str,
        custom_patterns: dict[str, str] | None = None
    ) -> tuple[str, dict[str, str], dict[str, str]]:
        """
        Sanitize field names in Grok patterns and custom patterns.

        Args:
            pattern_str: The main Grok pattern string.
            custom_patterns: Optional dictionary of custom patterns.

        Returns:
            Tuple containing:
            - Sanitized pattern string.
            - Sanitized custom patterns dictionary.
            - Mapping of safe keys to original field names.
        """
        if custom_patterns is None:
            custom_patterns = {}

        mapping: dict[str, str] = {}
        counter = [0]

        sanitized_pattern = self._sanitize_string(pattern_str, mapping, counter)

        sanitized_custom = {}
        for k, v in custom_patterns.items():
            sanitized_custom[k] = self._sanitize_string(v, mapping, counter)

        return sanitized_pattern, sanitized_custom, mapping

    def unflatten_dict(self, flat_dict: dict[str, Any]) -> dict[str, Any]:
        """
        Convert a flat dictionary with dot/bracket notation keys into a nested dictionary.

        Example:
            Input: {"client.ip": "192.168.1.1", "[server][port]": "80"}
            Output: {"client": {"ip": "192.168.1.1"}, "server": {"port": "80"}}

        Args:
            flat_dict: Flat dictionary with dot/bracket notation keys.

        Returns:
            Nested dictionary.
        """
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

    def find_partial_match(
        self,
        pattern_str: str,
        custom_patterns: dict[str, str],
        line: str,
        strict_mode: bool = False
    ) -> dict[str, Any]:
        """
        Progressively test pattern tokens to find the longest matching prefix when a full match fails.

        Args:
            pattern_str: The Grok pattern string.
            custom_patterns: Dictionary of custom patterns.
            line: The log line to match.
            strict_mode: If True, require a full line match (^...$). Otherwise, allow substring matches.

        Returns:
            Dictionary containing:
            - matched_prefix: The longest matching prefix of the pattern.
            - matched_fields: Fields captured before the mismatch.
            - unmatched_remainder: The part of the line that failed to match.
        """
        tokens = re.split(r'(%\{[^{}]+\}|\(?<[^>]+>.*?\))', pattern_str)
        tokens = [t for t in tokens if t]

        longest_matched_prefix = ""
        longest_matched_dict = {}
        longest_unmatched_remainder = line

        for i in range(1, len(tokens) + 1):
            sub_pattern = "".join(tokens[:i])
            try:
                sanitized_pattern, sanitized_custom, field_map = self.sanitize_field_names(
                    sub_pattern, custom_patterns
                )
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
            except Exception:  # noqa: BLE001 - pygrok/re can raise several undocumented
                # exception types for a malformed sub-pattern; any of them just means
                # "this prefix doesn't compile", so we stop widening the prefix here.
                break

        return {
            "matched_prefix": longest_matched_prefix,
            "matched_fields": longest_matched_dict,
            "unmatched_remainder": longest_unmatched_remainder
        }

    def _build_match_result(
        self,
        line: str,
        match: re.Match,
        field_map: dict[str, str],
        strict_mode: bool
    ) -> dict[str, Any]:
        """
        Build the result for a matched line, including extracted fields and spans.

        Args:
            line: The log line that matched.
            match: The regex match object.
            field_map: Mapping of safe keys to original field names.
            strict_mode: Whether strict mode was used.

        Returns:
            Dictionary containing:
            - matches_dict: Dictionary of matched field names and values.
            - spans_list: List of spans with field names and their positions.
        """
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
        return {"matches_dict": matches_dict, "spans_list": spans_list}

    def execute_match(
        self,
        pattern_str: str,
        custom_patterns_raw: str,
        text: str,
        strict_mode: bool = False
    ) -> list[dict[str, Any]]:
        """
        Execute Grok pattern matching against the provided text.

        Args:
            pattern_str: The Grok pattern string.
            custom_patterns_raw: Raw string of custom patterns.
            text: The log text to match against.
            strict_mode: If True, require a full line match (^...$). Otherwise, allow substring matches.

        Returns:
            List of dictionaries, each representing the match result for a line.
            Each result includes:
            - line_number: Line number in the input text.
            - matched: Whether the line matched the pattern.
            - line_text: The original line text.
            - segments: List of text segments with field annotations.
            - matches: Dictionary of matched field names and values.
            - ordered_matches: List of matches ordered by position in the line.
            - json_data: Nested dictionary of matched fields.
            - partial_match: Partial match information (if no full match).
        """
        if not pattern_str or not text:
            return []

        custom_patterns = self.parse_custom_patterns(custom_patterns_raw)
        sanitized_pattern, sanitized_custom, field_map = self.sanitize_field_names(
            pattern_str, custom_patterns
        )

        try:
            grok = Grok(sanitized_pattern, custom_patterns=sanitized_custom)
            compiled_regex = grok.regex_obj
        except Exception as e:
            # Normalizes any pygrok/re compilation failure (KeyError, re.error, etc.)
            # into a single user-facing ValueError.
            raise ValueError(f"Pattern Compilation Error: {e!s}") from e

        results = []
        for line_idx, line in enumerate(text.splitlines()):
            if not line.strip():
                continue

            match = compiled_regex.fullmatch(line) if strict_mode else compiled_regex.search(line)

            if match:
                match_result = self._build_match_result(line, match, field_map, strict_mode)
                matches_dict = match_result["matches_dict"]
                spans_list = match_result["spans_list"]

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
                partial_info = self.find_partial_match(
                    pattern_str, custom_patterns, line, strict_mode=strict_mode
                )
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

    def detect_grok_type(self, val: str) -> str:
        """
        Detect the most appropriate Grok type for a given value.

        Args:
            val: The value to analyze.

        Returns:
            The detected Grok type (e.g., "IP", "PATH", "INT", "TIMESTAMP_ISO8601").
        """
        if not val:
            return "DATA"

        cleaned = val.strip('\'"<>()[]{}')

        # A bare "[0-9a-fA-F:]+" match also accepts plain HH:MM:SS times (e.g.
        # "10:23:01" is all digits and colons), so require a real IPv6 signal
        # too: zero-compression ("::"), a hex letter, or more groups than a
        # timestamp would ever have (3+ colons).
        looks_like_ipv6 = self.ipv6_re.match(cleaned) and (
            '::' in cleaned or re.search(r'[a-fA-F]', cleaned) or cleaned.count(':') >= 3
        )
        if self.ipv4_re.match(cleaned) or (':' in cleaned and looks_like_ipv6):
            return "IP"

        if '/' in cleaned and self.path_re.match(cleaned):
            return "PATH"

        if self.timestamp_iso8601_re.match(cleaned):
            return "TIMESTAMP_ISO8601"

        if cleaned.isdigit():
            return "INT"

        if self.number_re.match(cleaned):
            return "NUMBER"

        return "NOTSPACE"

    def pregenerate_pattern(self, text: str, format_mode: str = "dot") -> str:
        """
        Automatically generate a Grok pattern from sample log text.

        Args:
            text: Sample log text (one or more lines).
            format_mode: Field naming format ("dot" for `client.ip` or "bracket" for `[client][ip]`).

        Returns:
            Generated Grok pattern.
        """
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        if not lines:
            return "%{GREEDYDATA:message}"

        def format_field(name: str, index: int) -> str:
            """Format a field name based on the selected naming convention."""
            field_name = name if name else f"field{index}"
            if format_mode == "bracket":
                parts = field_name.strip('[]').split('.')
                return "".join(f"[{p}]" for p in parts)
            return field_name

        def escape_literal(s: str) -> str:
            """Escape special regex characters in a literal string."""
            return re.sub(r'([\\^$\.|?*+()\[\]{}])', r'\\\1', s)

        def tokenize_line(line: str) -> list[tuple[str, bool]]:
            """
            Tokenize a log line into candidate values for pattern generation.

            Returns:
                List of tuples (token, is_candidate), where `is_candidate` indicates
                whether the token is a potential field (not just punctuation/whitespace).
            """
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

        SPECIFIC_TYPES = {"IP", "PATH", "INT", "NUMBER", "TIMESTAMP_ISO8601"}

        def is_specific(token_text: str) -> bool:
            return self.detect_grok_type(token_text) in SPECIFIC_TYPES

        # Each merged template segment: representative text, whether it must
        # become a %{...} field, whether it still corresponds to exactly one raw
        # token (vs. a multi-token span collapsed during alignment), and whether
        # it was missing from at least one sample line seen so far.
        class _Node:
            __slots__ = ("is_field", "optional", "single_token", "text")

            def __init__(self, text, is_field, single_token=True, optional=False):
                self.text = text
                self.is_field = is_field
                self.single_token = single_token
                self.optional = optional

        def align_key(text: str, specific: bool, uid) -> Any:
            # Stable literal text (punctuation, whitespace, plain keywords) anchors
            # the alignment between samples. Anything that already looks like an
            # IP/PATH/number/etc. never anchors, even if it happens to repeat
            # verbatim - it's still a variable slot, so it gets a unique key that
            # can never compare equal to anything.
            return uid if specific else text

        # Seed the merged template from the first sample line.
        template: list[_Node] = [
            _Node(tok, is_specific(tok)) for tok, _cand in tokenized_samples[0]
        ]

        # Progressively fold every other sample line into the template with a
        # sequence diff rather than positional indexing, so a line with an
        # extra or missing segment - not just a different value at a fixed
        # slot - still aligns correctly against the rest.
        for tokens in tokenized_samples[1:]:
            new_texts = [tok for tok, _cand in tokens]

            tmpl_keys = [align_key(n.text, (not n.single_token) or n.is_field, id(n)) for n in template]
            new_keys = [align_key(txt, is_specific(txt), object()) for txt in new_texts]

            matcher = difflib.SequenceMatcher(None, tmpl_keys, new_keys, autojunk=False)
            merged: list[_Node] = []

            for tag, i1, i2, j1, j2 in matcher.get_opcodes():
                if tag == "equal":
                    merged.extend(template[i1:i2])
                elif tag == "replace":
                    # Differing content at this position: always a field, even if
                    # it's not a "specific" type - the difference itself proves
                    # it's variable.
                    merged.append(_Node(
                        text=new_texts[j2 - 1],
                        is_field=True,
                        single_token=(i2 - i1 == 1 and j2 - j1 == 1),
                    ))
                elif tag == "delete":
                    # Present in earlier samples, absent from this one - keep it,
                    # but mark it optional so it's wrapped in (?:...)? below. A
                    # multi-token span collapses to one node, but only becomes a
                    # field if it actually contains variable content - a purely
                    # literal optional chunk (e.g. "[imp] ") stays literal.
                    seg = template[i1:i2]
                    if len(seg) == 1:
                        node = seg[0]
                    else:
                        node = _Node(
                            text="".join(n.text for n in seg),
                            is_field=any(n.is_field or is_specific(n.text) for n in seg),
                            single_token=False,
                        )
                    node.optional = True
                    merged.append(node)
                elif tag == "insert":
                    # This sample introduces material earlier ones didn't have.
                    seg_texts = new_texts[j1:j2]
                    merged.append(_Node(
                        text="".join(seg_texts),
                        is_field=any(is_specific(t) for t in seg_texts),
                        single_token=(j2 - j1 == 1),
                        optional=True,
                    ))

            template = merged

        # --- Render the merged template into a Grok pattern string ---
        field_counter = 0
        next_field_name = None
        raw_parts: list[tuple[str, bool]] = []  # (fragment, optional)

        for idx, node in enumerate(template):
            text = node.text
            treat_as_field = node.is_field or (node.single_token and is_specific(text))

            if node.single_token and not treat_as_field:
                kv_match = re.match(r'^([a-zA-Z0-9_\-]+)=', text)
                if kv_match:
                    next_field_name = kv_match.group(1)
                    raw_parts.append((escape_literal(text), node.optional))
                    continue

            if treat_as_field:
                field_counter += 1
                suggested_name = next_field_name if next_field_name else ""
                field_ref = format_field(suggested_name, field_counter)
                if node.single_token:
                    grok_type = self.detect_grok_type(text)
                else:
                    # Non-greedy DATA for an interior variable-width gap so it
                    # doesn't swallow past the next literal anchor; GREEDYDATA
                    # only makes sense as a trailing catch-all.
                    grok_type = "GREEDYDATA" if idx == len(template) - 1 else "DATA"
                raw_parts.append((f"%{{{grok_type}:{field_ref}}}", node.optional))
                next_field_name = None
            else:
                raw_parts.append((escape_literal(text), node.optional))

        # Merge contiguous optional segments into a single (?:...)? group
        # instead of wrapping each token individually - e.g. an optional
        # leading tag like "[imp] " becomes one group, not four.
        pattern_parts = []
        i = 0
        while i < len(raw_parts):
            frag, optional = raw_parts[i]
            if not optional:
                pattern_parts.append(frag)
                i += 1
                continue
            chunk = []
            j = i
            while j < len(raw_parts) and raw_parts[j][1]:
                chunk.append(raw_parts[j][0])
                j += 1
            pattern_parts.append(f"(?:{''.join(chunk)})?")
            i = j

        return "".join(pattern_parts)

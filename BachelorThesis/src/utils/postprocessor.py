import base64
import re
from collections import defaultdict

class PostProcessor:
    def __init__(self, results: dict):
        self.results = results

    # -------------------------
    # Public API
    # -------------------------
    def process(self):
        data = self._deduplicate(self.results)
        data = self._auto_decode(data)
        data = self._normalize(data)
        grouped = self._score_and_group(data)
        return grouped

    # -------------------------
    # Step 1: Deduplication
    # -------------------------
    def _deduplicate(self, data):
        result = {}

        for key, value in data.items():
            if isinstance(value, list):
                unique = list(set(value))
                result[key] = unique
            else:
                result[key] = value

        return result

    # -------------------------
    # Step 2: Detection helpers
    # -------------------------
    def _looks_base64(self, s):
        if not isinstance(s, str):
            return False
        return bool(re.fullmatch(r'[A-Za-z0-9+/=\n\r]{16,}', s.strip()))

    def _looks_hex(self, s):
        if not isinstance(s, str):
            return False
        return bool(re.fullmatch(r'[0-9a-fA-F\s]{16,}', s.strip()))

    # -------------------------
    # Step 3: Decoding
    # -------------------------
    def _decode_once(self, s):
        s = s.strip()

        try:
            if self._looks_base64(s):
                decoded = base64.b64decode(s)
                return decoded.decode(errors='ignore')
        except:
            pass

        try:
            if self._looks_hex(s):
                cleaned = s.replace(" ", "").replace("\n", "")
                decoded = bytes.fromhex(cleaned)
                return decoded.decode(errors='ignore')
        except:
            pass

        return s

    def _auto_decode(self, data):
        decoded = {}

        for key, value in data.items():
            if isinstance(value, str):
                v1 = self._decode_once(value)
                v2 = self._decode_once(v1) if v1 != value else v1
                decoded[key] = v2
            elif isinstance(value, list):
                new_list = []
                for item in value:
                    if isinstance(item, str):
                        v1 = self._decode_once(item)
                        v2 = self._decode_once(v1) if v1 != item else v1
                        new_list.append(v2)
                    else:
                        new_list.append(item)
                decoded[key] = new_list
            else:
                decoded[key] = value

        return decoded

    # -------------------------
    # Step 4: Normalize lists
    # -------------------------
    def _normalize(self, data):
        normalized = {}

        for key, value in data.items():
            if isinstance(value, list):
                counts = defaultdict(int)
                for item in value:
                    counts[item] += 1

                summarized = [
                    f"{item} (seen {count}x)" if count > 1 else item
                    for item, count in counts.items()
                ]
                normalized[key] = summarized
            else:
                normalized[key] = value

        return normalized

    # -------------------------
    # Step 5: Scoring
    # -------------------------
    def _score_value(self, v):
        if not isinstance(v, str):
            return "LOW"

        v_lower = v.lower()

        if "picoctf{" in v_lower or "flag" in v_lower:
            return "HIGH"

        if self._looks_base64(v):
            return "HIGH"

        if any(word in v_lower for word in ["secret", "password", "key"]):
            return "HIGH"

        if any(c.isalpha() for c in v) and len(v) > 12:
            return "MEDIUM"

        return "LOW"

    # -------------------------
    # Step 6: Grouping
    # -------------------------
    def _score_and_group(self, data):
        grouped = {
            "HIGH": {},
            "MEDIUM": {},
            "LOW": {}
        }

        for key, value in data.items():
            if isinstance(value, str):
                level = self._score_value(value)
            elif isinstance(value, list):
                level = "LOW"
                for item in value:
                    level = max(level, self._score_value(item), key=self._priority_rank)
            else:
                level = "LOW"

            grouped[level][key] = value

        return grouped

    def _priority_rank(self, level):
        order = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
        return order.get(level, 0)
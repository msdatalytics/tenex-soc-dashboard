# ZScaler Web Proxy Log Parser
# Similar to Google Chronicle SIEM normalization pipelines

from datetime import datetime
from typing import Optional

# Field mapping — defines the order of fields in raw log
FIELD_MAP = {
    0: "timestamp",
    1: "source_ip",
    2: "user",
    3: "http_method",
    4: "domain",
    5: "action",
    6: "status_code",
    7: "browser"
}

# Suspicious domains list — used for threat detection
SUSPICIOUS_DOMAINS = [
    ".ru", ".xyz", ".tk", ".pw", ".top",
    "malware", "suspicious", "phishing", "hack"
]

class ZScalerParser:
    """
    Parses ZScaler NSS web proxy logs into structured JSON.
    Designed to mimic SIEM normalization like Google Chronicle.
    """

    def parse_line(self, raw_line: str) -> Optional[dict]:
        """Parse a single log line into structured JSON"""
        try:
            # Split line by comma
            fields = raw_line.strip().split(",")

            # Must have at least 8 fields
            if len(fields) < 8:
                return None

            # Map fields using FIELD_MAP
            parsed = {}
            for index, field_name in FIELD_MAP.items():
                parsed[field_name] = fields[index].strip()

            # Clean up fields
            parsed["status_code"] = int(parsed["status_code"])
            parsed["timestamp"] = self._normalize_timestamp(parsed["timestamp"])
            parsed["is_suspicious_domain"] = self._check_suspicious_domain(parsed["domain"])

            return parsed

        except Exception as e:
            # Skip malformed lines gracefully
            print(f"Skipping malformed line: {raw_line} | Error: {e}")
            return None

    def parse_file(self, file_path: str) -> list:
        """Parse entire log file — returns list of structured records"""
        results = []

        with open(file_path, "r") as f:
            for line in f:
                # Skip empty lines
                if not line.strip():
                    continue

                parsed = self.parse_line(line)
                if parsed:
                    results.append(parsed)

        print(f"Parsed {len(results)} log entries successfully")
        return results

    def _normalize_timestamp(self, raw_ts: str) -> str:
        """Convert timestamp to ISO 8601 format"""
        try:
            dt = datetime.strptime(raw_ts, "%Y-%m-%d %H:%M:%S")
            return dt.isoformat()
        except:
            return raw_ts

    def _check_suspicious_domain(self, domain: str) -> bool:
        """Flag domains that match suspicious patterns"""
        domain_lower = domain.lower()
        return any(sus in domain_lower for sus in SUSPICIOUS_DOMAINS)

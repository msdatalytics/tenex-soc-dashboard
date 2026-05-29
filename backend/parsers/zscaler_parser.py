# ZScaler Web Proxy Log Parser
# Supports both:
# 1. Log format: timestamp,ip,user,method,domain,action,status,browser
# 2. Real ZScaler NSS JSON format (as used in Google Chronicle)

import json
from datetime import datetime
from typing import Optional

# CSV field mapping
FIELD_MAP = {
    0: "timestamp", 1: "source_ip", 2: "user",
    3: "http_method", 4: "domain", 5: "action",
    6: "status_code", 7: "browser"
}

# Suspicious domain patterns
SUSPICIOUS_DOMAINS = [
    ".ru", ".xyz", ".tk", ".pw", ".top",
    "malware", "suspicious", "phishing",
    "hack", "exploit", "botnet"
]

class ZScalerParser:
    """
    Parses ZScaler NSS web proxy logs into structured JSON.
    Supports both LOg and real ZScaler JSON formats.
    Similar to Google Chronicle SIEM normalization pipeline.
    """

    def parse_file(self, file_path: str) -> list:
        """Auto-detect format and parse entire file"""
        results = []

        with open(file_path, "r") as f:
            content = f.read().strip()

        # Auto-detect JSON vs CSV
        first_line = content.split("\n")[0].strip()
        if first_line.startswith("{") or first_line.startswith("["):
            print("Detected: ZScaler JSON format")
            results = self._parse_json_format(content)
        else:
            print("Detected: CSV format")
            results = self._parse_csv_format(content)

        print(f"Parsed {len(results)} log entries successfully")
        return results

    def _parse_json_format(self, content: str) -> list:
        """Parse real ZScaler NSS JSON format — one JSON object per line"""
        results = []
        lines = content.strip().split("\n")

        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line)
                # Support both wrapped {"event": {...}} and flat format
                event = raw.get("event", raw)
                parsed = self._normalize_json_event(event)
                if parsed:
                    results.append(parsed)
            except Exception as e:
                print(f"Skipping invalid JSON line: {e}")

        return results

    def _normalize_json_event(self, event: dict) -> Optional[dict]:
        """
        Normalize real ZScaler JSON event to standard schema.
        This mirrors how Google Chronicle normalizes ZScaler logs.
        """
        try:
            # Extract domain from hostname or url
            raw_url = event.get("hostname", event.get("url", ""))
            domain = raw_url.split("/")[0].split(":")[0]

            # Normalize action
            action_raw = event.get("action", event.get("reason", "Unknown"))
            action = "BLOCK" if action_raw.lower() in ["blocked", "block"] else "ALLOW"

            # Normalize useragent — truncate to browser name
            useragent = event.get("useragent", "Unknown")
            browser = self._extract_browser(useragent)

            return {
                # Standard fields
                "timestamp": self._normalize_timestamp(event.get("datetime", "")),
                "source_ip": event.get("ClientIP", ""),
                "user": event.get("user", event.get("deviceowner", "")),
                "http_method": event.get("requestmethod", "GET"),
                "domain": domain,
                "action": action,
                "status_code": int(event.get("status", 0)),
                "browser": browser,
                "is_suspicious_domain": self._check_suspicious_domain(domain),

                # Extended ZScaler fields — extra value for SOC analysts
                "threat_name": event.get("threatname", "None"),
                "threat_category": event.get("threatcategory", "None"),
                "threat_severity": event.get("threatseverity", "None"),
                "url_category": event.get("urlcategory", "None"),
                "page_risk": int(event.get("pagerisk", 0)),
                "department": event.get("department", "Unknown"),
                "device": event.get("devicehostname", "Unknown"),
                "location": event.get("location", "Unknown"),
                "app_name": event.get("appname", "Unknown"),
                "request_size": int(event.get("requestsize", 0)),
                "response_size": int(event.get("responsesize", 0)),
                "server_ip": event.get("serverip", ""),
                "format": "zscaler_json"
            }
        except Exception as e:
            print(f"Error normalizing event: {e}")
            return None

    def _parse_csv_format(self, content: str) -> list:
        """Parse simplified CSV format"""
        results = []
        for line in content.strip().split("\n"):
            if not line.strip():
                continue
            parsed = self._parse_csv_line(line)
            if parsed:
                results.append(parsed)
        return results

    def _parse_csv_line(self, raw_line: str) -> Optional[dict]:
        """Parse single CSV log line"""
        try:
            fields = raw_line.strip().split(",")
            if len(fields) < 8:
                return None

            parsed = {}
            for index, field_name in FIELD_MAP.items():
                parsed[field_name] = fields[index].strip()

            parsed["status_code"] = int(parsed["status_code"])
            parsed["timestamp"] = self._normalize_timestamp(parsed["timestamp"])
            parsed["is_suspicious_domain"] = self._check_suspicious_domain(parsed["domain"])

            # Add empty extended fields for consistency
            parsed["threat_name"] = "None"
            parsed["threat_category"] = "None"
            parsed["threat_severity"] = "None"
            parsed["url_category"] = "None"
            parsed["page_risk"] = 0
            parsed["department"] = "Unknown"
            parsed["device"] = "Unknown"
            parsed["location"] = "Unknown"
            parsed["app_name"] = "Unknown"
            parsed["request_size"] = 0
            parsed["response_size"] = 0
            parsed["server_ip"] = ""
            parsed["format"] = "csv"

            return parsed
        except Exception as e:
            print(f"Skipping malformed line: {raw_line} | Error: {e}")
            return None

    def _extract_browser(self, useragent: str) -> str:
        """Extract browser name from user agent string"""
        ua = useragent.lower()
        if "chrome" in ua:
            return "Chrome"
        elif "firefox" in ua:
            return "Firefox"
        elif "safari" in ua:
            return "Safari"
        elif "edge" in ua:
            return "Edge"
        else:
            return "Unknown"

    def _normalize_timestamp(self, raw_ts: str) -> str:
        """Convert timestamp to ISO 8601 format"""
        for fmt in ["%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"]:
            try:
                return datetime.strptime(raw_ts, fmt).isoformat()
            except:
                continue
        return raw_ts

    def _check_suspicious_domain(self, domain: str) -> bool:
        """Flag domains matching known malicious patterns"""
        domain_lower = domain.lower()
        return any(sus in domain_lower for sus in SUSPICIOUS_DOMAINS)

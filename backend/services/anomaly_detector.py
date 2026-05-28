# Anomaly Detection Service
# Rule-based threat detection — similar to SOC alert rules

from collections import Counter
from datetime import datetime
from typing import List

# Detection thresholds
HIGH_REQUEST_THRESHOLD = 5      # requests from same IP in short time
BLOCK_THRESHOLD = 3             # blocked requests from same IP
OFF_HOURS_START = 22            # 10 PM
OFF_HOURS_END = 6               # 6 AM

class AnomalyDetector:
    """
    Rule-based anomaly detection for SOC log analysis.
    Each rule returns an anomaly object with confidence score.
    """

    def analyze(self, logs: list) -> list:
        """Run all detection rules and return list of anomalies"""
        anomalies = []

        anomalies.extend(self._detect_high_volume(logs))
        anomalies.extend(self._detect_suspicious_domains(logs))
        anomalies.extend(self._detect_excessive_blocks(logs))
        anomalies.extend(self._detect_off_hours(logs))

        print(f"Detected {len(anomalies)} anomalies")
        return anomalies

    def _detect_high_volume(self, logs: list) -> list:
        """Detect IPs making too many requests"""
        anomalies = []
        ip_counts = Counter(log["source_ip"] for log in logs)

        for ip, count in ip_counts.items():
            if count >= HIGH_REQUEST_THRESHOLD:
                anomalies.append({
                    "type": "High Request Volume",
                    "severity": "HIGH",
                    "confidence": round(min(0.95, 0.6 + (count / 20)), 2),
                    "source_ip": ip,
                    "reason": f"{count} requests from {ip} detected",
                    "affected_logs": [l for l in logs if l["source_ip"] == ip]
                })

        return anomalies

    def _detect_suspicious_domains(self, logs: list) -> list:
        """Detect requests to suspicious domains"""
        anomalies = []
        suspicious = [l for l in logs if l.get("is_suspicious_domain")]

        for log in suspicious:
            anomalies.append({
                "type": "Suspicious Domain Access",
                "severity": "HIGH",
                "confidence": 0.92,
                "source_ip": log["source_ip"],
                "reason": f"Request to suspicious domain: {log['domain']}",
                "affected_logs": [log]
            })

        return anomalies

    def _detect_excessive_blocks(self, logs: list) -> list:
        """Detect IPs with many blocked requests"""
        anomalies = []
        blocked = [l for l in logs if l.get("action") == "BLOCK"]
        ip_blocks = Counter(l["source_ip"] for l in blocked)

        for ip, count in ip_blocks.items():
            if count >= BLOCK_THRESHOLD:
                anomalies.append({
                    "type": "Excessive Blocked Requests",
                    "severity": "MEDIUM",
                    "confidence": round(min(0.90, 0.55 + (count / 15)), 2),
                    "source_ip": ip,
                    "reason": f"{count} blocked requests from {ip}",
                    "affected_logs": [l for l in blocked if l["source_ip"] == ip]
                })

        return anomalies

    def _detect_off_hours(self, logs: list) -> list:
        """Detect requests outside business hours"""
        anomalies = []

        for log in logs:
            try:
                hour = datetime.fromisoformat(log["timestamp"]).hour
                if hour >= OFF_HOURS_START or hour < OFF_HOURS_END:
                    anomalies.append({
                        "type": "Off-Hours Activity",
                        "severity": "MEDIUM",
                        "confidence": 0.75,
                        "source_ip": log["source_ip"],
                        "reason": f"Request at {hour}:00 — outside business hours",
                        "affected_logs": [log]
                    })
            except:
                continue

        return anomalies

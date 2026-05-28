# Claude AI Threat Summary Service
# Uses Anthropic Claude API to generate natural language threat analysis
# This is where LLM/AI is used in this application

import anthropic
import json
import os

def generate_threat_summary(summary: dict, anomalies: list, timeline: list) -> str:
    """
    Uses Claude AI to generate a natural language SOC threat summary.
    This replaces generic rule outputs with human-readable analyst-style reporting.
    """
    try:
        client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

        # Build context for Claude
        high_anomalies = [a for a in anomalies if a.get("severity") == "HIGH"]
        medium_anomalies = [a for a in anomalies if a.get("severity") == "MEDIUM"]

        prompt = f"""You are a senior SOC analyst at a cybersecurity company.
Analyze this log data and write a brief, professional threat summary in 3-4 sentences.
Focus on the most critical findings. Be specific about IPs, domains, and users involved.

Log Summary:
- Total logs analyzed: {summary.get('total_logs')}
- Unique IPs: {summary.get('unique_ips')}
- Blocked requests: {summary.get('blocked_requests')}
- Anomalies detected: {summary.get('anomalies_detected')}

High severity anomalies:
{json.dumps(high_anomalies[:3], indent=2)}

Medium severity anomalies:
{json.dumps(medium_anomalies[:2], indent=2)}

Write a concise SOC analyst threat summary. Start with the most critical threat."""

        message = client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=300,
            messages=[{"role": "user", "content": prompt}]
        )

        return message.content[0].text

    except Exception as e:
        print(f"Claude AI summary failed: {e}")
        return generate_fallback_summary(summary, anomalies)

def generate_fallback_summary(summary: dict, anomalies: list) -> str:
    """Fallback summary if Claude API is unavailable"""
    high_count = len([a for a in anomalies if a.get("severity") == "HIGH"])
    medium_count = len([a for a in anomalies if a.get("severity") == "MEDIUM"])

    return (
        f"Analysis of {summary.get('total_logs')} log entries detected "
        f"{summary.get('anomalies_detected')} anomalies across "
        f"{summary.get('unique_ips')} unique IPs. "
        f"Found {high_count} HIGH severity and {medium_count} MEDIUM severity threats. "
        f"{summary.get('blocked_requests')} requests were blocked by the proxy. "
        f"Immediate investigation recommended for flagged IPs."
    )

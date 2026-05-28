from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required
from parsers.zscaler_parser import ZScalerParser
from services.anomaly_detector import AnomalyDetector
from services.ai_summary import generate_threat_summary
from models import save_analysis, get_analysis
from collections import Counter
import os

analysis_bp = Blueprint("analysis", __name__)
parser = ZScalerParser()
detector = AnomalyDetector()

@analysis_bp.route("/analyze/<file_id>", methods=["GET"])
@jwt_required()
def analyze(file_id):
    file_path = os.path.join(current_app.config["UPLOAD_FOLDER"], file_id)

    if not os.path.exists(file_path):
        return jsonify({"error": "File not found"}), 404

    logs = parser.parse_file(file_path)
    if not logs:
        return jsonify({"error": "No valid logs found"}), 400

    anomalies = detector.analyze(logs)

    blocked = [l for l in logs if l.get("action") == "BLOCK"]
    ip_counts = Counter(l["source_ip"] for l in logs)

    summary = {
        "total_logs": len(logs),
        "unique_ips": len(ip_counts),
        "blocked_requests": len(blocked),
        "anomalies_detected": len(anomalies),
        "allow_count": len([l for l in logs if l.get("action") == "ALLOW"]),
        "top_ips": [{"ip": ip, "count": count} for ip, count in ip_counts.most_common(5)]
    }

    timeline = []
    for log in logs:
        if log.get("action") == "BLOCK" or log.get("is_suspicious_domain"):
            timeline.append({
                "timestamp": log["timestamp"],
                "event": f"{'Blocked' if log['action'] == 'BLOCK' else 'Suspicious'} request to {log['domain']}",
                "severity": "HIGH" if log.get("is_suspicious_domain") else "MEDIUM",
                "user": log["user"],
                "source_ip": log["source_ip"]
            })

    # Generate Claude AI threat summary
    print("Generating Claude AI threat summary...")
    ai_summary = generate_threat_summary(summary, anomalies, timeline)

    result = {
        "summary": summary,
        "logs": logs,
        "anomalies": anomalies,
        "timeline": sorted(timeline, key=lambda x: x["timestamp"]),
        "ai_summary": ai_summary
    }

    save_analysis(file_id, summary, result)

    return jsonify(result), 200

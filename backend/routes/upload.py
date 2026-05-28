from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required
import os
import uuid

upload_bp = Blueprint("upload", __name__)

# Added .json support for real ZScaler NSS format
ALLOWED_EXTENSIONS = {"log", "txt", "json"}

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

@upload_bp.route("/upload", methods=["POST"])
@jwt_required()
def upload_file():
    if "file" not in request.files:
        return jsonify({"error": "No file provided"}), 400

    file = request.files["file"]

    if not file.filename:
        return jsonify({"error": "Empty filename"}), 400

    if not allowed_file(file.filename):
        return jsonify({"error": "Only .log, .txt and .json files allowed"}), 400

    unique_name = f"{uuid.uuid4()}_{file.filename}"
    file_path = os.path.join(current_app.config["UPLOAD_FOLDER"], unique_name)
    file.save(file_path)

    return jsonify({
        "message": "File uploaded successfully",
        "file_id": unique_name,
        "file_path": file_path
    }), 200

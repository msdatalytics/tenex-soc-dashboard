# Authentication Routes
# Simple JWT-based auth — register and login

from flask import Blueprint, request, jsonify
from flask_jwt_extended import create_access_token

auth_bp = Blueprint("auth", __name__)

# In-memory users for simplicity (no DB needed)
USERS = {
    "analyst@tenex.ai": "password123",
    "admin@tenex.ai": "admin123"
}

@auth_bp.route("/register", methods=["POST"])
def register():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400

    if email in USERS:
        return jsonify({"error": "User already exists"}), 409

    USERS[email] = password
    return jsonify({"message": "User registered successfully"}), 201

@auth_bp.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")

    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400

    if USERS.get(email) != password:
        return jsonify({"error": "Invalid credentials"}), 401

    # Create JWT token
    token = create_access_token(identity=email)
    return jsonify({
        "token": token,
        "email": email,
        "message": "Login successful"
    }), 200

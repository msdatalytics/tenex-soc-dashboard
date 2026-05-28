from flask import Flask
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from dotenv import load_dotenv
from models import init_db
import os

load_dotenv()

app = Flask(__name__)
CORS(app, origins="*")

app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", "tenex-secret-key-2026")
app.config["UPLOAD_FOLDER"] = "uploads"
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024

jwt = JWTManager(app)

from routes.auth import auth_bp
from routes.upload import upload_bp
from routes.analysis import analysis_bp

app.register_blueprint(auth_bp, url_prefix="/api/auth")
app.register_blueprint(upload_bp, url_prefix="/api")
app.register_blueprint(analysis_bp, url_prefix="/api")

@app.route("/")
def health():
    return {"status": "TENEX SOC Dashboard API running"}, 200

if __name__ == "__main__":
    os.makedirs("uploads", exist_ok=True)
    init_db()
    port = int(os.getenv("PORT", 5001))
    app.run(debug=False, host="0.0.0.0", port=port)

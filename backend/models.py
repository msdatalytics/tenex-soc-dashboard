# PostgreSQL Database Models
# Using SQLAlchemy ORM for clean database interactions

from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
import os

# Database URL — reads from environment variable
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://tenex:tenex123@localhost:5432/tenex_soc"
)

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

# --- Models ---

class Upload(Base):
    __tablename__ = "uploads"

    id = Column(Integer, primary_key=True)
    file_id = Column(String, nullable=False)
    filename = Column(String, nullable=False)
    uploaded_at = Column(DateTime, default=datetime.utcnow)

class AnalysisResult(Base):
    __tablename__ = "analysis_results"

    id = Column(Integer, primary_key=True)
    file_id = Column(String, nullable=False)
    total_logs = Column(Integer)
    anomalies_detected = Column(Integer)
    blocked_requests = Column(Integer)
    result_json = Column(Text)
    analyzed_at = Column(DateTime, default=datetime.utcnow)

# --- Helper functions ---

def init_db():
    """Create all tables"""
    Base.metadata.create_all(engine)
    print("PostgreSQL database initialized successfully")

def save_upload(file_id: str, filename: str):
    """Save upload record"""
    db = SessionLocal()
    try:
        upload = Upload(file_id=file_id, filename=filename)
        db.add(upload)
        db.commit()
    finally:
        db.close()

def save_analysis(file_id: str, summary: dict, full_result: dict):
    """Save analysis results"""
    import json
    db = SessionLocal()
    try:
        result = AnalysisResult(
            file_id=file_id,
            total_logs=summary.get("total_logs", 0),
            anomalies_detected=summary.get("anomalies_detected", 0),
            blocked_requests=summary.get("blocked_requests", 0),
            result_json=json.dumps(full_result)
        )
        db.add(result)
        db.commit()
    finally:
        db.close()

def get_analysis(file_id: str):
    """Get cached analysis from DB"""
    db = SessionLocal()
    try:
        return db.query(AnalysisResult)\
            .filter(AnalysisResult.file_id == file_id)\
            .order_by(AnalysisResult.id.desc())\
            .first()
    finally:
        db.close()

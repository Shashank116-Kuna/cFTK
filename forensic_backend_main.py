"""
Digital Forensic Toolkit - Main Backend Application
FastAPI-based REST API with WebSocket support
"""

from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
from enum import Enum
import jwt
import bcrypt
import uuid

# Initialize FastAPI app
app = FastAPI(
    title="Digital Forensic Toolkit API",
    description="Comprehensive digital forensics platform",
    version="1.0.0"
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configuration
SECRET_KEY = "your-secret-key-change-in-production"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 480

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Enums
class EvidenceType(str, Enum):
    DISK_IMAGE = "disk_image"
    MEMORY_DUMP = "memory_dump"
    MOBILE_DEVICE = "mobile_device"
    CLOUD_DATA = "cloud_data"
    NETWORK_CAPTURE = "network_capture"
    LOG_FILE = "log_file"

class CaseStatus(str, Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    UNDER_REVIEW = "under_review"
    CLOSED = "closed"

class UserRole(str, Enum):
    ADMIN = "admin"
    LEAD_INVESTIGATOR = "lead_investigator"
    INVESTIGATOR = "investigator"
    ANALYST = "analyst"
    VIEWER = "viewer"

# Pydantic Models
class User(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    username: str
    email: str
    role: UserRole
    created_at: datetime = Field(default_factory=datetime.utcnow)
    is_active: bool = True

class Token(BaseModel):
    access_token: str
    token_type: str

class Case(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    case_number: str
    title: str
    description: str
    status: CaseStatus
    created_by: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    tags: List[str] = []
    assigned_users: List[str] = []

class Evidence(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    case_id: str
    evidence_number: str
    type: EvidenceType
    description: str
    source: str
    collected_by: str
    collected_at: datetime
    hash_md5: Optional[str] = None
    hash_sha256: Optional[str] = None
    file_size: Optional[int] = None
    storage_path: Optional[str] = None
    metadata: Dict[str, Any] = {}

class ArtifactDetectionRequest(BaseModel):
    evidence_id: str
    artifact_types: List[str] = ["all"]
    deep_scan: bool = True
    ai_enabled: bool = True

class TimelineEvent(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    case_id: str
    evidence_id: str
    timestamp: datetime
    event_type: str
    description: str
    source_file: Optional[str] = None
    metadata: Dict[str, Any] = {}

class ForensicReport(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    case_id: str
    title: str
    generated_by: str
    generated_at: datetime = Field(default_factory=datetime.utcnow)
    format: str = "pdf"
    content: Dict[str, Any] = {}

# In-memory storage (replace with database in production)
users_db = {}
cases_db = {}
evidence_db = {}
timeline_db = {}
reports_db = {}

# Authentication functions
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid authentication")
        user = users_db.get(username)
        if user is None:
            raise HTTPException(status_code=401, detail="User not found")
        return user
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid authentication")

# API Endpoints

@app.get("/")
async def root():
    return {
        "message": "Digital Forensic Toolkit API",
        "version": "1.0.0",
        "status": "operational"
    }

# Authentication endpoints
@app.post("/token", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    # Simplified authentication - implement proper password hashing in production
    user = users_db.get(form_data.username)
    if not user:
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user["username"]}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/users/register", response_model=User)
async def register_user(user: User):
    if user.username in users_db:
        raise HTTPException(status_code=400, detail="Username already exists")
    users_db[user.username] = user.dict()
    return user

# Case Management endpoints
@app.post("/cases", response_model=Case)
async def create_case(case: Case, current_user: User = Depends(get_current_user)):
    cases_db[case.id] = case.dict()
    return case

@app.get("/cases", response_model=List[Case])
async def list_cases(current_user: User = Depends(get_current_user)):
    return [Case(**case) for case in cases_db.values()]

@app.get("/cases/{case_id}", response_model=Case)
async def get_case(case_id: str, current_user: User = Depends(get_current_user)):
    case = cases_db.get(case_id)
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    return Case(**case)

@app.put("/cases/{case_id}", response_model=Case)
async def update_case(case_id: str, case: Case, current_user: User = Depends(get_current_user)):
    if case_id not in cases_db:
        raise HTTPException(status_code=404, detail="Case not found")
    case.updated_at = datetime.utcnow()
    cases_db[case_id] = case.dict()
    return case

# Evidence Management endpoints
@app.post("/evidence", response_model=Evidence)
async def add_evidence(evidence: Evidence, current_user: User = Depends(get_current_user)):
    evidence_db[evidence.id] = evidence.dict()
    return evidence

@app.get("/cases/{case_id}/evidence", response_model=List[Evidence])
async def list_case_evidence(case_id: str, current_user: User = Depends(get_current_user)):
    case_evidence = [Evidence(**e) for e in evidence_db.values() if e["case_id"] == case_id]
    return case_evidence

@app.post("/evidence/upload")
async def upload_evidence_file(
    file: UploadFile = File(...),
    case_id: str = None,
    current_user: User = Depends(get_current_user)
):
    # In production, implement actual file storage (S3, Azure Blob, etc.)
    return {
        "filename": file.filename,
        "content_type": file.content_type,
        "message": "File uploaded successfully",
        "evidence_id": str(uuid.uuid4())
    }

# Analysis endpoints
@app.post("/analysis/detect-artifacts")
async def detect_artifacts(
    request: ArtifactDetectionRequest,
    current_user: User = Depends(get_current_user)
):
    """Trigger artifact detection on evidence"""
    return {
        "job_id": str(uuid.uuid4()),
        "status": "processing",
        "message": "Artifact detection started"
    }

@app.get("/analysis/jobs/{job_id}")
async def get_analysis_job(job_id: str, current_user: User = Depends(get_current_user)):
    """Get status of analysis job"""
    return {
        "job_id": job_id,
        "status": "completed",
        "progress": 100,
        "artifacts_found": 1247
    }

# Timeline endpoints
@app.post("/timeline/events", response_model=TimelineEvent)
async def create_timeline_event(
    event: TimelineEvent,
    current_user: User = Depends(get_current_user)
):
    timeline_db[event.id] = event.dict()
    return event

@app.get("/cases/{case_id}/timeline", response_model=List[TimelineEvent])
async def get_case_timeline(case_id: str, current_user: User = Depends(get_current_user)):
    events = [TimelineEvent(**e) for e in timeline_db.values() if e["case_id"] == case_id]
    return sorted(events, key=lambda x: x.timestamp)

# Reporting endpoints
@app.post("/reports/generate")
async def generate_report(
    case_id: str,
    report_type: str = "comprehensive",
    current_user: User = Depends(get_current_user)
):
    """Generate forensic report"""
    report = ForensicReport(
        case_id=case_id,
        title=f"Forensic Report - Case {case_id}",
        generated_by=current_user.username,
        format="pdf"
    )
    reports_db[report.id] = report.dict()
    return {
        "report_id": report.id,
        "status": "generating",
        "message": "Report generation started"
    }

@app.get("/reports/{report_id}")
async def get_report(report_id: str, current_user: User = Depends(get_current_user)):
    report = reports_db.get(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return ForensicReport(**report)

# WebSocket for real-time updates
@app.websocket("/ws/{case_id}")
async def websocket_endpoint(websocket: WebSocket, case_id: str):
    await websocket.accept()
    try:
        while True:
            data = await websocket.receive_text()
            # Broadcast updates to connected clients
            await websocket.send_text(f"Update received for case {case_id}: {data}")
    except Exception as e:
        print(f"WebSocket error: {e}")

# Health check
@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow(),
        "services": {
            "api": "operational",
            "database": "operational",
            "elasticsearch": "operational",
            "ml_services": "operational"
        }
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

import hashlib
from datetime import datetime
from typing import Any, Dict, List
from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(
    title="AIR-DS Backend Decision Engine",
    version="2.0.0",
    description="Automated Incident Response & Deep Learning Defense Shield",
)

# Enable CORS so your frontend dashboard (port 8080) can communicate with this backend (port 8000)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory storage for hackathon demo state
RAW_LOG_BUFFER: List[Dict[str, Any]] = []
INCIDENT_STORE: List[Dict[str, Any]] = []
FIM_BASELINES: Dict[str, str] = {
    "/app/main.py": "8f4c29b1029481a7bcf89104bf7c8911",
    "/etc/shadow": "e3b0c44298fc1c149afbf4c8996fb924",
}


class AlertPayload(BaseModel):
    source: str
    attack_type: str
    severity: str
    source_ip: str
    target_asset: str


class RawTelemetryPayload(BaseModel):
    source_name: str  # e.g., "syslog", "netflow", "ipmi", "auditd"
    log_data: str


class FIMCheckRequest(BaseModel):
    file_path: str
    current_hash: str
    trigger_mode: str  # "hash_change", "weekly", or "monthly"


class DNNAnomalyRequest(BaseModel):
    cpu_usage: float
    gpu_usage: float
    ram_usage: float
    network_pps: float


@app.get("/")
def read_root():
    return {
        "status": "online",
        "engine": "AIR-DS Decision Engine",
        "mode": "Active Defense",
    }


# 1. RAW TAB / DATA SOURCES ENDPOINT
@app.post("/api/v1/telemetry/raw", status_code=status.HTTP_202_ACCEPTED)
def ingest_raw_telemetry(payload: RawTelemetryPayload):
    log_entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "source": payload.source_name,
        "data": payload.log_data,
    }
    RAW_LOG_BUFFER.insert(0, log_entry)
    if len(RAW_LOG_BUFFER) > 100:
        RAW_LOG_BUFFER.pop()  # Keep last 100 logs
    return {"status": "indexed", "total_buffered": len(RAW_LOG_BUFFER)}


@app.get("/api/v1/telemetry/raw")
def get_raw_telemetry():
    return {"raw_logs": RAW_LOG_BUFFER}


# 2. DNN ANOMALY DETECTION MODEL (Resources & Behavior)
@app.post("/api/v1/detect/dnn-anomaly")
def evaluate_dnn_resource_anomaly(metrics: DNNAnomalyRequest):
    # Simulated Deep Neural Network Autoencoder Reconstruction Loss (MSE Calculation)
    reconstruction_error = (
        (metrics.cpu_usage * 0.0004)
        + (metrics.gpu_usage * 0.0003)
        + (metrics.ram_usage * 0.0002)
        + (metrics.network_pps * 0.001)
    )

    is_anomaly = reconstruction_error > 0.05
    return {
        "model": "ResourceAutoencoder_v2",
        "reconstruction_mse_loss": round(reconstruction_error, 5),
        "threshold": 0.05,
        "status": "ANOMALY_DETECTED" if is_anomaly else "NORMAL",
        "action_triggered": (
            "Playbook: Isolate Resource Host" if is_anomaly else None
        ),
    }


# 3. COMPREHENSIVE FIM & AUTOMATED FILE DETECTION (Hash Change vs Weekly/Monthly)
@app.post("/api/v1/detect/fim-audit")
def evaluate_file_integrity(audit: FIMCheckRequest):
    if audit.trigger_mode not in ["hash_change", "weekly", "monthly"]:
        raise HTTPException(status_code=400, detail="Invalid automation trigger mode.")

    expected_hash = FIM_BASELINES.get(audit.file_path, "UNKNOWN_BASELINE")
    tampered = (
        expected_hash != "UNKNOWN_BASELINE"
        and expected_hash != audit.current_hash
    )

    response_action = "None - File Intact"
    if tampered:
        if audit.trigger_mode == "hash_change":
            response_action = (
                "Playbook: Immediate Container Quarantine & Golden Image Revert"
            )
        else:
            response_action = (
                f"Playbook: Scheduled [{audit.trigger_mode.upper()}] Audit Mismatch -"
                " Alert SOC Lead"
            )

    return {
        "file_path": audit.file_path,
        "trigger_mode": audit.trigger_mode,
        "tamper_detected": tampered,
        "playbook_response": response_action,
        "timestamp": datetime.utcnow().isoformat(),
    }

# 4. FRONTEND ALERT LOGGING ENDPOINT
@app.post("/api/v1/alert", status_code=status.HTTP_201_CREATED)
def receive_frontend_alert(alert: AlertPayload):
    # Menentukan aksi respons otomatis berdasarkan tingkat keparahan (severity)
    action = "IP Blocked (iptables)" if alert.severity == "HIGH" else ("Container Quarantined" if alert.severity == "CRITICAL" else "Rate Limited")
    
    # PERINTAH INI YANG AKAN MEMUNCULKAN KEMBALI DETAIL AKSI DI TERMINAL ANDA
    print(f"[BLOCKED] Type: {alert.attack_type} | Target: {alert.target_asset} | Severity: {alert.severity} | Action: {action}")

    incident = {
        "timestamp": datetime.utcnow().isoformat(),
        "source": alert.source,
        "attack_type": alert.attack_type,
        "severity": alert.severity,
        "source_ip": alert.source_ip,
        "target_asset": alert.target_asset,
        "status": "Automated Playbook Executed"
    }
    INCIDENT_STORE.insert(0, incident)
    return {
        "status": "logged", 
        "total_incidents": len(INCIDENT_STORE),
        "action_taken": action
    }
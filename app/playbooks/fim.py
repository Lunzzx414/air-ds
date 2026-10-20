import hashlib
from datetime import datetime

def calculate_file_hash(file_path: str) -> str:
    hasher = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            while chunk := f.read(8192):
                hasher.update(chunk)
        return hasher.hexdigest()
    except FileNotFoundError:
        return "FILE_NOT_FOUND"

# Example baseline check (Triggered weekly/monthly or on change)
def audit_critical_files(file_paths: list[str], known_baselines: dict[str, str]) -> list[dict]:
    anomalies = []
    for path in file_paths:
        current_hash = calculate_file_hash(path)
        if path in known_baselines and known_baselines[path] != current_hash:
            anomalies.append({
                "file": path,
                "severity": "HIGH",
                "message": "File hash mismatch detected! Possible tampering or unauthorized modification.",
                "timestamp": datetime.utcnow().isoformat()
            })
    return anomalies
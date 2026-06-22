from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime
from typing import List, Dict, Any
import asyncio
import sys
import subprocess
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent))

# Initialize FastAPI app
app = FastAPI(
    title="SOC Dashboard API",
    description="Security Operations Center - Threat Detection API",
    version="0.1.0"
)

# Enable CORS for frontend communication
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:8000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Import ingestion module
from ingestion import get_logs, get_security_logs, get_log_count

# Global variable to store collector process
collector_process = None

# TODO: Import and setup database connection
# from .database import engine, SessionLocal, Base
# Base.metadata.create_all(bind=engine)

# TODO: Import detection module
# from .detection import ThreatDetector


@app.on_event("startup")
async def startup_event():
    """Start log collection and API on startup"""
    global collector_process
    
    print("=" * 60)
    print("SOC Dashboard API starting...")
    print("MongoDB ingestion module loaded")
    print("=" * 60)
    
    # Start the log collector process
    try:
        try :
            command = "systemctl --version"
            subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            print("✓ systemctl found. using journalctl for log collection.")
            collector_path = Path(__file__).parent.parent / "collector" / "journalLogs.py"

        except subprocess.CalledProcessError:
            collector_path = Path(__file__).parent.parent / "collector" / "syslog.py"

            print("✗ systemctl not found. falling back to syslog.")
            return
        collector_path = Path(__file__).parent.parent / "collector" / "journalLogs.py"
        print(f"\n🔄 Starting log collector from: {collector_path}")
        
        collector_process = subprocess.Popen(
            [sys.executable, str(collector_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        print(f"✓ Log collector started (PID: {collector_process.pid})")
        print("✓ Logs are being ingested into MongoDB in real-time")
    except Exception as e:
        print(f"✗ Failed to start log collector: {e}")


@app.on_event("shutdown")
async def shutdown_event():
    """Clean up collector process on shutdown"""
    global collector_process
    
    if collector_process:
        print("\n" + "=" * 60)
        print("Shutting down SOC Dashboard API...")
        print("Terminating log collector...")
        
        try:
            collector_process.terminate()
            collector_process.wait(timeout=5)
            print("✓ Log collector terminated")
        except subprocess.TimeoutExpired:
            collector_process.kill()
            print("✓ Log collector killed")
        except Exception as e:
            print(f"✗ Error terminating collector: {e}")
        
        print("=" * 60)


@app.get("/")
async def root():
    """Health check endpoint"""
    return {
        "status": "operational",
        "service": "SOC Dashboard API",
        "timestamp": datetime.utcnow().isoformat()
    }


@app.get("/api/stats")
async def get_stats() -> Dict[str, Any]:
    """
    Get dashboard statistics from MongoDB logs
    """
    log_count = get_log_count()
    return {
        "total_events": log_count,
        "total_events_trend": 5.2,
        "active_alerts": 24,
        "active_alerts_trend": 12,
        "avg_response_time": "4.2m",
        "response_time_trend": -8.1,
        "threat_score": 7.8,
        "threat_score_trend": 2.3,
        "timestamp": datetime.utcnow().isoformat()
    }


@app.get("/api/alerts")
async def get_alerts(limit: int = 50, offset: int = 0) -> Dict[str, Any]:
    """
    Get recent security alerts from MongoDB
    """
    security_logs = get_security_logs(limit=limit)
    alerts = [
        {
            "id": idx,
            "timestamp": log.get("INGESTION_TIMESTAMP", ""),
            "severity": "high" if log.get("_COMM") == "sudo" else "medium",
            "type": "SSH Login" if log.get("_SYSTEMD_UNIT") == "ssh.service" else "Sudo Command",
            "source": log.get("_HOSTNAME", "unknown"),
            "destination": "System",
            "description": f"Log from {log.get('_COMM', 'unknown')} - {log.get('MESSAGE', '')}",
            "status": "open"
        }
        for idx, log in enumerate(security_logs, 1)
    ]
    
    return {
        "alerts": alerts[offset:offset + limit],
        "total": len(alerts),
        "limit": limit,
        "offset": offset
    }


@app.get("/api/threats")
async def get_threats(limit: int = 10) -> Dict[str, Any]:
    """
    Get active threats
    TODO: Integrate with real threat detection engine
    """
    threats = [
        {
            "id": 1,
            "severity": "critical",
            "title": "SQL Injection Attempt",
            "description": "Detected SQL injection pattern in HTTP request",
            "source": "192.168.1.105",
            "target": "/api/users",
            "timestamp": "2024-01-15T14:35:22Z",
            "confidence": 0.98
        },
        {
            "id": 2,
            "severity": "high",
            "title": "Suspicious Port Scan",
            "description": "Systematic port scanning detected",
            "source": "203.45.67.89",
            "target": "10.0.0.0/24",
            "timestamp": "2024-01-15T14:28:15Z",
            "confidence": 0.85
        },
        {
            "id": 3,
            "severity": "medium",
            "title": "Failed Login Attempts",
            "description": "Multiple failed authentication attempts",
            "source": "10.0.1.120",
            "target": "admin@company.com",
            "timestamp": "2024-01-15T14:15:42Z",
            "confidence": 0.72
        }
    ]
    
    return {
        "threats": threats[:limit],
        "total": len(threats)
    }


@app.get("/api/timeline")
async def get_timeline(limit: int = 20) -> Dict[str, Any]:
    """
    Get event timeline
    TODO: Generate timeline from event logs
    """
    timeline = [
        {
            "id": 1,
            "timestamp": "2024-01-15T14:32:05Z",
            "severity": "critical",
            "title": "Critical Alert",
            "description": "Malware detection - C2 communication"
        },
        {
            "id": 2,
            "timestamp": "2024-01-15T14:28:15Z",
            "severity": "high",
            "title": "Unauthorized Access",
            "description": "Multiple failed authentication attempts"
        },
        {
            "id": 3,
            "timestamp": "2024-01-15T14:15:42Z",
            "severity": "medium",
            "title": "Anomalous Behavior",
            "description": "Large data exfiltration detected"
        }
    ]
    
    return {
        "timeline": timeline[:limit],
        "total": len(timeline)
    }


@app.get("/api/event-types")
async def get_event_types() -> Dict[str, Any]:
    """
    Get top event types
    TODO: Query database and aggregate event types
    """
    return {
        "event_types": [
            {
                "name": "Network Traffic Anomalies",
                "count": 1245,
                "percentage": 85
            },
            {
                "name": "Failed Authentication",
                "count": 892,
                "percentage": 62
            },
            {
                "name": "Malware Detection",
                "count": 648,
                "percentage": 45
            },
            {
                "name": "Data Exfiltration",
                "count": 547,
                "percentage": 38
            }
        ]
    }


@app.get("/api/source-ips")
async def get_source_ips(limit: int = 10) -> Dict[str, Any]:
    """
    Get top source IPs
    TODO: Query logs and identify suspicious IPs
    """
    return {
        "source_ips": [
            {
                "ip": "192.168.1.105",
                "location": "Internal Network",
                "event_count": 234,
                "threat_level": "high"
            },
            {
                "ip": "203.45.67.89",
                "location": "Unknown Location",
                "event_count": 156,
                "threat_level": "critical"
            },
            {
                "ip": "10.0.0.50",
                "location": "Internal Network",
                "event_count": 98,
                "threat_level": "medium"
            }
        ]
    }


@app.post("/api/alerts/{alert_id}/acknowledge")
async def acknowledge_alert(alert_id: int) -> Dict[str, Any]:
    """
    Acknowledge an alert
    TODO: Update alert status in database
    """
    return {
        "alert_id": alert_id,
        "status": "acknowledged",
        "timestamp": datetime.utcnow().isoformat()
    }


@app.post("/api/alerts/{alert_id}/resolve")
async def resolve_alert(alert_id: int) -> Dict[str, Any]:
    """
    Resolve an alert
    TODO: Update alert status and close investigation
    """
    return {
        "alert_id": alert_id,
        "status": "resolved",
        "timestamp": datetime.utcnow().isoformat()
    }


@app.post("/api/threats/{threat_id}/investigate")
async def investigate_threat(threat_id: int) -> Dict[str, Any]:
    """
    Start investigation on a threat
    TODO: Trigger detailed analysis and logging
    """
    return {
        "threat_id": threat_id,
        "status": "investigating",
        "timestamp": datetime.utcnow().isoformat()
    }


@app.get("/api/health")
async def health_check() -> Dict[str, str]:
    """Service health check"""
    return {"status": "healthy"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

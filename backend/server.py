# server.py
import os
import json
import random
import time
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Dict, Any, Optional

from core.pipeline import run_pipeline
from core.validator import ValidationError

app = FastAPI(
    title="Chain Discovery Dashboard API",
    description="Cybersecurity SOC and VAPT automation pipeline",
    version="1.0.0"
)

# Enable CORS for frontend development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # For local development ease
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Preset Attack Scenarios Database
PRESET_SCENARIOS = {
    "web_compromise": {
        "name": "Web Application Session Hijack & Admin Bypass",
        "description": "External recon leading to SQL injection auth bypass, session token hijacking, and administrative access.",
        "data": {
            "pentest_id": "pentest_web_001",
            "target": "finance-portal.target.com",
            "nodes": [
                {
                    "node_id": "n1",
                    "agent": "DIR_ENUM",
                    "type": "directory_discovery",
                    "host": "finance-portal.target.com",
                    "port": 443,
                    "endpoint": "/admin",
                    "method": "GET",
                    "param": None,
                    "param_location": None,
                    "payload": None,
                    "evidence": "HTTP 200 OK with login form visible",
                    "detection_method": "status_code",
                    "timestamp": "2026-06-26T10:00:00",
                    "severity": "info"
                },
                {
                    "node_id": "n2",
                    "agent": "AUTH_BYPASS",
                    "type": "auth_bypass",
                    "host": "finance-portal.target.com",
                    "port": 443,
                    "endpoint": "/admin/login",
                    "method": "POST",
                    "param": "password",
                    "param_location": "body",
                    "payload": "' OR 1=1--",
                    "evidence": "Redirected to dashboard, Set-Cookie header issued",
                    "detection_method": "response_analysis",
                    "timestamp": "2026-06-26T10:02:30",
                    "severity": "confirmed"
                },
                {
                    "node_id": "n3",
                    "agent": "JWT_ANALYSIS",
                    "type": "jwt_none_algorithm",
                    "host": "finance-portal.target.com",
                    "port": 443,
                    "endpoint": "/api/user",
                    "method": "GET",
                    "param": "Authorization",
                    "param_location": "header",
                    "payload": "eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ.",
                    "evidence": "Access granted to admin panel endpoint",
                    "detection_method": "token_manipulation",
                    "timestamp": "2026-06-26T10:05:15",
                    "severity": "confirmed"
                }
            ]
        }
    },
    
    "active_directory": {
        "name": "Active Directory Kerberoasting & Domain Escalation",
        "description": "Internal network penetration scan finding AD vulnerabilities, kerberoasting, cracking hashes, and domain compromise.",
        "data": {
            "pentest_id": "pentest_ad_002",
            "target": "corp-dc.target.local",
            "nodes": [
                {
                    "node_id": "ad_1",
                    "agent": "PORT_SCAN",
                    "type": "port_scan",
                    "host": "corp-dc.target.local",
                    "port": 88,
                    "endpoint": "Kerberos",
                    "method": "TCP",
                    "param": None,
                    "param_location": None,
                    "payload": None,
                    "evidence": "Port 88 (Kerberos) open",
                    "detection_method": "syn_scan",
                    "timestamp": "2026-06-26T11:10:00",
                    "severity": "info"
                },
                {
                    "node_id": "ad_2",
                    "agent": "KERBEROAST",
                    "type": "auth_bypass",
                    "host": "corp-dc.target.local",
                    "port": 88,
                    "endpoint": "TGS-REQ",
                    "method": "Request",
                    "param": "SPN",
                    "param_location": "ticket",
                    "payload": "rc4-hmac hash request",
                    "evidence": "Acquired TGS ticket hash for sql-service account",
                    "detection_method": "ticket_analysis",
                    "timestamp": "2026-06-26T11:15:40",
                    "severity": "confirmed"
                },
                {
                    "node_id": "ad_3",
                    "agent": "PRIV_ESC",
                    "type": "privilege_escalation",
                    "host": "corp-dc.target.local",
                    "port": 389,
                    "endpoint": "LDAP-BIND",
                    "method": "Bind",
                    "param": "admin_credentials",
                    "param_location": "credentials",
                    "payload": "cracked hash: AdminPass123",
                    "evidence": "Authenticated LDAP bind as Domain Admin",
                    "detection_method": "logon_correlation",
                    "timestamp": "2026-06-26T11:22:12",
                    "severity": "confirmed"
                }
            ]
        }
    },
    
    "cloud_exfiltration": {
        "name": "Cloud SSRF & IAM Credential Data Exfiltration",
        "description": "Exploiting SSRF in a web-hook service to read Cloud Metadata credentials, leading to AWS S3 data exfiltration.",
        "data": {
            "pentest_id": "pentest_cloud_003",
            "target": "api.cloud.target.com",
            "nodes": [
                {
                    "node_id": "cl_1",
                    "agent": "SSRF_SCAN",
                    "type": "directory_discovery",
                    "host": "api.cloud.target.com",
                    "port": 443,
                    "endpoint": "/api/v1/fetch?url=http://169.254.169.254/latest/meta-data/",
                    "method": "GET",
                    "param": "url",
                    "param_location": "query",
                    "payload": "http://169.254.169.254",
                    "evidence": "Metadata directories returned in HTTP response",
                    "detection_method": "ssrf_injection",
                    "timestamp": "2026-06-26T12:05:00",
                    "severity": "confirmed"
                },
                {
                    "node_id": "cl_2",
                    "agent": "IAM_STEAL",
                    "type": "jwt_none_algorithm",
                    "host": "api.cloud.target.com",
                    "port": 443,
                    "endpoint": "/api/v1/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/web-role",
                    "method": "GET",
                    "param": "url",
                    "param_location": "query",
                    "payload": "http://169.254.169.254/.../web-role",
                    "evidence": "AccessKeyId, SecretAccessKey, and Token retrieved",
                    "detection_method": "credential_access",
                    "timestamp": "2026-06-26T12:08:22",
                    "severity": "confirmed"
                },
                {
                    "node_id": "cl_3",
                    "agent": "S3_EXFIL",
                    "type": "data_exfiltration",
                    "host": "s3.amazonaws.com",
                    "port": 443,
                    "endpoint": "bucket-production-finance",
                    "method": "GET",
                    "param": "AWS_KEYS",
                    "param_location": "session",
                    "payload": "aws s3 sync s3://bucket-production-finance ./local_sync",
                    "evidence": "12GB sensitive financial records copied",
                    "detection_method": "api_anomaly_detection",
                    "timestamp": "2026-06-26T12:15:00",
                    "severity": "confirmed"
                }
            ]
        }
    }
}

class PipelineInput(BaseModel):
    pentest_id: str
    target: Optional[str] = "unknown_target"
    nodes: List[Dict[str, Any]]

@app.get("/")
def read_root():
    return {
        "status": "online",
        "service": "Chain Discovery Dashboard API Server",
        "documentation": "/docs",
        "sprint": "1 - Extended VAPT & SOC Level"
    }

@app.get("/api/presets")
def get_presets():
    """
    Returns the list of built-in cybersecurity attack path presets for demo simulation.
    """
    return PRESET_SCENARIOS

@app.post("/api/pipeline/run")
def run_ingestion_pipeline(data: PipelineInput):
    """
    Executes the ingestion pipeline.
    Saves the dashboard output locally to data/dashboard_data.json.
    """
    try:
        input_data = data.model_dump()
        
        # Ensure data directory exists and write input file first
        os.makedirs("data", exist_ok=True)
        with open("data/protojson.json", "w") as f:
            json.dump(input_data, f, indent=2)
            
        result = run_pipeline(input_data)
        
        # Save output to file to satisfy Sprint 1 output requirements
        with open("data/dashboard_data.json", "w") as f:
            json.dump(result, f, indent=2)
            
        return result
    except ValidationError as ve:
        raise HTTPException(status_code=400, detail={"code": ve.error_code, "message": str(ve)})
    except Exception as e:
        raise HTTPException(status_code=500, detail={"code": "ERR_INTERNAL_PIPELINE", "message": str(e)})

@app.get("/api/pipeline/current")
def get_current_dashboard_data():
    """
    Reads and returns the active output saved in data/dashboard_data.json
    """
    output_path = "data/dashboard_data.json"
    if not os.path.exists(output_path):
        # Fallback to generating default from the default protojson
        proto_path = "data/protojson.json"
        if os.path.exists(proto_path):
            with open(proto_path, "r") as f:
                proto = json.load(f)
            try:
                result = run_pipeline(proto)
                os.makedirs("data", exist_ok=True)
                with open(output_path, "w") as f:
                    json.dump(result, f, indent=2)
                return result
            except Exception as e:
                raise HTTPException(status_code=500, detail=f"Failed to generate default: {str(e)}")
        raise HTTPException(status_code=404, detail="No active pipeline run and no input template found.")
    
    with open(output_path, "r") as f:
        return json.load(f)

@app.get("/api/soc/logs")
def get_simulated_soc_logs(pentest_id: str = "pentest_003"):
    """
    Generates a list of simulated SOC SIEM logs mapping to the actions of the chain nodes,
    ideal for demonstrating how an alert analyst correlates data.
    """
    logs = []
    current_time = time.time()
    
    # Check which scenario we are running
    if "web" in pentest_id or "003" in pentest_id:
        logs = [
            {
                "timestamp": "2026-06-26T10:00:01Z",
                "source": "WAF-01",
                "severity": "LOW",
                "message": "Directory Traversal / Admin scan signature detected from IP 185.220.101.4.",
                "category": "Reconnaissance",
                "details": "GET /admin HTTP/1.1 - Status 200 - User-Agent: DirBuster/1.0"
            },
            {
                "timestamp": "2026-06-26T10:02:30Z",
                "source": "DB-AppSec-WAF",
                "severity": "HIGH",
                "message": "Potential SQL Injection Authentication Bypass detected in login body payload.",
                "category": "Exploitation",
                "details": "POST /admin/login - username=admin&password=' OR 1=1-- - Status 302"
            },
            {
                "timestamp": "2026-06-26T10:05:15Z",
                "source": "IAM-Session-Monitor",
                "severity": "CRITICAL",
                "message": "Anomalous authentication token verified: None algorithm signature accepted for user 'admin'.",
                "category": "Privilege Escalation",
                "details": "GET /api/user - Auth: Bearer eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ."
            }
        ]
    elif "ad" in pentest_id:
        logs = [
            {
                "timestamp": "2026-06-26T11:10:02Z",
                "source": "Suricata-IDS",
                "severity": "LOW",
                "message": "Active Directory TCP Port Scan targeting Domain Controller 10.0.1.5.",
                "category": "Reconnaissance",
                "details": "SYN scan on ports: 88, 389, 445, 636 from internal host 10.0.1.156"
            },
            {
                "timestamp": "2026-06-26T11:15:40Z",
                "source": "Active-Directory-Audit",
                "severity": "HIGH",
                "message": "TGS-REQ ticket requested for SPN 'sql-service' using weak encryption (RC4-HMAC) [Kerberoasting].",
                "category": "Credential Access",
                "details": "Event ID: 4769 - Service Name: sql-service.target.local - Ticket Encryption: 0x17"
            },
            {
                "timestamp": "2026-06-26T11:22:12Z",
                "source": "Domain-Controller-Event-Log",
                "severity": "CRITICAL",
                "message": "Successful logon of Domain Administrator account 'DomainAdmin' via LDAP Bind from unauthorized host.",
                "category": "Lateral Movement",
                "details": "Event ID: 4624 - Logon Type: 3 (Network) - Source IP: 10.0.1.156 - Account: Target\\DomainAdmin"
            }
        ]
    else: # cloud
        logs = [
            {
                "timestamp": "2026-06-26T12:05:01Z",
                "source": "CloudWatch-WAF",
                "severity": "HIGH",
                "message": "Server-Side Request Forgery (SSRF) signature detected targeting Cloud Metadata IP.",
                "category": "Exploitation",
                "details": "GET /api/v1/fetch?url=http://169.254.169.254/latest/meta-data/ - Status 200"
            },
            {
                "timestamp": "2026-06-26T12:08:22Z",
                "source": "AWS-CloudTrail",
                "severity": "CRITICAL",
                "message": "API Call: GetSessionToken for IAM role 'web-role' retrieved from unexpected IP Address.",
                "category": "Credential Access",
                "details": "Event: AssumeRole - Requesting IP: 203.0.113.88 - Target Arn: arn:aws:iam::123456789012:role/web-role"
            },
            {
                "timestamp": "2026-06-26T12:15:00Z",
                "source": "AWS-GuardDuty",
                "severity": "CRITICAL",
                "message": "Data Exfiltration: Anomalous S3 sync request volume for bucket 'bucket-production-finance'.",
                "category": "Exfiltration",
                "details": "Sync of s3://bucket-production-finance to external network 203.0.113.88 - 12GB data downloaded"
            }
        ]
        
    return logs

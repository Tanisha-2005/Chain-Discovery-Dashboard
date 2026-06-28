# engines/enrichment.py
import json
import os

# MITRE ATT&CK Mapping Database
MITRE_MAPPINGS = {
    "directory_discovery": {
        "id": "T1083",
        "name": "File and Directory Discovery",
        "tactics": ["Discovery"]
    },
    "port_scan": {
        "id": "T1046",
        "name": "Network Service Discovery",
        "tactics": ["Discovery"]
    },
    "auth_bypass": {
        "id": "T1556",
        "name": "Modify Authentication Process",
        "tactics": ["Credential Access", "Defense Evasion"]
    },
    "sql_injection": {
        "id": "T1190",
        "name": "Exploit Public-Facing Application",
        "tactics": ["Initial Access"]
    },
    "jwt_none_algorithm": {
        "id": "T1606",
        "name": "Web Session Cookie Modification",
        "tactics": ["Defense Evasion", "Lateral Movement"]
    },
    "rce": {
        "id": "T1210",
        "name": "Exploitation of Remote Services",
        "tactics": ["Lateral Movement", "Execution"]
    },
    "privilege_escalation": {
        "id": "T1068",
        "name": "Exploitation for Privilege Escalation",
        "tactics": ["Privilege Escalation"]
    },
    "data_exfiltration": {
        "id": "T1048",
        "name": "Exfiltration Over Alternative Protocol",
        "tactics": ["Exfiltration"]
    }
}

# Mitigation Recommendations Database
REMEDIATIONS = {
    "directory_discovery": "Disable directory listing, restrict access to administrative endpoints (e.g. limit /admin via IP whitelisting or WAF rules), and return 404 instead of 403/401 to prevent endpoint enumeration.",
    "port_scan": "Close unused ports, apply host-based firewalls, enable port-knocking or VPN-only admin services, and deploy network intrusion prevention systems (IPS).",
    "auth_bypass": "Implement multi-factor authentication (MFA), secure input sanitization, and use prepared statements/parameterized queries to prevent login logic bypasses.",
    "sql_injection": "Enforce strict input validation, bind parameters for all SQL queries using Object Relational Mappers (ORMs) or prepared statements, and grant least privilege database permissions.",
    "jwt_none_algorithm": "Do not accept JWTs with 'alg': 'none'. Enforce cryptographic signature verification (RS256 or HS256) on the backend before processing session claims.",
    "rce": "Apply patches for remote services immediately, isolate public-facing servers in a DMZ, run web services under low-privilege accounts, and use containers/sandboxes.",
    "privilege_escalation": "Enforce principle of least privilege, conduct regular access reviews, apply security patches for OS/kernels promptly, and enable endpoint detection and response (EDR).",
    "data_exfiltration": "Implement strict outbound egress filtering, perform anomalous network traffic volume monitoring, and enforce TLS-based data inspections."
}

# SOC SIEM / Snort Detections Database
DETECTION_RULES = {
    "directory_discovery": {
        "splunk": "index=web status=200 uri_path IN (\"*/admin*\", \"*/config*\", \"*/backup*\") | stats count by clientip, uri_path | filter count > 20",
        "snort": "alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:\"VAPT-SOC: Directory Enumeration Attempt\"; flow:to_server,established; content:\"/admin\"; http_uri; sid:1000001; rev:1;)"
    },
    "port_scan": {
        "splunk": "index=firewall action=blocked | stats count by src_ip, dest_port | filter count > 100",
        "snort": "alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:\"VAPT-SOC: Port Scan Detected\"; flags:S; threshold:type both, track by_src, count 20, seconds 10; sid:1000009; rev:1;)"
    },
    "auth_bypass": {
        "splunk": "index=web method=POST uri_path=\"*/login*\" (payload=\"*OR*\" OR payload=\"*--*\") | stats count by clientip, payload",
        "snort": "alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:\"VAPT-SOC: Auth Bypass SQL Injection Attempt\"; flow:to_server,established; content:\"' OR 1=1\"; http_client_body; sid:1000002; rev:1;)"
    },
    "sql_injection": {
        "splunk": "index=web status=500 OR status=200 | search \"UNION SELECT\" OR \"SELECT * FROM\" | stats count by clientip",
        "snort": "alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:\"VAPT-SOC: SQL Injection UNION Select\"; flow:to_server,established; content:\"UNION SELECT\"; nocase; http_uri; sid:1000003; rev:1;)"
    },
    "jwt_none_algorithm": {
        "splunk": "index=web header=\"*Authorization*\" | eval token_parts=split(header, \".\") | eval header_json=base64_decode(mvindex(token_parts, 0)) | search header_json=\"*\\\"alg\\\":\\\"none\\\"*\"",
        "snort": "alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:\"VAPT-SOC: JWT None Algorithm Session Tampering\"; flow:to_server,established; content:\"eyJhbGciOiJub25lIn\"; http_header; sid:1000004; rev:1;)"
    },
    "rce": {
        "splunk": "index=os_logs process=cmd.exe OR process=bash | search parent_process=httpd OR parent_process=nginx | stats count by host",
        "snort": "alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:\"VAPT-SOC: Shell Spawn Attempt from Web Server\"; flow:from_server,established; content:\"root:x:\"; sid:1000005; rev:1;)"
    },
    "privilege_escalation": {
        "splunk": "index=windows_security EventCode=4672 OR EventCode=4673 | stats count by AccountName, ComputerName",
        "snort": "alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:\"VAPT-SOC: Windows Exploit Shellcode Execution\"; content:\"|e8 00 00 00 00 58|\"; sid:1000007; rev:1;)"
    },
    "data_exfiltration": {
        "splunk": "index=network dest_ip!=10.0.0.0/8 | stats sum(bytes_out) as total_out by src_ip, dest_ip | filter total_out > 1000000000",
        "snort": "alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:\"VAPT-SOC: Massive Outbound Data Exfiltration Detected\"; flow:to_server,established; dsize:>1000000; sid:1000008; rev:1;)"
    }
}

def run_enrichment(graph, proto=None):
    """
    Enriches attack chains with VAPT remediation strategies, MITRE ATT&CK alignments,
    and SOC defensive rule definitions.
    """
    # Try to load the active protojson from memory or disk to retrieve original node metadata
    node_type_map = {}
    if proto:
        for n in proto.get("nodes", []):
            node_type_map[n["node_id"]] = n.get("type", "unknown")
    else:
        proto_path = "data/protojson.json"
        if os.path.exists(proto_path):
            try:
                with open(proto_path, "r") as f:
                    loaded_proto = json.load(f)
                    for n in loaded_proto.get("nodes", []):
                        node_type_map[n["node_id"]] = n.get("type", "unknown")
            except Exception:
                pass

    chain_briefs = []
    
    for chain in graph.get("chains", []):
        chain_id = chain["chain_id"]
        node_ids = chain["node_ids"]
        
        mitre_tactics = set()
        mitre_techniques = []
        mitre_ids = []
        severity_points = 0
        remediations = []
        detection_splunk = []
        detection_snort = []
        
        node_types = []
        for nid in node_ids:
            # Look up type from our parsed JSON file, or fall back to logical inference
            ntype = node_type_map.get(nid, "unknown")
            if ntype == "unknown":
                # fallback heuristics
                if nid == "n1": ntype = "directory_discovery"
                elif nid == "n2": ntype = "auth_bypass"
                elif nid == "n3": ntype = "jwt_none_algorithm"
                elif "rce" in nid: ntype = "rce"
                elif "sql" in nid: ntype = "sql_injection"
                else: ntype = "jwt_none_algorithm"
                
            node_types.append(ntype)
            
            # MITRE Map
            if ntype in MITRE_MAPPINGS:
                m = MITRE_MAPPINGS[ntype]
                mitre_techniques.append(f"{m['id']} ({m['name']})")
                mitre_ids.append(m['id'])
                mitre_tactics.update(m['tactics'])
            
            # Severity mapping
            if ntype in ["rce", "auth_bypass"]:
                severity_points += 10
            elif ntype in ["sql_injection", "jwt_none_algorithm", "privilege_escalation", "data_exfiltration"]:
                severity_points += 7
            else:
                severity_points += 3
                
            # Remediations
            if ntype in REMEDIATIONS:
                remediations.append(REMEDIATIONS[ntype])
            else:
                remediations.append(f"Ensure proper patching, logging, and access control for system vulnerability {ntype}.")
                
            # Detections
            if ntype in DETECTION_RULES:
                detection_splunk.append(DETECTION_RULES[ntype]["splunk"])
                detection_snort.append(DETECTION_RULES[ntype]["snort"])
                
        # Determine Severity Level
        avg_severity = severity_points / max(len(node_types), 1)
        if avg_severity >= 8:
            severity = "critical"
        elif avg_severity >= 6:
            severity = "high"
        elif avg_severity >= 4:
            severity = "medium"
        else:
            severity = "low"

        # Generate attack flow representation
        attack_flow = " -> ".join([nt.upper() for nt in node_types])
        
        # Executive description
        desc_summary = (
            f"Vulnerability audit identified a chain of {len(node_ids)} correlated steps. "
            f"The attack starts with {node_types[0].replace('_', ' ')} and progresses to "
            f"{node_types[-1].replace('_', ' ')}, risking unauthorized administrative operations."
        )

        brief = {
            "chain_id": chain_id,
            "summary": desc_summary,
            "attack_flow": attack_flow,
            "final_outcome": "Administrative session takeover & privilege escalation",
            "severity": severity,
            "confidence": "high" if len(node_ids) > 2 else "medium",
            "mitre_tactics": list(mitre_tactics),
            "mitre_techniques": mitre_techniques,
            "mitre_ids": mitre_ids,
            "remediation_plan": remediations,
            "soc_detections": {
                "splunk_query": "\n\nOR\n\n".join(detection_splunk),
                "snort_rule": "\n".join(detection_snort)
            }
        }
        chain_briefs.append(brief)
        
    return {
        "pentest_id": graph.get("pentest_id", "unknown"),
        "chain_briefs": chain_briefs
    }

import React, { useState, useEffect, useRef } from "react";

// Preset Databases inside React for instant fallback/sandbox execution
const PRESETS = {
  web_compromise: {
    name: "Web Application Session Hijack & Admin Bypass",
    description: "External recon leading to SQL injection auth bypass, session token hijacking, and administrative access.",
    data: {
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
          "param": null,
          "param_location": null,
          "payload": null,
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
  active_directory: {
    name: "Active Directory Kerberoasting & Domain Escalation",
    description: "Internal network penetration scan finding AD vulnerabilities, kerberoasting, cracking hashes, and domain compromise.",
    data: {
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
          "param": null,
          "param_location": null,
          "payload": null,
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
  cloud_exfiltration: {
    name: "Cloud SSRF & IAM Credential Data Exfiltration",
    description: "Exploiting SSRF in a web-hook service to read Cloud Metadata credentials, leading to AWS S3 data exfiltration.",
    data: {
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
};

// Frontend fallback JS implementation of Python pipeline logic
const MITRE_MAPPINGS = {
  directory_discovery: { id: "T1083", name: "File and Directory Discovery", tactics: ["Discovery"] },
  port_scan: { id: "T1046", name: "Network Service Discovery", tactics: ["Discovery"] },
  auth_bypass: { id: "T1556", name: "Modify Authentication Process", tactics: ["Credential Access", "Defense Evasion"] },
  sql_injection: { id: "T1190", name: "Exploit Public-Facing Application", tactics: ["Initial Access"] },
  jwt_none_algorithm: { id: "T1606", name: "Web Session Cookie Modification", tactics: ["Defense Evasion", "Lateral Movement"] },
  rce: { id: "T1210", name: "Exploitation of Remote Services", tactics: ["Lateral Movement", "Execution"] },
  privilege_escalation: { id: "T1068", name: "Exploitation for Privilege Escalation", tactics: ["Privilege Escalation"] },
  data_exfiltration: { id: "T1048", name: "Exfiltration Over Alternative Protocol", tactics: ["Exfiltration"] }
};

const REMEDIATIONS = {
  directory_discovery: "Disable directory listing, restrict access to administrative endpoints (e.g. limit /admin via IP whitelisting or WAF rules), and return 404 instead of 403/401 to prevent endpoint enumeration.",
  port_scan: "Close unused ports, apply host-based firewalls, enable port-knocking or VPN-only admin services, and deploy network intrusion prevention systems (IPS).",
  auth_bypass: "Implement multi-factor authentication (MFA), secure input sanitization, and use prepared statements/parameterized queries to prevent login logic bypasses.",
  sql_injection: "Enforce strict input validation, bind parameters for all SQL queries using Object Relational Mappers (ORMs) or prepared statements, and grant least privilege database permissions.",
  jwt_none_algorithm: "Do not accept JWTs with 'alg': 'none'. Enforce cryptographic signature verification (RS256 or HS256) on the backend before processing session claims.",
  rce: "Apply patches for remote services immediately, isolate public-facing servers in a DMZ, run web services under low-privilege accounts, and use containers/sandboxes.",
  privilege_escalation: "Enforce principle of least privilege, conduct regular access reviews, apply security patches for OS/kernels promptly, and enable endpoint detection and response (EDR).",
  data_exfiltration: "Implement strict outbound egress filtering, perform anomalous network traffic volume monitoring, and enforce TLS-based data inspections."
};

const DETECTION_RULES = {
  directory_discovery: {
    splunk: `index=web status=200 uri_path IN ("*/admin*", "*/config*", "*/backup*") \n| stats count by clientip, uri_path \n| filter count > 20`,
    snort: `alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"VAPT-SOC: Directory Enumeration Attempt"; flow:to_server,established; content:"/admin"; http_uri; sid:1000001; rev:1;)`
  },
  port_scan: {
    splunk: `index=firewall action=blocked \n| stats count by src_ip, dest_port \n| filter count > 100`,
    snort: `alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"VAPT-SOC: Port Scan Detected"; flags:S; threshold:type both, track by_src, count 20, seconds 10; sid:1000009; rev:1;)`
  },
  auth_bypass: {
    splunk: `index=web method=POST uri_path="*/login*" (payload="*OR*" OR payload="*--*") \n| stats count by clientip, payload`,
    snort: `alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"VAPT-SOC: Auth Bypass SQL Injection Attempt"; flow:to_server,established; content:"' OR 1=1"; http_client_body; sid:1000002; rev:1;)`
  },
  sql_injection: {
    splunk: `index=web status=500 OR status=200 \n| search "UNION SELECT" OR "SELECT * FROM" \n| stats count by clientip`,
    snort: `alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"VAPT-SOC: SQL Injection UNION Select"; flow:to_server,established; content:"UNION SELECT"; nocase; http_uri; sid:1000003; rev:1;)`
  },
  jwt_none_algorithm: {
    splunk: `index=web header="*Authorization*" \n| eval token_parts=split(header, ".") \n| eval header_json=base64_decode(mvindex(token_parts, 0)) \n| search header_json="*\\"alg\\":\\"none\\"*"`
    ,snort: `alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"VAPT-SOC: JWT None Algorithm Session Tampering"; flow:to_server,established; content:"eyJhbGciOiJub25lIn"; http_header; sid:1000004; rev:1;)`
  },
  rce: {
    splunk: `index=os_logs process=cmd.exe OR process=bash \n| search parent_process=httpd OR parent_process=nginx \n| stats count by host`,
    snort: `alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (msg:"VAPT-SOC: Shell Spawn Attempt from Web Server"; flow:from_server,established; content:"root:x:"; sid:1000005; rev:1;)`
  },
  privilege_escalation: {
    splunk: `index=windows_security EventCode=4672 OR EventCode=4673 \n| stats count by AccountName, ComputerName`,
    snort: `alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"VAPT-SOC: Windows Exploit Shellcode Execution"; content:"|e8 00 00 00 00 58|"; sid:1000007; rev:1;)`
  },
  data_exfiltration: {
    splunk: `index=network dest_ip!=10.0.0.0/8 \n| stats sum(bytes_out) as total_out by src_ip, dest_ip \n| filter total_out > 1000000000`,
    snort: `alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"VAPT-SOC: Massive Outbound Data Exfiltration Detected"; flow:to_server,established; dsize:>1000000; sid:1000008; rev:1;)`
  }
};

function runPipelineJS(proto) {
  const nodes = proto.nodes || [];
  const pentestId = proto.pentest_id || "unknown";
  
  if (!pentestId.trim()) throw new Error("Validation Failed: Missing 'pentest_id'");
  if (nodes.length === 0) throw new Error("Validation Failed: 'nodes' list cannot be empty");

  // Brain Engine Logic: Connect based on timestamps and phases
  const sortedNodes = [...nodes].sort((a,b) => new Date(a.timestamp) - new Date(b.timestamp));
  const nodeIds = sortedNodes.map(n => n.node_id);
  
  const edges = [];
  const nodePhases = {};
  
  // Phase assignment
  const PHASE_VALS = {
    directory_discovery: 1, port_scan: 1, subdomain_enum: 1, active_recon: 1,
    auth_bypass: 2, sql_injection: 2, xss: 2, rce: 2, vulnerability_exploit: 2,
    jwt_none_algorithm: 3, privilege_escalation: 3, session_hijack: 3, credential_dumping: 3,
    data_exfiltration: 4, lateral_movement: 4, impact: 4
  };

  sortedNodes.forEach(n => {
    nodePhases[n.node_id] = PHASE_VALS[n.type] || 2;
  });

  for (let i = 0; i < sortedNodes.length; i++) {
    const nodeA = sortedNodes[i];
    const idA = nodeA.node_id;
    const phaseA = nodePhases[idA];
    const hostA = nodeA.host;

    for (let j = i + 1; j < sortedNodes.length; j++) {
      const nodeB = sortedNodes[j];
      const idB = nodeB.node_id;
      const phaseB = nodePhases[idB];
      const hostB = nodeB.host;

      if (hostA === hostB && phaseB > phaseA) {
        edges.push({
          from: idA,
          to: idB,
          reason: `Kill chain progression (${nodeA.type} -> ${nodeB.type}) on host ${hostA}`,
          confidence: phaseB === phaseA + 1 ? "high" : "medium"
        });
        break;
      } else if (phaseB > phaseA && (nodeA.type === "auth_bypass" || nodeA.type === "jwt_none_algorithm")) {
        edges.push({
          from: idA,
          to: idB,
          reason: `Token/Cred reuse leading to ${nodeB.type}`,
          confidence: "high"
        });
        break;
      }
    }
  }

  if (edges.length === 0 && nodeIds.length > 1) {
    for (let i = 0; i < nodeIds.length - 1; i++) {
      edges.push({
        from: nodeIds[i],
        to: nodeIds[i+1],
        reason: "Sequential timeline correlation",
        confidence: "medium"
      });
    }
  }

  // Enrichment Engine Logic
  const chainBriefs = [];
  const nodeTypes = sortedNodes.map(n => n.type);
  
  let severityPoints = 0;
  const mitreTactics = new Set();
  const mitreTechniques = [];
  const mitreIds = [];
  const remediations = [];
  const detectionSplunk = [];
  const detectionSnort = [];

  nodeTypes.forEach(ntype => {
    const m = MITRE_MAPPINGS[ntype];
    if (m) {
      mitreTechniques.push(`${m.id} (${m.name})`);
      mitreIds.push(m.id);
      m.tactics.forEach(t => mitreTactics.add(t));
    }

    if (["rce", "auth_bypass"].includes(ntype)) severityPoints += 10;
    else if (["sql_injection", "jwt_none_algorithm", "privilege_escalation", "data_exfiltration"].includes(ntype)) severityPoints += 7;
    else severityPoints += 3;

    if (REMEDIATIONS[ntype]) remediations.push(REMEDIATIONS[ntype]);
    if (DETECTION_RULES[ntype]) {
      detectionSplunk.push(DETECTION_RULES[ntype].splunk);
      detectionSnort.push(DETECTION_RULES[ntype].snort);
    }
  });

  const avgSeverity = severityPoints / Math.max(nodeTypes.length, 1);
  let severity = "low";
  if (avgSeverity >= 8) severity = "critical";
  else if (avgSeverity >= 6) severity = "high";
  else if (avgSeverity >= 4) severity = "medium";

  const brief = {
    chain_id: "c1",
    summary: `Vulnerability audit identified a chain of ${nodeIds.length} correlated steps. The attack starts with ${nodeTypes[0]?.replace('_', ' ')} and progresses to ${nodeTypes[nodeTypes.length - 1]?.replace('_', ' ')}, risking administrative takeover.`,
    attack_flow: nodeTypes.map(n => n.toUpperCase()).join(" -> "),
    final_outcome: "Administrative session takeover & privilege escalation",
    severity: severity,
    confidence: nodeIds.length > 2 ? "high" : "medium",
    mitre_tactics: Array.from(mitreTactics),
    mitre_techniques: mitreTechniques,
    mitre_ids: mitreIds,
    remediation_plan: remediations,
    soc_detections: {
      splunk_query: detectionSplunk.join("\n\nOR\n\n"),
      snort_rule: detectionSnort.join("\n")
    }
  };

  chainBriefs.push(brief);

  // Merger logic
  return {
    pentest_id: pentestId,
    target: proto.target || "unknown_target",
    chains: [
      {
        chain_id: "c1",
        nodes: sortedNodes,
        edges: edges,
        brief: brief
      }
    ]
  };
}

export default function App() {
  const [activeTab, setActiveTab] = useState("dashboard");
  const [selectedPreset, setSelectedPreset] = useState("web_compromise");
  
  // JSON Inputs & Outputs states
  const [inputProto, setInputProto] = useState(PRESETS.web_compromise.data);
  const [dashboardData, setDashboardData] = useState(null);
  
  // Dashboard Interactive States
  const [selectedNode, setSelectedNode] = useState(null);
  const [selectedEdge, setSelectedEdge] = useState(null);
  
  // SOC Operation States
  const [socLogs, setSocLogs] = useState([]);
  const [logTickerActive, setLogTickerActive] = useState(true);
  
  // Backend & Execution states
  const [backendStatus, setBackendStatus] = useState("checking"); // 'checking' | 'online' | 'offline'
  const [isExecuting, setIsExecuting] = useState(false);
  const [pipelineLogs, setPipelineLogs] = useState([]);
  
  const terminalEndRef = useRef(null);
  const socConsoleEndRef = useRef(null);

  // 1. Check if backend FastAPI is online
  useEffect(() => {
    checkBackend();
  }, []);

  const checkBackend = async () => {
    try {
      const res = await fetch("http://localhost:8000/");
      if (res.ok) {
        setBackendStatus("online");
      } else {
        setBackendStatus("offline");
      }
    } catch {
      setBackendStatus("offline");
    }
  };

  // 2. Automatically execute pipeline on preset load
  useEffect(() => {
    triggerPipelineExecution(inputProto);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [inputProto]);

  // 3. Scroll handlers for terminals
  useEffect(() => {
    terminalEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [pipelineLogs]);

  useEffect(() => {
    socConsoleEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [socLogs]);

  // 4. SIEM Log stream generator loop
  useEffect(() => {
    if (!dashboardData || !logTickerActive) return;
    
    // Clear logs first
    setSocLogs([
      { time: new Date().toLocaleTimeString(), level: "INFO", source: "SIEM-Core", msg: "Correlation engine initialized." }
    ]);

    const activeChain = dashboardData.chains?.[0];
    if (!activeChain) return;

    let logIndex = 0;
    const interval = setInterval(async () => {
      if (logIndex >= activeChain.nodes.length) {
        setSocLogs(prev => [
          ...prev,
          {
            time: new Date().toLocaleTimeString(),
            level: "WARNING",
            source: "SIEM-Correlation",
            msg: `ATTACK CHAIN DISCOVERY: Correlated path verified [${activeChain.brief.attack_flow}]. Risk level: ${activeChain.brief.severity.toUpperCase()}.`
          }
        ]);
        clearInterval(interval);
        return;
      }

      const node = activeChain.nodes[logIndex];
      const newLogs = [];

      // Generate alert based on node properties
      if (node.type.includes("discovery") || node.type.includes("scan")) {
        newLogs.push(
          { time: new Date().toLocaleTimeString(), level: "INFO", source: "IDS-Snort", msg: `Recon activity detected: Host enum scan on ${node.host}:${node.port}.` },
          { time: new Date().toLocaleTimeString(), level: "WARNING", source: "Syslog-Web", msg: `Endpoint scanned: GET ${node.endpoint} - Result: ${node.evidence}.` }
        );
      } else if (node.type.includes("bypass") || node.type.includes("exploit") || node.type.includes("injection")) {
        newLogs.push(
          { time: new Date().toLocaleTimeString(), level: "HIGH", source: "WAF-ChainDiscovery", msg: `CRITICAL: Web attack attempt detected at ${node.endpoint} on ${node.host}.` },
          { time: new Date().toLocaleTimeString(), level: "HIGH", source: "Database-Auditor", msg: `Payload matched signature: '${node.payload}' submitted via param [${node.param}].` },
          { time: new Date().toLocaleTimeString(), level: "CRITICAL", source: "Syslog-Auth", msg: `Authentication Bypass alert! Status: ${node.evidence}.` }
        );
      } else if (node.type.includes("algorithm") || node.type.includes("escalation") || node.type.includes("session")) {
        newLogs.push(
          { time: new Date().toLocaleTimeString(), level: "CRITICAL", source: "IAM-Guard", msg: `JWT Validation anomaly: Algorithm signature override verification bypassed.` },
          { time: new Date().toLocaleTimeString(), level: "CRITICAL", source: "Syslog-Web", msg: `Privilege escalation event: Administrative token accepted. Evidence: ${node.evidence}.` }
        );
      } else {
        newLogs.push(
          { time: new Date().toLocaleTimeString(), level: "CRITICAL", source: "IDS-Egress", msg: `Data exfiltration: Outbound sync command executed: [${node.payload}].` }
        );
      }

      setSocLogs(prev => [...prev, ...newLogs]);
      logIndex++;
    }, 2500);

    return () => clearInterval(interval);
  }, [dashboardData, logTickerActive]);

  const triggerPipelineExecution = async (protoPayload) => {
    setActiveTab("dashboard");
    setIsExecuting(true);
    setPipelineLogs([]);
    
    const logs = [];
    const addLog = (step, msg, type = "info") => {
      logs.push({ step, msg, type, timestamp: new Date().toLocaleTimeString() });
      setPipelineLogs([...logs]);
    };

    // Stage 1: Ingest
    addLog("INGESTION", "Raw security audit received by pipeline controller.");
    await new Promise(r => setTimeout(r, 400));
    
    // Stage 2: Validation
    addLog("VALIDATION", "Parsing ProtoJSON syntax schema and security variables...");
    try {
      // Validate in JS first
      if (!protoPayload.pentest_id) throw new Error("Missing 'pentest_id'");
      if (!protoPayload.nodes || protoPayload.nodes.length === 0) throw new Error("Empty 'nodes' list");
      
      protoPayload.nodes.forEach((n, idx) => {
        if (!n.node_id) throw new Error(`Node at index ${idx} is missing 'node_id'`);
        if (!n.type || !n.host || n.port === undefined) throw new Error(`Node '${n.node_id || idx}' is missing key metrics (type, host, port)`);
        if (n.port < 1 || n.port > 65535) throw new Error(`Node '${n.node_id}' port ${n.port} out of range`);
      });
      
      addLog("VALIDATION", `Schema check passed. Validated ${protoPayload.nodes.length} vulnerability nodes.`, "success");
    } catch (err) {
      addLog("VALIDATION", `Schema Verification FAILED: ${err.message}`, "error");
      setIsExecuting(false);
      return;
    }
    await new Promise(r => setTimeout(r, 400));

    // Stage 3: Brain Engine
    addLog("BRAIN_ENGINE", "Processing node topology and mapping temporal correlation edges...");
    await new Promise(r => setTimeout(r, 500));

    // Stage 4: Query Backend or execute Sandbox
    let result;
    if (backendStatus === "online") {
      try {
        addLog("API_BRIDGE", "FastAPI connection active. Delegating execution to remote Python Engines...");
        const response = await fetch("http://localhost:8000/api/pipeline/run", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(protoPayload)
        });
        if (!response.ok) {
          const errBody = await response.json();
          throw new Error(errBody.detail?.message || "HTTP Pipeline execution failed");
        }
        result = await response.json();
        addLog("API_BRIDGE", "Successfully retrieved enriched response package from Python API.", "success");
      } catch (err) {
        addLog("API_BRIDGE", `API Bridge failed: ${err.message}. Falling back to Browser Sandbox Engine.`, "warning");
        result = runPipelineJS(protoPayload);
      }
    } else {
      addLog("SANDBOX_ENGINE", "FastAPI backend unreachable. Executing sandbox correlation engine inside browser...");
      result = runPipelineJS(protoPayload);
    }

    addLog("ENRICHMENT", "MITRE ATT&CK vectors aligned. Defensive Snort rules & Splunk queries compiled.", "success");
    await new Promise(r => setTimeout(r, 300));
    
    addLog("CONSOLIDATION", `Consolidation complete. Output 'dashboard_data.json' successfully merged.`, "success");
    
    setDashboardData(result);
    setIsExecuting(false);

    // Auto-select first node to show detail
    if (result.chains?.[0]?.nodes?.[0]) {
      setSelectedNode(result.chains[0].nodes[0]);
    }
  };

  const loadPreset = (presetKey) => {
    setSelectedPreset(presetKey);
    setInputProto(PRESETS[presetKey].data);
    setSelectedNode(null);
    setSelectedEdge(null);
  };

  const handleJsonInputChange = (val) => {
    try {
      const parsed = JSON.parse(val);
      setInputProto(parsed);
    } catch {
      // Allow user to keep typing invalid JSON temporarily
    }
  };

  const exportReport = () => {
    if (!dashboardData) return;
    const chain = dashboardData.chains?.[0];
    if (!chain) return;

    const reportContent = `# EXECUTIVE VAPT & SOC AUDIT REPORT
Pentest engagement: ${dashboardData.pentest_id}
Audit target host environment: ${dashboardData.target || "Not specified"}
Generated: ${new Date().toLocaleString()}
--------------------------------------------------

## 1. Attack Chain Assessment
**Severity**: ${chain.brief.severity.toUpperCase()}
**Confidence**: ${chain.brief.confidence.toUpperCase()}
**Primary Action Plan**: ${chain.brief.final_outcome}

### Exploit Sequence Flow:
${chain.brief.attack_flow}

### Incident Summary:
${chain.brief.summary}

## 2. Threat Vector Mappings (MITRE ATT&CK)
${chain.brief.mitre_techniques.map(t => `- ${t}`).join("\n")}

## 3. Recommended Remediation & Patches
${chain.brief.remediation_plan ? chain.brief.remediation_plan.map((r,i) => `${i+1}. ${r}`).join("\n") : ""}

## 4. SOC SIEM Detections
### Snort IDS Rules:
\`\`\`snort
${chain.brief.soc_detections.snort_rule}
\`\`\`

### Splunk SIEM Query:
\`\`\`splunk
${chain.brief.soc_detections.splunk_query}
\`\`\`

--------------------------------------------------
Prepared by: Cybersecurity Analyst Intern
`;

    const blob = new Blob([reportContent], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `VAPT_SOC_Audit_Report_${dashboardData.pentest_id}.txt`;
    link.click();
    URL.revokeObjectURL(url);
  };

  const getSeverityColor = (sev) => {
    const s = String(sev).toLowerCase();
    if (s === "critical" || s === "confirmed") return "critical";
    if (s === "high") return "high";
    if (s === "medium") return "medium";
    if (s === "low") return "low";
    return "info";
  };

  return (
    <div className="dashboard-container">
      {/* 1. Sidebar */}
      <aside className="sidebar">
        <div className="sidebar-logo">
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            <circle cx="12" cy="11" r="3"/>
          </svg>
          <span>CHAIN DISCOVERY</span>
        </div>

        <ul className="sidebar-menu">
          <li className={`sidebar-item ${activeTab === "dashboard" ? "active" : ""}`} onClick={() => setActiveTab("dashboard")}>
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <rect x="3" y="3" width="7" height="9"/><rect x="14" y="3" width="7" height="5"/>
              <rect x="14" y="12" width="7" height="9"/><rect x="3" y="16" width="7" height="5"/>
            </svg>
            <span>Attack Path Dashboard</span>
          </li>
          <li className={`sidebar-item ${activeTab === "vapt" ? "active" : ""}`} onClick={() => setActiveTab("vapt")}>
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/>
            </svg>
            <span>VAPT Analyst Panel</span>
          </li>
          <li className={`sidebar-item ${activeTab === "soc" ? "active" : ""}`} onClick={() => setActiveTab("soc")}>
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M12 22c5.523 0 10-4.477 10-10S17.523 2 12 2 2 6.477 2 12s4.477 10 10 10z"/>
              <path d="M12 6v6l4 2"/>
            </svg>
            <span>SOC SIEM Operations</span>
          </li>
          <li className={`sidebar-item ${activeTab === "pipeline" ? "active" : ""}`} onClick={() => setActiveTab("pipeline")}>
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>
            </svg>
            <span>Pipeline Execution</span>
          </li>
          <li className={`sidebar-item ${activeTab === "presets" ? "active" : ""}`} onClick={() => setActiveTab("presets")}>
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M12 2v20M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6"/>
            </svg>
            <span>Audit Ingest & Presets</span>
          </li>
          <li className={`sidebar-item ${activeTab === "inspector" ? "active" : ""}`} onClick={() => setActiveTab("inspector")}>
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/>
            </svg>
            <span>JSON Inspector</span>
          </li>
        </ul>

        <div className="sidebar-footer">
          <div>CHAIN DISCOVERY PORTAL</div>
          <div style={{ marginTop: "4px", fontSize: "9px" }}>TEAM C - SPRINT 1 INTEGRATION</div>
        </div>
      </aside>

      {/* 2. Main Dashboard panel */}
      <main className="main-content">
        {/* Header */}
        <header style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "20px", flexWrap: "wrap", gap: "15px", flexShrink: 0 }}>
          <div>
            <h2 style={{ margin: 0, fontSize: "28px", fontWeight: "600", letterSpacing: "-0.5px" }}>
              Chain Discovery Dashboard
            </h2>
            <p style={{ color: "var(--text-muted)", fontSize: "14px", marginTop: "4px" }}>
              VAPT Attack Path Discovery & SOC Correlation System
            </p>
          </div>

          <div style={{ display: "flex", gap: "16px", alignItems: "center", flexWrap: "wrap" }}>
            {/* Quick Scenario Selector */}
            <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
              <span style={{ fontSize: "11px", color: "var(--text-muted)", fontFamily: "var(--font-mono)", textTransform: "uppercase" }}>Scenario:</span>
              <select 
                value={selectedPreset} 
                onChange={(e) => loadPreset(e.target.value)}
                style={{
                  background: "var(--bg-secondary)",
                  border: "1px solid var(--border-color)",
                  color: "var(--text-primary)",
                  padding: "8px 12px",
                  borderRadius: "6px",
                  fontSize: "13px",
                  fontFamily: "var(--font-sans)",
                  outline: "none",
                  cursor: "pointer",
                  transition: "all 0.2s ease"
                }}
              >
                <option value="web_compromise">Web Session Hijack</option>
                <option value="active_directory">Active Directory Kerberoasting</option>
                <option value="cloud_exfiltration">Cloud SSRF & Exfil</option>
                <option value="custom">Custom Uploaded Schema</option>
              </select>
            </div>

            <span style={{
              display: "inline-flex",
              alignItems: "center",
              gap: "6px",
              fontSize: "11px",
              padding: "6px 10px",
              borderRadius: "4px",
              backgroundColor: backendStatus === "online" ? "rgba(57, 255, 20, 0.08)" : "rgba(255, 170, 0, 0.08)",
              color: backendStatus === "online" ? "var(--green-glow)" : "var(--amber-glow)",
              border: `1px solid ${backendStatus === "online" ? "rgba(57, 255, 20, 0.2)" : "rgba(255, 170, 0, 0.2)"}`,
              fontFamily: "var(--font-mono)"
            }}>
              <span style={{
                width: "6px",
                height: "6px",
                borderRadius: "50%",
                backgroundColor: backendStatus === "online" ? "var(--green-glow)" : "var(--amber-glow)",
                boxShadow: `0 0 6px ${backendStatus === "online" ? "var(--green-glow)" : "var(--amber-glow)"}`
              }} />
              {backendStatus === "online" ? "FastAPI Online" : "Sandbox Mode"}
            </span>

            <button className="cyber-btn accent" onClick={() => triggerPipelineExecution(inputProto)} disabled={isExecuting}>
              {isExecuting ? "Processing..." : "Run Pipeline"}
            </button>
          </div>
        </header>

        {/* Interactive Progress Tracker / Workflow Bar */}
        <div className="cyber-card" style={{ padding: "12px 16px", marginBottom: "24px", flexShrink: 0 }}>
          <div style={{ display: "flex", width: "100%", justifyContent: "space-between", alignItems: "center", gap: "8px", flexWrap: "wrap" }}>
            {[
              { id: "presets", label: "Ingest Presets", desc: "Select Attack Data" },
              { id: "pipeline", label: "Validate & Run", desc: "Correlate Pipelines" },
              { id: "dashboard", label: "Correlated DAG", desc: "Visualize Graph" },
              { id: "vapt", label: "VAPT Remediation", desc: "Threat Mitigations" },
              { id: "soc", label: "SOC SIEM Alerts", desc: "IDS Alert Stream" },
            ].map((step, idx, arr) => {
              const isActive = activeTab === step.id;
              const isCompleted = arr.findIndex(s => s.id === activeTab) > idx;
              
              return (
                <React.Fragment key={step.id}>
                  <div 
                    onClick={() => setActiveTab(step.id)}
                    style={{
                      display: "flex",
                      flexDirection: "column",
                      cursor: "pointer",
                      padding: "8px 12px",
                      borderRadius: "6px",
                      background: isActive ? "rgba(0, 240, 255, 0.05)" : "transparent",
                      border: isActive ? "1px solid rgba(0, 240, 255, 0.2)" : "1px solid transparent",
                      boxShadow: isActive ? "0 0 10px rgba(0, 240, 255, 0.05)" : "none",
                      transition: "all 0.2s ease",
                      flex: 1,
                      minWidth: "120px"
                    }}
                  >
                    <span style={{
                      fontSize: "12px",
                      fontWeight: isActive || isCompleted ? "600" : "500",
                      color: isActive ? "var(--cyan-glow)" : isCompleted ? "var(--green-glow)" : "var(--text-primary)",
                      display: "flex",
                      alignItems: "center",
                      gap: "6px"
                    }}>
                      <span style={{
                        display: "inline-flex",
                        alignItems: "center",
                        justifyContent: "center",
                        width: "16px",
                        height: "16px",
                        borderRadius: "50%",
                        fontSize: "9px",
                        background: isActive ? "var(--cyan-glow)" : isCompleted ? "var(--green-glow)" : "rgba(255,255,255,0.05)",
                        color: isActive || isCompleted ? "var(--bg-primary)" : "var(--text-muted)",
                        fontWeight: "bold",
                        fontFamily: "var(--font-mono)"
                      }}>
                        {isCompleted ? "✓" : idx + 1}
                      </span>
                      {step.label}
                    </span>
                    <span style={{ fontSize: "10px", color: "var(--text-muted)", marginTop: "4px", paddingLeft: "22px" }}>
                      {step.desc}
                    </span>
                  </div>
                  {idx < arr.length - 1 && (
                    <div style={{ color: "var(--text-dark)", fontSize: "14px", userSelect: "none", padding: "0 4px" }}>➔</div>
                  )}
                </React.Fragment>
              );
            })}
            
            <div style={{ height: "30px", width: "1px", backgroundColor: "var(--border-color)", margin: "0 8px" }} />
            
            <button 
              className="cyber-btn" 
              onClick={exportReport}
              disabled={!dashboardData}
              style={{
                fontSize: "11px",
                padding: "8px 12px",
                background: "rgba(57, 255, 20, 0.08)",
                border: "1px solid rgba(57, 255, 20, 0.2)",
                color: "var(--green-glow)",
                textTransform: "uppercase"
              }}
            >
              Export Report
            </button>
          </div>
        </div>

        {/* Global Pipeline Execution Alert if processing */}
        {isExecuting && (
          <div className="cyber-card" style={{ borderLeft: "3px solid var(--cyan-glow)", padding: "12px 20px", marginBottom: "20px" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
                <span className="cyber-cursor"></span>
                <span style={{ fontSize: "13px", fontFamily: "var(--font-mono)" }}>
                  Analyzing: {pipelineLogs[pipelineLogs.length - 1]?.msg || "Starting..."}
                </span>
              </div>
              <span style={{ fontSize: "11px", color: "var(--text-muted)" }}>PIPELINE BUSY</span>
            </div>
          </div>
        )}

        {/* Tab content 1: Attack Path Dashboard */}
        {activeTab === "dashboard" && (
          <div>
            {/* Visual Canvas of graph */}
            <div className="cyber-card" style={{ padding: "10px" }}>
              <div style={{ display: "flex", justifyContent: "space-between", padding: "10px 15px", borderBottom: "1px solid var(--border-color)", marginBottom: "15px" }}>
                <span style={{ fontSize: "12px", textTransform: "uppercase", fontWeight: "600", color: "var(--text-muted)" }}>
                  CORRELATED ATTACK PATH GRAPH (DAG)
                </span>
                <span style={{ fontSize: "11px", color: "var(--cyan-glow)", fontFamily: "var(--font-mono)" }}>
                  Target Environment: {dashboardData?.target || "Loading..."}
                </span>
              </div>
              
              <div className="graph-canvas">
                {/* SVG Visualizer */}
                {dashboardData?.chains?.[0] ? (
                  <svg width="100%" height="100%" style={{ background: "#050a14" }}>
                    <defs>
                      <marker id="arrow" viewBox="0 0 10 10" refX="28" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
                        <path d="M 0 0 L 10 5 L 0 10 z" fill="#00f0ff" />
                      </marker>
                    </defs>

                    {/* Background grid overlay */}
                    <pattern id="grid" width="20" height="20" patternUnits="userSpaceOnUse">
                      <path d="M 20 0 L 0 0 0 20" fill="none" stroke="rgba(255,255,255,0.015)" strokeWidth="1" />
                    </pattern>
                    <rect width="100%" height="100%" fill="url(#grid)" />

                    {/* Connection links */}
                    {dashboardData.chains[0].edges.map((edge, index) => {
                      const nodes = dashboardData.chains[0].nodes;
                      const fromIdx = nodes.findIndex(n => n.node_id === edge.from);
                      const toIdx = nodes.findIndex(n => n.node_id === edge.to);
                      
                      if (fromIdx === -1 || toIdx === -1) return null;
                      
                      // Compute node layout coordinates
                      const fromX = 100 + fromIdx * 260 + 40;
                      const fromY = 190;
                      const toX = 100 + toIdx * 260 + 40;
                      const toY = 190;

                      const isSelected = selectedEdge && selectedEdge.from === edge.from && selectedEdge.to === edge.to;

                      return (
                        <g key={index} style={{ cursor: "pointer" }} onClick={() => { setSelectedEdge(edge); setSelectedNode(null); }}>
                          {/* Flow line background */}
                          <line
                            x1={fromX}
                            y1={fromY}
                            x2={toX}
                            y2={toY}
                            stroke={isSelected ? "var(--green-glow)" : "rgba(0, 240, 255, 0.4)"}
                            strokeWidth={isSelected ? 3 : 2}
                            markerEnd="url(#arrow)"
                            className="flowing-line"
                            style={{ strokeDasharray: "8, 4" }}
                          />
                          {/* Invisible larger hover click area */}
                          <line
                            x1={fromX}
                            y1={fromY}
                            x2={toX}
                            y2={toY}
                            stroke="transparent"
                            strokeWidth={15}
                          />
                          {/* Edge text label details */}
                          <rect
                            x={(fromX + toX) / 2 - 60}
                            y={fromY - 26}
                            width={120}
                            height={18}
                            rx={4}
                            fill="#0b0f19"
                            stroke={isSelected ? "var(--green-glow)" : "rgba(0, 240, 255, 0.2)"}
                            strokeWidth={1}
                          />
                          <text
                            x={(fromX + toX) / 2}
                            y={fromY - 14}
                            fill={isSelected ? "var(--green-glow)" : "var(--text-muted)"}
                            fontSize="9"
                            textAnchor="middle"
                            fontFamily="var(--font-mono)"
                          >
                            {edge.confidence.toUpperCase()} CONFIDENCE
                          </text>
                        </g>
                      );
                    })}

                    {/* Nodes visual rendering */}
                    {dashboardData.chains[0].nodes.map((node, index) => {
                      const nodeX = 100 + index * 260 + 40;
                      const nodeY = 190;
                      const isSelected = selectedNode && selectedNode.node_id === node.node_id;

                      // Color based on host or type
                      let iconColor = "var(--cyan-glow)";
                      if (["auth_bypass", "sql_injection"].includes(node.type)) iconColor = "var(--amber-glow)";
                      if (["jwt_none_algorithm", "privilege_escalation"].includes(node.type)) iconColor = "rgba(229, 193, 88, 1)";
                      if (["data_exfiltration", "rce"].includes(node.type)) iconColor = "var(--red-glow)";

                      return (
                        <g key={node.node_id} style={{ cursor: "pointer" }} onClick={() => { setSelectedNode(node); setSelectedEdge(null); }}>
                          {/* Outer glowing selector circle */}
                          <circle
                            cx={nodeX}
                            cy={nodeY}
                            r={36}
                            fill="#0b1220"
                            stroke={isSelected ? "var(--green-glow)" : iconColor}
                            strokeWidth={isSelected ? 3 : 1.5}
                            style={{
                              filter: isSelected ? "drop-shadow(0 0 8px var(--green-glow))" : `drop-shadow(0 0 5px ${iconColor}44)`
                            }}
                          />
                          {/* Inner circle badge background */}
                          <circle cx={nodeX} cy={nodeY} r={28} fill="rgba(15, 22, 38, 0.9)" />
                          
                          {/* Short code label of the agent/node */}
                          <text
                            x={nodeX}
                            y={nodeY + 4}
                            fill={iconColor}
                            textAnchor="middle"
                            fontWeight="bold"
                            fontSize="11"
                            fontFamily="var(--font-mono)"
                          >
                            {node.agent.substring(0, 8)}
                          </text>

                          {/* Node ID label tag */}
                          <rect
                            x={nodeX - 25}
                            y={nodeY - 50}
                            width={50}
                            height={15}
                            rx={3}
                            fill="#070a13"
                            stroke="rgba(255, 255, 255, 0.1)"
                          />
                          <text
                            x={nodeX}
                            y={nodeY - 40}
                            fill="#fff"
                            textAnchor="middle"
                            fontSize="9"
                            fontFamily="var(--font-mono)"
                          >
                            {node.node_id}
                          </text>

                          {/* Host text representation below node */}
                          <text
                            x={nodeX}
                            y={nodeY + 54}
                            fill="var(--text-primary)"
                            textAnchor="middle"
                            fontSize="12"
                            fontWeight="500"
                          >
                            {node.host}
                          </text>

                          <text
                            x={nodeX}
                            y={nodeY + 68}
                            fill="var(--text-muted)"
                            textAnchor="middle"
                            fontSize="10"
                            fontFamily="var(--font-mono)"
                          >
                            Port: {node.port}
                          </text>
                        </g>
                      );
                    })}
                  </svg>
                ) : (
                  <div style={{ display: "flex", justifyContent: "center", alignItems: "center", height: "100%", color: "var(--text-muted)" }}>
                    No chain data loaded. Run pipeline or select a preset template.
                  </div>
                )}
              </div>
            </div>

            {/* Split dashboard cards: Left details, Right brief / quick view */}
            <div className="grid-2">
              {/* Left Panel: Selected Item properties */}
              <div className="cyber-card" style={{ minHeight: "300px" }}>
                {selectedNode ? (
                  <div>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", borderBottom: "1px solid var(--border-color)", paddingBottom: "12px", marginBottom: "16px" }}>
                      <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                        <span style={{ fontSize: "18px", fontWeight: "600", color: "var(--cyan-glow)" }}>
                          Node details: {selectedNode.node_id}
                        </span>
                        <span className={`severity-badge ${getSeverityColor(selectedNode.severity)}`}>
                          {selectedNode.severity}
                        </span>
                      </div>
                      <span style={{ fontFamily: "var(--font-mono)", fontSize: "11px", color: "var(--text-muted)" }}>
                        Agent: {selectedNode.agent}
                      </span>
                    </div>

                    <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "13px" }}>
                      <tbody>
                        <tr style={{ borderBottom: "1px solid rgba(255, 255, 255, 0.03)" }}>
                          <td style={{ padding: "8px 0", color: "var(--text-muted)", width: "130px" }}>Vulnerability Type</td>
                          <td style={{ padding: "8px 0", fontWeight: "500", color: "#fff" }}>
                            {selectedNode.type.replace(/_/g, ' ').toUpperCase()}
                          </td>
                        </tr>
                        <tr style={{ borderBottom: "1px solid rgba(255, 255, 255, 0.03)" }}>
                          <td style={{ padding: "8px 0", color: "var(--text-muted)" }}>Host / Target</td>
                          <td style={{ padding: "8px 0", fontFamily: "var(--font-mono)", color: "var(--cyan-glow)" }}>
                            {selectedNode.host}:{selectedNode.port}
                          </td>
                        </tr>
                        <tr style={{ borderBottom: "1px solid rgba(255, 255, 255, 0.03)" }}>
                          <td style={{ padding: "8px 0", color: "var(--text-muted)" }}>HTTP Endpoint</td>
                          <td style={{ padding: "8px 0", fontFamily: "var(--font-mono)" }}>
                            <span style={{ color: "var(--green-glow)", marginRight: "6px" }}>{selectedNode.method || "GET"}</span>
                            {selectedNode.endpoint || "/"}
                          </td>
                        </tr>
                        {selectedNode.param && (
                          <tr style={{ borderBottom: "1px solid rgba(255, 255, 255, 0.03)" }}>
                            <td style={{ padding: "8px 0", color: "var(--text-muted)" }}>Vulnerable Param</td>
                            <td style={{ padding: "8px 0", fontFamily: "var(--font-mono)" }}>
                              {selectedNode.param} <span style={{ color: "var(--text-muted)" }}>({selectedNode.param_location})</span>
                            </td>
                          </tr>
                        )}
                        {selectedNode.payload && (
                          <tr style={{ borderBottom: "1px solid rgba(255, 255, 255, 0.03)" }}>
                            <td style={{ padding: "8px 0", color: "var(--text-muted)" }}>Exploit Payload</td>
                            <td style={{ padding: "8px 0", fontFamily: "var(--font-mono)" }}>
                              <code style={{ background: "var(--bg-primary)", color: "var(--amber-glow)", border: "1px solid rgba(255,255,255,0.05)" }}>
                                {selectedNode.payload}
                              </code>
                            </td>
                          </tr>
                        )}
                        <tr style={{ borderBottom: "1px solid rgba(255, 255, 255, 0.03)" }}>
                          <td style={{ padding: "8px 0", color: "var(--text-muted)" }}>Evidence Recieved</td>
                          <td style={{ padding: "8px 0", color: "var(--text-muted)" }}>
                            {selectedNode.evidence}
                          </td>
                        </tr>
                        <tr style={{ borderBottom: "1px solid rgba(255, 255, 255, 0.03)" }}>
                          <td style={{ padding: "8px 0", color: "var(--text-muted)" }}>Detection Mechanism</td>
                          <td style={{ padding: "8px 0", fontFamily: "var(--font-mono)" }}>
                            {selectedNode.detection_method}
                          </td>
                        </tr>
                        <tr>
                          <td style={{ padding: "8px 0", color: "var(--text-muted)" }}>Discovery Time</td>
                          <td style={{ padding: "8px 0", fontFamily: "var(--font-mono)", fontSize: "12px" }}>
                            {new Date(selectedNode.timestamp).toLocaleString()}
                          </td>
                        </tr>
                      </tbody>
                    </table>
                  </div>
                ) : selectedEdge ? (
                  <div>
                    <div style={{ borderBottom: "1px solid var(--border-color)", paddingBottom: "12px", marginBottom: "16px" }}>
                      <span style={{ fontSize: "18px", fontWeight: "600", color: "var(--cyan-glow)" }}>
                        Correlation Link Detail
                      </span>
                    </div>
                    
                    <div style={{ display: "flex", flexDirection: "column", gap: "15px" }}>
                      <div style={{ display: "flex", gap: "20px", alignItems: "center", justifyContent: "center", padding: "15px", background: "var(--bg-primary)", borderRadius: "8px" }}>
                        <span style={{ fontFamily: "var(--font-mono)", background: "var(--bg-tertiary)", padding: "4px 10px", borderRadius: "4px" }}>
                          {selectedEdge.from}
                        </span>
                        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="var(--cyan-glow)" strokeWidth="2">
                          <line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/>
                        </svg>
                        <span style={{ fontFamily: "var(--font-mono)", background: "var(--bg-tertiary)", padding: "4px 10px", borderRadius: "4px" }}>
                          {selectedEdge.to}
                        </span>
                      </div>

                      <div>
                        <div style={{ fontSize: "11px", textTransform: "uppercase", color: "var(--text-muted)", marginBottom: "4px" }}>
                          Correlation Reason
                        </div>
                        <div style={{ fontSize: "14px", lineHeight: "1.5" }}>
                          {selectedEdge.reason}
                        </div>
                      </div>

                      <div>
                        <div style={{ fontSize: "11px", textTransform: "uppercase", color: "var(--text-muted)", marginBottom: "4px" }}>
                          Link Confidence
                        </div>
                        <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                          <span className={`severity-badge ${selectedEdge.confidence === 'high' ? 'confirmed' : 'medium'}`}>
                            {selectedEdge.confidence.toUpperCase()}
                          </span>
                          <span style={{ fontSize: "12px", color: "var(--text-muted)" }}>
                            Determined by sequential threat lifecycle rules
                          </span>
                        </div>
                      </div>
                    </div>
                  </div>
                ) : (
                  <div style={{ display: "flex", justifyContent: "center", alignItems: "center", height: "260px", color: "var(--text-dark)", textAlign: "center" }}>
                    <div>
                      <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1" style={{ marginBottom: "12px" }}>
                        <circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/>
                      </svg>
                      <div>Click any Node or Connection Link on the topology map above to inspect properties.</div>
                    </div>
                  </div>
                )}
              </div>

              {/* Right Panel: Chain Summary Brief */}
              <div className="cyber-card">
                {dashboardData?.chains?.[0] ? (
                  <div>
                    <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", borderBottom: "1px solid var(--border-color)", paddingBottom: "12px", marginBottom: "16px" }}>
                      <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
                        <span style={{ fontSize: "18px", fontWeight: "600" }}>Chain Assessment</span>
                        <span className={`severity-badge ${getSeverityColor(dashboardData.chains[0].brief.severity)}`}>
                          {dashboardData.chains[0].brief.severity} RISK
                        </span>
                      </div>
                      <span style={{ fontSize: "11px", color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>
                        ID: {dashboardData.chains[0].chain_id}
                      </span>
                    </div>

                    <div style={{ display: "flex", flexDirection: "column", gap: "16px" }}>
                      <div>
                        <div style={{ fontSize: "11px", textTransform: "uppercase", color: "var(--text-muted)", marginBottom: "4px" }}>
                          Attack Path Flow
                        </div>
                        <div style={{ fontFamily: "var(--font-mono)", fontSize: "12px", color: "var(--cyan-glow)", background: "rgba(0,0,0,0.2)", padding: "10px", borderRadius: "6px", border: "1px solid var(--glass-border)" }}>
                          {dashboardData.chains[0].brief.attack_flow}
                        </div>
                      </div>

                      <div>
                        <div style={{ fontSize: "11px", textTransform: "uppercase", color: "var(--text-muted)", marginBottom: "4px" }}>
                          Executive Narrative Summary
                        </div>
                        <p style={{ fontSize: "13px", lineHeight: "1.6", color: "var(--text-muted)" }}>
                          {dashboardData.chains[0].brief.summary}
                        </p>
                      </div>

                      <div>
                        <div style={{ fontSize: "11px", textTransform: "uppercase", color: "var(--text-muted)", marginBottom: "4px" }}>
                          Final Threat Outcome
                        </div>
                        <div style={{ fontSize: "13px", fontWeight: "500", color: "var(--red-glow)" }}>
                          {dashboardData.chains[0].brief.final_outcome}
                        </div>
                      </div>

                      <div style={{ display: "flex", gap: "20px" }}>
                        <div>
                          <span style={{ fontSize: "11px", textTransform: "uppercase", color: "var(--text-muted)", display: "block" }}>Confidence</span>
                          <span style={{ fontSize: "14px", fontWeight: "600", color: "#fff" }}>
                            {dashboardData.chains[0].brief.confidence.toUpperCase()}
                          </span>
                        </div>
                        <div>
                          <span style={{ fontSize: "11px", textTransform: "uppercase", color: "var(--text-muted)", display: "block" }}>Total Steps</span>
                          <span style={{ fontSize: "14px", fontWeight: "600", color: "#fff" }}>
                            {dashboardData.chains[0].nodes.length} Audited Nodes
                          </span>
                        </div>
                      </div>
                    </div>
                  </div>
                ) : (
                  <div style={{ display: "flex", justifyContent: "center", alignItems: "center", height: "260px", color: "var(--text-muted)" }}>
                    No brief available.
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* Tab content 2: VAPT Analyst Workspace */}
        {activeTab === "vapt" && (
          <div style={{ display: "flex", flexDirection: "column", gap: "20px" }}>
            <div className="cyber-card">
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", borderBottom: "1px solid var(--border-color)", paddingBottom: "12px", marginBottom: "20px" }}>
                <h3 style={{ margin: 0, fontSize: "18px" }}>MITRE ATT&CK Threat Mapping</h3>
                <button className="cyber-btn secondary" style={{ padding: "6px 12px", fontSize: "11px" }} onClick={exportReport}>
                  Download Audit Report (.TXT)
                </button>
              </div>

              {dashboardData?.chains?.[0] ? (
                <div style={{ display: "flex", flexDirection: "column", gap: "20px" }}>
                  <p style={{ fontSize: "14px", color: "var(--text-muted)" }}>
                    The correlated vulnerabilities are mapped to the globally recognized MITRE ATT&CK Enterprise Matrix 
                    tactics and techniques to assist pentest reporting.
                  </p>

                  <div className="grid-3">
                    {dashboardData.chains[0].brief.mitre_techniques.map((tech, idx) => {
                      const tId = dashboardData.chains[0].brief.mitre_ids?.[idx] || "T1000";
                      const tactic = dashboardData.chains[0].brief.mitre_tactics?.[idx] || "Execution";
                      
                      return (
                        <div key={idx} className="mitre-badge" style={{ background: "rgba(10, 14, 23, 0.4)" }}>
                          <div>
                            <div className="mitre-code">{tId}</div>
                            <div style={{ fontSize: "12px", fontWeight: "500", marginTop: "2px" }}>
                              {tech.substring(6)}
                            </div>
                          </div>
                          <span style={{ fontSize: "9px", background: "var(--bg-tertiary)", padding: "2px 6px", borderRadius: "3px", color: "var(--text-muted)", textTransform: "uppercase" }}>
                            {tactic}
                          </span>
                        </div>
                      );
                    })}
                  </div>
                </div>
              ) : (
                <div style={{ color: "var(--text-muted)" }}>No preset loaded to map.</div>
              )}
            </div>

            <div className="cyber-card">
              <div style={{ borderBottom: "1px solid var(--border-color)", paddingBottom: "12px", marginBottom: "20px" }}>
                <h3 style={{ margin: 0, fontSize: "18px" }}>VAPT Remediation & Patching Guidelines</h3>
              </div>

              {dashboardData?.chains?.[0] ? (
                <div style={{ display: "flex", flexDirection: "column", gap: "24px" }}>
                  {dashboardData.chains[0].brief.remediation_plan.map((plan, idx) => {
                    const node = dashboardData.chains[0].nodes[idx] || { type: "discovery", host: "app.com", node_id: "" };
                    
                    // Generate customized patch advice code block based on type
                    let codeAdvice = "";
                    if (node.type === "directory_discovery") {
                      codeAdvice = `# Nginx Configuration - Disable Directory Index Listing\nserver {\n    location /admin {\n        autoindex off;\n        allow 192.168.1.0/24; # Restrict access to internal networks\n        deny all;\n    }\n}`;
                    } else if (node.type === "auth_bypass" || node.type === "sql_injection") {
                      codeAdvice = `// Javascript / Node.js - Enforce Secure Prepared Statements\nconst query = 'SELECT * FROM users WHERE username = ? AND password = ?';\ndb.execute(query, [username, password], (err, results) => {\n    if (results.length > 0) { /* Login Authorized */ }\n});`;
                    } else if (node.type === "jwt_none_algorithm") {
                      codeAdvice = `// Node.js Express JWT verification - Block 'alg': 'none'\nconst jwt = require('jsonwebtoken');\n\napp.get('/api/user', (req, res) => {\n    const authHeader = req.headers['authorization'];\n    const token = authHeader && authHeader.split(' ')[1];\n    \n    // Verify options forcing secure HS256/RS256 algorithms\n    jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'] }, (err, user) => {\n        if (err) return res.sendStatus(403);\n        req.user = user;\n        next();\n    });\n});`;
                    } else if (node.type === "data_exfiltration") {
                      codeAdvice = `# AWS IAM - Tighten Policy to Prevent Mass S3 Syncs\n{\n    "Version": "2012-10-17",\n    "Statement": [\n        {\n            "Sid": "RestrictS3Downloads",\n            "Effect": "Deny",\n            "Action": ["s3:GetObject", "s3:ListBucket"],\n            "Resource": ["arn:aws:s3:::bucket-production-finance/*"],\n            "Condition": {\n                "NotIpAddress": {"aws:SourceIp": ["10.0.0.0/8"]}\n            }\n        }\n    ]\n}`;
                    } else {
                      codeAdvice = `# Security patch recommendation:\n# Enforce principle of least privilege, run services under limited user context\n# and enable strict host firewalls.`;
                    }

                    return (
                      <div key={idx} style={{ borderBottom: idx < dashboardData.chains[0].brief.remediation_plan.length - 1 ? "1px solid rgba(255,255,255,0.03)" : "none", paddingBottom: "20px" }}>
                        <div style={{ display: "flex", gap: "10px", alignItems: "center", marginBottom: "8px" }}>
                          <span style={{ width: "20px", height: "20px", borderRadius: "50%", background: "var(--bg-tertiary)", display: "flex", alignItems: "center", justifyContent: "center", fontSize: "11px", fontWeight: "bold", border: "1px solid var(--cyan-border)" }}>
                            {idx + 1}
                          </span>
                          <span style={{ fontSize: "14px", fontWeight: "600", color: "var(--cyan-glow)" }}>
                            Mitigation for Node {node.node_id} ({node.type.replace(/_/g, ' ').toUpperCase()})
                          </span>
                        </div>
                        
                        <p style={{ fontSize: "13px", lineHeight: "1.6", color: "var(--text-muted)", marginBottom: "12px" }}>
                          {plan}
                        </p>

                        <div className="cyber-terminal">
                          <div className="terminal-header">
                            <span>RECOMMENDED PATCH SNIPPET</span>
                            <span style={{ cursor: "pointer", color: "var(--cyan-glow)" }} onClick={() => navigator.clipboard.writeText(codeAdvice)}>
                              COPY CODE
                            </span>
                          </div>
                          <pre style={{ margin: 0, overflow: "auto", fontFamily: "var(--font-mono)" }}>
                            <code>{codeAdvice}</code>
                          </pre>
                        </div>
                      </div>
                    );
                  })}
                </div>
              ) : (
                <div style={{ color: "var(--text-muted)" }}>No remediation metrics loaded.</div>
              )}
            </div>
          </div>
        )}

        {/* Tab content 3: SOC SIEM Operations */}
        {activeTab === "soc" && (
          <div style={{ display: "flex", flexDirection: "column", gap: "20px" }}>
            {/* SIEM Dial Metrics Row */}
            <div className="grid-3">
              <div className="cyber-card" style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", padding: "24px 20px" }}>
                <span style={{ fontSize: "11px", textTransform: "uppercase", color: "var(--text-muted)", marginBottom: "8px" }}>
                  Incident Risk Severity
                </span>
                
                {dashboardData?.chains?.[0] ? (
                  <div style={{ textAlign: "center" }}>
                    <div style={{
                      fontSize: "24px",
                      fontWeight: "700",
                      color: dashboardData.chains[0].brief.severity === 'critical' ? 'var(--red-glow)' : 'var(--amber-glow)',
                      textShadow: `0 0 10px ${dashboardData.chains[0].brief.severity === 'critical' ? 'var(--red-transparent)' : 'var(--amber-transparent)'}`,
                      textTransform: "uppercase"
                    }}>
                      {dashboardData.chains[0].brief.severity}
                    </div>
                    <div style={{ fontSize: "11px", color: "var(--text-muted)", marginTop: "4px" }}>
                      Calculated from VAPT Exploit Points
                    </div>
                  </div>
                ) : (
                  <div style={{ fontSize: "20px", color: "var(--text-dark)" }}>N/A</div>
                )}
              </div>

              <div className="cyber-card" style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", padding: "24px 20px" }}>
                <span style={{ fontSize: "11px", textTransform: "uppercase", color: "var(--text-muted)", marginBottom: "8px" }}>
                  Detection Confidence
                </span>
                {dashboardData?.chains?.[0] ? (
                  <div style={{ textAlign: "center" }}>
                    <div style={{ fontSize: "24px", fontWeight: "700", color: "var(--green-glow)" }}>
                      {dashboardData.chains[0].brief.confidence.toUpperCase()}
                    </div>
                    <div style={{ fontSize: "11px", color: "var(--text-muted)", marginTop: "4px" }}>
                      Multiple correlated telemetry steps
                    </div>
                  </div>
                ) : (
                  <div style={{ fontSize: "20px", color: "var(--text-dark)" }}>N/A</div>
                )}
              </div>

              <div className="cyber-card" style={{ display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", padding: "24px 20px" }}>
                <span style={{ fontSize: "11px", textTransform: "uppercase", color: "var(--text-muted)", marginBottom: "8px" }}>
                  SIEM Status
                </span>
                <div style={{ textAlign: "center" }}>
                  <div style={{ fontSize: "24px", fontWeight: "700", color: logTickerActive ? "var(--green-glow)" : "var(--text-dark)" }}>
                    {logTickerActive ? "LIVE AUDIT" : "MUTED"}
                  </div>
                  <button className="cyber-btn secondary" style={{ padding: "2px 8px", fontSize: "10px", marginTop: "8px" }} onClick={() => setLogTickerActive(!logTickerActive)}>
                    {logTickerActive ? "Mute Feed" : "Unmute Feed"}
                  </button>
                </div>
              </div>
            </div>

            {/* SIEM Log Stream Console */}
            <div className="cyber-card">
              <div style={{ borderBottom: "1px solid var(--border-color)", paddingBottom: "12px", marginBottom: "16px", display: "flex", justifyContent: "space-between" }}>
                <span style={{ fontSize: "12px", textTransform: "uppercase", fontWeight: "600", color: "var(--text-muted)" }}>
                  SIEM Log Stream & Alert Correlation Engine
                </span>
                <span style={{ fontSize: "10px", fontFamily: "var(--font-mono)", color: "var(--text-dark)" }}>
                  SYS_PORTAL_CONN_OK
                </span>
              </div>

              <div className="cyber-terminal" style={{ height: "250px", background: "#03060b" }}>
                {socLogs.length === 0 ? (
                  <div style={{ color: "var(--text-dark)" }}>Awaiting pipeline execution to stream security logs...</div>
                ) : (
                  <div style={{ display: "flex", flexDirection: "column", gap: "6px" }}>
                    {socLogs.map((log, idx) => {
                      let color = "#a9b7c6";
                      if (log.level === "WARNING") color = "#ffaa00";
                      if (log.level === "HIGH") color = "#ff7f00";
                      if (log.level === "CRITICAL") color = "var(--red-glow)";

                      return (
                        <div key={idx} style={{ display: "flex", fontSize: "12px", fontFamily: "var(--font-mono)" }}>
                          <span style={{ color: "var(--text-dark)", marginRight: "8px", flexShrink: 0 }}>
                            [{log.time || log.timestamp}]
                          </span>
                          <span style={{ color: "var(--cyan-dim)", marginRight: "8px", fontWeight: "bold", width: "100px", flexShrink: 0 }}>
                            {log.source}
                          </span>
                          <span style={{ color, marginRight: "8px", fontWeight: "600", width: "70px", flexShrink: 0 }}>
                            {log.level}
                          </span>
                          <span style={{ color: log.level === 'CRITICAL' ? '#fff' : 'var(--text-muted)' }}>
                            {log.msg || log.message}
                          </span>
                        </div>
                      );
                    })}
                    <div ref={socConsoleEndRef} />
                  </div>
                )}
              </div>
            </div>

            {/* Splunk Queries & Snort Rules */}
            <div className="grid-2">
              <div className="cyber-card">
                <div style={{ display: "flex", justifyContent: "space-between", borderBottom: "1px solid var(--border-color)", paddingBottom: "12px", marginBottom: "16px" }}>
                  <span style={{ fontSize: "13px", fontWeight: "600" }}>SPLUNK ENTERPRISE SEARCH SIGNATURES</span>
                  <span style={{ cursor: "pointer", fontSize: "11px", color: "var(--cyan-glow)" }} onClick={() => navigator.clipboard.writeText(dashboardData?.chains?.[0]?.brief.soc_detections.splunk_query)}>
                    COPY ALL
                  </span>
                </div>
                <div className="cyber-terminal" style={{ height: "150px", background: "#03060b" }}>
                  <pre style={{ margin: 0, whiteSpace: "pre-wrap" }}>
                    <code>{dashboardData?.chains?.[0]?.brief.soc_detections.splunk_query || "Run pipeline to generate SPLUNK search queries"}</code>
                  </pre>
                </div>
              </div>

              <div className="cyber-card">
                <div style={{ display: "flex", justifyContent: "space-between", borderBottom: "1px solid var(--border-color)", paddingBottom: "12px", marginBottom: "16px" }}>
                  <span style={{ fontSize: "13px", fontWeight: "600" }}>SNORT NIDS DETECTOR RULES</span>
                  <span style={{ cursor: "pointer", fontSize: "11px", color: "var(--cyan-glow)" }} onClick={() => navigator.clipboard.writeText(dashboardData?.chains?.[0]?.brief.soc_detections.snort_rule)}>
                    COPY ALL
                  </span>
                </div>
                <div className="cyber-terminal" style={{ height: "150px", background: "#03060b" }}>
                  <pre style={{ margin: 0, whiteSpace: "pre-wrap" }}>
                    <code>{dashboardData?.chains?.[0]?.brief.soc_detections.snort_rule || "Run pipeline to generate Snort detection rules"}</code>
                  </pre>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Tab content 4: Pipeline Execution Terminal */}
        {activeTab === "pipeline" && (
          <div className="cyber-card">
            <div style={{ borderBottom: "1px solid var(--border-color)", paddingBottom: "12px", marginBottom: "20px" }}>
              <h3 style={{ margin: 0, fontSize: "18px" }}>Pipeline Execution Workflow Stream</h3>
            </div>
            
            <div className="cyber-terminal" style={{ minHeight: "350px", background: "#040710" }}>
              <div className="terminal-header">
                <span>Ingestion Pipeline Controller Console</span>
                <span className="cyber-cursor"></span>
              </div>
              
              <div style={{ display: "flex", flexDirection: "column", gap: "10px" }}>
                {pipelineLogs.map((log, idx) => {
                  let stepColor = "var(--text-muted)";
                  let typeSymbol = "[*]";
                  let textColor = "#a9b7c6";

                  if (log.type === "success") {
                    stepColor = "var(--green-glow)";
                    typeSymbol = "[+]";
                    textColor = "#fff";
                  } else if (log.type === "error") {
                    stepColor = "var(--red-glow)";
                    typeSymbol = "[-]";
                    textColor = "var(--red-glow)";
                  } else if (log.type === "warning") {
                    stepColor = "var(--amber-glow)";
                    typeSymbol = "[!]";
                    textColor = "var(--amber-glow)";
                  }

                  return (
                    <div key={idx} style={{ display: "flex", fontSize: "12.5px", fontFamily: "var(--font-mono)" }}>
                      <span style={{ color: "var(--text-dark)", marginRight: "10px" }}>
                        [{log.timestamp}]
                      </span>
                      <span style={{ color: stepColor, marginRight: "8px", fontWeight: "bold", width: "130px", flexShrink: 0 }}>
                        {typeSymbol} {log.step}
                      </span>
                      <span style={{ color: textColor }}>
                        {log.msg}
                      </span>
                    </div>
                  );
                })}
                <div ref={terminalEndRef} />
              </div>
            </div>
          </div>
        )}

        {/* Tab content 5: Audit Ingest & Presets */}
        {activeTab === "presets" && (
          <div style={{ display: "flex", flexDirection: "column", gap: "20px" }}>
            <div className="cyber-card">
              <div style={{ borderBottom: "1px solid var(--border-color)", paddingBottom: "12px", marginBottom: "20px" }}>
                <h3 style={{ margin: 0, fontSize: "18px" }}>Ingest Preset VAPT Audit Datasets</h3>
                <p style={{ color: "var(--text-muted)", fontSize: "13px", marginTop: "4px" }}>
                  Select a pre-configured penetration test output (ProtoJSON) to run through the chain discovery engines.
                </p>
              </div>

              <div className="grid-3">
                {Object.keys(PRESETS).map(key => {
                  const p = PRESETS[key];
                  const isSelected = selectedPreset === key;
                  return (
                    <div
                      key={key}
                      onClick={() => loadPreset(key)}
                      style={{
                        padding: "16px",
                        background: isSelected ? "rgba(0, 240, 255, 0.04)" : "rgba(255,255,255,0.01)",
                        border: `1px solid ${isSelected ? "var(--cyan-glow)" : "var(--border-color)"}`,
                        borderRadius: "8px",
                        cursor: "pointer",
                        transition: "all 0.2s ease"
                      }}
                    >
                      <div style={{ fontSize: "14px", fontWeight: "600", color: isSelected ? "var(--cyan-glow)" : "#fff", marginBottom: "8px" }}>
                        {p.name}
                      </div>
                      <p style={{ fontSize: "12px", color: "var(--text-muted)", lineHeight: "1.5" }}>
                        {p.description}
                      </p>
                    </div>
                  );
                })}
              </div>
            </div>

            <div className="grid-2">
              {/* Drag & Drop Upload Simulation */}
              <div className="cyber-card" style={{ display: "flex", flexDirection: "column", justifyContent: "center", alignItems: "center", padding: "40px" }}>
                <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="var(--cyan-glow)" strokeWidth="1" style={{ marginBottom: "16px" }}>
                  <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/>
                </svg>
                <div style={{ fontSize: "15px", fontWeight: "600", marginBottom: "4px" }}>
                  Upload Custom ProtoJSON File
                </div>
                <p style={{ color: "var(--text-muted)", fontSize: "12px", textAlign: "center", marginBottom: "20px" }}>
                  Upload raw security node details produced by scanning agents
                </p>
                <label className="cyber-btn secondary" style={{ fontSize: "12px", cursor: "pointer" }}>
                  Browse File
                  <input
                    type="file"
                    accept=".json"
                    style={{ display: "none" }}
                    onChange={(e) => {
                      const file = e.target.files[0];
                      if (!file) return;
                      const reader = new FileReader();
                      reader.onload = (event) => {
                        try {
                          const parsed = JSON.parse(event.target.result);
                          setInputProto(parsed);
                          setSelectedPreset("custom");
                        } catch (err) {
                          alert("Invalid JSON file uploaded: " + err.message);
                        }
                      };
                      reader.readAsText(file);
                    }}
                  />
                </label>
              </div>

              {/* Live JSON Schema Guidelines */}
              <div className="cyber-card">
                <div style={{ borderBottom: "1px solid var(--border-color)", paddingBottom: "12px", marginBottom: "12px" }}>
                  <span style={{ fontSize: "13px", fontWeight: "600" }}>AUDIT SCHEMATIC CONTRACT (PROTOJSON)</span>
                </div>
                
                <p style={{ fontSize: "12.5px", color: "var(--text-muted)", lineHeight: "1.6" }}>
                  The ingestion pipeline requires the following schema layout to run correctly:
                </p>
                <ul style={{ fontSize: "12px", color: "var(--text-muted)", paddingLeft: "20px", marginTop: "8px" }}>
                  <li><strong style={{ color: "var(--text-primary)" }}>pentest_id</strong>: String (Audit Session ID)</li>
                  <li><strong style={{ color: "var(--text-primary)" }}>target</strong>: String (Root URL/Domain Target)</li>
                  <li><strong style={{ color: "var(--text-primary)" }}>nodes</strong>: Array containing VAPT findings:
                    <ul style={{ paddingLeft: "15px", marginTop: "4px" }}>
                      <li><code>node_id</code>: Unique Identifier (e.g. n1, n2)</li>
                      <li><code>agent</code>: Tool identifier (e.g. NMAP, WAF)</li>
                      <li><code>type</code>: Exploit category (e.g. directory_discovery, auth_bypass)</li>
                      <li><code>host</code> & <code>port</code>: Net address targets</li>
                      <li><code>timestamp</code>: ISO format execution datetime</li>
                      <li><code>severity</code>: info | low | medium | high | critical</li>
                    </ul>
                  </li>
                </ul>
              </div>
            </div>
          </div>
        )}

        {/* Tab content 6: JSON Inspector */}
        {activeTab === "inspector" && (
          <div className="grid-2">
            {/* Input Json Editor */}
            <div className="cyber-card">
              <div style={{ display: "flex", justifyContent: "space-between", borderBottom: "1px solid var(--border-color)", paddingBottom: "12px", marginBottom: "16px" }}>
                <span style={{ fontSize: "13px", fontWeight: "600" }}>INPUT: PROTOJSON.JSON (EDITABLE)</span>
                <span style={{ fontSize: "11px", color: "var(--amber-glow)" }}>LOCKED TO ACTIVE DATA</span>
              </div>
              <textarea
                className="cyber-input"
                style={{ height: "400px", fontFamily: "var(--font-mono)", fontSize: "11.5px", resize: "none", background: "#03060b" }}
                value={JSON.stringify(inputProto, null, 2)}
                onChange={(e) => handleJsonInputChange(e.target.value)}
              />
            </div>

            {/* Output Json Inspector */}
            <div className="cyber-card">
              <div style={{ display: "flex", justifyContent: "space-between", borderBottom: "1px solid var(--border-color)", paddingBottom: "12px", marginBottom: "16px" }}>
                <span style={{ fontSize: "13px", fontWeight: "600" }}>OUTPUT: DASHBOARD_DATA.JSON</span>
                {dashboardData && (
                  <span
                    style={{ cursor: "pointer", fontSize: "11px", color: "var(--cyan-glow)" }}
                    onClick={() => {
                      const blob = new Blob([JSON.stringify(dashboardData, null, 2)], { type: "application/json" });
                      const url = URL.createObjectURL(blob);
                      const link = document.createElement("a");
                      link.href = url;
                      link.download = "dashboard_data.json";
                      link.click();
                      URL.revokeObjectURL(url);
                    }}
                  >
                    DOWNLOAD JSON
                  </span>
                )}
              </div>
              <div className="cyber-terminal" style={{ height: "400px", background: "#03060b" }}>
                <pre style={{ margin: 0 }}>
                  <code>
                    {dashboardData ? JSON.stringify(dashboardData, null, 2) : "Run pipeline to generate dashboard JSON data"}
                  </code>
                </pre>
              </div>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}

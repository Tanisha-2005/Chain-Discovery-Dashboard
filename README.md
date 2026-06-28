# Chain Discovery Dashboard 🛡️
### Professional Cybersecurity VAPT & SOC Correlation Intern Project

Chain Discovery Dashboard is an interactive cybersecurity analysis dashboard that ingests raw vulnerability node datasets (ProtoJSON) and correlates them into actionable attack chains (directed graphs). It serves dual roles:
1. **VAPT Analyst Portal**: Reviewing security exploits, mapping threats to the MITRE ATT&CK matrix, and formulating remediation code patches.
2. **SOC Incident Responder Console**: Monitoring live simulated logs correlating to the attack path, inspecting SIEM Splunk queries, and capturing Snort NIDS rules.

---

## 1. Pipeline Execution Architecture

The system is designed as a **6-stage deterministic pipeline** ensuring strict contract validation:

```
          [Raw ProtoJSON Ingest]
                     │
                     ▼
          1. Schema Validation (validator.py)
                     │
                     ▼
          2. Attack Chain Discovery (brain.py)
                     │
                     ▼
          3. Topology Check (validator.py)
                     │
                     ▼
          4. Threat Intelligence Enrichment (enrichment.py)
                     │
                     ▼
          5. Enrichment Verification (validator.py)
                     │
                     ▼
          6. Consolidation Merger (merger.py)
                     │
                     ▼
          [Dashboard JSON Output]
```

---

## 2. Upgraded Architecture (Sprint 1 vs VAPT/SOC Level)

To shift the prototype from a simple linear mock to a professional cybersecurity intern project, we have introduced several critical features:

| Feature | Sprint 1 Prototype | Chain Discovery Dashboard Professional Level (Upgraded) |
|---|---|---|
| **Input Validation** | Basic dictionary check | Deep validation on syntax, valid hosts/ports (1-65535), duplicate check, and error codes. |
| **Brain Engine** | Hardcoded mock sequence | Dynamic rule-based correlation mapping nodes based on Kill Chain phases (Recon -> Exploit -> Privilege Esc -> Exfil). |
| **Enrichment** | Standard text briefs | Full MITRE ATT&CK Technique attribution, customizable remediations, Splunk queries, and Snort rules. |
| **Interface** | CLI only | High-contrast React dashboard with interactive SVG attack graph visualizations, log stream terminal, and preset selectors. |
| **API Layer** | Stateless offline CLI | FastAPI server hosting endpoints for running the pipeline, generating live SIEM logs, and serving presets. |

---

## 3. Directory Layout

```
chain-discovery-dashboard/
├── backend/
│   ├── core/
│   │   ├── pipeline.py        # Orchestrates the validation & run sequence
│   │   ├── validator.py       # Deep VAPT input/output structure validator
│   │   └── merger.py          # Merges nodes, edges, and briefings
│   ├── engines/
│   │   ├── brain.py           # Correlates findings into directed graphs
│   │   └── enrichment.py      # Computes MITRE, Splunk, Snort rule metrics
│   ├── data/
│   │   ├── protojson.json     # Input template for audit runs
│   │   └── dashboard_data.json# Output generated dashboard payload
│   ├── main.py                # Python CLI entrypoint
│   └── server.py              # FastAPI server serving REST APIs
│
├── frontend/                  # Vite + React Client Dashboard
│   ├── src/
│   │   ├── App.jsx            # Core Dashboard UI (VAPT & SOC tabs)
│   │   ├── index.css          # Dark cyberpunk cyber-themed design system
│   │   └── main.jsx           # Root react rendering entry
│   ├── index.html             # Web page viewport and meta tags
│   └── package.json           # Frontend dependency config
│
├── run_dev.bat                # Windows double-click dev environment launcher
└── README.md                  # System user manual (This document)
```

---

## 4. Setting Up & Running

### Prerequisites
* **Python 3.8+** (FastAPI and Uvicorn packages must be installed)
* **Node.js v16+** (For building the React frontend)

### Installation & Launch (Windows Auto-Start)
Simply double-click the **`run_dev.bat`** file in the root directory. This script will automatically:
1. Open a terminal window and launch the FastAPI server: `http://localhost:8000`
2. Open a second terminal window and run the Vite React app: `http://localhost:5173`

### Manual Execution

#### 1. Starting the Backend Server
```bash
cd backend
python main.py --server
```
*(FastAPI Swagger Interactive documentation is available at `http://localhost:8000/docs`)*

#### 2. Running the Offline Pipeline CLI (Sprint 1 backward compatible)
```bash
cd backend
python main.py
```
This loads `data/protojson.json` and outputs `data/dashboard_data.json` locally.

#### 3. Starting the Frontend UI
```bash
cd frontend
npm install
npm run dev
```

---

## 5. Dashboard Workspaces & Capabilities

* **Interactive Topology Map**: Displays the attack path as a node-link diagram. Visual indicators represent vulnerability states. Hovering/clicking nodes lists ports, methods, payloads, and retrieved audit evidence.
* **VAPT Analyst Panel**: Shows patching instructions, copyable configuration files (like Nginx server blocks, parameterized queries, and safe JWT verification libraries), and generates executive summaries.
* **SOC SIEM Operations**: Contains a real-time console log, risk indices, Splunk search parameters, and Snort network signatures.
* **Ingest & Presets Manager**: Contains 3 threat templates (Web Exploitation, Active Directory lateral movements, and AWS cloud exfiltration) as well as direct drag-and-drop file upload.
* **Offline Sandbox Mode**: In the event that the Python backend is stopped, the frontend continues to operate via an identical Web Assembly/JavaScript fallback, ensuring demo-stability at all times.

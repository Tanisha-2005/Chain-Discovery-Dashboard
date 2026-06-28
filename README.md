# Chain Discovery Dashboard 🛡️
### Professional Cybersecurity VAPT & SOC Correlation System

Chain Discovery Dashboard is an interactive cybersecurity analysis dashboard that ingests raw vulnerability node datasets (ProtoJSON) and correlates them into actionable attack chains (directed graphs). It serves dual roles:
1. **VAPT Analyst Portal**: Reviewing security exploits, mapping threats to the MITRE ATT&CK matrix, and formulating remediation code patches.
2. **SOC Incident Responder Console**: Monitoring live simulated logs correlating to the attack path, inspecting SIEM Splunk queries, and capturing Snort NIDS rules.

---

## 1. System Architecture

The system is designed as a **6-stage deterministic pipeline** ensuring strict contract validation and threat enrichment:

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

### Core Pipeline Capabilities
* **Input Validation**: Deep validation on syntax, valid hosts/ports (1-65535), duplicate check, and error codes.
* **Brain Engine**: Dynamic rule-based correlation mapping nodes based on Kill Chain phases (Recon -> Exploit -> Privilege Esc -> Exfil).
* **Enrichment**: Full MITRE ATT&CK Technique attribution, customizable remediations, Splunk queries, and Snort rules.
* **Interface**: High-contrast React dashboard with interactive SVG attack graph visualizations, log stream terminal, and preset selectors.
* **API Layer**: FastAPI server hosting endpoints for running the pipeline, generating live SIEM logs, and serving presets.

---

## 2. Directory Layout

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

## 3. Setting Up & Running

### Prerequisites
* **Python 3.8+** (FastAPI and Uvicorn packages must be installed)
* **Node.js v16+** (For building the React frontend)

### Installation & Launch (Windows Auto-Start)
Simply double-click the **`run_dev.bat`** file in the root directory. This script will automatically:
1. Open a terminal window and launch the FastAPI server: `http://localhost:8000`
2. Open a second terminal window and run the Vite React app: `http://localhost:5173`

### Manual Execution

#### 1. Starting the Backend API Server
```bash
cd backend
python main.py --server
```
*(FastAPI Swagger Interactive documentation is available at `http://localhost:8000/docs`)*

#### 2. Running the Offline Pipeline CLI
```bash
cd backend
python main.py
```
This processes the security audit locally by loading `data/protojson.json` and generating `data/dashboard_data.json`.

#### 3. Starting the Frontend UI
```bash
cd frontend
npm install
npm run dev
```

---

## 4. Dashboard Workspaces & Capabilities

* **Interactive Topology Map**: Displays the attack path as a node-link diagram. Visual indicators represent vulnerability states. Hovering/clicking nodes lists ports, methods, payloads, and retrieved audit evidence.
* **VAPT Analyst Panel**: Shows patching instructions, copyable configuration files (like Nginx server blocks, parameterized queries, and safe JWT verification libraries), and generates executive summaries.
* **SOC SIEM Operations**: Contains a real-time console log, risk indices, Splunk search parameters, and Snort network signatures.
* **Ingest & Presets Manager**: Contains 3 threat templates (Web Exploitation, Active Directory lateral movements, and AWS cloud exfiltration) as well as direct drag-and-drop file upload.
* **Offline Sandbox Mode**: In the event that the Python backend is offline, the frontend continues to operate via an identical Web Assembly/JavaScript fallback, ensuring maximum stability.

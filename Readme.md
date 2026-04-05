# SentinelBench

**Detection quality benchmarking for Microsoft Sentinel — because "detected" is not the same as "detected in time."**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue)](https://python.org)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-v14-red)](https://attack.mitre.org)
[![Platform](https://img.shields.io/badge/SIEM-Microsoft%20Sentinel-0078D4)](https://azure.microsoft.com/en-us/products/microsoft-sentinel)

---

## The Problem

Most security teams assume their SIEM is working. They configure detection rules, watch the dashboard, and move on. But two questions almost nobody can answer with evidence are:

1. **Does Sentinel actually alert when a real attack technique runs?**
2. **If it does alert — how long did it take, and was the severity rating correct?**

A detection that fires 45 minutes after execution is operationally useless against a fast-moving attacker. A credential-dumping attempt logged as *Low* severity gets deprioritised by the analyst and never investigated. Both outcomes look like "working security" on paper. Neither is.

Commercial platforms like AttackIQ and Picus Security answer these questions — but they cost upwards of $30,000 per year and are designed for enterprise security teams. SentinelBench is an open-source alternative built around a single, precise workflow: **simulate, observe, measure, suggest**.

---

## What SentinelBench Does

SentinelBench executes safe, lab-isolated attack simulations drawn from Atomic Red Team, then queries the Microsoft Sentinel Log Analytics API to measure three things per technique:

| Metric | Description |
|--------|-------------|
| **Caught / Missed** | Did Sentinel fire any alert for this technique? |
| **Detection Latency** | How many seconds elapsed between technique execution and alert creation? |
| **Severity Accuracy** | Does the assigned severity match the ATT&CK-defined impact level of the technique? |

For every missed detection, SentinelBench generates a KQL (Kusto Query Language) detection rule seeded with the actual event data from the simulation run — not a generic template, but a rule that would have caught this specific execution on your specific log source configuration.

The results are visualised as an ATT&CK heatmap where colour encodes latency (not just binary pass/fail), giving a security team a continuous quality score rather than a compliance checkbox.

---

## Why Latency and Severity Matter More Than Coverage

Most detection validation tools report coverage: *n out of m techniques detected*. That framing treats all detections as equal. They are not.

Consider two SOC scenarios:

- **Scenario A**: A brute-force attempt (T1110.001) fires an alert 4 minutes after execution with severity *High*. The analyst investigates immediately, containment begins within 10 minutes.
- **Scenario B**: LSASS credential dumping (T1003.001) fires an alert 52 minutes after execution with severity *Informational*. The analyst queues it for end-of-day review. By then, the attacker has harvested credentials and established persistence on three additional hosts.

Both scenarios score as "detected" on a coverage report. Only one reflects a security posture that would contain a real incident. SentinelBench measures the difference.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        Lab Environment                       │
│                  (Windows VM — isolated network)             │
│                                                              │
│   ┌──────────────────────────────────────────────────────┐  │
│   │          Simulation Engine (Python + PowerShell)     │  │
│   │   Atomic Red Team atomic executes technique T-XXXX   │  │
│   │   Records: technique ID, timestamp_exec, host info   │  │
│   └────────────────────┬─────────────────────────────────┘  │
│                        │ Windows Event logs                  │
│                        ▼                                     │
│   ┌──────────────────────────────────────────────────────┐  │
│   │         Microsoft Sentinel (Log Analytics)           │  │
│   │   Ingests: SecurityEvent, Sysmon, MDE telemetry      │  │
│   └────────────────────┬─────────────────────────────────┘  │
└────────────────────────┼────────────────────────────────────┘
                         │ Log Analytics REST API
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                    SentinelBench Core                        │
│                                                              │
│  ┌─────────────────┐    ┌──────────────────────────────┐   │
│  │  Alert Observer │    │   Metrics Engine              │   │
│  │                 │    │                               │   │
│  │  Polls Sentinel │    │  • Caught / Missed flag       │   │
│  │  API at T+0,    │───▶│  • Latency = T_alert - T_exec │   │
│  │  T+2, T+5,      │    │  • Severity delta vs ATT&CK   │   │
│  │  T+10 minutes   │    │    expected impact            │   │
│  └─────────────────┘    └──────────────┬───────────────┘   │
│                                         │                    │
│  ┌──────────────────────────────────────▼───────────────┐   │
│  │               KQL Suggestion Engine                   │   │
│  │                                                       │   │
│  │  Only fires on missed detections                      │   │
│  │  Pulls raw logs (EventID, process name, cmdline,      │   │
│  │  parent process) from the simulation window           │   │
│  │  Generates targeted KQL using event-seeded templates  │   │
│  │  Tags each rule with: ATT&CK ID, data source,        │   │
│  │  confidence level, and false-positive risk note       │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                              │
│  ┌──────────────────────────────────────────────────────┐   │
│  │                  SQLite Result Store                  │   │
│  │  run_id · technique_id · timestamp_exec · latency_s  │   │
│  │  caught · severity_assigned · severity_expected ·    │   │
│  │  kql_suggestion · raw_log_sample                     │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│                   Dashboard  (React + D3.js)                 │
│                                                              │
│   View 1 — ATT&CK Heatmap                                   │
│   Colour encodes latency gradient (green → amber → red)     │
│   Grey = not covered in v1 scope                            │
│                                                              │
│   View 2 — Run History Table                                 │
│   Per-technique: result, latency (s), severity match, date  │
│                                                              │
│   View 3 — Remediation Panel                                 │
│   Missed detections only, with generated KQL + copy button  │
└─────────────────────────────────────────────────────────────┘
```

---

## Techniques Covered in v1

SentinelBench v1 covers **15 techniques** across four tactics chosen for high prevalence in real incident investigations and high variance in Sentinel's default detection coverage.

### Execution — 3 techniques

| ATT&CK ID | Technique | Why included |
|-----------|-----------|--------------|
| T1059.001 | PowerShell | Most common execution vector in enterprise environments; Sentinel's PowerShell alerting is highly configuration-dependent |
| T1059.003 | Windows Command Shell | Baseline; validates event log ingestion is functioning correctly |
| T1569.002 | Service Execution | Frequently used for persistence payloads; lower-profile than PowerShell in most rule sets |

### Persistence — 3 techniques

| ATT&CK ID | Technique | Why included |
|-----------|-----------|--------------|
| T1547.001 | Registry Run Keys / Startup Folder | Extremely common; many Sentinel environments have this rule but with high false-positive suppression that inadvertently hides real activity |
| T1053.005 | Scheduled Task/Job | High-impact persistence mechanism with significant latency variation across Sentinel configurations |
| T1136.001 | Create Local Account | Simple, high-signal technique; useful as a calibration baseline for the metrics engine |

### Credential Access — 5 techniques

| ATT&CK ID | Technique | Why included |
|-----------|-----------|--------------|
| T1003.001 | LSASS Memory | The highest-impact credential dumping technique; latency here has the most direct operational consequence |
| T1110.001 | Brute Force — Password Guessing | Tests whether Sentinel's failed-login correlation is active and correctly thresholded |
| T1552.001 | Credentials in Files | Tests file-access telemetry; frequently blind spot in Sentinel deployments without MDE integration |
| T1555.003 | Credentials from Web Browsers | Low severity by default in most rule sets despite high attacker value; severity accuracy test |
| T1040 | Network Sniffing | Tests whether network telemetry is flowing; often reveals gaps in log source configuration |

### Defense Evasion — 4 techniques

| ATT&CK ID | Technique | Why included |
|-----------|-----------|--------------|
| T1070.001 | Clear Windows Event Logs | Meta-technique: if an attacker runs this and Sentinel doesn't alert, all subsequent detections in that window are compromised |
| T1562.001 | Disable or Modify Tools (AV) | Tests whether Defender for Endpoint telemetry is correctly forwarded to Sentinel |
| T1027 | Obfuscated Files or Information | Tests behaviour-based vs signature-based detection; reveals over-reliance on static rules |
| T1112 | Modify Registry | High false-positive volume technique; useful for testing whether severity suppression is misconfigured |

---

## Metrics Reference

### Detection Latency

Latency is measured as the elapsed time in seconds between `timestamp_exec` (when the Atomic Red Team script triggers the technique) and `timestamp_alert` (when the first matching Sentinel incident or alert is created, as returned by the Log Analytics API).

SentinelBench polls the API at four checkpoints: T+2min, T+5min, T+10min, and T+15min. If no alert is found by T+15min, the technique is recorded as **Missed**.

Latency thresholds used in the heatmap colour encoding:

| Latency | Colour | Operational interpretation |
|---------|--------|---------------------------|
| < 3 minutes | Green | Detection is operationally effective |
| 3–10 minutes | Amber | Detection exists but response window is narrow |
| > 10 minutes | Red | Detection is present but unlikely to prevent attacker progress |
| No alert | Dark red | Detection gap — KQL suggestion generated |

### Severity Accuracy

Each ATT&CK technique has a documented impact level based on MITRE's own data source characterisation and community-validated severity assignments. SentinelBench compares the severity Sentinel assigned to the triggered alert against the expected severity for that technique.

A **severity delta** of +1 or more (e.g., Sentinel fires *Low* for a technique with expected impact *High*) is flagged as a severity miscalibration and highlighted in the remediation panel alongside the KQL suggestion.

### KQL Suggestion Quality

Generated KQL rules are tagged with a confidence level:

- **High confidence** — Rule is seeded directly from observed EventIDs and process names in the simulation window; low false-positive risk
- **Medium confidence** — Rule uses technique-class heuristics; requires review before production deployment
- **Requires tuning** — Template generated but relies on environment-specific data (e.g., username patterns, IP ranges); manual adjustment needed before use

All generated rules include inline comments explaining the detection logic and a false-positive risk note.

---

## Setup

### Prerequisites

- Windows 10/11 VM (isolated, no production network connectivity)
- Microsoft Sentinel workspace with Log Analytics
- Azure AD App Registration with **Log Analytics Reader** role
- [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) installed on the lab VM
- Python 3.10+
- Node 18+ (for the dashboard)

### Environment Variables

```bash
SENTINEL_WORKSPACE_ID=your-workspace-id
SENTINEL_CLIENT_ID=your-app-registration-client-id
SENTINEL_CLIENT_SECRET=your-client-secret
SENTINEL_TENANT_ID=your-tenant-id
POLL_INTERVAL_MINUTES=2
MAX_WAIT_MINUTES=15
```

### Install & Run

```bash
# Clone the repo
git clone https://github.com/DivyTR/sentinelbench
cd sentinelbench

# Install Python dependencies
pip install -r requirements.txt

# Run a single technique test
python sentinelbench.py --technique T1003.001

# Run the full v1 suite (all 15 techniques)
python sentinelbench.py --suite v1

# Start the dashboard
cd dashboard && npm install && npm run dev
```

---

## Limitations

These are not weaknesses to apologise for — they are the honest boundary conditions of v1. Understanding them is part of using the tool correctly.

**1. Lab environment only — not production safe.**
Atomic Red Team simulations write registry keys, create local accounts, attempt LSASS reads, and perform other actions that would be immediately disruptive in a production environment. SentinelBench is designed exclusively for isolated lab VMs. Running it against production infrastructure is outside its intended use and could cause genuine harm.

**2. Sentinel ingestion lag is not isolated.**
Latency measurements include Microsoft's own log ingestion pipeline, which adds a variable 1–3 minute lag between event generation and Log Analytics availability. This is labelled in all latency outputs and does not affect caught/missed accuracy, but means sub-5-minute latency measurements should be interpreted with awareness of this baseline.

**3. KQL suggestions are starting points, not production rules.**
Generated rules are seeded with real event data from your lab environment but are not hardened against false positives in a production environment. Every generated rule must be reviewed, tested, and tuned before deployment. SentinelBench deliberately labels rule confidence and flags tuning requirements — it is a detection engineering accelerator, not an autonomous rule deployer.

**4. 15 techniques is not comprehensive coverage.**
MITRE ATT&CK v14 documents 600+ (sub-)techniques. SentinelBench v1 covers 15. It is a focused quality benchmark, not a full coverage audit. The techniques were selected for prevalence and detection variance, not completeness.

**5. Windows-only in v1.**
All simulations target Windows endpoints. Linux, macOS, and cloud-native attack paths (e.g., T1078.004 — Valid Accounts: Cloud Accounts) are out of scope for v1.

---

## Roadmap

| Version | Focus |
|---------|-------|
| **v1 (current)** | 15 Windows techniques · Sentinel integration · Latency + severity metrics · KQL suggestions for missed detections · ATT&CK heatmap dashboard |
| **v2** | Expand to 50 techniques · Add Linux endpoint support · Severity calibration scoring across full run history · Multi-run trend analysis (is coverage improving over time?) |
| **v3** | LLM-assisted KQL rule improvement · Natural language explanation of each detection gap for non-technical stakeholders · Export to PDF report |

---

## Why I Built This

I work as a SOC Analyst at TCS, monitoring enterprise environments daily using Microsoft Sentinel and Defender XDR. The question I kept returning to was simple: *the rules are deployed, but how do I know they actually work?*

Most validation in real SOC environments is reactive — you discover a rule was broken or misconfigured after a real incident surfaces the gap. SentinelBench is my attempt to make that validation proactive, evidence-based, and repeatable.

The latency and severity accuracy dimensions emerged from direct incident response experience: two incidents where detections fired, but either too late or at too low a severity to drive the right response. Both outcomes look like working security from the outside. Neither contained the threat.

---

## Author

**Divyansh Tripathi** — Cyber Security Analyst · TCS · PJPT Certified  
[linkedin.com/in/divyansh-tripathi](https://linkedin.com/in/divyansh-tripathi) · [github.com/DivyTR](https://github.com/DivyTR)

---

## License

MIT License — see [LICENSE](LICENSE) for details.

> **Responsible use**: SentinelBench is designed for use in isolated lab environments against infrastructure you own and are authorised to test. Never run attack simulations against systems you do not own or have explicit written permission to test.

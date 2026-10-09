# SentinelBench

**Detection quality benchmarking for Microsoft Sentinel — because "detected" is not the same as "detected in time."**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue)](https://python.org)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-v19-red)](https://attack.mitre.org)
[![Platform](https://img.shields.io/badge/SIEM-Microsoft%20Sentinel-0078D4)](https://azure.microsoft.com/en-us/products/microsoft-sentinel)

---

## The Problem

Most security teams assume their SIEM is working. They configure detection rules, watch the dashboard, and move on. But two questions almost nobody can answer with evidence are:

1. **Does Sentinel actually alert when a real attack technique runs?**
2. **If it does alert — how long did it take, and was the severity rating appropriate?**

A detection that fires 45 minutes after execution is operationally useless against a fast-moving attacker. A credential-dumping attempt logged as *Low* severity gets deprioritised by the analyst and never investigated. Both outcomes look like "working security" on paper. Neither is.

Commercial breach-and-attack-simulation platforms answer these questions but cost upwards of $30,000 per year. SentinelBench is an open-source take on the same workflow for a single SIEM, built around four steps: **simulate, observe, measure, suggest.**

---

## Project status

This is an active build, developed in phases. It runs against a real Azure Sentinel lab, not just in theory.

| Phase | What | State |
|---|---|---|
| 0 | Correct measurement engine, pinned ART tests, unit tests, CI | **done** |
| 1 | Reproducible Azure lab as Terraform (workspace, Sentinel, monitored Windows VM, cost guardrails) | **done** |
| 2 | Measurement runs against real Sentinel — config A (no rules) and config B (built-in rules) | **in progress** |
| 3 | Closed loop — generate rules for the gaps, deploy, re-measure; published results write-up | planned |

Final coverage/latency numbers are deliberately **not** published in this README yet; they are being collected and will be added with the methodology that produced them. The measurement engine and its integrity rules (below) are the part that is settled.

---

## Why latency and severity, not just coverage

Most detection-validation tools report coverage: *n of m techniques detected*. That framing treats all detections as equal. They are not. A rule that fires an hour late, or at a severity an analyst will deprioritise, counts as a "pass" on a coverage report and as a failure in a real incident. SentinelBench measures the difference: for every technique it records **caught/missed, detection latency, and severity accuracy**, and colour-codes the ATT&CK heatmap by latency rather than a binary pass/fail.

---

## How it works

```
 ┌───────────────────────────── Azure lab (infra/, Terraform) ─────────────────────────────┐
 │                                                                                          │
 │   Windows Server 2022 VM                         Log Analytics workspace + Sentinel      │
 │   ├─ Sysmon (pinned config)                      ├─ SecurityEvent  (Security log)        │
 │   ├─ Azure Monitor Agent  ──── DCRs ───────────▶ └─ Event          (Sysmon, PowerShell   │
 │   ├─ Atomic Red Team (pinned commit, by GUID)                       4104, Defender, Sys) │
 │   ├─ Python + SentinelBench                                                              │
 │   └─ system-assigned identity ─ Log Analytics Reader ─▶ (no secrets anywhere)            │
 │                                                                                          │
 └──────────────────────────────────────────┬───────────────────────────────────────────────┘
                                             │  Log Analytics REST API (managed identity)
                                             ▼
 ┌──────────────────────────────── SentinelBench (runs on the VM) ──────────────────────────┐
 │  SimulationRunner   run the pinned ART test for a technique; confirm it actually executed │
 │  MetricsEngine      poll at T+2/5/10/15 min; record caught / latency / severity           │
 │  SentinelClient     query Sentinel; match alerts to the technique (see Measurement)       │
 │  KQLGenerator       for a miss, emit a candidate detection rule                            │
 │  SQLite store       one row per technique per run                                          │
 └──────────────────────────────────────────┬───────────────────────────────────────────────┘
                                             ▼
 ┌──────────────────────────────── Dashboard (React + D3.js + FastAPI) ─────────────────────┐
 │  ATT&CK heatmap (colour = latency) · run history · remediation panel (gaps + generated KQL)│
 └──────────────────────────────────────────────────────────────────────────────────────────┘
```

The lab is built entirely by Terraform in [`infra/`](infra/README.md), so anyone can reproduce it with one `terraform apply`. SentinelBench authenticates with the VM's managed identity (Log Analytics Reader), so no client secret exists in the project.

---

## Measurement: what counts as a detection

Matching a simulated technique to a real Sentinel detection is harder than it looks, and getting it wrong produces impressive-but-false numbers. These rules are what make the results trustworthy; several were added after an early run reported ~80% coverage that turned out to be measurement artifacts.

- **Match the rule's declared ATT&CK mapping, never the captured event.** A detection counts for technique *X* only if the alert's `Techniques` column lists *X*. SentinelBench never extracts technique IDs from `ExtendedProperties` or entity text — those contain the triggering command line, and every technique is launched by a harness command that names it (`Invoke-AtomicTest T1552.001 …`), so reading them would credit a rule with "detecting" its own invocation.
- **Breadth guard against catch-all rules.** Some Microsoft rules are mapped to dozens of techniques (the "Powershell Empire Cmdlets" rule is tagged with **51**). One such rule firing is a generic "suspicious toolkit" alert, not a specific detection, so an alert whose mapping lists more than a threshold number of techniques is ignored for attribution. Specific rules, and the single-technique rules SentinelBench generates, pass.
- **Exact technique-ID match**, including the parent technique, never substring (`has "T1059"` would wrongly match `T1059.003`).
- **Checkpoint-bounded polling.** Each poll considers only alerts created up to its own checkpoint, so a slow, paused, or resumed run can never backfill a late alert as an in-time detection.
- **Host-scoped.** Alerts must name the lab host, so unrelated workspace activity is ignored.
- **"Missed" means no qualifying rule fired — not "no telemetry."** The simulation's own events are confirmed present in the workspace, so a miss is a detection gap, not a plumbing failure.

### Experiment design

Benchmarking a brand-new workspace is uninteresting (it has no rules, so everything misses). SentinelBench compares configurations:

- **Config A — control:** empty workspace, no analytics rules. Confirms the pipeline and establishes the floor (everything missed).
- **Config B — built-in rules:** Microsoft's Windows Security Events analytics rules enabled at 5-minute frequency, to measure what the out-of-box detection *logic* catches, decoupled from Sentinel's default (hourly-to-daily) rule cadence.
- **Config C — closed loop (planned):** SentinelBench generates rules for config B's gaps, deploys them, and re-measures to show the gaps close.

---

## Techniques covered

SentinelBench v1 covers **15 techniques** across five ATT&CK v19 tactics, chosen for prevalence in real investigations and for variance in Sentinel's default coverage.

Each technique is pinned to **one specific Atomic Red Team test by GUID** (`art_guid` in `core/simulation_runner.py`), so every run executes exactly the same procedure. Test *numbers* are not used: they shift between ART releases, and test #1 is often a Linux or macOS test that `Invoke-AtomicTest` silently skips on Windows. SentinelBench also checks ART's output to confirm a test actually executed, rather than trusting the exit code.

Two notes on IDs:
- SentinelBench uses **ATT&CK v19** IDs and tactics. v19 split the old Defense Evasion tactic into **Stealth** (TA0005) and **Defense Impairment** (TA0112), and revoked *Clear Windows Event Logs* (T1070.001 → T1685.005) and *Disable or Modify Tools* (T1562.001 → T1685). Sentinel content written before v19 still tags the old IDs, so alert matching accepts both.
- Every upstream Windows test for T1110.001 needs Active Directory, so v1 uses a custom atomic in [`atomics/T1110.001`](atomics/T1110.001/T1110.001.yaml) that generates failed logons against a standing local account via the `LogonUser` API.

| Tactic | Techniques |
|---|---|
| Execution | T1059.001 PowerShell · T1059.003 Windows Command Shell · T1569.002 Service Execution |
| Persistence | T1547.001 Registry Run Keys · T1053.005 Scheduled Task · T1136.001 Create Local Account |
| Credential Access | T1003.001 LSASS Memory · T1110.001 Brute Force · T1552.001 Credentials in Files · T1555.003 Browser Credentials · T1040 Network Sniffing |
| Stealth | T1027 Obfuscated Files or Information |
| Defense Impairment | T1685.005 Clear Event Logs · T1685 Disable/Modify Tools · T1112 Modify Registry |

The suite runs defence-tampering techniques last (T1685 then T1685.005), so stopping Defender or clearing logs can't affect the measurement of any earlier technique.

---

## Metrics reference

### Detection latency

Elapsed seconds between `timestamp_exec` (taken immediately before the ART test executes, after prerequisites) and the creation time of the first qualifying alert. Polls run at T+2/5/10/15 min; nothing by the cutoff is a **miss**. The cutoff is configurable with `--max-wait` (e.g. `--max-wait 3` for a control run where every technique misses anyway).

| Latency | Band | Interpretation |
|---|---|---|
| < 3 min | Green | Operationally effective |
| 3–10 min | Amber | Narrow response window |
| > 10 min | Red | Unlikely to prevent attacker progress |
| No alert | Missed | Detection gap — KQL suggestion generated |

Latency includes Microsoft's ingestion lag (typically 1–3 min); interpret sub-5-minute values with that floor in mind.

### Severity accuracy

MITRE ATT&CK does not assign severities to techniques. The expected severity (`severity_expected` in `core/simulation_runner.py`) is SentinelBench's own rubric, based on a technique's position in an intrusion and its impact if missed. The tool compares Sentinel's assigned severity against that rubric, so severity results mean "does Sentinel agree with this rubric," not ground truth. A positive delta (Sentinel rated it lower than expected) is flagged as a miscalibration.

### KQL suggestions

For a miss, SentinelBench emits a candidate rule tagged with a confidence level (`high` / `medium` / `requires_tuning`), its data source, and a false-positive note. Rules are currently per-technique templates; seeding them from the event data observed during the run (via `core/evidence.py`, which separates the technique's own processes from harness and background noise) is implemented for PowerShell and the generic fallback, with per-technique seeding in progress. Every generated rule is a starting point for a detection engineer, not a production rule.

---

## Setup

The recommended path is the Terraform lab in [`infra/`](infra/README.md): one `terraform apply` builds the workspace, Sentinel onboarding, a monitored Windows VM with Sysmon and Atomic Red Team, and cost guardrails (ingestion cap, budget alerts, VM auto-shutdown). The lab README has the full run-through, including enabling config B's analytics rules.

### Run

```bash
# one technique (fast feedback)
python sentinelbench.py --technique T1059.003

# the full 15-technique suite
python sentinelbench.py --suite v1

# a baseline/control run with a short cutoff (everything misses anyway)
python sentinelbench.py --suite v1 --max-wait 3

# review a run
python sentinelbench.py --history 5
python sentinelbench.py --run-id <id> --show-results
python sentinelbench.py --run-id <id> --show-kql

# dashboard
cd dashboard && npm install && npm run dev
```

`SENTINEL_AUTH` selects how the tool reaches Log Analytics: `managed_identity` (the lab VM), `azure_cli` (your `az login`), or `client_secret` (an app registration). See [`.env.example`](.env.example).

---

## Development

```bash
pip install -r requirements-dev.txt
ruff check .
pytest -q
```

The test suite runs without Azure or Windows: the Log Analytics client, PowerShell, and the clock are replaced with fakes, so the matching logic, timing, and ATT&CK handling are all unit-tested (including regressions for each measurement bug found in real runs). CI runs lint, the Python tests, a dashboard build, and `terraform validate` on every push.

---

## Limitations

These are the honest boundary conditions of v1 — several discovered by running the tool and distrusting a result that looked too good.

1. **Lab only — not production safe.** ART simulations write registry keys, create accounts, attempt LSASS reads, and clear logs. Run only in an isolated lab you own.
2. **Ingestion lag is included in latency.** Microsoft's pipeline adds a variable 1–3 min between event and query availability; it is a floor on measured latency, not a measurement error.
3. **Logs-only deployment.** The lab collects Windows Security Events and Sysmon, not Defender XDR / MDE. Many built-in Sentinel rules require those connectors and therefore cannot fire here — which is itself a realistic finding about "Windows logs only" deployments, but it bounds what config B can detect.
4. **Simulation fidelity shapes detectability.** A detection can miss because the rule is absent *or* because the simulation doesn't reproduce the exact signal the rule keys on. Known examples: the brute-force test generates 4625 (type 3) events via a local API call with **no source IP**, so rules that correlate failures per source IP do not fire; and T1136.001's account is removed by ART's own cleanup, so whether a "created-and-deleted-within-10-min" rule catches it depends on cleanup timing rather than the creation itself. Both are documented per run.
5. **Severity is a rubric, not ground truth** (see Metrics).
6. **Defender may pre-empt a technique.** Real-time protection can block e.g. the LSASS dump before it completes, changing what telemetry (and which detection) is possible.
7. **15 techniques, Windows only.** A focused quality benchmark, not a coverage audit; Linux/macOS/cloud are out of scope for v1.

---

## Roadmap

| Version | Focus |
|---|---|
| **v1 (current)** | 15 Windows techniques · reproducible Terraform lab · correct measurement engine with integrity guards · config A/B experiment · KQL suggestions for gaps · heatmap dashboard |
| **v2** | Config C closed loop (generate → deploy → re-measure) · event-seeded KQL for all techniques · repeated runs with variance · published results and methodology write-up |
| **v3** | Expand technique set and tactics · Linux endpoint support · multi-run trend analysis · PDF/stakeholder reporting |

---

## Why I built this

I work as a SOC Analyst at TCS, monitoring enterprise environments with Microsoft Sentinel and Defender XDR. The question I kept returning to was simple: *the rules are deployed, but how do I know they actually work?*

Most validation in real SOCs is reactive — you find a broken or misconfigured rule after an incident surfaces the gap. SentinelBench is my attempt to make that validation proactive, evidence-based, and repeatable. The latency and severity dimensions came from direct incident response: detections that fired, but too late or too quietly to drive the right response. Both look like working security from the outside. Neither contained the threat.

---

## Author

**Divyansh Tripathi** — Cyber Security Analyst · TCS · PJPT Certified
[linkedin.com/in/divyansh-tripathi](https://linkedin.com/in/divyansh-tripathi) · [github.com/DivyTR](https://github.com/DivyTR)

---

## License

MIT License — see [LICENSE](LICENSE) for details.

> **Responsible use**: SentinelBench is for use in isolated lab environments against infrastructure you own and are authorised to test. Never run attack simulations against systems you do not own or have explicit written permission to test.

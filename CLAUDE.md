# SentinelBench — working context

> Cross-session memory for Claude Code. Keep this accurate and current. The
> "Status" and "Next" sections are the live state; update them as work lands.
> Last updated: **2026-10-10** (commit `063719b`).

## What this project is

Detection-quality benchmarking for Microsoft Sentinel. It executes pinned
Atomic Red Team techniques on a lab VM, then measures whether Sentinel's
analytics rules actually fire, how fast, and at what severity — and for the
misses, generates candidate KQL detection rules seeded from the technique's
real telemetry.

Owner is a SOC analyst (Microsoft Sentinel + Defender XDR at TCS). This is a
portfolio project for a Masters-in-cybersecurity application (Germany, Oct 2027
intake) and a job switch. **The entire value of the project is honesty of
measurement** — it exists to answer "the rules are deployed, but do they
actually work?" An inflated number destroys the point. User preference,
reinforced everywhere: brutal honesty, no flattery, no fabricated data.

## The central invariant — do not regress

An earlier version reported **12/15 caught** for config B. That was false,
caused by three bugs. The honest number is **~2/15**. The fixes, which must be
preserved:

1. **Match alerts on the declared `Techniques` column only** — never `Tactics`
   (holds tactic names, never technique IDs) and never `ExtendedProperties` /
   event text (the ART harness command line contains the technique ID, e.g.
   `Invoke-AtomicTest T1552.001 ...`, which falsely credited one broadly-firing
   rule as a detection for a dozen techniques). See `check_alert_for_technique`.
2. **Breadth guard** — ignore any rule tagged with more than
   `MAX_ALERT_TECHNIQUES` (= 8) techniques. The Empire-cmdlet built-in rule is
   tagged with 51 techniques; it's a catch-all, not a per-technique detection.
3. **Standing brute-force account** — the custom T1110.001 atomic uses a
   standing local account with no create/delete churn, so account-lifecycle
   rules don't get miscredited to brute force.

These are locked by tests in `tests/test_sentinel_client.py`. If a change
makes the caught count jump, suspect a regression here first.

## Architecture

- `sentinelbench.py` — CLI orchestrator. `--suite v1`, `--technique <ID>`,
  `--max-wait <min>` (use a small value for all-missed control runs),
  `--dry-run`, `--history`, `--show-kql`/`--show-results` with `--run-id`.
- `core/simulation_runner.py` — `TECHNIQUES` registry (15 techniques, each
  pinned to an ART `auto_generated_guid`, not a test number). Runs
  `Invoke-AtomicTest`; kills the whole process tree on timeout (taskkill /T on
  Windows). `V1_SUITE_ORDER` runs defence-tampering last.
- `core/sentinel_client.py` — Log Analytics query API. Auth modes: managed
  identity (default on the VM, via IMDS), azure_cli, client_secret.
  `check_alert_for_technique` (the invariant above), `fetch_raw_logs`,
  `collect_evidence`. `TECHNIQUE_EVENT_HINTS` maps technique → EventIDs/table.
- `core/metrics_engine.py` — polls at **T+2/5/10/15 min** from exec time (not
  call time); records caught/missed, latency, severity delta. Each poll only
  considers alerts created up to its checkpoint, so late polling can't
  mis-credit or mis-time a catch.
- `core/evidence.py` — **process-lineage attribution.** Walks the parent/child
  PID tree down from the execution-step launcher (found by the pinned ART GUID,
  excluding -GetPrereqs/-CheckPrereqs/-Cleanup) to isolate the technique's own
  processes from the ART harness (hostname/whoami), console plumbing (conhost),
  and background noise (Edge/WMI). This is what lets generated rules key on the
  real technique instead of the Invoke-AtomicTest wrapper.
- `core/kql_generator.py` — per-technique + generic rule templates, seeded via
  `_extract_field` from the attributed evidence rows.
- `core/db.py` — SQLite results storage.
- `infra/terraform/` — lab IaC (resource group, VNet, Windows VM, Log Analytics
  workspace, DCRs, optional Sentinel onboarding gated on `enable_sentinel`).
- `infra/scripts/bootstrap.ps1.tftpl` — VM bootstrap: audit policy, pinned
  Sysmon, pinned ART, Python, SentinelBench, provenance.json. Uses `$SbRoot`
  (not `$Root`, which collides with the ART module's own variable).
- `atomics/T1110.001/` — custom brute-force atomic (standing account via
  `LogonUser` type-3 failures; no AD required; no cleanup).

## Experiment design

- **Config A — control:** empty workspace, no rules. Floor; everything missed.
- **Config B — built-in rules:** Microsoft's Windows Security Events analytics
  rules enabled at 5-min frequency. Measures the detection *logic*, decoupled
  from Sentinel's slow default cadence. **Honest result ≈ 2/15.**
- **Config C — closed loop (NOT BUILT YET):** generate rules for config B's
  gaps, deploy as `[SB-C]` scheduled rules, re-measure, show the gaps close.
  This is the project's headline claim and currently vaporware.

## Honest limitations (already documented in README §Limitations)

- Brute-force (T1110.001) generates 4625 type-3 events with **no source IP**
  (local `LogonUser` call), so rules correlating failures per source IP can't
  fire. Real miss, not a tool bug.
- T1136.001's account is removed by ART cleanup, so a "created-and-deleted"
  rule catching it depends on cleanup timing, not creation.
- **Logs-only lab:** Windows Security Events + Sysmon, no Defender XDR / MDE.
  Many built-in rules need those connectors and can't fire here — itself a
  realistic finding about "Windows-logs-only" deployments, but it bounds B.

## Lab / Azure specifics (for re-acquiring the environment)

- Resource group `rg-sbench-lab`, VM `vm-sbench`.
- Region and VM size live in the user's **local, gitignored** `*.tfvars`
  (not in the repo). From session history: region `centralindia`, size
  `Standard_B2s_v2` (the committed default `Standard_B2s` hit SkuNotAvailable).
  Recover exact values with `az vm show -g rg-sbench-lab -n vm-sbench`.
- Workspace GUID is a terraform output / stored in the VM's SentinelBench env;
  the Log Analytics query CLI needs the **GUID**, not the workspace name.
- Start/stop: `az vm start -g rg-sbench-lab -n vm-sbench` /
  `az vm deallocate -g rg-sbench-lab -n vm-sbench`.
- On the VM, SentinelBench runs under **managed identity** — no stored
  credentials. **Never paste secrets (admin passwords, tokens) into chat.**
- **The VM has no git, and `C:\SentinelBench\app` is a ZIP extract, not a
  clone.** The bootstrap installs SentinelBench by downloading
  `github.com/DivyTR/SentinelBench/archive/refs/heads/<branch>.zip` (public
  repo) and extracting it — so `git pull` does NOT work on the VM. To update
  the VM to new commits, re-download and extract that ZIP into `app\`,
  preserving `app\.env` (workspace ID + auth) and `app\sentinelbench.db` (run
  history). Verify the swap with `Test-Path app\CLAUDE.md` + a `Select-String`
  for a known-new symbol. Python *is* on PATH (installer added it); git is not.

## Status (2026-10-10)

- Measurement integrity: **done** (commits through `15ce396`). The ~2/15 honest
  result was validated by a manual cross-check query.
- README rewrite to match reality: **done** (`4ceeceb`).
- Evidence-lineage wiring into the pipeline: **infrastructure done** (`063719b`),
  127 tests pass. Verified on live Sentinel (smoke test, run 5f8b3244):
  `collect_evidence` runs without error and attributed rows reach the
  generators. **BUT only 2/10 generators consume them** — `_gen_T1059_001`
  (PowerShell) and `_generic_generator` use `_extract_field`; the other 8
  per-technique generators (T1059.003, T1569.002, T1547.001, T1053.005,
  T1136.001, T1003.001, T1110.001, T1685.005) emit sound but **static**
  behavioral templates that ignore `raw_logs`. So "rules seeded from real
  telemetry" is true for a subset, not all. Widening consumption is config-C
  work and can be applied **retroactively** to a run's stored `raw_logs`
  (no VM re-run needed). The README already states this honestly
  ("per-technique seeding in progress").
- **Clean config B re-run with the current tool: NOT done.** This is the
  immediate next action. It produces correct per-technique catches/latencies
  and the KQL suggestions for the gaps, which are config C's input.
- Config C deployer: **not built.**
- Alert suppression (rules re-fired ~170× across a run): **not done**; fold
  into the config C deployer (scheduled-rule `suppressionDuration`).

## Next

1. **(user, VM)** Update the VM's code via ZIP re-download (no git on the VM —
   see Lab specifics). Confirm `[SB-B]` built-in rules
   are enabled. **Smoke test first:** `python sentinelbench.py --technique
   T1059.003 --max-wait 3` — the evidence code has never run against live
   Sentinel, so this catches a KQL runtime error cheaply before the long run.
2. **(user, VM, ~3.4h unattended)** Full config B re-run:
   `python sentinelbench.py --suite v1 --notes "config B, evidence wiring"`.
3. **(together)** Analyze results (expect ~2–3/15); confirm which rules fired
   and why.
4. **(Claude, parallel to the run)** Two pure-Python, no-VM tasks, either order:
   (a) Build the config C rule deployer: ARM REST
   `Microsoft.SecurityInsights/alertRules` (new token scope vs. the query API),
   dry-run-able, with alert suppression, `[SB-C]` tagging, tests.
   (b) Widen evidence consumption beyond the 2/10 generators so more rules are
   actually seeded from `raw_logs` (apply retroactively to the config B run's
   stored evidence). (b) directly strengthens the headline claim; (a) is the
   bigger vaporware→real lever.
5. **(together)** Config C: deploy generated rules for the gaps, re-measure,
   show gaps close, produce the A/B/C comparison and a results write-up.
6. **Later:** resume-bullet rewrite; decide whether this CLAUDE.md is kept when
   the branch is merged to main (it's working memory, not necessarily a
   shipped artifact).

## Conventions

- Work on branch `claude/pensive-bohr-nxf0zf`. Don't push elsewhere without
  explicit permission.
- `python -m ruff check . && python -m pytest -q` must pass before commit.
  ruff pinned to `0.16.10` (two binaries exist on some machines; use the
  pinned one). Config in `pyproject.toml`.
- Commits end with the `Co-Authored-By` / `Claude-Session` footer.
- Don't open a PR unless the user asks.

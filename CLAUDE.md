# SentinelBench — working context

> Cross-session memory for Claude Code. Keep this accurate and current. The
> "Status" and "Next" sections are the live state; update them as work lands.
> Last updated: **2026-10-11**. If a fresh session is picking this up: read
> "Status" and "Next" first — they are authoritative over any older phrasing
> elsewhere in this file. Config A/B/C are all real now (config C deployed and
> measured); the project is in the **results + write-up** phase.

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
caused by three bugs. The honest number is **1-2/15** (measured 1/15 in run
c5ba877d; T1136.001 is timing-variable, so a run can show 2). The fixes, which
must be preserved:

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
- `core/kql_generator.py` — per-technique + generic **behavioral** rule
  templates. Evidence is used to *ground* a rule (a `// Lab evidence` comment
  via `_evidence_grounding`) but deliberately NOT seeded into detection logic
  — ART's lab artifacts (test service/task/account names, harness-parented
  processes) would overfit the rule. Decision recorded 2026-10-10 ("option A").
- `core/rule_deployer.py` — config C **deploy** step. Pushes generated rules
  into Sentinel as `[SB-C]` scheduled analytics rules via the **ARM** API
  (`management.azure.com` — a different token audience, and the workspace's ARM
  path: subscription/RG/**name**, not the query GUID). Dry-run by default;
  `deploy_run(run_id)`, `teardown()`, `list_sb_rules()`. **Suppression OFF by
  default** (`suppress=True` for production) — PT5H suppression corrupts
  cross-run measurement; see Status. Rule payload sets a tactic per technique
  (ARM requires it) and the parent technique id for crediting. CLI:
  `--deploy-config-c --run-id <id> [--apply]`, `--teardown-config-c [--apply]`
  (preview unless `--apply`). Also `--regenerate-kql --run-id <id>` rewrites a
  run's stored suggestions with the current generator (deploy reads stored KQL,
  so generator fixes need this to reach an existing run). Self-contained ARM
  auth (deliberate copy of the 3 modes, not shared with SentinelClient).
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
  from Sentinel's slow default cadence. **Measured: 1/15** (run c5ba877d;
  ~1-2/15 given T1136.001 timing variance).
- **Config C — closed loop (BUILT + DEPLOYED):** generate rules for config B's
  gaps, deploy as `[SB-C]` scheduled rules via ARM, re-measure, show the gaps
  close. The headline claim, now real — see Status for results. A/B/C numbers:
  **0/15 → 1/15 → ~6-7/15** (control → built-in → built-in + generated).

## Honest limitations (already documented in README §Limitations)

- Brute-force (T1110.001) generates 4625 type-3 events with **no source IP**
  (local `LogonUser` call), so rules correlating failures per source IP can't
  fire. Real miss, not a tool bug.
- T1136.001's account is removed by ART cleanup, so a built-in
  "created-and-deleted" rule catching it depends on cleanup timing. (Config C's
  `[SB-C]` rule avoids this — it keys on the 4720 creation event, which
  persists in the log after the account is deleted.)
- **T1003.001 (LSASS): no telemetry in the lab.** The workspace has no 4656
  (needs a SACL/"Audit Kernel Object" on lsass) and no Sysmon EventID 10
  (ProcessAccess not in the pinned Sysmon config). So no rule — built-in or
  generated — can detect LSASS access here. Documented config C residual, a
  telemetry-coverage limitation, not a rule failure.
- **T1547.001: rule-vs-atomic mismatch.** 1462 Sysmon-13 (registry) events
  exist but none touch a Run key, so the ART atomic likely used the
  startup-folder (file) variant or a path the rule doesn't cover. The `[SB-C]`
  registry rule therefore never matched. Fixable by aligning the rule to what
  the atomic actually does; left as a documented residual.
- **Logs-only lab:** Windows Security Events + Sysmon, no Defender XDR / MDE.
  Many built-in rules need those connectors and can't fire here — itself a
  realistic finding about "Windows-logs-only" deployments, but it bounds B.
- **`[SB-C]` catch latency ~7-10 min (amber/red band).** Scheduled rules run on
  a 5-min cadence + ingestion lag, so generated rules close the coverage gap
  but not instantly. Config B's built-ins were measured at the same 5-min
  cadence, so A/B/C latency is comparable.

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
- **Auto-shutdown drift:** the shutdown time lives in terraform
  (`auto_shutdown_time`, default `2300` IST). The user changed it to `0300` in
  the portal, which terraform does not know — so `terraform apply` reverts it
  to 2300. To keep 3am, set `auto_shutdown_time = "0300"` in the local tfvars
  before applying.
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
- Evidence-lineage wiring into the pipeline: **done** (`063719b`). Verified on
  live Sentinel (smoke test, run 5f8b3244): `collect_evidence` runs without
  error and attributed rows reach the generators.
- Generator evidence policy **resolved ("option A", 2026-10-10)**: rules are
  behavioral templates *grounded* in evidence (a `// Lab evidence` comment on
  every rule when telemetry exists) but evidence is **never seeded into
  detection logic** — in an ART lab the observed artifacts are synthetic and
  would overfit the rule. The old PowerShell/generic literal seeding was
  removed; the generic fallback now offers the observed process as a
  commented-out, "verify-not-an-artifact" suggestion, not an active filter.
  Docstring + README overclaims corrected. The earlier "widen seeding to more
  generators" task is intentionally NOT being done — it was the wrong goal.
- **Clean config B re-run with the current tool: DONE** (run `c5ba877d`,
  2026-10-10, 15/15 executed clean on commit `97f3faa`). Result: **1/15
  caught (6.7%)**. The one catch: T1685.005 Clear Event Logs — caught at
  T+10min, alert created at T+189s, severity **Medium (expected High →
  miscalibration finding)**. T1136.001 (account create/delete) MISSED this
  run where earlier analysis expected it; consistent with the documented
  cleanup/cadence timing sensitivity — run-to-run variance on a marginal
  detection. **VERIFIED** by a `SecurityAlert | ago(6h)` cross-check:
  exactly three rules fired in the window and the matcher handled each
  correctly — (1) "Security Event log cleared" [T1070] → credited to
  T1685.005 (T1070 is its pre-v19 lineage, in match_ids), the 1 catch;
  (2) "Powershell Empire Cmdlets" [51 techniques] → excluded by breadth
  guard; (3) "User account created and deleted" [**T1098, T1078**] → NOT
  credited to T1136.001, because it declares account-manipulation/valid-
  account techniques, not T1136 or its lineage. No under-crediting bug;
  1/15 stands.
  **Finding (tag mismatch):** T1136.001's account activity DID trigger a
  rule, but tagged T1098/T1078 — so the activity was detected yet
  mis-attributed by technique. "Did an alert fire?" (yes, loose) vs "does
  Sentinel have T1136.001-mapped coverage?" (no) are different questions;
  this project measures the latter. Belongs in the write-up. Do NOT add
  T1098/T1078 to T1136's match_ids — that reintroduces the fuzzy matching
  the breadth guard/Techniques-only fix removed.
  **Open (minor):** the account alerts cluster at 6:51–7:01 PM but T1136.001
  ran ~3h earlier (tech 4/15); couldn't map them to exec time from
  timestamps alone. Either a very-late detection or unrelated churn; doesn't
  change 1/15. `--show-results` prints per-technique exec times if we want
  the chain.
  **Headline:** ~12/15 techniques triggered NO alert at all in a Windows-
  logs-only deployment. KQL suggestions for the gaps are stored in the run;
  they are config C's input.
- Config C deploy: **DONE live** (2026-10-11). 8 `[SB-C]` scheduled rules
  deployed to the workspace via ARM for run c5ba877d's gaps (T1059.001/003,
  T1569.002, T1136.001, T1547.001, T1053.005, T1110.001, T1003.001); the 6
  `requires_tuning` skeletons skipped. Getting there surfaced bugs ARM's
  validators caught that nothing else had: (a) ARM needs a `tactics` entry per
  `techniques`; (b) generated KQL used `!has_any` (not a KQL operator →
  `not(x has_any ...)`), under-escaped backslashes in T1053.005, and a
  non-existent `HandleID` column in T1003.001 — all fixed in kql_generator.
  `--regenerate-kql --run-id <id>` rewrites a run's stored suggestions with the
  current generator (needed because deploy reads stored KQL, not fresh). The
  role grant + 3 ARM env vars (SUBSCRIPTION_ID/RESOURCE_GROUP/WORKSPACE_NAME =
  137e3504.../rg-sbench-lab/log-sbench-1n7xg) are in place on the VM `.env`.
  Workspace name `log-sbench-1n7xg`, query GUID `a6dd0ef6-bb96-4fc3-a768-
  cdabca5f9d81`. **A clean config C re-run (suppression off) is in flight** —
  record its result per Next #1.
- (historical) Config C deployer prerequisites — now all satisfied:
  1. **Role grant: in terraform now** (`azurerm_role_assignment.
     vm_writes_sentinel_rules`, Microsoft Sentinel Contributor on the
     workspace) — just needs `terraform apply` (creates one resource, does not
     touch the VM). Until applied, live deploys 403.
  2. Env vars `SENTINEL_SUBSCRIPTION_ID` / `SENTINEL_RESOURCE_GROUP` /
     `SENTINEL_WORKSPACE_NAME`: terraform now **outputs** all three
     (`sentinel_subscription_id` / `sentinel_resource_group` /
     `sentinel_workspace_name`) — copy into the VM `.env` or export them.
     Bootstrap `.env` writing was deliberately NOT modified: changing the
     bootstrap script re-triggers the VM extension, which re-downloads the
     pinned code ZIP and would revert the VM's branch.
  3. Open question to validate on first live deploy: do v19 technique IDs
     (e.g. T1685) pass ARM's `techniques` enum? If not, deploy with
     `include_attack_mapping=False` and have the config C re-run match `[SB-C]`
     rules by display-name prefix instead of the Techniques column.
- Alert suppression: **OFF by default** (reversed 2026-10-11). PT5H suppression
  was briefly on to curb re-fire, but it silently corrupts measurement — a rule
  that fired in a canary or earlier run stays suppressed for hours, so the next
  run false-MISSES it. The metrics engine credits only the first alert per
  window, so re-fire is cosmetic, not a correctness problem; cross-run
  suppression is. `build_rule_payload(suppress=True)` re-enables it for
  production rules.
- **Config C first run (c90b3f9c, 2026-10-11): 4/15 raw, but the cross-check
  shows 6/8 deployed rules actually work.** SecurityAlert (7h) confirms these
  `[SB-C]` rules fired with correct tag+severity: T1059.001, T1053.005,
  T1110.001 (credited in-run) and T1569.002, T1059.003, T1136.001 (fired
  earlier that morning → PT5H-suppressed through their full-run window → FALSE
  MISSES). Telemetry query: Sysmon 13 = 1462, 4697 = 1 exist; **4656 and Sysmon
  10 absent**. So of the 2 non-firing rules: T1547.001 has its telemetry
  (Sysmon 13) but didn't match → **rule-logic/parse bug to investigate** (the
  TargetObject values ART wrote need checking); T1003.001 **can't fire** — no
  4656, no Sysmon 10 → genuine **telemetry-coverage gap** (documented
  limitation). Net: with suppression off, config C ≈ **1 built-in + 6 [SB-C] =
  ~7/15** pending a clean re-run; T1547.001 could make 8 if the parse is fixed.

## Next — finish-line checklist

Config A/B/C are built and the lab works end to end. What remains is turning
the runs into a defensible, presentable result. In order:

**In flight:** a clean config C re-run is executing on the VM — suppression now
OFF, rules re-deployed (`--deploy-config-c ... --apply` on the suppression-off
code). It will be a new run_id, labelled "config C clean (suppression off)".

1. **Record the clean config C result** when it finishes: caught/15, which
   techniques, latencies, severity deltas. If any deployed-rule technique still
   shows missed, cross-check with
   `SecurityAlert | where AlertName startswith "[SB-C]"` to separate a real miss
   from timing. Expected ~6-7/15 (the 6 working `[SB-C]` rules + T1685.005
   built-in); T1547.001 and T1003.001 miss (documented residuals). Update
   Status with the final **A/B/C: 0/15 → 1/15 → N/15**.
2. **Config A control** (labelled 0/15 floor): built-in rules disabled, run
   `--suite v1 --max-wait 3 --notes "config A control"`. Fast (all missed).
   Asserted but never captured as a run.
3. **Optional:** one config B repeat for run-to-run variance.
4. **Results write-up** — the portfolio centerpiece. Methodology + A/B/C +
   the honest arc: the 12/15→1/15 integrity fix (Techniques-only matching +
   breadth guard), config C closing gaps, and the residuals stated plainly
   (T1003.001 telemetry gap, T1547.001 atomic mismatch, log-clear severity
   miscalibration, scheduled-rule latency). The measurement artifacts we caught
   and corrected (fake 12/15; suppression false-misses) are evidence of rigor —
   feature them, don't hide them.
5. **README:** fold the real results in (it has methodology but the results/
   roadmap tables still say "planned"/"in progress"); flip them to done.
6. **Dashboard** (`dashboard/`, React + `api.py`): point at the real run DB,
   capture a screenshot/GIF for the README.
7. **Resume bullets** — rewrite around the real, defensible numbers.
8. **Teardown + stop:** `--teardown-config-c --apply` when analysis is done,
   then `az vm deallocate -g rg-sbench-lab -n vm-sbench`.
9. **PR to main** only when the user asks. Branch `claude/pensive-bohr-nxf0zf`
   holds everything. Decide whether this CLAUDE.md ships to main or stays
   working memory.

**Known fixable residuals (not blockers):** T1547.001 rule-vs-atomic mismatch;
the 6 `requires_tuning` techniques (T1552.001, T1555.003, T1040, T1112, T1027,
T1685) have no behavioral rule — honestly skipped, would need per-technique
generators (out of v1 scope).

## Conventions

- Work on branch `claude/pensive-bohr-nxf0zf`. Don't push elsewhere without
  explicit permission.
- `python -m ruff check . && python -m pytest -q` must pass before commit.
  ruff pinned to `0.16.10` (two binaries exist on some machines; use the
  pinned one). Config in `pyproject.toml`.
- Commits end with the `Co-Authored-By` / `Claude-Session` footer.
- Don't open a PR unless the user asks.

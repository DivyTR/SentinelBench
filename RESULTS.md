# SentinelBench — Results

**The question:** In a Windows-logs-only Microsoft Sentinel deployment, how many
of 15 ATT&CK techniques do the out-of-the-box analytics rules actually detect —
how fast, and at what severity — and can auto-generated rules close the gaps?

**The measured answer:**

| Config | Analytics rules in the workspace | Techniques detected within 15 min |
|-------:|----------------------------------|:---------------------------------:|
| **A — control** | none | **0 / 15** *(by construction)* |
| **B — built-in** | Microsoft's Windows Security Events rules, 5-min frequency | **1 / 15** |
| **C — closed loop** | built-in **+** SentinelBench-generated rules | **7 / 15** |

Microsoft's built-in rules caught **1 of 15**. SentinelBench generated candidate
rules for the gaps, deployed them to Sentinel, and re-measured: detection rose to
**7 of 15** — the generated rules closed **6** gaps. Every number below traces to a
specific, reproducible run, and every caveat is stated rather than buried.

> This project's only real value is honesty of measurement. An earlier version of
> the tool reported **12/15** for config B. That was false — three measurement bugs
> inflated it. Finding and fixing them (see *Measurement integrity*) is as much a
> result as the detection numbers themselves.

---

## How detection is measured

- **Lab.** A Terraform-provisioned Windows VM with Sysmon and the Azure Monitor
  Agent, shipping Windows Security Events + Sysmon to a Log Analytics workspace
  with Microsoft Sentinel enabled. **Logs-only** — no Defender XDR / MDE.
  Anyone can rebuild it with `terraform apply`.
- **Techniques.** 15 MITRE ATT&CK techniques, each executed with a pinned Atomic
  Red Team test (pinned by `auto_generated_guid`, not test number, for
  reproducibility). ATT&CK v19 taxonomy (Defense Evasion split into Stealth /
  Defense Impairment).
- **"Detected"** means: after a technique executes, a *qualifying* Sentinel alert
  is created within **15 minutes** (polled at T+2/5/10/15). An alert qualifies only
  if:
  1. its declared **`Techniques`** column intersects the technique's ATT&CK ID(s) —
     we never read event text or the `Tactics` column;
  2. the rule maps to **≤ 8 techniques** (a *breadth guard* — a rule tagged with
     dozens of techniques is a catch-all, not a per-technique detection);
  3. it names the lab host.
- **Latency** = alert-creation time − execution time. **Severity accuracy** =
  assigned severity vs. the ATT&CK-derived expected severity.

The per-technique window and the declared-`Techniques`-only matching are the whole
ballgame: they are what separate "a rule fired somewhere" from "this technique is
actually covered."

---

## Config B — built-in rules: 1 / 15

*(run `c5ba877d`, 2026-10-10)*

| Technique | Detected | Latency | Severity (got / expected) |
|-----------|:--------:|:-------:|:-------------------------:|
| T1685.005 Clear Windows Event Logs | ✅ | 189 s | Medium / **High** |
| the other 14 | ❌ | — | — |

Cross-checked against the raw `SecurityAlert` table: exactly three rules fired in
the window, and the matcher handled each correctly —

- **"Security Event log cleared"** `[T1070]` → credited to T1685.005 (T1070 is its
  pre-v19 parent). The one catch.
- **"Powershell Empire Cmdlets"** `[51 techniques]` → excluded by the breadth
  guard. (Crediting this catch-all to all 51 is exactly how the fake 12/15 arose.)
- **"User account created and deleted"** `[T1098, T1078]` → *not* credited to
  T1136.001. The activity was detected, but the rule declares account-manipulation
  techniques, not Create-Account — see *Findings*.

**Headline for config B: ~12 of 15 techniques triggered no alert at all** in a
Windows-logs-only deployment.

---

## Config C — closed loop: 7 / 15

*(run `289b61d3`, 2026-10-11)*

SentinelBench generated a behavioral candidate rule for each miss, deployed the 8
with a real detection (via the Azure Resource Manager API, tagged `[SB-C]`), and
the suite was re-run against built-in **+** generated rules.

| # | Technique | Config B | Config C | Latency (C) | Detected by |
|--:|-----------|:--------:|:--------:|:-----------:|-------------|
| 1 | T1059.003 Windows Command Shell | ❌ | ✅ | 93 s | `[SB-C]` |
| 2 | T1059.001 PowerShell | ❌ | ✅ | 88 s | `[SB-C]` |
| 3 | T1569.002 Service Execution | ❌ | ✅ | 566 s | `[SB-C]` |
| 4 | T1136.001 Create Local Account | ❌ | ✅ | 561 s | `[SB-C]` |
| 5 | T1053.005 Scheduled Task/Job | ❌ | ✅ | 562 s | `[SB-C]` |
| 6 | T1110.001 Brute Force | ❌ | ✅ | 553 s | `[SB-C]` |
| 7 | T1685.005 Clear Windows Event Logs | ✅ | ✅ | 131 s | built-in |
| 8 | T1547.001 Registry Run Keys | ❌ | ❌ | — | *rule/atomic mismatch* |
| 9 | T1003.001 LSASS Memory | ❌ | ❌ | — | *no telemetry in lab* |
| 10–15 | T1552.001, T1555.003, T1040, T1112, T1027, T1685 | ❌ | ❌ | — | *no rule generated* |

**Config C = 7/15.** Of the 7, **6 are SentinelBench's generated `[SB-C]` rules**
and 1 is the pre-existing built-in. The generated rules closed 6 gaps the built-ins
missed — verified at the alert level: each caught technique's own rule fired.

---

## Findings

1. **Measurement integrity is the hardest part, not an afterthought.** The tool
   first reported **12/15** for config B. Three bugs caused it: (a) matching the
   technique ID out of the alert's *event text* — which contained the ART harness
   command line `Invoke-AtomicTest T1xxx`, so a technique matched its own
   invocation; (b) crediting a 51-technique catch-all rule to every technique; (c)
   account create/delete churn from the test harness. Matching on the declared
   `Techniques` column only, a breadth guard, and a standing brute-force account
   brought it to the honest **1/15**. *A benchmark you can't trust is worse than no
   benchmark.*

2. **"Detected" and "covered" are different questions.** T1136.001 (Create Local
   Account): in config B, Microsoft's "account created and deleted" rule *did* fire
   on the activity — but tagged `T1098/T1078` (Account Manipulation / Valid
   Accounts), not T1136. An analyst triaging that alert investigates account
   manipulation, not account creation. So "did an alert fire?" (yes) and "does
   Sentinel have T1136.001-mapped coverage?" (no) have different answers.
   SentinelBench measures the second — the one that matters for ATT&CK coverage —
   and a generated T1136-tagged rule closed it in config C.

3. **Coverage closes, but at scheduled-rule speed.** The generated rules are
   scheduled analytics rules (5-min cadence); their catches land at ~9 minutes
   (553–566 s) vs. the built-in log-clear rule's ~2–3 min. The gap is *closed* but
   not instant — an honest latency finding, measured at the same 5-min cadence for
   both configs so the comparison is fair.

4. **A built-in rule under-rates a High action.** The log-clear rule flags event-log
   clearing — a defense-evasion action that should be High — at **Medium**. A real,
   reportable severity-calibration gap.

5. **The methodology caught its own measurement artifacts.** The first config C run
   scored 4/15; a cross-check revealed 3 of those "misses" were an alert-suppression
   setting silently suppressing rules that had fired earlier in testing. Removing it
   gave the true 7/15. Separately, because ARM requires parent-level ATT&CK tags,
   sibling sub-techniques (T1059.001 / T1059.003) can cross-attribute *severity*
   (the catch count is exact; one of the two recorded severity-miscalibrations is
   this artifact). Both were found by distrusting the numbers, not accepting them.

---

## Limitations (honest, and bounding)

- **Logs-only lab.** Windows Security Events + Sysmon, no Defender XDR / MDE. Many
  built-in Sentinel rules require those connectors and cannot fire here — itself a
  realistic finding about "we only forward Windows logs" deployments, but it bounds
  what config B can achieve.
- **T1003.001 (LSASS) is undetectable in this lab.** No 4656 (requires a SACL on
  lsass) and no Sysmon Event ID 10 (ProcessAccess not in the pinned Sysmon config),
  so *no* rule — built-in or generated — has anything to fire on. A
  telemetry-coverage gap, not a rule failure.
- **T1547.001: rule-vs-atomic mismatch.** 1 462 Sysmon registry events existed but
  none touched a Run key, so the ART atomic used a variant the generated registry
  rule didn't cover. Fixable by aligning the rule to the atomic.
- **6 techniques had no rule generated** (T1552.001, T1555.003, T1040, T1112,
  T1027, T1685). The generator produced only generic skeletons for these, which
  were deliberately *not* deployed — a match-everything rule is noise, not a
  detection. Honestly skipped rather than counted as fake coverage.
- **Brute force (T1110.001) produces no source IP** (local `LogonUser` API), so
  source-IP-correlation rules can't fire; the generated rule catches on the failure
  *volume* instead.
- **One run per config.** T1136.001 is timing-variable, so config B can read 1 or 2
  depending on cleanup timing; repeated runs for variance are future work. Config A
  (0/15) is the definitional floor, not a separately timed run.

---

## Reproducibility

```bash
# 1. Build the lab (Log Analytics + Sentinel + Windows VM + Sysmon + AMA + DCRs)
cd infra/terraform && terraform apply

# 2. Run the suite
python sentinelbench.py --suite v1                       # config B / C

# 3. Config C: generate, deploy, re-measure
python sentinelbench.py --deploy-config-c --run-id <run> --apply
python sentinelbench.py --suite v1 --notes "config C"
python sentinelbench.py --teardown-config-c --apply      # clean up
```

Run IDs behind the numbers above: config B `c5ba877d` (2026-10-10), config C
`289b61d3` (2026-10-11), both on a `Standard_B2s_v2` lab VM in a single Azure
subscription.

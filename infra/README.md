# SentinelBench lab infrastructure

Terraform that builds the complete lab in one Azure resource group:

| Component | Details |
|---|---|
| Log Analytics workspace | PerGB2018, 30-day retention, **daily ingestion cap** (default 1 GB) |
| Microsoft Sentinel | Onboarded only when `enable_sentinel = true` |
| Windows Server 2022 VM | `Standard_B2s`, system-assigned managed identity, RDP allowed **only from your IP**, auto-shutdown every night |
| Azure Monitor Agent + DCR | Security log → `SecurityEvent`; Sysmon, PowerShell 4104, selected System events, Defender and Task Scheduler logs → `Event` |
| Bootstrap | Audit policy, Sysmon (pinned config, SHA-256 verified), Atomic Red Team (pinned commits), Python, SentinelBench with managed-identity auth |
| Budget | Monthly budget on the resource group with email alerts at 50/80/100% and forecast 100% |

Nothing secret is created except the VM's admin password (a Terraform output).
SentinelBench on the VM authenticates as the VM's managed identity, which has
**Log Analytics Reader** on the workspace and nothing else.

## Prerequisites

- An Azure subscription where you are Owner (a new free account is)
- [Azure CLI](https://learn.microsoft.com/cli/azure/install-azure-cli) and `az login`
- [Terraform](https://developer.hashicorp.com/terraform/install) 1.9 or newer
- An RDP client

## 1. Deploy without Sentinel

Enabling Sentinel starts its free-trial clock, so first prove the plumbing works.

```bash
cd infra/terraform
cp terraform.tfvars.example terraform.tfvars   # fill in your values
terraform init
terraform plan -out lab.tfplan
terraform apply lab.tfplan
```

Bootstrap runs as part of `apply` and takes roughly 15–30 minutes, mostly downloading
Atomic Red Team. If it fails, read `C:\SentinelBench\bootstrap.log` on the VM.

## 2. Check that telemetry arrives

Wait about 10 minutes after `apply` finishes, then run these in the workspace's
**Logs** blade (or `az monitor log-analytics query -w $(terraform output -raw workspace_id) --analytics-query "..."`):

```kusto
// Agent is connected
Heartbeat | summarize last_seen = max(TimeGenerated) by Computer

// Sysmon is flowing (expect EventIDs 1, 3, 11, 13, ...)
Event | where Source == "Microsoft-Windows-Sysmon" | summarize count() by EventID

// Security log is flowing (expect 4624, 4688, ...)
SecurityEvent | summarize count() by EventID

// What is costing you ingestion
Usage | where TimeGenerated > ago(1d) | summarize MB = sum(Quantity) by DataType | order by MB desc
```

I am not certain whether the workspace accepts `SecurityEvent` data before
Sentinel (or Defender for Cloud) is enabled on it. If `Heartbeat` and `Event` have
data but `SecurityEvent` is empty, that is the likely reason. Enable Sentinel
(step 3) and check again before debugging further.

## 3. Enable Sentinel

```bash
# terraform.tfvars: enable_sentinel = true
terraform apply
```

At this point the workspace has **no analytics rules**, which is benchmark
configuration A (the control). Configuration B, Content Hub out-of-the-box rules,
is installed separately in Phase 3.

## 4. Run SentinelBench on the VM

```bash
terraform output -raw admin_password   # copy it
terraform output vm_public_ip
```

RDP in as `sbadmin`, then:

1. **Open Microsoft Edge once** and close it. T1555.003 copies the Edge profile,
   which only exists after the first launch.
2. Open **PowerShell as Administrator** (most tests need elevation):

```powershell
cd C:\SentinelBench\app
python sentinelbench.py --technique T1059.003   # one technique first
python sentinelbench.py --suite v1               # full suite: up to ~4 hours
```

`C:\SentinelBench\provenance.json` records the exact Sysmon version, config hash,
ART commits, Defender state and audit policy of the run. Keep a copy with every
set of results you publish.

## 5. Stop paying

- The VM **deallocates nightly** at `auto_shutdown_time`. Start it again with
  `az vm start -g rg-sbench-lab -n vm-sbench`.
- Stopping it from inside Windows does **not** deallocate it, so compute billing
  continues. Use the portal, `az vm deallocate` or auto-shutdown.
- Between experiment sessions: `terraform destroy`. Everything is reproducible.
  Copy `C:\SentinelBench\app\sentinelbench.db` and `provenance.json` off the VM first.

Approximate running costs: the VM is billed per hour while running. The OS disk,
the public IP and log retention are billed even when the VM is deallocated.
Log ingestion is billed per GB once any Sentinel/Log Analytics free allowance runs
out. Check current prices for your region in the
[Azure pricing calculator](https://azure.microsoft.com/pricing/calculator/). The
budget alerts are the safety net.

## Design decisions worth knowing

- **Windows Update is disabled** (`patch_mode = "Manual"`). An update or reboot in
  the middle of a run would corrupt the results. The VM is short-lived and only your
  IP can reach it; patch it manually if you keep it for weeks.
- **Defender stays on**, with one folder exclusion for `C:\AtomicRedTeam`, so ART's
  payload files are not quarantined before a test starts. Behaviour monitoring, AMSI
  and Tamper Protection still act on what the tests *do*. Several tests (LSASS dump,
  stopping WinDefend) are expected to be blocked; the block itself is telemetry.
- **The bootstrap script is VM custom data.** Editing
  `scripts/bootstrap.ps1.tftpl` therefore **replaces the VM** on the next apply.
  That is deliberate: the lab is disposable and should always match the code.
- **Pinned inputs**: the Sysmon config (release tag + SHA-256), Atomic Red Team and
  invoke-atomicredteam (commit SHAs). Sysinternals publishes no versioned Sysmon
  URLs, so the binary is the latest signed release. Its version is recorded in
  `provenance.json`.
- **Clock accuracy**: latency is measured against the VM's clock. Azure VMs sync
  time from the host, but record `w32tm /query /status` alongside results if
  sub-second precision matters to your claims.

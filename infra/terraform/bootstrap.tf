# ── VM bootstrap ──────────────────────────────────────────────────────────────
#
# The full script travels as custom_data (written by Azure to
# C:\AzureData\CustomData.bin, up to 64 KB) and a small run command executes
# it. That keeps the script out of command-line length limits and makes it
# readable in one place: ../scripts/bootstrap.ps1.tftpl.

locals {
  bootstrap_script = templatefile("${path.module}/../scripts/bootstrap.ps1.tftpl", {
    workspace_id         = azurerm_log_analytics_workspace.lab.workspace_id
    art_atomics_commit   = var.art_atomics_commit
    invoke_art_commit    = var.invoke_art_commit
    sysmon_config_url    = var.sysmon_config_url
    sysmon_config_sha256 = lower(var.sysmon_config_sha256)
    sentinelbench_repo   = var.sentinelbench_repo
    sentinelbench_ref    = var.sentinelbench_ref
  })
}

resource "azurerm_virtual_machine_run_command" "bootstrap" {
  name               = "sentinelbench-bootstrap"
  location           = azurerm_resource_group.lab.location
  virtual_machine_id = azurerm_windows_virtual_machine.lab.id
  tags               = var.tags

  source {
    script = <<-EOT
      # bootstrap sha256: ${sha256(local.bootstrap_script)}
      $ErrorActionPreference = 'Stop'
      New-Item -ItemType Directory -Force -Path C:\SentinelBench | Out-Null
      Copy-Item C:\AzureData\CustomData.bin C:\SentinelBench\bootstrap.ps1 -Force
      & powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\SentinelBench\bootstrap.ps1
      exit $LASTEXITCODE
    EOT
  }

  timeouts {
    create = "90m"
    update = "90m"
  }

  # Sysmon and the agent should both be in place before the first benchmark;
  # ordering after the DCR association means telemetry from bootstrap itself
  # is already flowing.
  depends_on = [
    azurerm_virtual_machine_extension.ama,
    azurerm_monitor_data_collection_rule_association.events,
  ]
}

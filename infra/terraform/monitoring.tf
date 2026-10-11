# ── Azure Monitor Agent + data collection ─────────────────────────────────────
#
# What reaches the workspace, and which table it lands in:
#
#   SecurityEvent  <- Security log (all events). Audit policy on the VM decides
#                     what is generated: 4688 process creation with command
#                     line, 4624/4625 logons, 4697 service install, 4698 task
#                     creation, 4720 account creation, 1102 log cleared, ...
#   Event          <- Sysmon, PowerShell script blocks (4104), selected System
#                     events (7045 service installed, 104 log cleared), Windows
#                     Defender operational log (1116/1117 detections and blocks),
#                     Task Scheduler registrations.

resource "azurerm_virtual_machine_extension" "ama" {
  name                       = "AzureMonitorWindowsAgent"
  virtual_machine_id         = azurerm_windows_virtual_machine.lab.id
  publisher                  = "Microsoft.Azure.Monitor"
  type                       = "AzureMonitorWindowsAgent"
  type_handler_version       = "1.0"
  auto_upgrade_minor_version = true
  automatic_upgrade_enabled  = true
  tags                       = var.tags
}

# Two rules on purpose. The Microsoft-SecurityEvent stream is rejected
# ("Data collection rule is invalid") unless the workspace has Sentinel (or
# Defender for Cloud) enabled, so the Security-log rule only exists when
# enable_sentinel is true. The Event rule works on a plain workspace and is
# enough to prove the pipeline before the Sentinel trial clock starts.

resource "azurerm_monitor_data_collection_rule" "events" {
  name                = "dcr-${local.name}-events"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
  kind                = "Windows"
  tags                = var.tags

  destinations {
    log_analytics {
      name                  = "lab-workspace"
      workspace_resource_id = azurerm_log_analytics_workspace.lab.id
    }
  }

  data_sources {
    windows_event_log {
      name    = "sysmon-and-friends"
      streams = ["Microsoft-Event"]
      x_path_queries = [
        "Microsoft-Windows-Sysmon/Operational!*",
        "Microsoft-Windows-PowerShell/Operational!*[System[(EventID=4103 or EventID=4104)]]",
        "System!*[System[(EventID=104 or EventID=7036 or EventID=7040 or EventID=7045)]]",
        "Microsoft-Windows-Windows Defender/Operational!*",
        "Microsoft-Windows-TaskScheduler/Operational!*[System[(EventID=106 or EventID=140 or EventID=141)]]",
      ]
    }
  }

  data_flow {
    streams      = ["Microsoft-Event"]
    destinations = ["lab-workspace"]
  }
}

resource "azurerm_monitor_data_collection_rule_association" "events" {
  name                    = "dcra-${local.name}-events"
  target_resource_id      = azurerm_windows_virtual_machine.lab.id
  data_collection_rule_id = azurerm_monitor_data_collection_rule.events.id
}

# Right after onboarding, Azure still rejects a Security-log rule with the
# same "Data collection rule is invalid" error for a few minutes. Observed on
# the first deployment: the identical rule succeeded on a retry ~5 minutes
# later. If 5 minutes ever proves too short, simply re-run terraform apply.
resource "time_sleep" "after_sentinel_onboarding" {
  count           = var.enable_sentinel ? 1 : 0
  create_duration = "5m"
  depends_on      = [azurerm_sentinel_log_analytics_workspace_onboarding.lab]
}

resource "azurerm_monitor_data_collection_rule" "security" {
  count               = var.enable_sentinel ? 1 : 0
  name                = "dcr-${local.name}-security"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
  kind                = "Windows"
  tags                = var.tags

  destinations {
    log_analytics {
      name                  = "lab-workspace"
      workspace_resource_id = azurerm_log_analytics_workspace.lab.id
    }
  }

  data_sources {
    windows_event_log {
      name           = "security-events"
      streams        = ["Microsoft-SecurityEvent"]
      x_path_queries = ["Security!*"]
    }
  }

  data_flow {
    streams      = ["Microsoft-SecurityEvent"]
    destinations = ["lab-workspace"]
  }

  depends_on = [time_sleep.after_sentinel_onboarding]
}

resource "azurerm_monitor_data_collection_rule_association" "security" {
  count                   = var.enable_sentinel ? 1 : 0
  name                    = "dcra-${local.name}-security"
  target_resource_id      = azurerm_windows_virtual_machine.lab.id
  data_collection_rule_id = azurerm_monitor_data_collection_rule.security[0].id
}

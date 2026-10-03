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

resource "azurerm_monitor_data_collection_rule" "lab" {
  name                = "dcr-${local.name}-windows"
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
    streams      = ["Microsoft-SecurityEvent"]
    destinations = ["lab-workspace"]
  }

  data_flow {
    streams      = ["Microsoft-Event"]
    destinations = ["lab-workspace"]
  }
}

resource "azurerm_monitor_data_collection_rule_association" "lab" {
  name                    = "dcra-${local.name}-windows"
  target_resource_id      = azurerm_windows_virtual_machine.lab.id
  data_collection_rule_id = azurerm_monitor_data_collection_rule.lab.id
}

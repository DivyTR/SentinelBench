output "vm_public_ip" {
  description = "RDP to this address (only from admin_source_cidr)."
  value       = azurerm_public_ip.vm.ip_address
}

output "vm_computer_name" {
  description = "Windows hostname; SentinelBench filters alerts to it."
  value       = azurerm_windows_virtual_machine.lab.computer_name
}

output "admin_username" {
  value = var.admin_username
}

output "admin_password" {
  description = "terraform output -raw admin_password"
  value       = random_password.admin.result
  sensitive   = true
}

output "workspace_id" {
  description = "Log Analytics workspace (customer) ID, i.e. SENTINEL_WORKSPACE_ID."
  value       = azurerm_log_analytics_workspace.lab.workspace_id
}

output "workspace_resource_id" {
  value = azurerm_log_analytics_workspace.lab.id
}

output "sentinel_enabled" {
  value = var.enable_sentinel
}

# ── config C rule deployment (ARM) ──────────────────────────────────────────────
# The rule deployer talks to ARM, which addresses the workspace by
# subscription / resource group / name — not the query GUID above. Set these
# three as env vars on the VM before `--deploy-config-c`.

output "sentinel_subscription_id" {
  description = "SENTINEL_SUBSCRIPTION_ID for config C rule deployment."
  value       = data.azurerm_client_config.current.subscription_id
}

output "sentinel_resource_group" {
  description = "SENTINEL_RESOURCE_GROUP for config C rule deployment."
  value       = azurerm_resource_group.lab.name
}

output "sentinel_workspace_name" {
  description = "SENTINEL_WORKSPACE_NAME (the ARM resource name, not the query GUID)."
  value       = azurerm_log_analytics_workspace.lab.name
}

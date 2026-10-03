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

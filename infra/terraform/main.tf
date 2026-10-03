locals {
  name = var.prefix
}

resource "azurerm_resource_group" "lab" {
  name     = "rg-${local.name}-lab"
  location = var.location
  tags     = var.tags
}

# ── Log Analytics + Sentinel ──────────────────────────────────────────────────

resource "random_string" "suffix" {
  length  = 5
  upper   = false
  special = false
}

resource "azurerm_log_analytics_workspace" "lab" {
  name                = "log-${local.name}-${random_string.suffix.result}"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
  sku                 = "PerGB2018"
  retention_in_days   = var.log_retention_days
  daily_quota_gb      = var.log_daily_quota_gb
  tags                = var.tags
}

resource "azurerm_sentinel_log_analytics_workspace_onboarding" "lab" {
  count        = var.enable_sentinel ? 1 : 0
  workspace_id = azurerm_log_analytics_workspace.lab.id
}

# ── Network: one subnet, RDP from your IP only ────────────────────────────────

resource "azurerm_virtual_network" "lab" {
  name                = "vnet-${local.name}"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
  address_space       = ["10.42.0.0/16"]
  tags                = var.tags
}

resource "azurerm_subnet" "lab" {
  name                 = "snet-lab"
  resource_group_name  = azurerm_resource_group.lab.name
  virtual_network_name = azurerm_virtual_network.lab.name
  address_prefixes     = ["10.42.1.0/24"]
}

resource "azurerm_network_security_group" "lab" {
  name                = "nsg-${local.name}"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
  tags                = var.tags

  security_rule {
    name                       = "allow-rdp-from-admin"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "3389"
    source_address_prefix      = var.admin_source_cidr
    destination_address_prefix = "*"
  }
}

resource "azurerm_subnet_network_security_group_association" "lab" {
  subnet_id                 = azurerm_subnet.lab.id
  network_security_group_id = azurerm_network_security_group.lab.id
}

resource "azurerm_public_ip" "vm" {
  name                = "pip-${local.name}-vm"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
  allocation_method   = "Static"
  sku                 = "Standard"
  tags                = var.tags
}

resource "azurerm_network_interface" "vm" {
  name                = "nic-${local.name}-vm"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
  tags                = var.tags

  ip_configuration {
    name                          = "primary"
    subnet_id                     = azurerm_subnet.lab.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.vm.id
  }
}

# ── Lab VM ────────────────────────────────────────────────────────────────────

resource "random_password" "admin" {
  length           = 24
  special          = true
  override_special = "!#%*-_=+"
  min_lower        = 2
  min_upper        = 2
  min_numeric      = 2
  min_special      = 2
}

resource "azurerm_windows_virtual_machine" "lab" {
  # Windows computer names are limited to 15 characters; SentinelBench uses
  # this name to filter alerts to this host.
  name                  = "vm-${local.name}"
  computer_name         = "${local.name}-lab"
  location              = azurerm_resource_group.lab.location
  resource_group_name   = azurerm_resource_group.lab.name
  size                  = var.vm_size
  admin_username        = var.admin_username
  admin_password        = random_password.admin.result
  network_interface_ids = [azurerm_network_interface.vm.id]
  tags                  = var.tags

  # Windows Update must not install or reboot in the middle of a benchmark
  # run. The VM is short-lived and reachable only from admin_source_cidr;
  # patch it manually between runs if you keep it for long.
  patch_mode                = "Manual"
  automatic_updates_enabled = false

  # Written to C:\AzureData\CustomData.bin; executed by the run command below.
  custom_data = base64encode(local.bootstrap_script)

  identity {
    type = "SystemAssigned"
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "StandardSSD_LRS"
  }

  source_image_reference {
    publisher = "MicrosoftWindowsServer"
    offer     = "WindowsServer"
    sku       = "2022-datacenter-smalldisk-g2"
    version   = "latest"
  }
}

resource "azurerm_dev_test_global_vm_shutdown_schedule" "lab" {
  virtual_machine_id    = azurerm_windows_virtual_machine.lab.id
  location              = azurerm_resource_group.lab.location
  enabled               = true
  daily_recurrence_time = var.auto_shutdown_time
  timezone              = var.auto_shutdown_timezone
  tags                  = var.tags

  notification_settings {
    enabled = false
  }
}

# SentinelBench on the VM authenticates as the VM's managed identity, so no
# client secret exists anywhere.
resource "azurerm_role_assignment" "vm_reads_logs" {
  scope                = azurerm_log_analytics_workspace.lab.id
  role_definition_name = "Log Analytics Reader"
  principal_id         = azurerm_windows_virtual_machine.lab.identity[0].principal_id
}

# ── Cost guardrail ────────────────────────────────────────────────────────────

resource "azurerm_consumption_budget_resource_group" "lab" {
  name              = "budget-${local.name}-lab"
  resource_group_id = azurerm_resource_group.lab.id
  amount            = var.budget_amount
  time_grain        = "Monthly"

  time_period {
    start_date = var.budget_start_date
  }

  dynamic "notification" {
    for_each = {
      actual-50      = { threshold = 50, type = "Actual" }
      actual-80      = { threshold = 80, type = "Actual" }
      actual-100     = { threshold = 100, type = "Actual" }
      forecasted-100 = { threshold = 100, type = "Forecasted" }
    }
    content {
      enabled        = true
      operator       = "GreaterThanOrEqualTo"
      threshold      = notification.value.threshold
      threshold_type = notification.value.type
      contact_emails = [var.budget_contact_email]
    }
  }

  lifecycle {
    # Azure rewrites start_date formatting; avoid perpetual diffs.
    ignore_changes = [time_period]
  }
}

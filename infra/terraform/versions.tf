terraform {
  required_version = ">= 1.9"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 5.8"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

provider "azurerm" {
  features {
    resource_group {
      # Let `terraform destroy` remove things created outside Terraform
      # (e.g. Sentinel content you install from the portal while experimenting).
      prevent_deletion_if_contains_resources = false
    }
  }
  subscription_id = var.subscription_id

  # A new subscription has almost no resource providers registered, and
  # azurerm 5.x does not register them implicitly. Register exactly the
  # namespaces this lab uses (Terraform waits for registration to finish).
  resource_providers_to_register = [
    "Microsoft.Compute",              # VM, extensions, run command
    "Microsoft.Consumption",          # budget
    "Microsoft.DevTestLab",           # VM auto-shutdown schedule
    "Microsoft.Insights",             # data collection rule + association
    "Microsoft.ManagedIdentity",      # VM system-assigned identity
    "Microsoft.Network",              # VNet, NSG, public IP, NIC
    "Microsoft.OperationalInsights",  # Log Analytics workspace
    "Microsoft.OperationsManagement", # Sentinel onboarding dependencies
    "Microsoft.SecurityInsights",     # Sentinel
  ]
}

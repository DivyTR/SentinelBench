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
}

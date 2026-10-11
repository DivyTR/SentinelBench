variable "subscription_id" {
  description = "Azure subscription to deploy into (az account show --query id -o tsv)."
  type        = string
}

variable "location" {
  description = "Azure region. Pick one close to you that offers the VM size."
  type        = string
  default     = "germanywestcentral"
}

variable "prefix" {
  description = "Short name prefix for all resources."
  type        = string
  default     = "sbench"

  validation {
    condition     = can(regex("^[a-z][a-z0-9]{2,9}$", var.prefix))
    error_message = "prefix must be 3-10 lowercase letters/digits, starting with a letter."
  }
}

variable "admin_source_cidr" {
  description = "Your public IP as a /32 (curl -s https://ifconfig.me). The only address allowed to RDP to the VM."
  type        = string

  validation {
    condition     = can(cidrhost(var.admin_source_cidr, 0)) && !contains(["0.0.0.0/0", "*"], var.admin_source_cidr)
    error_message = "admin_source_cidr must be a specific CIDR such as 203.0.113.7/32, never 0.0.0.0/0."
  }
}

variable "admin_username" {
  description = "Local administrator account on the lab VM."
  type        = string
  default     = "sbadmin"
}

variable "vm_size" {
  description = "VM size. Windows + Sysmon + Azure Monitor Agent + ART needs at least 2 vCPU / 4 GiB."
  type        = string
  default     = "Standard_B2s"
}

variable "enable_sentinel" {
  description = <<-EOT
    Onboard Microsoft Sentinel to the workspace. Leave false for the first
    apply to check that logs flow, then set true when you are ready to start
    benchmarking (enabling Sentinel starts its free-trial clock).
  EOT
  type        = bool
  default     = false
}

variable "log_daily_quota_gb" {
  description = "Hard cap on daily Log Analytics ingestion. Ingestion stops for the day once reached (a missed-detection risk, so watch the Usage table)."
  type        = number
  default     = 1
}

variable "log_retention_days" {
  description = "Log Analytics retention."
  type        = number
  default     = 30
}

variable "auto_shutdown_time" {
  description = "Daily VM auto-shutdown time (HHMM, in auto_shutdown_timezone). Shutdown deallocates, so compute billing stops."
  type        = string
  default     = "2300"
}

variable "auto_shutdown_timezone" {
  description = "Windows time zone ID for auto-shutdown."
  type        = string
  default     = "India Standard Time"
}

variable "budget_amount" {
  description = "Monthly budget for the lab resource group, in your billing currency."
  type        = number
  default     = 30
}

variable "budget_contact_email" {
  description = "Email that receives budget alerts."
  type        = string
}

variable "budget_start_date" {
  description = "First day of the month the budget starts, RFC3339 (e.g. 2026-10-01T00:00:00Z)."
  type        = string
}

variable "sentinelbench_repo" {
  description = "GitHub owner/repo the VM downloads SentinelBench from. Must be public, or the download step is skipped."
  type        = string
  default     = "DivyTR/SentinelBench"
}

variable "sentinelbench_ref" {
  description = "Branch, tag or commit of SentinelBench to install on the VM."
  type        = string
  default     = "main"
}

variable "art_atomics_commit" {
  description = "Atomic Red Team commit to install atomics from. Pinned so every run executes identical tests."
  type        = string
  default     = "388942adbd9641f4dfdcf079d7efe9a75ec0ac43"
}

variable "invoke_art_commit" {
  description = "invoke-atomicredteam (the PowerShell execution framework) commit to install."
  type        = string
  default     = "8af478bb9e4637df568ac1e596553b025b16cd1b"
}

variable "sysmon_config_url" {
  description = "Pinned sysmon-modular release asset."
  type        = string
  default     = "https://github.com/olafhartong/sysmon-modular/releases/download/configs-082cba578667/sysmonconfig.xml"
}

variable "sysmon_config_sha256" {
  description = "SHA-256 of sysmon_config_url; the VM refuses a config that does not match."
  type        = string
  default     = "f115aac5770dae468e5cfb48c58a8b6e37588208a31f1b746812c534577a244b"
}

variable "tags" {
  description = "Tags applied to every resource."
  type        = map(string)
  default = {
    project = "sentinelbench"
    purpose = "lab"
  }
}

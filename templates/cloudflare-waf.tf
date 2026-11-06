# DEFCON-1 Military-Grade Cloudflare WAF & Ruleset Terraform Configuration
# Provider: cloudflare/cloudflare ~> 4.0
# Enforces edge threat scoring, bot challenges, sensitive file blocking, and brute-force throttling.

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 4.0"
    }
  }
}

variable "zone_id" {
  type        = string
  description = "Cloudflare Target Zone ID"
}

# 1. Custom WAF Ruleset (Phase: http_request_firewall_custom)
resource "cloudflare_ruleset" "defcon_waf_rules" {
  zone_id     = var.zone_id
  name        = "DEFCON-1 Application Shield"
  description = "Military-grade WAF rules protecting against reconnaissance, bots, and perimeter scans"
  kind        = "zone"
  phase       = "http_request_firewall_custom"

  # Rule 1: Block Reconnaissance & Sensitive File Probing (SpiderFoot EASM Shield)
  rules {
    action      = "block"
    expression  = "(http.request.uri.path contains \"/phpmyadmin\") or (http.request.uri.path contains \"/.env\") or (http.request.uri.path contains \"/.git\") or (http.request.uri.path contains \"/wp-login.php\") or (http.request.uri.path contains \"/xmlrpc.php\")"
    description = "Instantly drop requests probing for VCS repositories (.git), environment files (.env), or legacy admin consoles"
    enabled     = true
  }

  # Rule 2: Challenge Suspicious Threat Scores & Automated Scrapers
  rules {
    action      = "managed_challenge"
    expression  = "(cf.threat_score gt 20) or (cf.bot_management.score lt 20 and not cf.bot_management.verified_bot)"
    description = "Managed challenge against high threat scores, headless bot scrapers, and suspicious IP reputations"
    enabled     = true
  }
}

# 2. Rate Limiting Ruleset for Authentication Endpoints (Phase: http_ratelimit)
resource "cloudflare_ruleset" "defcon_rate_limiting" {
  zone_id     = var.zone_id
  name        = "DEFCON-1 Auth Rate Limiting"
  description = "Strict anti-brute-force rate limiting on authentication endpoints"
  kind        = "zone"
  phase       = "http_ratelimit"

  rules {
    action      = "block"
    expression  = "(http.request.uri.path in {\"/api/auth/login\" \"/api/auth/token\" \"/api/auth/reset-password\" \"/api/v1/auth/login\"})"
    description = "Enforce max 5 login attempts per 60 seconds per IP, blocking for 15 minutes upon threshold breach"
    enabled     = true

    ratelimit {
      characteristics     = ["cf.unique_visitor_id"]
      period              = 60
      requests_per_period = 5
      mitigation_timeout  = 900
    }
  }
}


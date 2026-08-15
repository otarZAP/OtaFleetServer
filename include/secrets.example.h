#pragma once
// ─────────────────────────────────────────────────────────────────────────────
//  OtaFleetServer — secrets template
//  Copy this file to secrets.h and fill in real values before building.
//  secrets.h is gitignored and must NOT be committed to source control.
// ─────────────────────────────────────────────────────────────────────────────

// ─── WiFi network to join (STA mode) ─────────────────────────────────────────
#define WIFI_SSID        "your_wifi_ssid"
#define WIFI_PASSWORD    "your_wifi_password"

// ─── Fallback soft-AP password (used if STA connect fails) ───────────────────
#define FALLBACK_AP_PASS "change_me_min8chars"

// ─── Web admin credentials ────────────────────────────────────────────────────
#define ADMIN_USER       "admin"
#define ADMIN_PASS       "change_me_admin_password"

// ─── Firmware signing key — must match OTA_HMAC_KEY on every fleet device ────
#define OTA_HMAC_KEY     "change_me_unique_signing_key_min32chars"
